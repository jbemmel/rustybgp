// Copyright (C) 2019-2024 The RustyBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Borrowed views of canonical four-octet AS_PATH data.
//!
//! Construction validates every segment before exposing a view. Iteration then
//! borrows the original bytes and decodes individual ASNs without allocating.

use crate::bgp::Attribute;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed canonical AS path")]
pub struct MalformedAsPath;

/// A validated path. No ASN values, segment kinds, or repetitions are changed.
#[derive(Debug, Clone, Copy)]
pub struct AsPath<'a> {
    bytes: &'a [u8],
    encoding: Encoding,
    summary: Option<AsPathSummary>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Encoding {
    Canonical,
    #[cfg(feature = "packed-as-paths")]
    Escaped,
}

/// Small, on-demand routing summary; policy endpoint matching is distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsPathSummary {
    pub hop_count: usize,
    pub origin: Option<u32>,
}

impl<'a> AsPath<'a> {
    /// Validate the complete canonical encoding, including any trailing segment.
    /// ASN zero and empty segments retain the existing packet layer's semantics.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, MalformedAsPath> {
        let mut rest = bytes;
        while !rest.is_empty() {
            if rest.len() < 2
                || !(Attribute::AS_PATH_TYPE_SET..=Attribute::AS_PATH_TYPE_CONFED_SET)
                    .contains(&rest[0])
            {
                return Err(MalformedAsPath);
            }
            let size = 2 + usize::from(rest[1]) * 4;
            rest = rest.get(size..).ok_or(MalformedAsPath)?;
        }
        Ok(Self {
            bytes,
            encoding: Encoding::Canonical,
            summary: None,
        })
    }

    #[cfg(feature = "packed-as-paths")]
    pub(crate) fn stored(bytes: &'a [u8], encoding: Encoding, summary: AsPathSummary) -> Self {
        Self {
            bytes,
            encoding,
            summary: Some(summary),
        }
    }

    #[cfg(feature = "packed-as-paths")]
    pub(crate) fn canonical_bytes(self) -> impl Iterator<Item = u8> + 'a {
        self.segments().flat_map(|segment| {
            [segment.kind(), segment.len() as u8]
                .into_iter()
                .chain(segment.asns().flat_map(u32::to_be_bytes))
        })
    }

    pub fn segments(self) -> AsPathSegments<'a> {
        AsPathSegments {
            rest: self.bytes,
            encoding: self.encoding,
        }
    }

    /// Test presence, not multiplicity. All input was validated at construction,
    /// so a match cannot hide a malformed trailing segment.
    pub fn contains_any(self, targets: &[u32]) -> bool {
        self.segments()
            .any(|segment| segment.asns().any(|asn| targets.contains(&asn)))
    }

    pub fn summary(self) -> AsPathSummary {
        if let Some(summary) = self.summary {
            return summary;
        }
        let mut hop_count = 0;
        let mut origin = None;
        for segment in self.segments() {
            match segment.kind() {
                Attribute::AS_PATH_TYPE_SEQ => hop_count += segment.len(),
                Attribute::AS_PATH_TYPE_SET => hop_count += 1,
                _ => {}
            }
            origin = if segment.kind() == Attribute::AS_PATH_TYPE_SEQ {
                segment.asns().next_back()
            } else {
                None
            };
        }
        AsPathSummary { hop_count, origin }
    }
}

/// Borrowed ASN payload and segment type, retaining even empty segments.
#[derive(Debug, Clone, Copy)]
pub struct AsPathSegment<'a> {
    kind: u8,
    bytes: &'a [u8],
    count: usize,
    encoding: Encoding,
}

impl<'a> AsPathSegment<'a> {
    pub fn kind(self) -> u8 {
        self.kind
    }

    pub fn len(self) -> usize {
        self.count
    }

    pub fn is_empty(self) -> bool {
        self.count == 0
    }

    pub fn asns(self) -> AsPathAsns<'a> {
        AsPathAsns {
            bytes: self.bytes,
            count: self.count,
            encoding: self.encoding,
        }
    }
}

/// Bounded, allocation-free ASN decoding, retaining repetitions.
#[derive(Debug, Clone)]
pub struct AsPathAsns<'a> {
    bytes: &'a [u8],
    count: usize,
    encoding: Encoding,
}

impl Iterator for AsPathAsns<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        if self.count == 0 {
            return None;
        }
        let (asn, size) = decode(self.bytes, self.encoding);
        self.bytes = &self.bytes[size..];
        self.count -= 1;
        Some(asn)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.count, Some(self.count))
    }
}

impl DoubleEndedIterator for AsPathAsns<'_> {
    fn next_back(&mut self) -> Option<u32> {
        if self.count == 0 {
            return None;
        }
        let start = match self.encoding {
            Encoding::Canonical => self.bytes.len() - 4,
            #[cfg(feature = "packed-as-paths")]
            Encoding::Escaped => {
                // Escape payloads can contain zero units. Walk validated ASN
                // boundaries, never infer an escape by scanning backwards.
                let mut offset = 0;
                for _ in 1..self.count {
                    offset += decode(&self.bytes[offset..], self.encoding).1;
                }
                offset
            }
        };
        let asn = decode(&self.bytes[start..], self.encoding).0;
        self.bytes = &self.bytes[..start];
        self.count -= 1;
        Some(asn)
    }
}

impl ExactSizeIterator for AsPathAsns<'_> {}
impl std::iter::FusedIterator for AsPathAsns<'_> {}

fn decode(bytes: &[u8], encoding: Encoding) -> (u32, usize) {
    match encoding {
        Encoding::Canonical => (u32::from_be_bytes(bytes[..4].try_into().unwrap()), 4),
        #[cfg(feature = "packed-as-paths")]
        Encoding::Escaped => {
            let unit = u16::from_be_bytes(bytes[..2].try_into().unwrap());
            if unit != 0 {
                (u32::from(unit), 2)
            } else {
                (u32::from_be_bytes(bytes[2..6].try_into().unwrap()), 6)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct AsPathSegments<'a> {
    rest: &'a [u8],
    encoding: Encoding,
}

impl<'a> Iterator for AsPathSegments<'a> {
    type Item = AsPathSegment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        // Only AsPath::segments constructs this iterator, after full validation.
        let count = usize::from(self.rest[1]);
        let mut size = 2;
        match self.encoding {
            Encoding::Canonical => size += count * 4,
            #[cfg(feature = "packed-as-paths")]
            Encoding::Escaped => {
                for _ in 0..count {
                    size += decode(&self.rest[size..], self.encoding).1;
                }
            }
        }
        let (segment, rest) = self.rest.split_at(size);
        self.rest = rest;
        Some(AsPathSegment {
            kind: segment[0],
            bytes: &segment[2..],
            count,
            encoding: self.encoding,
        })
    }
}

impl std::iter::FusedIterator for AsPathSegments<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::AsPathIter;

    fn attribute(segments: &[(u8, &[u32])]) -> Attribute {
        let mut bytes = Vec::new();
        for (kind, asns) in segments {
            bytes.extend_from_slice(&[*kind, asns.len() as u8]);
            for asn in *asns {
                bytes.extend_from_slice(&asn.to_be_bytes());
            }
        }
        Attribute::new_with_bin(Attribute::AS_PATH, bytes).unwrap()
    }

    #[test]
    fn borrowed_segments_preserve_types_values_and_repetitions() {
        let attr = attribute(&[
            (2, &[1, 1, 65535, 65536, u32::MAX]),
            (1, &[9, 7]),
            (3, &[42, 42]),
            (4, &[6, 5]),
        ]);
        let path = attr.as_path().unwrap();
        #[cfg(not(feature = "packed-as-paths"))]
        assert_eq!(path.bytes.as_ptr(), attr.binary().unwrap().as_ptr());
        let borrowed: Vec<_> = path
            .segments()
            .map(|s| s.asns().collect::<Vec<_>>())
            .collect();
        assert_eq!(borrowed, AsPathIter::new(&attr).collect::<Vec<_>>());
        assert_eq!(
            path.segments().map(|s| s.kind()).collect::<Vec<_>>(),
            [2, 1, 3, 4]
        );
        assert!(path.contains_any(&[100, u32::MAX]));
        assert!(!path.contains_any(&[]));
        assert!(!path.contains_any(&[100]));
        assert_eq!(attr.as_path_count(1).unwrap(), 2);
        assert_eq!(attr.as_path_count(42).unwrap(), 2);
        assert_eq!(
            path.summary(),
            AsPathSummary {
                hop_count: 6,
                origin: None
            }
        );
        assert_eq!(path.summary().hop_count, attr.as_path_length());
        assert_eq!(path.summary().origin, attr.as_path_origin());
    }

    #[test]
    fn summary_uses_routing_not_serialized_endpoint_semantics() {
        for kind in 1..=4 {
            let attr = attribute(&[(3, &[90]), (2, &[65536, 7, 7]), (kind, &[12, 13])]);
            let summary = attr.as_path().unwrap().summary();
            assert_eq!(summary.hop_count, attr.as_path_length());
            assert_eq!(summary.origin, attr.as_path_origin());
            assert_eq!(summary.origin, if kind == 2 { Some(13) } else { None });
        }
        // No u8 overflow when multiple full segments exceed 255 hops.
        let full = vec![65001; 255];
        let attr = attribute(&[(2, &full), (2, &full)]);
        assert_eq!(attr.as_path().unwrap().summary().hop_count, 510);
        assert_eq!(attr.as_path_length(), 510);
    }

    #[test]
    fn empty_path_segments_and_zero_retain_existing_semantics() {
        for segments in [
            vec![],
            vec![(2, &[][..])],
            vec![(1, &[][..])],
            vec![(2, &[0][..])],
        ] {
            let attr = attribute(&segments);
            let path = attr.as_path().unwrap();
            assert_eq!(path.summary().hop_count, attr.as_path_length());
            assert_eq!(path.summary().origin, attr.as_path_origin());
            assert_eq!(path.contains_any(&[0]), attr.as_path_count(0).unwrap() > 0);
        }
        let path = AsPath::from_bytes(&[]).unwrap();
        let mut segments = path.segments();
        assert!(segments.next().is_none());
        assert!(segments.next().is_none());
    }

    #[test]
    fn reject_complete_malformed_path_even_after_a_matching_prefix() {
        for bytes in [
            vec![2],
            vec![2, 1],
            vec![2, 1, 0, 0, 1],
            vec![0, 0],
            vec![5, 0],
            vec![2, 0, 3],
        ] {
            assert!(AsPath::from_bytes(&bytes).is_err(), "{bytes:?}");
        }
        let prefix = attribute(&[(2, &[65001])]);
        for tail in [vec![2], vec![2, 1, 0], vec![5, 0]] {
            let mut bytes = prefix.binary().unwrap().to_vec();
            bytes.extend(tail);
            let attr = Attribute::new_with_bin(Attribute::AS_PATH, bytes).unwrap();
            assert!(attr.as_path().is_err());
        }
        let other = Attribute::new_with_bin(Attribute::COMMUNITY, vec![2, 0]).unwrap();
        assert!(other.as_path().is_err());
        assert!(
            Attribute::new_with_value(Attribute::ORIGIN, 0)
                .unwrap()
                .as_path()
                .is_err()
        );
    }

    #[test]
    fn deterministic_generated_paths_match_owned_iterator() {
        let mut state = 42u32;
        for count in 0..100 {
            let mut bytes = Vec::new();
            for segment in 0..count % 7 {
                bytes.extend_from_slice(&[1 + (segment % 4) as u8, (count % 20) as u8]);
                for _ in 0..count % 20 {
                    state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                    bytes.extend_from_slice(&state.to_be_bytes());
                }
            }
            let attr = Attribute::new_with_bin(Attribute::AS_PATH, bytes).unwrap();
            let owned = AsPathIter::new(&attr).collect::<Vec<_>>();
            let path = attr.as_path().unwrap();
            assert_eq!(
                path.segments()
                    .map(|s| s.asns().collect::<Vec<_>>())
                    .collect::<Vec<_>>(),
                owned
            );
            for target in [0, 65535, state] {
                assert_eq!(
                    path.contains_any(&[target]),
                    owned.iter().flatten().any(|asn| *asn == target)
                );
            }
        }
    }
}
