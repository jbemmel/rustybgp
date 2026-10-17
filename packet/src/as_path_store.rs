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

//! Receive-local, bounded weak interning. Entries outlive the store through Arc.
//! No mutable arena, decoded cache, relocation, or global receive-path lock.
use crate::as_path::{AsPath, AsPathSummary, Encoding, MalformedAsPath};
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, Weak};

const LENGTH_ESCAPE: u32 = 127;
const MAX_OFFSET_UNITS: usize = (1 << 25) - 1;

/// Common four-byte descriptor. Exceptional lengths live in the owning entry's
/// byte slice length. Each PR 2 entry owns one immutable allocation (offset zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathDescriptor(u32);

impl PathDescriptor {
    pub fn new(offset: usize, length: usize) -> Result<Self, StoreError> {
        if !offset.is_multiple_of(2) || !length.is_multiple_of(2) || offset / 2 > MAX_OFFSET_UNITS {
            return Err(StoreError::Capacity);
        }
        let units = (length / 2).min(LENGTH_ESCAPE as usize) as u32;
        Ok(Self(((offset / 2) as u32) << 7 | units))
    }

    pub fn word(self) -> u32 {
        self.0
    }
    pub fn offset(self) -> usize {
        (self.0 >> 7) as usize * 2
    }
    pub fn inline_length(self) -> Option<usize> {
        let units = self.0 & LENGTH_ESCAPE;
        (units != LENGTH_ESCAPE).then_some(units as usize * 2)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Malformed(#[from] MalformedAsPath),
    #[error("AS-path store capacity exhausted")]
    Capacity,
}

/// Stable, immutable ownership for routes, clones and asynchronous event queues.
/// The owning Arc is the stable handle; equality is path content, not its address.
#[derive(Debug)]
pub struct PathEntry {
    descriptor: PathDescriptor,
    bytes: Box<[u8]>,
    canonical_len: usize,
    canonical_hash: u64,
    encoding: Encoding,
    summary: AsPathSummary,
}

impl PathEntry {
    fn new(canonical: &[u8]) -> Result<Self, StoreError> {
        let view = AsPath::from_bytes(canonical)?;
        let summary = view.summary();
        let mut packed_len = 0usize;
        let mut has_zero = false;
        for segment in view.segments() {
            packed_len += 2;
            for asn in segment.asns() {
                has_zero |= asn == 0;
                packed_len += if asn <= u16::MAX as u32 { 2 } else { 6 };
            }
        }
        // Canonical fallback preserves packet semantics for zero and avoids
        // expansion on wide-heavy paths. No ambiguous zero escape is emitted.
        let compact = !has_zero && packed_len < canonical.len();
        let bytes = if compact {
            let mut out = Vec::with_capacity(packed_len);
            for segment in view.segments() {
                out.extend_from_slice(&[segment.kind(), segment.len() as u8]);
                for asn in segment.asns() {
                    if asn <= u16::MAX as u32 {
                        out.extend_from_slice(&(asn as u16).to_be_bytes());
                    } else {
                        out.extend_from_slice(&[0, 0]);
                        out.extend_from_slice(&asn.to_be_bytes());
                    }
                }
            }
            out.into_boxed_slice()
        } else {
            canonical.into()
        };
        Ok(Self {
            descriptor: PathDescriptor::new(0, bytes.len())?,
            bytes,
            canonical_len: canonical.len(),
            canonical_hash: content_hash(canonical),
            encoding: if compact {
                Encoding::Escaped
            } else {
                Encoding::Canonical
            },
            summary,
        })
    }

    pub fn descriptor(&self) -> PathDescriptor {
        self.descriptor
    }
    pub fn stored_bytes(&self) -> usize {
        self.bytes.len()
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Build the path that results from prepending one AS number.
    ///
    /// A path kept in canonical form is copied. A compact path splices the new
    /// AS number onto its stored bytes when that number fits in 16 bits.
    /// The previous entry is left unchanged.
    pub(crate) fn prepended(&self, kind: u8, asn: u32) -> Result<Self, StoreError> {
        let narrow = (1..=u16::MAX as u32).contains(&asn);
        if !self.is_compact() {
            let merge = !self.bytes.is_empty() && self.bytes[0] == kind && self.bytes[1] < 255;
            let mut canonical = Vec::with_capacity(self.bytes.len() + if merge { 4 } else { 6 });
            canonical.extend_from_slice(&[kind, if merge { self.bytes[1] + 1 } else { 1 }]);
            canonical.extend_from_slice(&asn.to_be_bytes());
            canonical.extend_from_slice(if merge { &self.bytes[2..] } else { &self.bytes });
            return Self::from_canonical_bytes(canonical, self.summary_after_prepend(kind, asn));
        }
        if narrow {
            return self.prepend_compact(kind, asn);
        }
        let mut canonical = Vec::with_capacity(self.canonical_len + 6);
        let mut segments = self.as_path().segments();
        let first = segments.next();
        if let Some(segment) = first.filter(|segment| segment.kind() == kind && segment.len() < 255)
        {
            write_segment(
                &mut canonical,
                kind,
                std::iter::once(asn).chain(segment.asns()),
            );
        } else {
            write_segment(&mut canonical, kind, std::iter::once(asn));
            if let Some(segment) = first {
                write_segment(&mut canonical, segment.kind(), segment.asns());
            }
        }
        for segment in segments {
            write_segment(&mut canonical, segment.kind(), segment.asns());
        }
        Self::new(&canonical)
    }

    fn prepend_compact(&self, kind: u8, asn: u32) -> Result<Self, StoreError> {
        let merge = !self.bytes.is_empty() && self.bytes[0] == kind && self.bytes[1] < 255;
        let mut packed = Vec::with_capacity(self.bytes.len() + if merge { 2 } else { 4 });
        packed.push(kind);
        packed.push(if merge { self.bytes[1] + 1 } else { 1 });
        packed.extend_from_slice(&(asn as u16).to_be_bytes());
        packed.extend_from_slice(if merge { &self.bytes[2..] } else { &self.bytes });
        let summary = self.summary_after_prepend(kind, asn);
        let canonical_len = self.canonical_len + if merge { 4 } else { 6 };
        let hash = hash_expanded(&packed, canonical_len);
        Self::assemble(packed, canonical_len, hash, Encoding::Escaped, summary)
    }

    fn summary_after_prepend(&self, kind: u8, asn: u32) -> AsPathSummary {
        let mut summary = self.summary;
        if kind == crate::bgp::Attribute::AS_PATH_TYPE_SEQ {
            summary.hop_count += 1;
            if self.canonical_len == 0 {
                summary.origin = Some(asn);
            }
        }
        summary
    }

    fn from_canonical_bytes(
        canonical: Vec<u8>,
        summary: AsPathSummary,
    ) -> Result<Self, StoreError> {
        let hash = content_hash(&canonical);
        let len = canonical.len();
        Self::assemble(canonical, len, hash, Encoding::Canonical, summary)
    }

    fn assemble(
        bytes: Vec<u8>,
        canonical_len: usize,
        canonical_hash: u64,
        encoding: Encoding,
        summary: AsPathSummary,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            descriptor: PathDescriptor::new(0, bytes.len())?,
            bytes: bytes.into_boxed_slice(),
            canonical_len,
            canonical_hash,
            encoding,
            summary,
        })
    }
    pub fn canonical_len(&self) -> usize {
        self.canonical_len
    }
    pub fn is_compact(&self) -> bool {
        matches!(self.encoding, Encoding::Escaped)
    }
    pub fn as_path(&self) -> AsPath<'_> {
        let offset = self.descriptor.offset();
        let length = self
            .descriptor
            .inline_length()
            .unwrap_or(self.bytes.len() - offset);
        AsPath::stored(
            &self.bytes[offset..offset + length],
            self.encoding,
            self.summary,
        )
    }
    pub(crate) fn fingerprint(&self) -> u64 {
        self.canonical_hash
    }
    pub(crate) fn matches(&self, canonical: &[u8]) -> bool {
        self.canonical_len == canonical.len()
            && self
                .as_path()
                .canonical_bytes()
                .eq(canonical.iter().copied())
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.canonical_len);
        out.extend(self.as_path().canonical_bytes());
        out
    }
}

impl PartialEq for PathEntry {
    fn eq(&self, other: &Self) -> bool {
        self.canonical_len == other.canonical_len
            && self.canonical_hash == other.canonical_hash
            && self
                .as_path()
                .canonical_bytes()
                .eq(other.as_path().canonical_bytes())
    }
}
impl Eq for PathEntry {}
impl Hash for PathEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical_hash.hash(state);
    }
}

fn write_segment(out: &mut Vec<u8>, kind: u8, asns: impl Iterator<Item = u32>) {
    let start = out.len();
    out.extend_from_slice(&[kind, 0]);
    let mut count = 0u8;
    for asn in asns {
        out.extend_from_slice(&asn.to_be_bytes());
        count += 1;
    }
    out[start + 1] = count;
}

pub(crate) fn content_hash(canonical: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    canonical.hash(&mut hasher);
    hasher.finish()
}

/// Hash the canonical four-octet image of escaped bytes without allocating it.
fn hash_expanded(packed: &[u8], canonical_len: usize) -> u64 {
    let mut hasher = DefaultHasher::new();
    canonical_len.hash(&mut hasher);
    let view = AsPath::stored(
        packed,
        Encoding::Escaped,
        AsPathSummary {
            hop_count: 0,
            origin: None,
        },
    );
    for segment in view.segments() {
        hasher.write(&[segment.kind(), segment.len() as u8]);
        for asn in segment.asns() {
            hasher.write(&asn.to_be_bytes());
        }
    }
    hasher.finish()
}

/// At most max_records weak references; live payload ownership stays with attrs.
/// Hash collisions replace an accelerator entry, never establish equality.
#[derive(Debug)]
pub struct AsPathStore {
    entries: HashMap<u64, Weak<PathEntry>>,
    max_records: usize,
    operations: usize,
}

impl Default for AsPathStore {
    fn default() -> Self {
        Self::new(16_384)
    }
}

impl AsPathStore {
    pub fn new(max_records: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_records,
            operations: 0,
        }
    }
    pub fn records(&self) -> usize {
        self.entries.len()
    }
    pub fn capacity(&self) -> usize {
        self.entries.capacity()
    }
    pub fn purge_expired(&mut self) {
        self.entries.retain(|_, entry| entry.strong_count() != 0);
    }

    /// Intern a transformed/shared entry without expanding its canonical bytes.
    pub fn intern_attributes(&mut self, attributes: &mut Arc<Vec<crate::bgp::Attribute>>) {
        for i in 0..attributes.len() {
            if attributes[i].code() != crate::bgp::Attribute::AS_PATH {
                continue;
            }
            let mut candidate = attributes[i].clone();
            candidate.intern_as_path(self);
            let Some(new) = candidate.packed_as_path() else {
                continue;
            };
            if attributes[i]
                .packed_as_path()
                .is_some_and(|old| Arc::ptr_eq(old, new))
            {
                continue;
            }
            Arc::make_mut(attributes)[i] = candidate;
        }
    }

    pub fn intern_entry(&mut self, entry: Arc<PathEntry>) -> Arc<PathEntry> {
        let hash = entry.fingerprint();
        if let Some(existing) = self.entries.get(&hash).and_then(Weak::upgrade)
            && (Arc::ptr_eq(&existing, &entry) || *existing == *entry)
        {
            return existing;
        }
        self.remember(hash, &entry);
        entry
    }

    fn remember(&mut self, hash: u64, entry: &Arc<PathEntry>) {
        self.operations = self.operations.wrapping_add(1);
        if self.operations.is_multiple_of(1024) {
            self.purge_expired();
        }
        if self.max_records != 0 {
            if self.entries.len() >= self.max_records
                && !self.entries.contains_key(&hash)
                && let Some(key) = self.entries.keys().next().copied()
            {
                self.entries.remove(&key);
            }
            self.entries.insert(hash, Arc::downgrade(entry));
        }
    }

    pub fn intern(&mut self, canonical: &[u8]) -> Result<Arc<PathEntry>, StoreError> {
        self.intern_hashed(canonical, content_hash(canonical))
    }

    fn intern_hashed(&mut self, canonical: &[u8], hash: u64) -> Result<Arc<PathEntry>, StoreError> {
        if let Some(entry) = self.entries.get(&hash).and_then(Weak::upgrade)
            && entry.matches(canonical)
        {
            return Ok(entry);
        }
        let entry = Arc::new(PathEntry::new(canonical)?);
        self.remember(hash, &entry);
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::Attribute;

    fn canonical(segments: &[(u8, &[u32])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (kind, asns) in segments {
            bytes.extend_from_slice(&[*kind, asns.len() as u8]);
            for asn in *asns {
                bytes.extend_from_slice(&asn.to_be_bytes());
            }
        }
        bytes
    }

    #[test]
    fn exact_codec_preserves_boundaries_types_duplicates_and_escape_payload_zeros() {
        let bytes = canonical(&[
            (2, &[1, 65535, 65536, 1, 1, 2]),
            (1, &[9, 3]),
            (3, &[7, 7]),
            (4, &[8, 4]),
            (2, &[]),
        ]);
        let mut store = AsPathStore::new(8);
        let entry = store.intern(&bytes).unwrap();
        assert!(entry.is_compact());
        assert_eq!(entry.canonical_bytes(), bytes);
        assert_eq!(
            entry.as_path().summary(),
            AsPath::from_bytes(&bytes).unwrap().summary()
        );
        let parts: Vec<_> = entry.as_path().segments().collect();
        assert_eq!(
            parts[0].asns().rev().collect::<Vec<_>>(),
            [2, 1, 1, 65536, 65535, 1]
        );
        let mut mixed = parts[0].asns();
        assert_eq!(mixed.next(), Some(1));
        assert_eq!(mixed.next_back(), Some(2));
        assert_eq!(mixed.len(), 4);
        assert_eq!(mixed.collect::<Vec<_>>(), [65535, 65536, 1, 1]);
        assert_eq!(std::mem::size_of::<PathDescriptor>(), 4);
        assert_eq!(entry.descriptor().offset(), 0);
        assert_eq!(
            entry.descriptor().inline_length(),
            Some(entry.stored_bytes())
        );
    }

    #[test]
    fn zero_wide_heavy_and_empty_paths_use_canonical_fallback() {
        let mut store = AsPathStore::new(8);
        for bytes in [
            canonical(&[(2, &[0, 1])]),
            canonical(&[(2, &[u32::MAX, 65536])]),
            canonical(&[(2, &[1, 65536])]),
            canonical(&[(1, &[])]),
            vec![],
        ] {
            let entry = store.intern(&bytes).unwrap();
            assert!(!entry.is_compact());
            assert_eq!(entry.stored_bytes(), bytes.len());
            assert_eq!(entry.canonical_bytes(), bytes);
        }
    }

    #[test]
    fn long_paths_and_descriptor_limits_never_truncate_or_wrap() {
        let full = vec![65535; 255];
        let bytes = canonical(&[(2, &full), (2, &full), (3, &[65536])]);
        let entry = AsPathStore::new(1).intern(&bytes).unwrap();
        assert_eq!(entry.descriptor().inline_length(), None);
        assert_eq!(entry.as_path().summary().hop_count, 510);
        assert_eq!(entry.canonical_bytes(), bytes);
        for (offset, length) in [(1, 2), (0, 3), (1 << 26, 2)] {
            assert!(PathDescriptor::new(offset, length).is_err());
        }
        assert_eq!(
            PathDescriptor::new((1 << 26) - 2, 252)
                .unwrap()
                .inline_length(),
            Some(252)
        );
        assert_eq!(PathDescriptor::new(0, 254).unwrap().inline_length(), None);
    }

    #[test]
    fn collisions_shapes_and_store_eviction_cannot_change_live_entries() {
        let a = canonical(&[(2, &[1, 2])]);
        let b = canonical(&[(1, &[1, 2])]);
        let c = canonical(&[(2, &[1]), (2, &[2])]);
        let mut store = AsPathStore::new(1);
        let first = store.intern_hashed(&a, 42).unwrap();
        let second = store.intern_hashed(&b, 42).unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_ne!(first, second);
        let third = store.intern_hashed(&c, 42).unwrap();
        assert_ne!(first, third);
        assert_eq!(store.records(), 1);
        drop(store);
        let reader = std::thread::spawn(move || first.canonical_bytes());
        assert_eq!(reader.join().unwrap(), a);
        assert_eq!(second.canonical_bytes(), b);
    }

    #[test]
    fn hits_share_entries_and_dead_records_are_reclaimed() {
        let bytes = canonical(&[(2, &[1, 2, 2])]);
        let mut store = AsPathStore::new(4);
        let a = store.intern(&bytes).unwrap();
        let b = store.intern(&bytes).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        let weak = Arc::downgrade(&a);
        drop(a);
        drop(b);
        assert!(weak.upgrade().is_none());
        store.purge_expired();
        assert_eq!(store.records(), 0);
        for i in 1..3000 {
            let bytes = canonical(&[(2, &[i])]);
            drop(store.intern(&bytes).unwrap());
            assert!(store.records() <= 4);
        }
        store.purge_expired();
        assert_eq!(store.records(), 0);
        for bad in [vec![2], vec![2, 1, 0], vec![5, 0]] {
            assert!(store.intern(&bad).is_err());
        }
        let entry = AsPathStore::new(0).intern(&bytes).unwrap();
        let mut left = AsPathStore::new(4);
        assert!(Arc::ptr_eq(&entry, &left.intern_entry(Arc::clone(&entry))));
    }

    #[test]
    fn attribute_clones_and_changed_paths_have_independent_lifetimes() {
        let bytes = canonical(&[(2, &[1, 2, 2])]);
        let a = Attribute::new_with_bin(Attribute::AS_PATH, bytes.clone()).unwrap();
        let b = a.clone();
        let changed = a.as_path_prepend(65001);
        assert_eq!(a.binary().unwrap().as_ref(), bytes);
        assert_eq!(b.binary().unwrap().as_ref(), bytes);
        assert_eq!(changed.as_path_count(2).unwrap(), 2);
        assert_eq!(changed.as_path_length(), 4);
        assert!(Arc::ptr_eq(
            a.packed_as_path().unwrap(),
            b.packed_as_path().unwrap()
        ));
        assert!(!Arc::ptr_eq(
            a.packed_as_path().unwrap(),
            changed.packed_as_path().unwrap()
        ));
    }

    #[test]
    fn prepend_splices_compact_storage_and_copies_canonical_storage() {
        let compact = canonical(&[(2, &[1, 65536, 2]), (1, &[9])]);
        let entry = AsPathStore::new(0).intern(&compact).unwrap();
        assert!(entry.is_compact());
        let narrow = entry.prepended(2, 65001).unwrap();
        let expected = canonical(&[(2, &[65001, 1, 65536, 2]), (1, &[9])]);
        assert!(narrow.is_compact());
        assert!(narrow.stored_bytes() < narrow.canonical_len());
        assert_eq!(narrow.canonical_bytes(), expected);
        assert_eq!(narrow.fingerprint(), content_hash(&expected));
        assert_eq!(
            narrow.as_path().summary(),
            AsPath::from_bytes(&expected).unwrap().summary()
        );
        let wide = entry.prepended(2, 70_000).unwrap();
        assert_eq!(
            wide.canonical_bytes(),
            canonical(&[(2, &[70_000, 1, 65536, 2]), (1, &[9])])
        );
        let confed = entry.prepended(3, 65001).unwrap();
        assert_eq!(
            confed.as_path().summary().hop_count,
            entry.as_path().summary().hop_count
        );
        assert_eq!(
            confed.as_path().summary().origin,
            entry.as_path().summary().origin
        );

        let members = vec![1u32; 255];
        let full = canonical(&[(2, &members)]);
        let split = AsPathStore::new(0)
            .intern(&full)
            .unwrap()
            .prepended(2, 65001)
            .unwrap();
        let mut expected_split = canonical(&[(2, &[65001])]);
        expected_split.extend_from_slice(&full);
        assert_eq!(split.canonical_bytes(), expected_split);

        let fallback = canonical(&[(2, &[0, 1])]);
        let copied = AsPathStore::new(0)
            .intern(&fallback)
            .unwrap()
            .prepended(2, 65001)
            .unwrap();
        let expected_copy = canonical(&[(2, &[65001, 0, 1])]);
        assert!(!copied.is_compact());
        assert_eq!(copied.bytes(), expected_copy.as_slice());
        assert_eq!(copied.fingerprint(), content_hash(&expected_copy));
    }
}
