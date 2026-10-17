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
//! Compaction builds a new arena off to the side and publishes it only when it
//! is smaller. There is no lock on the receive path.
use crate::as_path::{AsPath, AsPathSummary, Encoding, MalformedAsPath};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

const LENGTH_ESCAPE: u32 = 127;
const MAX_OFFSET_UNITS: usize = (1 << 25) - 1;

/// Common four-byte descriptor. Exceptional lengths use the owning entry's
/// stored_len. Private allocations start at zero; checkpoint entries use slices.
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
    /// Private encoding, or a shared generation arena.
    bytes: Arc<[u8]>,
    /// Length of this path's slice. The arena may be longer.
    stored_len: usize,
    /// Segment headers when `bytes` holds ASN payloads only.
    shapes: Option<Box<[(u8, u8)]>>,
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
        let encoding = if compact {
            Encoding::Escaped
        } else {
            Encoding::Canonical
        };
        Self::assemble(
            bytes.into_vec(),
            canonical.len(),
            content_hash(canonical),
            encoding,
            summary,
        )
    }

    pub fn descriptor(&self) -> PathDescriptor {
        self.descriptor
    }
    pub fn stored_bytes(&self) -> usize {
        self.stored_len
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        self.slice()
    }
    fn slice(&self) -> &[u8] {
        let offset = self.descriptor.offset();
        &self.bytes[offset..offset + self.stored_len]
    }
    pub(crate) fn external_shapes(&self) -> bool {
        self.shapes.is_some()
    }

    /// Build the path that results from prepending one AS number.
    ///
    /// A path kept in canonical form is copied. A compact path splices the new
    /// AS number onto its stored bytes when that number fits in 16 bits.
    /// The previous entry is left unchanged.
    pub(crate) fn prepended(&self, kind: u8, asn: u32) -> Result<Self, StoreError> {
        let narrow = (1..=u16::MAX as u32).contains(&asn);
        if self.shapes.is_some() {
            return self.prepend_from_view(kind, asn);
        }
        if !self.is_compact() {
            let bytes = self.slice();
            let merge = !bytes.is_empty() && bytes[0] == kind && bytes[1] < 255;
            let mut canonical = Vec::with_capacity(bytes.len() + if merge { 4 } else { 6 });
            canonical.extend_from_slice(&[kind, if merge { bytes[1] + 1 } else { 1 }]);
            canonical.extend_from_slice(&asn.to_be_bytes());
            canonical.extend_from_slice(if merge { &bytes[2..] } else { bytes });
            return Self::from_canonical_bytes(canonical, self.summary_after_prepend(kind, asn));
        }
        if narrow {
            return self.prepend_compact(kind, asn);
        }
        self.prepend_from_view(kind, asn)
    }

    fn prepend_from_view(&self, kind: u8, asn: u32) -> Result<Self, StoreError> {
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
        let bytes = self.slice();
        let merge = !bytes.is_empty() && bytes[0] == kind && bytes[1] < 255;
        let mut packed = Vec::with_capacity(bytes.len() + if merge { 2 } else { 4 });
        packed.push(kind);
        packed.push(if merge { bytes[1] + 1 } else { 1 });
        packed.extend_from_slice(&(asn as u16).to_be_bytes());
        packed.extend_from_slice(if merge { &bytes[2..] } else { bytes });
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
        let stored_len = bytes.len();
        Ok(Self {
            descriptor: PathDescriptor::new(0, stored_len)?,
            bytes: Arc::from(bytes),
            stored_len,
            shapes: None,
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
        AsPath::stored_shaped(
            self.slice(),
            self.encoding,
            Some(self.summary),
            self.shapes.as_deref(),
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

    /// Quiescent checkpoint over a complete set of route attribute owners.
    /// Callers exclude inserts/withdrawals until this returns. Old readers keep
    /// immutable entries; the store never strongly owns published entries.
    pub fn compact_attributes(
        &mut self,
        attributes: &mut [&mut Arc<Vec<crate::bgp::Attribute>>],
        options: CompactOptions,
    ) -> CompactOutcome {
        let started = Instant::now();
        if attributes.len() > options.max_owners {
            return CompactOutcome::Discarded;
        }
        let mut live = Vec::new();
        let mut seen = HashSet::new();
        let mut seen_owners = HashSet::new();
        let mut charge = attributes.len().saturating_mul(256);
        for owner in attributes.iter() {
            if seen_owners.insert(Arc::as_ptr(owner)) {
                charge = charge.saturating_add(std::mem::size_of_val(owner.as_slice()));
                for attr in owner.iter() {
                    charge = charge.saturating_add(attr.clone_allocation_bytes());
                }
                if charge > options.max_scratch_bytes {
                    return CompactOutcome::Discarded;
                }
            }
            for attr in owner.iter() {
                if let Some(entry) = attr.packed_as_path()
                    && seen.insert(Arc::as_ptr(entry))
                {
                    // Conservative reservation estimate for candidates, exact
                    // keys, bounds, temporary encodings and builder indices.
                    charge = charge.saturating_add(entry.canonical_len.saturating_mul(2048) + 2048);
                    if charge > options.max_scratch_bytes
                        || started.elapsed() > options.max_duration
                    {
                        return CompactOutcome::Discarded;
                    }
                    live.push(Arc::clone(entry));
                }
            }
        }
        if live.is_empty() {
            return CompactOutcome::Discarded;
        }
        let before = footprint(&live);
        // Canonical bytes, not fingerprints, determine identity and ordering.
        let mut unique = BTreeMap::new();
        for entry in &live {
            let Some(candidate) = Candidate::from_entry(entry) else {
                return CompactOutcome::Discarded;
            };
            unique.entry(entry.canonical_bytes()).or_insert(candidate);
        }
        if let Some(tail) = options.export_tail {
            if tail.asn == 0 || !matches!(tail.kind, 2 | 3) {
                return CompactOutcome::Discarded;
            }
            let mut exports = Vec::new();
            for candidate in unique.values() {
                let Some(exported) = candidate.with_export_tail(tail) else {
                    return CompactOutcome::Discarded;
                };
                let key = exported.canonical_bytes();
                exports.push((key, exported));
            }
            for (key, candidate) in exports {
                unique.entry(key).or_insert(candidate);
            }
        }
        let mut candidates: Vec<_> = unique.into_iter().collect();
        candidates.sort_by(|(ka, a), (kb, b)| {
            b.payload
                .len()
                .cmp(&a.payload.len())
                .then_with(|| ka.cmp(kb))
        });
        let mut arena = Arena {
            requested: candidates
                .iter()
                .map(|(_, c)| (content_hash(&c.payload), c.payload.len()))
                .collect(),
            long_lengths: candidates
                .iter()
                .map(|(_, c)| c.payload.len())
                .filter(|&n| n > LINE)
                .collect(),
            work_remaining: options.max_scratch_bytes,
            ..Default::default()
        };
        let mut placed = Vec::new();
        let mut shared_slices = 0;
        for (_, candidate) in &candidates {
            if started.elapsed() > options.max_duration {
                return CompactOutcome::Discarded;
            }
            let Some((offset, shared)) = arena.place(
                &candidate.payload,
                &candidate.bounds,
                options.max_arena_bytes,
            ) else {
                return CompactOutcome::Discarded;
            };
            placed.push(offset);
            shared_slices += usize::from(shared);
        }
        // Arc<[u8]> itself need not be line aligned. Reserve padding, then align
        // the data inside the final allocation (no moving allocation afterwards).
        let mut bytes: Arc<[u8]> = vec![0; arena.buf.len() + LINE - 1].into();
        let prefix = (LINE - bytes.as_ptr() as usize % LINE) % LINE;
        Arc::get_mut(&mut bytes).unwrap()[prefix..prefix + arena.buf.len()]
            .copy_from_slice(&arena.buf);
        let mut built = BTreeMap::new();
        for ((key, candidate), offset) in candidates.iter().zip(placed) {
            let Ok(entry) = candidate.entry(Arc::clone(&bytes), offset + prefix) else {
                return CompactOutcome::Discarded;
            };
            if entry.canonical_bytes() != *key {
                return CompactOutcome::Discarded;
            }
            built.insert(key.clone(), Arc::new(entry));
        }
        let entries: Vec<_> = built.values().cloned().collect();
        let after = footprint(&entries);
        if after >= before || started.elapsed() > options.max_duration {
            return CompactOutcome::Discarded;
        }
        // Cache transformed attribute vectors by the original allocation so
        // prefix fanout and original/import attribute sharing are preserved.
        let mut adopted = HashMap::new();
        for owner in attributes.iter_mut() {
            let key = Arc::as_ptr(owner);
            let replacement = adopted.entry(key).or_insert_with(|| {
                let mut updated = Arc::clone(owner);
                for i in 0..updated.len() {
                    if let Some(old) = updated[i].packed_as_path()
                        && let Some(new) = built.get(&old.canonical_bytes())
                    {
                        let mut attr = updated[i].clone();
                        attr.retarget_as_path(Arc::clone(new));
                        Arc::make_mut(&mut updated)[i] = attr;
                    }
                }
                updated
            });
            **owner = Arc::clone(replacement);
        }
        // Keep the accelerator bounded. Evicted live entries still resolve
        // through route ownership and will be included in the next checkpoint.
        let accelerator_limit = self.max_records.min(self.entries.capacity());
        self.entries.clear();
        for entry in entries.iter().take(accelerator_limit) {
            self.remember(entry.fingerprint(), entry);
        }
        CompactOutcome::Published {
            entries: entries.len(),
            shared_slices,
            before_bytes: before,
            after_bytes: after,
            arena_bytes: bytes.len(),
            scratch_bytes_estimate: charge,
            transition_bytes_estimate: before.saturating_add(after).saturating_add(charge),
        }
    }
}

const LINE: usize = 64;

/// Requested allocation bytes, excluding allocator rounding/bookkeeping and
/// the unchanged accelerator. Count each allocation once, even for slices.
fn footprint(entries: &[Arc<PathEntry>]) -> usize {
    let mut seen_entries = HashSet::new();
    let mut seen_payloads = HashSet::new();
    let mut bytes = 0;
    for entry in entries {
        if !seen_entries.insert(Arc::as_ptr(entry)) {
            continue;
        }
        bytes += std::mem::size_of::<PathEntry>() + 2 * std::mem::size_of::<usize>();
        bytes += entry
            .shapes
            .as_ref()
            .map_or(0, |s| std::mem::size_of_val(s.as_ref()));
        if seen_payloads.insert(Arc::as_ptr(&entry.bytes) as *const u8) {
            bytes += entry.bytes.len() + 2 * std::mem::size_of::<usize>();
        }
    }
    bytes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactOptions {
    /// Synthetic local-AS prefix placed ahead of each received payload.
    /// `None` keeps received paths only.
    pub export_tail: Option<ExportTail>,
    pub max_owners: usize,
    pub max_scratch_bytes: usize,
    pub max_arena_bytes: usize,
    pub max_duration: Duration,
}

impl Default for CompactOptions {
    fn default() -> Self {
        Self {
            export_tail: None,
            max_owners: 1_000_000,
            max_scratch_bytes: 256 * 1024 * 1024,
            max_arena_bytes: 32 * 1024 * 1024,
            max_duration: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportTail {
    pub asn: u32,
    pub kind: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactOutcome {
    Published {
        entries: usize,
        shared_slices: usize,
        before_bytes: usize,
        after_bytes: usize,
        arena_bytes: usize,
        scratch_bytes_estimate: usize,
        transition_bytes_estimate: usize,
    },
    Discarded,
}

struct Candidate {
    payload: Vec<u8>,
    shapes: Vec<(u8, u8)>,
    bounds: Vec<usize>,
    encoding: Encoding,
    canonical_len: usize,
    hash: u64,
    summary: AsPathSummary,
}

impl Candidate {
    fn from_entry(entry: &PathEntry) -> Option<Self> {
        let mut payload = Vec::new();
        let mut shapes = Vec::new();
        let mut bounds = vec![0];
        for segment in entry.as_path().segments() {
            let count = u8::try_from(segment.len()).ok()?;
            shapes.push((segment.kind(), count));
            for asn in segment.asns() {
                push_asn(&mut payload, entry.encoding, asn)?;
                bounds.push(payload.len());
            }
        }
        Some(Self {
            payload,
            shapes,
            bounds,
            encoding: entry.encoding,
            canonical_len: entry.canonical_len,
            hash: entry.canonical_hash,
            summary: entry.summary,
        })
    }

    fn with_export_tail(&self, tail: ExportTail) -> Option<Self> {
        let mut payload = Vec::new();
        push_asn(&mut payload, self.encoding, tail.asn)?;
        payload.extend_from_slice(&self.payload);
        let mut shapes = self.shapes.clone();
        if let Some((kind, count)) = shapes.first_mut()
            && *kind == tail.kind
            && *count < 255
        {
            *count += 1;
        } else {
            shapes.insert(0, (tail.kind, 1));
        }
        let mut bounds = vec![0];
        let mut offset = 0;
        for &(kind, count) in &shapes {
            let _ = kind;
            for _ in 0..count {
                offset += asn_width(&payload[offset..], self.encoding)?;
                bounds.push(offset);
            }
        }
        let view = AsPath::stored_shaped(&payload, self.encoding, None, Some(&shapes));
        let summary = view.summary();
        let canonical: Vec<u8> = view.canonical_bytes().collect();
        let hash = content_hash(&canonical);
        let canonical_len = canonical.len();
        Some(Self {
            payload,
            shapes,
            bounds,
            encoding: self.encoding,
            canonical_len,
            hash,
            summary,
        })
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        AsPath::stored_shaped(
            &self.payload,
            self.encoding,
            Some(self.summary),
            Some(&self.shapes),
        )
        .canonical_bytes()
        .collect()
    }

    fn entry(&self, arena: Arc<[u8]>, offset: usize) -> Result<PathEntry, StoreError> {
        Ok(PathEntry {
            descriptor: PathDescriptor::new(offset, self.payload.len())?,
            bytes: arena,
            stored_len: self.payload.len(),
            shapes: Some(self.shapes.clone().into_boxed_slice()),
            canonical_len: self.canonical_len,
            canonical_hash: self.hash,
            encoding: self.encoding,
            summary: self.summary,
        })
    }
}

fn push_asn(out: &mut Vec<u8>, encoding: Encoding, asn: u32) -> Option<()> {
    match encoding {
        Encoding::Canonical => out.extend_from_slice(&asn.to_be_bytes()),
        Encoding::Escaped if asn == 0 => return None,
        Encoding::Escaped if asn <= u32::from(u16::MAX) => {
            out.extend_from_slice(&(asn as u16).to_be_bytes());
        }
        Encoding::Escaped => {
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(&asn.to_be_bytes());
        }
    }
    Some(())
}

fn asn_width(bytes: &[u8], encoding: Encoding) -> Option<usize> {
    match encoding {
        Encoding::Canonical => bytes.get(..4).map(|_| 4),
        Encoding::Escaped => {
            let unit = u16::from_be_bytes(bytes.get(..2)?.try_into().ok()?);
            if unit != 0 {
                Some(2)
            } else {
                bytes.get(..6).map(|_| 6)
            }
        }
    }
}

#[derive(Default)]
struct Arena {
    buf: Vec<u8>,
    // Short windows: at most 32 endpoints per ASN start. Long paths
    // share requested suffixes; total hashing/comparison work is bounded.
    windows: HashMap<(u64, usize), Vec<usize>>,
    requested: HashSet<(u64, usize)>,
    long_lengths: HashSet<usize>,
    work_remaining: usize,
}

impl Arena {
    fn place(&mut self, payload: &[u8], bounds: &[usize], limit: usize) -> Option<(usize, bool)> {
        if payload.is_empty() {
            return Some((0, true));
        }
        self.work_remaining = self.work_remaining.checked_sub(payload.len())?;
        let key = (content_hash(payload), payload.len());
        if let Some(candidates) = self.windows.get(&key) {
            for &offset in candidates {
                self.work_remaining = self.work_remaining.checked_sub(payload.len())?;
                if (payload.len() > LINE || offset % LINE + payload.len() <= LINE)
                    && self.buf[offset..offset + payload.len()] == *payload
                {
                    return Some((offset, true));
                }
            }
        }
        let offset = aligned_offset(self.buf.len(), payload.len());
        let end = offset.checked_add(payload.len())?;
        if end.checked_add(LINE - 1)? > limit {
            return None;
        }
        PathDescriptor::new(offset.checked_add(LINE - 2)?, payload.len()).ok()?;
        self.buf.resize(offset, 0);
        self.buf.extend_from_slice(payload);
        for (index, &start) in bounds.iter().enumerate() {
            for &end in &bounds[index + 1..] {
                let len = end - start;
                if len > LINE {
                    break;
                }
                if (offset + start) % LINE + len > LINE {
                    continue;
                }
                self.work_remaining = self.work_remaining.checked_sub(len)?;
                let window = &payload[start..end];
                let key = (content_hash(window), len);
                if self.requested.contains(&key) {
                    let slots = self.windows.entry(key).or_default();
                    if !slots
                        .iter()
                        .any(|&prior| self.buf[prior..prior + len] == *window)
                    {
                        slots.push(offset + start);
                    }
                }
            }
        }
        // Prepend-derived long tails are indexed only at lengths that are
        // actually requested. Hashing work is explicitly bounded.
        for &start in bounds {
            let len = payload.len() - start;
            if len > LINE && self.long_lengths.contains(&len) {
                self.work_remaining = self.work_remaining.checked_sub(len)?;
                self.windows
                    .entry((content_hash(&payload[start..]), len))
                    .or_default()
                    .push(offset + start);
            }
        }
        Some((offset, false))
    }
}

fn aligned_offset(cursor: usize, len: usize) -> usize {
    let cursor = (cursor + 1) & !1;
    if len > LINE {
        return cursor;
    }
    let line_off = cursor % LINE;
    if line_off + len <= LINE {
        cursor
    } else {
        cursor + (LINE - line_off)
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

    fn owners(paths: &[Vec<u8>]) -> Vec<Arc<Vec<Attribute>>> {
        paths
            .iter()
            .map(|p| {
                Arc::new(vec![
                    Attribute::new_with_bin(Attribute::AS_PATH, p.clone()).unwrap(),
                ])
            })
            .collect()
    }

    fn checkpoint(
        store: &mut AsPathStore,
        owners: &mut [Arc<Vec<Attribute>>],
        options: CompactOptions,
    ) -> CompactOutcome {
        store.compact_attributes(&mut owners.iter_mut().collect::<Vec<_>>(), options)
    }

    #[test]
    fn checkpoint_is_complete_bounded_and_releases_withdrawn_entries() {
        let paths: Vec<_> = (1..=128)
            .map(|i| canonical(&[(2, &[i, 65535, 65536, 9, 8, 7])]))
            .collect();
        let mut owners = owners(&paths);
        let mut store = AsPathStore::new(1); // Accelerator cannot contain all live paths.
        for owner in &mut owners {
            store.intern_attributes(owner);
        }
        let held = Arc::clone(owners[0][0].packed_as_path().unwrap());
        let outcome = checkpoint(&mut store, &mut owners, CompactOptions::default());
        let CompactOutcome::Published {
            before_bytes,
            after_bytes,
            ..
        } = outcome
        else {
            panic!("{outcome:?}");
        };
        assert!(after_bytes < before_bytes);
        assert!(store.records() <= 1);
        for (owner, expected) in owners.iter().zip(&paths) {
            let entry = owner[0].packed_as_path().unwrap();
            assert_eq!(entry.canonical_bytes(), *expected);
            assert!(entry.shapes.is_some());
            let address = entry.slice().as_ptr() as usize;
            assert!(address % LINE + entry.stored_len <= LINE);
        }
        assert_eq!(held.canonical_bytes(), paths[0]);
        assert!(held.shapes.is_none());
        let weak = Arc::downgrade(owners[0][0].packed_as_path().unwrap());
        owners.clear();
        assert!(weak.upgrade().is_none());
        store.purge_expired();
        assert_eq!(store.records(), 0);
    }

    #[test]
    fn checkpoint_preserves_fanout_and_is_deterministic() {
        let paths: Vec<_> = (1..=64).map(|i| canonical(&[(2, &[i, 2, 3, 4])])).collect();
        let mut first = owners(&paths);
        first.push(Arc::clone(&first[0]));
        let mut second = owners(&paths);
        second.reverse();
        let mut store = AsPathStore::default();
        assert!(matches!(
            checkpoint(&mut store, &mut first, CompactOptions::default()),
            CompactOutcome::Published { .. }
        ));
        assert!(Arc::ptr_eq(&first[0], first.last().unwrap()));
        assert!(matches!(
            checkpoint(&mut store, &mut second, CompactOptions::default()),
            CompactOutcome::Published { .. }
        ));
        second.reverse();
        for (a, b) in first.iter().zip(&second) {
            let a = a[0].packed_as_path().unwrap();
            let b = b[0].packed_as_path().unwrap();
            // Prefix padding depends on allocation address; relative placement does not.
            let relative = |e: &PathEntry| e.slice().as_ptr() as usize % LINE;
            assert_eq!(relative(a), relative(b));
            assert_eq!(a.stored_len, b.stored_len);
        }
    }

    #[test]
    fn checkpoint_failure_does_not_change_attributes_or_cache() {
        let mut owners = owners(&[canonical(&[(2, &[1, 2, 3])])]);
        let original = Arc::clone(&owners[0]);
        let mut store = AsPathStore::default();
        for options in [
            CompactOptions {
                max_scratch_bytes: 0,
                ..Default::default()
            },
            CompactOptions {
                max_arena_bytes: 0,
                ..Default::default()
            },
            CompactOptions {
                max_owners: 0,
                ..Default::default()
            },
            CompactOptions {
                max_duration: Duration::ZERO,
                ..Default::default()
            },
            CompactOptions {
                export_tail: Some(ExportTail { asn: 1, kind: 99 }),
                ..Default::default()
            },
            CompactOptions::default(), // Padding makes this tiny generation larger.
        ] {
            assert_eq!(
                checkpoint(&mut store, &mut owners, options),
                CompactOutcome::Discarded
            );
            assert!(Arc::ptr_eq(&original, &owners[0]));
            assert_eq!(store.records(), 0);
        }
    }

    #[test]
    fn rollover_confederations_zero_and_shapes_reconstruct_exactly() {
        let members = vec![1; 255];
        let full = canonical(&[(2, &members)]);
        let mut rolled = canonical(&[(2, &[65001])]);
        rolled.extend_from_slice(&full);
        let mut paths = vec![
            full,
            rolled,
            canonical(&[(3, &[65002]), (2, &[9, 8, 7])]),
            canonical(&[(2, &[9, 8, 7])]),
            canonical(&[(1, &[0, u32::MAX]), (2, &[])]),
        ];
        paths.extend((1..=64).map(|i| canonical(&[(2, &[i, 8, 7])])));
        let mut owners = owners(&paths);
        let old = owners.clone();
        let mut store = AsPathStore::default();
        assert!(matches!(
            checkpoint(&mut store, &mut owners, CompactOptions::default()),
            CompactOutcome::Published { .. }
        ));
        for ((owner, old), path) in owners.iter().zip(&old).zip(&paths) {
            assert_eq!(owner[0], old[0]);
            assert_eq!(owner[0].packed_as_path().unwrap().canonical_bytes(), *path);
            assert_eq!(owner[0].encode_to_bytes(), old[0].encode_to_bytes());
        }
        let full = owners[0][0].packed_as_path().unwrap();
        let rolled = owners[1][0].packed_as_path().unwrap();
        assert_eq!(full.descriptor.offset(), rolled.descriptor.offset() + 2);
        assert_eq!(
            full.prepended(2, 65001).unwrap().canonical_bytes(),
            paths[1]
        );
    }

    #[test]
    fn short_slices_of_long_parents_never_cross_lines_and_capacity_is_fallible() {
        let mut arena = Arena {
            work_remaining: 1_000_000,
            ..Default::default()
        };
        let payload: Vec<u8> = (1..=50u16).flat_map(u16::to_be_bytes).collect();
        let bounds: Vec<_> = (0..=50).map(|i| i * 2).collect();
        arena.place(&payload, &bounds, 4096).unwrap();
        // This occurrence crosses offset 64 and must get its own placement.
        let (offset, shared) = arena
            .place(&payload[60..68], &[0, 2, 4, 6, 8], 4096)
            .unwrap();
        assert!(!shared);
        assert!(offset % LINE + 8 <= LINE);
        let candidate =
            Candidate::from_entry(&PathEntry::new(&canonical(&[(2, &[1])])).unwrap()).unwrap();
        assert!(
            candidate
                .entry(Arc::from([0u8; 4]), (MAX_OFFSET_UNITS + 1) * 2)
                .is_err()
        );
    }

    #[test]
    fn export_tail_defaults_off_and_keeps_received_semantics() {
        assert!(CompactOptions::default().export_tail.is_none());
        let path = PathEntry::new(&canonical(&[(2, &[1, 2, 3])])).unwrap();
        let candidate = Candidate::from_entry(&path).unwrap();
        let exported = candidate
            .with_export_tail(ExportTail {
                asn: 65001,
                kind: 2,
            })
            .unwrap();
        assert_eq!(
            exported.canonical_bytes(),
            canonical(&[(2, &[65001, 1, 2, 3])])
        );
        assert_eq!(path.canonical_bytes(), canonical(&[(2, &[1, 2, 3])]));
    }
}
