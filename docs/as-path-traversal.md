# Borrowed AS-path traversal

`Attribute::as_path()` returns a validated borrowed view over the existing
canonical four-octet bytes. `segments()` retains segment kinds and boundaries;
`segment.asns()` yields `u32` values directly from those bytes without allocating
vectors. The owned `AsPathIter` API remains available unchanged.

```rust
let path = attr.as_path()?;
let found = path.contains_any(&[65001, 65002]);
let summary = path.summary(); // on demand; no cache or decoded member copy
for segment in path.segments() {
    let kind = segment.kind();
    for asn in segment.asns() {
        // Inspect ASN and segment kind without changing either.
        std::hint::black_box((kind, asn));
    }
}
```

Construction validates the complete path before exposing segments, including a
trailing malformed segment after an apparent match. It scans segment headers and
bounds, not every ASN. Traversal is then allocation-free and may stop at a match.
Empty paths/segments and ASN zero keep the existing packet layer's semantics;
this API does not introduce new UPDATE acceptance rules or normalize values.
Policy matching returns false for malformed paths; empty terminal segments yield
no endpoint instead of indexing an empty vector.

Simple AS-path policy matchers and the leftmost-AS prepend action use borrowed
traversal. Routing-loop detection uses one presence query for both the local AS
and an enabled confederation ID. The multiplicity-sensitive `as_path_count()`
is unchanged. Loop checks still reject malformed trailing input before accepting
a prefix match, as the previous fallible count did.

`AsPathSummary` reports hop count and optional routing origin without allocating.
AS_SET contributes one hop, confederation segments none; origin exists only when
the final segment is a nonempty AS_SEQUENCE. Simple policy endpoint matching
retains its serialized last-member semantics, including sets/confederations.
The existing routing length/origin helpers are unchanged in this patch. Summaries
are not stored on routes or used as a policy endpoint shortcut.

## Measurements

17 October 2026; Intel Core i7-10850H, Rust 1.98.1, release/bench profile with
workspace LTO, pinned CPU 2. Master baseline is `603d350`; the identical public-API
table benchmark was copied into an isolated worktree with the same Cargo.lock.
Three fresh processes per version, alternating version order between rounds;
each process warms 10,000 operations then measures seven batches of 100,000.
The table reports the median of the three process medians, in ns/operation.

| Operation | Master ns | Borrowed ns | Allocation/reallocation calls per operation |
| --- | ---: | ---: | ---: |
| policy/include | 52.97 | 33.60 | 1 → 0 |
| update_parse_validate_policy/include | 355.20 | 339.73 | 11 → 10 |
| policy/origin | 74.06 | 32.84 | 2 → 0 |
| update_parse_validate_policy/origin | 374.10 | 335.98 | 12 → 10 |
| policy/only_miss | 71.72 | 31.65 | 2 → 0 |
| update_parse_validate_policy/only_miss | 377.43 | 329.86 | 12 → 10 |

Policy-only cases cycle 64 four-ASN attributes with repeats and wide ASNs;
include/origin cases alternate hits and misses. The only matcher always misses.
UPDATE cases copy a pre-encoded IPv4 UPDATE, parse and validate it, then apply
the actual import policy. They include parser allocations; policy-only cases
measure the actual public import-policy API. Results are checked on every call.
These are not route installation, peer fanout, full-feed, or concurrent-daemon
throughput measurements.

A separate traversal benchmark compares owned versus borrowed decode and two
full ASN counts versus a borrowed two-target presence miss. It covers short
paths, mixed segment types, and four 255-member segments. Borrowed decode,
presence, and summary loops assert zero allocations. Its seven-batch samples
are summarized in [traversal.csv](benchmarks/as-path/traversal.csv).

A counting system allocator is enabled in both versions. Atomic bookkeeping on
allocation/reallocation adds cost to allocating operations, so timing ratios are
instrumented microbenchmark results, not uninstrumented production speedups.
Counts include vector growth reallocations. No hardware counters, cold-cache,
traffic-weighted corpus, or confidence intervals were collected. This was an
active desktop; variation is retained in each CSV's min/max batch times.

Raw table results: [master round 1](benchmarks/as-path/master-1.csv),
[round 2](benchmarks/as-path/master-2.csv), [round 3](benchmarks/as-path/master-3.csv),
[borrowed round 1](benchmarks/as-path/borrowed-1.csv),
[round 2](benchmarks/as-path/borrowed-2.csv), [round 3](benchmarks/as-path/borrowed-3.csv).

## Reproduction

```sh
cargo bench -p rustybgp-packet --bench as_path --no-run
cargo bench -p rustybgp-table --bench as_path --no-run
# Run the emitted executables with taskset -c 2 after compilation completes.
# AS_PATH_BENCH_ITERATIONS overrides the default 100000 operations per batch.
```

For a base comparison, create a detached worktree at the base commit; copy
`table/benches/as_path.rs`, `packet/benches/support/mod.rs`, and the same
`Cargo.lock` into it, and add the table Cargo.toml `[[bench]]` stanza with
`name = "as_path"` and `harness = false`. Build in a separate target directory.
The table harness intentionally uses only APIs available on the base commit.
Run base/current executables sequentially with identical iteration counts and
CPU affinity, alternating order between process rounds. Compare each workload
separately; do not attribute parser or allocator behavior to the path decoder.
