# Exact packed AS paths

`packed-as-paths` is off by default. With it enabled, an UPDATE's AS_PATH becomes
one immutable `PathEntry` behind an `Arc` when the message is parsed, after
two-octet AS numbers have been reconciled with AS4_PATH. Every prefix from that
UPDATE keeps the same entry, including prefixes that land in different table
shards. A later insert reuses that entry. The store itself holds only weak
references, capped at 16,384 records, and drops records whose entries are gone.

The attribute still compares and hashes as the canonical four-octet path, so
outbound UPDATEs group the same way when two entries hold the same path. The
four-octet wire image is unchanged. ASN 0 and a path whose packed form is not
smaller stay in today's four-octet layout inside the entry. A packed ASN in
1..=65535 occupies two octets. Any larger ASN occupies a two-octet zero marker
followed by the four-octet value. Each entry owns its bytes at offset zero.
Moving those bytes, sharing a slice of another path, and rebuilding the store
in the background belong to a later change.

Hop count and origin are stored on the entry. AS_SET still counts as one hop,
confederation segments as zero, and the origin is present only when the path
ends in a nonempty AS_SEQUENCE. Prepend builds a new entry and leaves the
previous one unchanged. A canonical entry is copied with the new AS number
spliced in. A packed entry splices a 16-bit AS number onto its stored bytes.
A wider prepend walks the path and chooses the layout again.

## Census

17 October 2026, from `rib.20261017.0000.bz2` via `tools/as_path_corpus.py`.
17,476,709 RIB entries, 2,135,078 distinct exact encodings. Counts are in
[census.json](benchmarks/packed-as-path/census.json).

| Quantity | Value |
| --- | ---: |
| Canonical path bytes | 47,702,910 |
| Adaptive stored bytes | 34,075,394 |
| Narrow ASNs (1..=65535) | 8,611,526 |
| Wide ASNs | 2,245,979 |
| ASN 0 | 0 |
| Longest canonical path | 1,036 bytes |

Wide ASNs are 20.7% of encoded ASNs, under the point where the packed layout
grows (half the ASNs wider than 16 bits). 1,855,618 of the 2,135,078 distinct
paths are stored packed.

## Retained memory

The retention program keeps one record per observation and charges each record
the size of `Attribute`. RSS is `VmHWM` after the set is built and checked.

| Workload | Raw RSS | Packed RSS | Raw payload | Packed payload |
| --- | ---: | ---: | ---: | ---: |
| 2,135,078 distinct snapshot paths | 291 MB | 453 MB | 47,702,910 | 34,075,394 |
| 1,000,000 observations of 512 paths | 73 MB | 42 MB | 9,863,220 | 3,038 |
| 50,000 distinct wide-only paths | 8.6 MB | 13.1 MB | 900,000 | 900,000 |

The snapshot's packed payload is smaller, and the process is larger: the run
records 85,403,120 bytes of attribute slots and 153,725,616 bytes of entry
control blocks, with 16,384 weak index slots. The repeated case is where sharing
wins. The wide-only case stores every path in canonical form (`compact_entries`
0) and still pays for an entry per path. Raw lines:
[snapshot](benchmarks/packed-as-path/snapshot-raw.txt),
[repeated](benchmarks/packed-as-path/repeated-raw.txt),
[wide](benchmarks/packed-as-path/wide_unique-raw.txt). Packed lines:
[snapshot](benchmarks/packed-as-path/snapshot-packed.txt),
[repeated](benchmarks/packed-as-path/repeated-packed.txt),
[wide](benchmarks/packed-as-path/wide_unique-packed.txt).

## Policy and table replay

Same host and method as [borrowed traversal](as-path-traversal.md): Intel Core
i7-10850H, Rust 1.98.1, release/bench profile with workspace LTO, pinned CPU 2.
Three fresh processes, alternating order. The table is the median of the three
process medians.

| Operation | Feature off, ns | Feature on, ns | Allocations per operation |
| --- | ---: | ---: | ---: |
| policy/include | 30.86 | 45.68 | 0 → 0 |
| update_parse_validate_policy/include | 338.47 | 492.14 | 10 → 12 |
| policy/origin | 30.82 | 38.68 | 0 → 0 |
| update_parse_validate_policy/origin | 339.81 | 497.22 | 10 → 12 |
| policy/only_miss | 28.80 | 34.58 | 0 → 0 |
| update_parse_validate_policy/only_miss | 337.07 | 483.74 | 10 → 12 |

Rounds: [off 1](benchmarks/packed-as-path/policy-default-1.csv),
[off 2](benchmarks/packed-as-path/policy-default-2.csv),
[off 3](benchmarks/packed-as-path/policy-default-3.csv),
[on 1](benchmarks/packed-as-path/policy-enabled-1.csv),
[on 2](benchmarks/packed-as-path/policy-enabled-2.csv),
[on 3](benchmarks/packed-as-path/policy-enabled-3.csv).

In-process table replay, 4 workers, 80,000 operations, median of three
processes, operations/second:

| Shards | Feature off | Feature on |
| ---: | ---: | ---: |
| 1 | 1,606,660 | 1,427,316 |
| 4 | 2,959,891 | 2,559,827 |
| 16 | 2,814,733 | 2,599,179 |

Files are `replay-default-<shards>-<round>.txt` and
`replay-enabled-<shards>-<round>.txt` in
[benchmarks/packed-as-path](benchmarks/packed-as-path). Each process locks
shards and inserts or removes 64 short paths. Peer I/O and the export queue
are outside this loop.

## Traversal, prepend, and encode

One pinned process with the feature off, from
[traversal-default.csv](benchmarks/packed-as-path/traversal-default.csv).
Three pinned processes with the feature on, after prepend learned to copy
canonical storage and to splice a 16-bit AS number onto packed storage. The
table uses the median of those three process medians. Short and mixed paths in
this bench are half wide ASNs, so they stay canonical. The long path is four
255-member segments and is packed, because two thirds of its ASNs fit in 16 bits.

| Operation | Feature off, ns | Feature on, ns | Allocations per operation |
| --- | ---: | ---: | ---: |
| short/borrowed_decode | 3.70 | 7.46 | 0 → 0 |
| short/prepend | 20.11 | 51.51 | 1 → 2 |
| short/wire_encode | 32.71 | 17.04 | 2 → 1 |
| mixed/prepend | 20.82 | 62.45 | 1 → 2 |
| mixed/wire_encode | 63.20 | 17.79 | 2 → 1 |
| long/borrowed_summary | 9.00 | 8.14 | 0 → 0 |
| long/prepend | 61.92 | 4,321.11 | 1 → 2 |
| long/wire_encode | 102.80 | 3,036.84 | 2 → 1 |
| long/borrowed_decode | 388.34 | 1,696.11 | 0 → 0 |

Enabled rounds:
[1](benchmarks/packed-as-path/traversal-enabled-1.csv),
[2](benchmarks/packed-as-path/traversal-enabled-2.csv),
[3](benchmarks/packed-as-path/traversal-enabled-3.csv).
A cached summary on a retained entry is 4.25 ns in
[store.csv](benchmarks/packed-as-path/store.csv). Decoding a packed long path,
and expanding one to the wire, still walks every ASN.

## Reproduction

```sh
python3 tools/as_path_corpus.py rib.bz2 /tmp/as-paths.bin \
  --inetcompression /path/to/InetCompression
cargo bench -p rustybgp-packet --bench packed_as_path \
  --features packed-as-paths --no-run
cargo bench -p rustybgp-packet --bench as_path --no-run
cargo bench -p rustybgp-packet --bench as_path --features packed-as-paths --no-run
cargo bench -p rustybgp-table --bench as_path --no-run
cargo bench -p rustybgp-table --bench as_path --features packed-as-paths --no-run
cargo bench -p rustybgp-table --bench path_store_replay --no-run
cargo bench -p rustybgp-table --bench path_store_replay --features packed-as-paths --no-run
# Run the emitted executables with taskset -c 2.
# packed_as_path <raw|packed> <corpus> [observations] [distinct keys]
# path_store_replay <shards> <workers> <iterations>
```

Source hashes for the files that define this behavior are in
[source-signatures.json](benchmarks/packed-as-path/source-signatures.json).
The feature stays off until a workload with repeated paths pays for the slower
parse, policy walk, and long-path export.
