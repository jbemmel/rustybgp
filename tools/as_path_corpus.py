#!/usr/bin/env python3
"""Extract exact MRT AS_PATH bytes using a local InetCompression checkout.

Writes uint32-big-endian byte length followed by canonical four-octet AS_PATH
bytes per distinct encoding. No normalization, sorting of set members, or slice
reduction is performed. InetCompression is an optional benchmark-time dependency.
"""
import argparse
from collections import deque
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
import struct
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rib")
    parser.add_argument("output")
    parser.add_argument("--inetcompression", required=True)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("workers must be positive")
    sys.path.insert(0, args.inetcompression)
    from count_as_paths import record_batches, parse_batch

    started = time.perf_counter()
    paths, pending = set(), deque()
    entries = 0
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for batch in record_batches(args.rib):
            pending.append(pool.submit(parse_batch, batch))
            if len(pending) >= args.workers * 2:
                found, count = pending.popleft().result()
                paths.update(found)
                entries += count
        while pending:
            found, count = pending.popleft().result()
            paths.update(found)
            entries += count
    narrow = wide = zero = original = escaped = adaptive = maximum = 0
    with open(args.output, "wb") as output:
        for path in sorted(paths):
            output.write(struct.pack("!I", len(path)))
            output.write(path)
            original += len(path)
            position = packed = 0
            has_zero = False
            while position < len(path):
                _, count = path[position:position + 2]
                position += 2
                packed += 2
                for _ in range(count):
                    asn = int.from_bytes(path[position:position + 4], "big")
                    position += 4
                    narrow += 0 < asn <= 65535
                    wide += asn > 65535
                    zero += asn == 0
                    has_zero |= asn == 0
                    packed += 2 if 0 < asn <= 65535 else 6
            escaped += packed
            adaptive += len(path) if has_zero else min(len(path), packed)
            maximum = max(maximum, len(path))
    with open(args.output, "rb") as corpus:
        digest = hashlib.file_digest(corpus, "sha256").hexdigest()
    report = dict(entries=entries, distinct_exact_encodings=len(paths),
                  canonical_bytes=original, escaped_bytes=escaped,
                  adaptive_bytes=adaptive, narrow_asns=narrow, wide_asns=wide,
                  zero_asns=zero, max_canonical_bytes=maximum,
                  extraction_seconds=time.perf_counter() - started,
                  corpus_sha256=digest)
    with open(args.output + ".json", "w") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
