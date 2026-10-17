//! Exact corpus verification and retained-memory/churn controls for the opt-in store.
use rustybgp_packet::Attribute;
use rustybgp_packet::as_path_store::{AsPathStore, PathEntry};
use std::hint::black_box;
use std::io::{Cursor, Read};
use std::sync::Arc;
use std::time::Instant;

mod support;
#[global_allocator]
static ALLOCATOR: support::CountingAllocator = support::CountingAllocator;

// A PackedPath variant does not shrink Attribute's enum slot: other variants
// still contain Vec. Charge both retention controls the actual Attribute size.
struct RawRecord {
    bytes: Vec<u8>,
    _metadata: [u8; std::mem::size_of::<Attribute>() - std::mem::size_of::<Vec<u8>>()],
}
struct SharedRecord {
    entry: Arc<PathEntry>,
    _metadata: [u8; std::mem::size_of::<Attribute>() - std::mem::size_of::<Arc<PathEntry>>()],
}

fn corpus(path: &str) -> Vec<Vec<u8>> {
    let mut cursor = Cursor::new(std::fs::read(path).unwrap());
    let mut paths = Vec::new();
    while cursor.position() < cursor.get_ref().len() as u64 {
        let mut length = [0; 4];
        cursor.read_exact(&mut length).unwrap();
        let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
        cursor.read_exact(&mut bytes).unwrap();
        paths.push(bytes);
    }
    paths
}

fn rss() -> String {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .filter(|line| line.starts_with("VmHWM:") || line.starts_with("VmRSS:"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn main() {
    assert_eq!(
        std::mem::size_of::<RawRecord>(),
        std::mem::size_of::<Attribute>()
    );
    assert_eq!(
        std::mem::size_of::<SharedRecord>(),
        std::mem::size_of::<Attribute>()
    );
    let args: Vec<_> = std::env::args().collect();
    if args.len() >= 3 {
        let paths = corpus(&args[2]);
        let observations: usize = args
            .get(3)
            .map(|s| s.parse().unwrap())
            .unwrap_or(paths.len());
        let distinct: usize = args
            .get(4)
            .map(|s| s.parse().unwrap())
            .unwrap_or(paths.len());
        assert!(distinct > 0 && distinct <= paths.len());
        let start = Instant::now();
        if args[1] == "raw" {
            let retained: Vec<_> = (0..observations)
                .map(|i| RawRecord {
                    bytes: paths[i % distinct].clone(),
                    _metadata: Default::default(),
                })
                .collect();
            println!(
                "mode=raw observations={} keys={} payload_bytes={} attribute_record_bytes={} elapsed_s={:.6} {}",
                retained.len(),
                distinct,
                retained
                    .iter()
                    .map(|record| record.bytes.len())
                    .sum::<usize>(),
                retained.capacity() * std::mem::size_of::<RawRecord>(),
                start.elapsed().as_secs_f64(),
                rss()
            );
            black_box(retained);
        } else {
            assert_eq!(args[1], "packed");
            let mut store = AsPathStore::default();
            let mut retained = Vec::with_capacity(observations);
            let mut unique = 0usize;
            let mut bytes = 0;
            let mut compact = 0;
            for i in 0..observations {
                let path = &paths[i % distinct];
                let entry = store.intern(path).unwrap();
                if Arc::strong_count(&entry) == 1 {
                    unique += 1;
                    bytes += entry.stored_bytes();
                    compact += usize::from(entry.is_compact());
                }
                retained.push(SharedRecord {
                    entry,
                    _metadata: Default::default(),
                });
            }
            let build_seconds = start.elapsed().as_secs_f64();
            let verify_start = Instant::now();
            for (i, entry) in retained.iter().enumerate() {
                assert_eq!(entry.entry.canonical_bytes(), paths[i % distinct]);
            }
            let verification_seconds = verify_start.elapsed().as_secs_f64();
            println!(
                "mode=packed observations={} keys={} entries={} compact_entries={} payload_bytes={} attribute_record_bytes={} entry_control_bytes={} interner_records={} interner_capacity={} build_s={:.6} verification_s={:.6} {}",
                retained.len(),
                distinct,
                unique,
                compact,
                bytes,
                retained.capacity() * std::mem::size_of::<SharedRecord>(),
                unique * (std::mem::size_of::<PathEntry>() + 2 * std::mem::size_of::<usize>()),
                store.records(),
                store.capacity(),
                build_seconds,
                verification_seconds,
                rss()
            );
            // No owner remains in the weak interner after routes/events drop.
            drop(retained);
            store.purge_expired();
            assert_eq!(store.records(), 0);
        }
        return;
    }
    println!("operation,median_ns,allocations_per_op,min_ns,max_ns");
    let canonical = [
        vec![2, 4],
        [65001u32, 65536, 65001, 7]
            .into_iter()
            .flat_map(u32::to_be_bytes)
            .collect(),
    ]
    .concat();
    let mut store = AsPathStore::default();
    let entry = store.intern(&canonical).unwrap();
    support::measure(
        "store/retained_hit",
        |_| {
            let hit = store.intern(black_box(&canonical)).unwrap();
            assert!(Arc::ptr_eq(&hit, &entry));
            hit.stored_bytes() as u64
        },
        true,
    );
    support::measure(
        "store/expired_miss",
        |_| {
            AsPathStore::new(0)
                .intern(black_box(&canonical))
                .unwrap()
                .stored_bytes() as u64
        },
        false,
    );
    support::measure(
        "store/cached_summary",
        |_| black_box(&entry).as_path().summary().hop_count as u64,
        true,
    );
    support::measure(
        "store/churn",
        |i| {
            let mut path = canonical.clone();
            path[2..6].copy_from_slice(&(i as u32).to_be_bytes());
            let value = store.intern(&path).unwrap().stored_bytes() as u64;
            assert!(store.records() <= 16_384);
            value
        },
        false,
    );
}
