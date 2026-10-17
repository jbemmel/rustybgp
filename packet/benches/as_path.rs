use rustybgp_packet::bgp::{AsPathIter, Attribute};
use std::hint::black_box;

mod support;
#[global_allocator]
static ALLOCATOR: support::CountingAllocator = support::CountingAllocator;

fn main() {
    println!("operation,median_ns,allocations_per_op,min_ns,max_ns");
    for (name, kinds, count) in [("short", vec![2], 4), ("mixed", vec![2, 1, 3, 4], 4)] {
        let mut bytes = Vec::new();
        for kind in kinds {
            bytes.extend_from_slice(&[kind, count]);
            for i in 0..count {
                // Includes duplicates, narrow and wide ASNs.
                bytes.extend_from_slice(
                    &(if i % 3 == 0 { 65536 } else { u32::from(i) + 1 }).to_be_bytes(),
                );
            }
        }
        let attr = Attribute::new_with_bin(Attribute::AS_PATH, bytes).unwrap();
        let owned = || {
            AsPathIter::new(black_box(&attr))
                .flatten()
                .map(u64::from)
                .sum::<u64>()
        };
        let borrowed = || {
            black_box(&attr)
                .as_path()
                .unwrap()
                .segments()
                .flat_map(|segment| segment.asns())
                .map(u64::from)
                .sum::<u64>()
        };
        assert_eq!(owned(), borrowed());
        support::measure(&format!("{name}/owned_decode"), |_| owned(), false);
        support::measure(&format!("{name}/borrowed_decode"), |_| borrowed(), true);
        support::measure(
            &format!("{name}/prepend"),
            |_| {
                black_box(black_box(&attr).as_path_prepend(65000));
                1
            },
            false,
        );
        support::measure(
            &format!("{name}/wire_encode"),
            |_| black_box(&attr).encode_to_bytes().len() as u64,
            false,
        );
        let targets = [black_box(u32::MAX), black_box(u32::MAX - 1)];
        support::measure(
            &format!("{name}/two_counts_miss"),
            |_| {
                u64::from(
                    attr.as_path_count(targets[0]).unwrap() > 0
                        || attr.as_path_count(targets[1]).unwrap() > 0,
                )
            },
            true,
        );
        support::measure(
            &format!("{name}/borrowed_presence_miss"),
            |_| u64::from(attr.as_path().unwrap().contains_any(&targets)),
            true,
        );
        support::measure(
            &format!("{name}/borrowed_summary"),
            |_| {
                let summary = black_box(&attr).as_path().unwrap().summary();
                summary.hop_count as u64 + u64::from(summary.origin.unwrap_or(0))
            },
            true,
        );
    }
}
