//! In-process route-table contention/churn control, not a TCP daemon benchmark.
use rustybgp_packet::{Attribute, Family, bgp};
use rustybgp_table::{PeerRole, Source, Table};
use std::net::Ipv4Addr;
use std::sync::{Arc, Barrier, Mutex};
use std::time::Instant;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let shards: usize = args.get(1).map(|s| s.parse().unwrap()).unwrap_or(4);
    let workers: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(4);
    let iterations: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(20_000);
    assert!(shards > 0 && shards <= 255 && workers > 0 && iterations > 0);
    let tables = Arc::new(
        (0..shards)
            .map(|i| Mutex::new(Table::new(i as u32)))
            .collect::<Vec<_>>(),
    );
    #[cfg(feature = "packed-as-paths")]
    let mut receive_store = rustybgp_packet::as_path_store::AsPathStore::default();
    let attrs = Arc::new(
        (0..64u32)
            .map(|i| {
                Arc::new(vec![
                    Attribute::empty_as_path()
                        .as_path_prepend(65001)
                        .as_path_prepend(65002 + i % 2),
                ])
            })
            .collect::<Vec<_>>(),
    );
    #[cfg(feature = "packed-as-paths")]
    let attrs = Arc::new(
        attrs
            .iter()
            .map(|attributes| {
                let mut attributes = Arc::clone(attributes);
                receive_store.intern_attributes(&mut attributes);
                attributes
            })
            .collect::<Vec<_>>(),
    );
    let barrier = Arc::new(Barrier::new(workers + 1));
    let mut threads = Vec::new();
    for worker in 0..workers {
        let tables = tables.clone();
        let attrs = attrs.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let source = Arc::new(Source::new(
                Ipv4Addr::new(192, 0, 2, worker as u8 + 1).into(),
                Ipv4Addr::LOCALHOST.into(),
                65002,
                65000,
                Ipv4Addr::new(192, 0, 2, worker as u8 + 1),
                PeerRole::Ebgp,
            ));
            let mut latency = Vec::with_capacity(iterations);
            barrier.wait();
            for i in 0..iterations {
                let key = (i % 1024) as u32;
                let net = bgp::Nlri::V4(bgp::Ipv4Net {
                    addr: Ipv4Addr::from(0x0a000000 | (key << 8)),
                    mask: 24,
                });
                let start = Instant::now();
                let mut table = tables[key as usize % tables.len()].lock().unwrap();
                if i.is_multiple_of(16) && (i / 1024).is_multiple_of(2) {
                    table.remove(source.clone(), Family::IPV4, net, 0, None);
                } else {
                    table.insert(
                        source.clone(),
                        Family::IPV4,
                        net,
                        0,
                        Some(bgp::Nexthop::V4(Ipv4Addr::new(192, 0, 2, worker as u8 + 1))),
                        attrs[(i + i / 1024) % attrs.len()].clone(),
                        None,
                        false,
                        false,
                        None,
                        0,
                    );
                }
                drop(table);
                latency.push(start.elapsed().as_nanos() as u64);
            }
            latency
        }));
    }
    let start = Instant::now();
    barrier.wait();
    let mut samples = Vec::new();
    for thread in threads {
        samples.extend(thread.join().unwrap());
    }
    let elapsed = start.elapsed().as_secs_f64();
    samples.sort_unstable();
    let live: usize = tables
        .iter()
        .map(|t| t.lock().unwrap().collect_loc_rib_paths(&Family::IPV4).len())
        .sum();
    assert!(live > 0);
    println!(
        "shards={shards} workers={workers} operations={} seconds={elapsed:.6} ops_per_second={:.0} p50_ns={} p95_ns={} p99_ns={} live_destinations={live}",
        samples.len(),
        samples.len() as f64 / elapsed,
        samples[samples.len() / 2],
        samples[samples.len() * 95 / 100],
        samples[samples.len() * 99 / 100]
    );
    // Keep input objects alive until every worker completes; the table owns its
    // own handles too. This excludes packet parsing and peer serialization.
    std::hint::black_box((attrs, tables));
}
