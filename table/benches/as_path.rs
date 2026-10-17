//! Uses only existing public APIs, so the same harness runs on the base commit.
use bytes::BytesMut;
use rustybgp_packet::{Attribute, Family, PathNlri, bgp};
use rustybgp_table::{
    Actions, ConditionConfig, DefinedSetConfig, Disposition, MatchOption, PeerRole,
    PolicyDirection, PolicyTable, Source, apply_import,
};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

#[path = "../../packet/benches/support/mod.rs"]
mod support;
#[global_allocator]
static ALLOCATOR: support::CountingAllocator = support::CountingAllocator;

fn main() {
    println!("operation,median_ns,allocations_per_op,min_ns,max_ns");
    let source = Arc::new(Source::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        65001,
        65000,
        Ipv4Addr::new(192, 0, 2, 1),
        PeerRole::Ebgp,
    ));
    let net = bgp::Nlri::V4(bgp::Ipv4Net {
        addr: Ipv4Addr::new(203, 0, 113, 0),
        mask: 24,
    });
    for (name, pattern) in [
        ("include", "_65536_"),
        ("origin", "_7$"),
        ("only_miss", "^7$"),
    ] {
        let mut table = PolicyTable::new();
        table
            .add_defined_set(DefinedSetConfig::AsPath {
                name: "paths".into(),
                patterns: vec![pattern.into()],
            })
            .unwrap();
        table
            .add_statement(
                "match",
                vec![ConditionConfig::AsPathSet("paths".into(), MatchOption::Any)],
                Some(Disposition::Reject),
                Actions::default(),
            )
            .unwrap();
        table.add_policy("policy", vec!["match".into()]).unwrap();
        let (_, policy) = table
            .add_assignment(
                "global",
                PolicyDirection::Import,
                Disposition::Accept,
                vec!["policy".into()],
            )
            .unwrap();
        let attrs: Vec<_> = (0..64)
            .map(|i| {
                let mut bytes = vec![2, 4];
                for asn in [65001u32, 65536 + i % 2, 65001, 7 + i % 2] {
                    bytes.extend_from_slice(&asn.to_be_bytes());
                }
                Arc::new(vec![
                    Attribute::new_with_value(Attribute::ORIGIN, 0).unwrap(),
                    Attribute::new_with_bin(Attribute::AS_PATH, bytes).unwrap(),
                ])
            })
            .collect();
        support::measure(
            &format!("policy/{name}"),
            |i| {
                let mut nh = Some(bgp::Nexthop::V4(Ipv4Addr::new(192, 0, 2, 1)));
                let (filtered, _) = apply_import(
                    black_box(&policy),
                    None,
                    &source,
                    &net,
                    black_box(&attrs[i % attrs.len()]),
                    &mut nh,
                );
                assert_eq!(filtered, name != "only_miss" && i % 2 == 0);
                u64::from(filtered)
            },
            false,
        );
        // Parse and validate a genuine UPDATE, then apply the same import policy.
        let mut codec = bgp::PeerCodec::new();
        codec.set_family(Family::IPV4, Default::default());
        let mut wire = BytesMut::new();
        codec
            .encode_to(
                &bgp::Message::Update(bgp::Update::Reach {
                    family: Family::IPV4,
                    entries: vec![PathNlri::new(net.clone())],
                    nexthop: Some(bgp::Nexthop::V4(Ipv4Addr::new(192, 0, 2, 1))),
                    attr: attrs[0].clone(),
                }),
                &mut wire,
            )
            .unwrap();
        support::measure(
            &format!("update_parse_validate_policy/{name}"),
            |_| {
                let mut input = BytesMut::from(black_box(wire.as_ref()));
                let parsed = codec.try_parse(&mut input).unwrap().unwrap();
                let mut messages = bgp::validate_message(parsed, true).unwrap();
                let bgp::Message::Update(bgp::Update::Reach {
                    attr, mut nexthop, ..
                }) = messages.next().unwrap()
                else {
                    panic!("expected reachable UPDATE");
                };
                let (filtered, _) = apply_import(&policy, None, &source, &net, &attr, &mut nexthop);
                assert_eq!(filtered, name != "only_miss");
                u64::from(filtered)
            },
            false,
        );
        // Model an installed route retaining the entry between UPDATEs. The
        // preceding case deliberately releases every decoded path each time.
        let held = codec
            .try_parse(&mut BytesMut::from(wire.as_ref()))
            .unwrap()
            .unwrap();
        let held: Vec<_> = bgp::validate_message(held, true).unwrap().collect();
        support::measure(
            &format!("update_retained_path/{name}"),
            |_| {
                let mut input = BytesMut::from(black_box(wire.as_ref()));
                let parsed = codec.try_parse(&mut input).unwrap().unwrap();
                let mut messages = bgp::validate_message(parsed, true).unwrap();
                let bgp::Message::Update(bgp::Update::Reach {
                    attr, mut nexthop, ..
                }) = messages.next().unwrap()
                else {
                    panic!("expected reachable UPDATE");
                };
                let (filtered, _) = apply_import(&policy, None, &source, &net, &attr, &mut nexthop);
                assert_eq!(filtered, name != "only_miss");
                u64::from(filtered)
            },
            false,
        );
        black_box(held);
    }
}
