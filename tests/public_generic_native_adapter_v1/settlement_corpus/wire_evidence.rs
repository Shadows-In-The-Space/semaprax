//! Typed, native-only physical observations. These are not projected onto the
//! different heap/registry model used by the interpreter or Wasm model.

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Measurements {
    peak_allocations: u64,
    peak_bytes: u64,
    peak_child_handles: u64,
    endpoint_invoked: bool,
    release_order: Vec<(u32, u32)>,
    secondary_cleanup: Vec<i32>,
}

pub(super) fn read(closed_row: &str) -> Measurements {
    let field = |name: &str| {
        closed_row
            .split(' ')
            .filter_map(|item| item.split_once('='))
            .find_map(|(key, value)| (key == name).then_some(value))
            .expect("missing native measurement")
    };
    let number = |name| {
        let text = field(name);
        let value = text.parse::<u64>().expect("invalid native counter");
        assert_eq!(text, value.to_string(), "noncanonical native counter");
        value
    };
    let invoked = number("endpoint_invoked");
    assert!(invoked <= 1, "invalid endpoint invocation count");
    let releases = field("release_order");
    let release_order: Vec<(u32, u32)> = if releases.is_empty() {
        Vec::new()
    } else {
        releases
            .split(',')
            .map(|entry| {
                let (direction, index) = entry.split_once(':').expect("invalid release pair");
                let direction = direction.parse::<u32>().expect("invalid release direction");
                let index = index.parse::<u32>().expect("invalid release index");
                assert!(
                    direction <= 1 && index < 256,
                    "release identity out of bounds"
                );
                assert_eq!(
                    entry,
                    format!("{direction}:{index}"),
                    "noncanonical release pair"
                );
                (direction, index)
            })
            .collect()
    };
    assert!(release_order.len() <= 1024, "release count bound");
    let secondary = field("secondary_cleanup");
    let secondary_cleanup = if secondary.is_empty() {
        Vec::new()
    } else {
        secondary
            .split(',')
            .map(|status| {
                assert_eq!(status, "11", "unknown cleanup status");
                11
            })
            .collect::<Vec<_>>()
    };
    assert!(secondary_cleanup.len() <= 16, "cleanup status count bound");
    Measurements {
        peak_allocations: number("peak_alloc"),
        peak_bytes: number("peak_bytes"),
        peak_child_handles: number("peak_handles"),
        endpoint_invoked: invoked == 1,
        release_order,
        secondary_cleanup,
    }
}

#[test]
fn native_wire_rejects_duplicate_missing_reordered_and_noncanonical_fields() {
    const ROW: &str = "CASE case_id=fixture accepted=0 status=6 live_alloc=0 live_handles=0 \
        fixture_live=0 fixture_peak=1 overwrite=0 trace=14 result=- live_bytes=0 \
        peak_alloc=1 peak_bytes=8 peak_handles=0 endpoint_invoked=0 release_order= secondary_cleanup=";
    super::parse_native_line(ROW, "native-c11-O0");
    for corrupt in [
        ROW.replace("accepted=0", "accepted=2"),
        ROW.replace("accepted=0", "accepted=0 accepted=0"),
        ROW.replace("accepted=0 ", ""),
        ROW.replace("accepted=0 status=6", "status=6 accepted=0"),
        ROW.replace("peak_alloc=1", "peak_alloc=01"),
        ROW.replace("endpoint_invoked=0", "endpoint_invoked=2"),
        ROW.replace("release_order= ", "release_order=0:1,,0:0 "),
        ROW.replace("release_order= ", "release_order=0:256 "),
        ROW.replace("secondary_cleanup=", "secondary_cleanup=11,"),
        format!("{ROW} unknown=0"),
    ] {
        assert!(
            std::panic::catch_unwind(|| super::parse_native_line(&corrupt, "native-c11-O0"))
                .is_err(),
            "accepted malformed native evidence: {corrupt}"
        );
    }
}
