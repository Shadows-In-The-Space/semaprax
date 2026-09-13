use super::*;

fn limits() -> GenericIoLimits {
    GenericIoLimits {
        max_request_bytes: 3,
        max_total_request_bytes: 6,
        max_total_response_bytes: 8,
    }
}

#[test]
fn exact_reservation_and_settlement_preserve_unknown_failure_exposure() {
    let mut accounting = GenericIoAccounting::new(limits());
    accounting
        .reserve(0, "request-0".to_owned(), "abc".to_owned(), 4)
        .unwrap();
    accounting.observe(0, 2, false).unwrap();
    accounting
        .reserve(1, "request-1".to_owned(), "def".to_owned(), 4)
        .unwrap();
    accounting.observe(1, 0, true).unwrap();
    assert_eq!(
        accounting.totals().unwrap(),
        GenericIoTotals {
            reserved_request_bytes: 6,
            reserved_response_bytes: 8,
            observed_response_bytes: 2,
            unknown_response_reservation_bytes: 4,
        }
    );
}

#[test]
fn overflow_or_a_widened_successor_refuses_before_mutation() {
    let mut accounting = GenericIoAccounting::new(limits());
    assert_eq!(
        accounting
            .reserve(0, "request".to_owned(), "wide".to_owned(), 1)
            .unwrap_err()
            .0,
        GENERIC_IO_REQUEST_LIMIT
    );
    assert!(accounting.attempts().is_empty());
    let carry = GenericIoTotals {
        reserved_request_bytes: 3,
        reserved_response_bytes: 4,
        observed_response_bytes: 0,
        unknown_response_reservation_bytes: 4,
    };
    let wider = GenericIoLimits {
        max_request_bytes: 4,
        max_total_request_bytes: 7,
        max_total_response_bytes: 9,
    };
    assert_eq!(
        GenericIoAccounting::with_carry(wider, &limits(), carry)
            .unwrap_err()
            .0,
        GENERIC_IO_CAPACITY
    );
}
