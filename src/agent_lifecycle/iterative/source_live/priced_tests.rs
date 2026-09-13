//! Actual source execution must reserve distinct work and money before dispatch.
use super::*;
use crate::live_invocation::source_journal::SourceTerminalStatus;

#[test]
fn priced_source_boundaries_and_terminal_recovery_keep_distinct_accounting() {
    let compiled = lifecycle();
    let task = task();
    let clock = Clock { now: 1 };
    let cancellation = AgentCancellation::default();
    for (ceiling, malformed, dispatches, effects) in [
        (0, false, 0, 0),
        (14, false, 1, 1),
        (15, false, 1, 1),
        (14, true, 1, 0),
    ] {
        let mut policy = policy(1000);
        policy.reservation_units = 2;
        let pricing = SourceLivePricing {
            currency: "USD".into(),
            minor_unit_exponent: 6,
            price_per_work_unit_minor: 7,
            money_ceiling_minor: ceiling,
        };
        let mut source = Source {
            responses: vec![
                if malformed {
                    b"not-json".to_vec()
                } else {
                    Source::valid_response(&compiled)
                };
                2
            ],
            calls: 0,
            deployment: DEPLOYMENT.into(),
            response_limit: 4096,
            reservation_units: 2,
        };
        let mut read = Read { calls: 0 };
        let mut store = Store::default();
        let failure = compiled
            .run_live_durable_priced(
                request(&task, &policy, &clock, &cancellation),
                &pricing,
                &mut source,
                &mut read,
                &mut store,
            )
            .err()
            .expect("money ceiling stops the multi-turn or retry fixture");
        assert_eq!(
            failure.selected,
            Some(SourceTerminalStatus::BudgetExhausted),
            "ceiling {ceiling}, malformed {malformed}"
        );
        assert_eq!((source.calls, read.calls), (dispatches, effects));
        assert_eq!(
            (failure.model_dispatches, failure.effect_dispatches),
            (dispatches as u32, effects as u32)
        );
        let checkpoint = failure.checkpoint.unwrap();
        assert_eq!(checkpoint.committed_reserved_units(), dispatches as i64 * 2);
        let totals = checkpoint.priced_totals().expect("priced receipt");
        assert_eq!(totals.reserved_minor, dispatches as i64 * 14);
        assert_eq!(
            totals.unknown_charge_reservation_minor,
            totals.reserved_minor
        );
        assert_eq!(totals.observed_charge_minor, 0);
        let mut source = Source {
            responses: Vec::new(),
            calls: 0,
            deployment: DEPLOYMENT.into(),
            response_limit: 4096,
            reservation_units: 2,
        };
        let mut read = Read { calls: 0 };
        let mut recovered_store = Store::default();
        let resumed = compiled
            .run_live_durable_priced(
                SourceLiveRequest {
                    checkpoint: Some(&store.document),
                    ..request(&task, &policy, &clock, &cancellation)
                },
                &pricing,
                &mut source,
                &mut read,
                &mut recovered_store,
            )
            .unwrap();
        assert_eq!(
            (
                source.calls,
                read.calls,
                resumed.model_dispatches,
                resumed.effect_dispatches
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(resumed.checkpoint.generation(), checkpoint.generation());
        assert_eq!(
            resumed.checkpoint.priced_totals(),
            checkpoint.priced_totals()
        );
        assert!(recovered_store.document.is_empty());
        let changed_price = SourceLivePricing {
            price_per_work_unit_minor: 8,
            ..pricing.clone()
        };
        assert!(compiled
            .run_live_durable_priced(
                SourceLiveRequest {
                    checkpoint: Some(&store.document),
                    ..request(&task, &policy, &clock, &cancellation)
                },
                &changed_price,
                &mut source,
                &mut read,
                &mut recovered_store,
            )
            .is_err());
        assert_eq!((source.calls, read.calls), (0, 0));
        assert!(recovered_store.document.is_empty());
    }
}
