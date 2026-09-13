use super::Stage;
use std::cell::RefCell;
use std::time::Instant;

const MAX_DEPTH: usize = 64;
const MAX_SPANS: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StageObservation {
    pub calls: u64,
    /// Wall time including nested instrumented stages.
    pub inclusive_ns: u128,
    /// Wall time excluding nested instrumented stages on this thread.
    pub self_ns: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observation {
    pub total_ns: u128,
    pub stages: [StageObservation; Stage::ALL.len()],
    /// False if the bounded observer could not record the whole operation.
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureBusy;

struct Frame {
    stage: Stage,
    start: Instant,
    child_ns: u128,
}

struct Session {
    stack: Vec<Frame>,
    stages: [StageObservation; Stage::ALL.len()],
    calls: u64,
    complete: bool,
}

thread_local! {
    static ACTIVE: RefCell<Option<Session>> = const { RefCell::new(None) };
}

struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        ACTIVE.with(|active| {
            active.borrow_mut().take();
        });
    }
}

/// Observe one synchronous operation. Nested captures refuse without running
/// their closure. Unwinding drops the current session; no state survives it.
/// `T` may itself be an error: refusal-path measurements are not successes.
pub fn capture<T>(operation: impl FnOnce() -> T) -> Result<(T, Observation), CaptureBusy> {
    ACTIVE.with(|active| {
        let mut active = active.borrow_mut();
        if active.is_some() {
            return Err(CaptureBusy);
        }
        *active = Some(Session {
            stack: Vec::with_capacity(MAX_DEPTH),
            stages: [StageObservation::default(); Stage::ALL.len()],
            calls: 0,
            complete: true,
        });
        Ok(())
    })?;
    let _reset = Reset;
    let start = Instant::now();
    let value = operation();
    let total_ns = start.elapsed().as_nanos();
    let session = ACTIVE
        .with(|active| active.borrow_mut().take())
        .expect("capture owns session");
    Ok((
        value,
        Observation {
            total_ns,
            complete: session.complete && session.stack.is_empty(),
            stages: session.stages,
        },
    ))
}

pub(crate) struct Span(Option<usize>);

pub(crate) fn span(stage: Stage) -> Span {
    Span(ACTIVE.with(|active| {
        let mut active = active.borrow_mut();
        let session = active.as_mut()?;
        if session.stack.len() == MAX_DEPTH || session.calls == MAX_SPANS {
            session.complete = false;
            return None;
        }
        session.calls += 1;
        let depth = session.stack.len();
        session.stack.push(Frame {
            stage,
            start: Instant::now(),
            child_ns: 0,
        });
        Some(depth)
    }))
}

impl Drop for Span {
    fn drop(&mut self) {
        let Some(depth) = self.0 else {
            return;
        };
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            let Some(session) = active.as_mut() else {
                return;
            };
            if session.stack.len() != depth + 1 {
                session.complete = false;
                return;
            }
            let frame = session.stack.pop().expect("checked nonempty span stack");
            let elapsed = frame.start.elapsed().as_nanos();
            let observation = &mut session.stages[frame.stage as usize];
            observation.calls += 1;
            observation.inclusive_ns += elapsed;
            observation.self_ns += elapsed.saturating_sub(frame.child_ns);
            if let Some(parent) = session.stack.last_mut() {
                parent.child_ns += elapsed;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_stages_partition_time_and_nested_capture_does_not_run() {
        let (value, report) = capture(|| {
            let _outer = span(Stage::Resolve);
            assert_eq!(capture(|| panic!("must not run")), Err(CaptureBusy));
            {
                let _inner = span(Stage::HirValidate);
            }
            7
        })
        .unwrap();
        assert_eq!(value, 7);
        assert!(report.complete);
        let outer = report.stages[Stage::Resolve as usize];
        let inner = report.stages[Stage::HirValidate as usize];
        assert_eq!((outer.calls, inner.calls), (1, 1));
        assert_eq!(outer.inclusive_ns, outer.self_ns + inner.inclusive_ns);
        assert!(report.total_ns >= outer.inclusive_ns);
    }

    #[test]
    fn unwind_and_thread_boundaries_do_not_leak_observation_state() {
        let _ = std::panic::catch_unwind(|| {
            capture(|| {
                let _span = span(Stage::Parse);
                panic!("fixture");
            })
        });
        let (_, report) = capture(|| {
            let (_, child) = std::thread::spawn(|| {
                capture(|| {
                    let _span = span(Stage::Parse);
                })
                .unwrap()
            })
            .join()
            .unwrap();
            assert!(child.complete);
            assert_eq!(child.stages[Stage::Parse as usize].calls, 1);
        })
        .unwrap();
        assert!(report.complete);
        assert_eq!(report.stages[Stage::Parse as usize].calls, 0);
    }

    #[test]
    fn exceeding_depth_is_visible_and_does_not_change_the_operation() {
        let (count, report) = capture(|| {
            let spans = (0..=MAX_DEPTH)
                .map(|_| span(Stage::Resolve))
                .collect::<Vec<_>>();
            let count = spans.len();
            for guard in spans.into_iter().rev() {
                drop(guard);
            }
            count
        })
        .unwrap();
        assert_eq!(count, MAX_DEPTH + 1);
        assert!(!report.complete);
        assert_eq!(
            report.stages[Stage::Resolve as usize].calls,
            MAX_DEPTH as u64
        );
    }
}
