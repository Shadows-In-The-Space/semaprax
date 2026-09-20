//! Bounded local Node process control for the Core Wasm stage executor.

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::agent_lifecycle::stages::invariant;
use crate::agent_runtime::AgentCancellation;
use crate::diagnostic::Diagnostic;

pub(super) const MAX_NODE_STDOUT_BYTES: usize = 16 * 1024 * 1024;
const NODE_POLL_INTERVAL: Duration = Duration::from_millis(2);

struct ReapedChild {
    child: Child,
    reaped: bool,
}

impl ReapedChild {
    fn terminate_and_reap(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.reaped = true;
    }
}

impl Drop for ReapedChild {
    fn drop(&mut self) {
        if !self.reaped {
            self.terminate_and_reap();
        }
    }
}

struct BoundedOutput {
    bytes: Vec<u8>,
    overflowed: bool,
    read_failed: bool,
}

fn capture_bounded(
    mut stdout: impl Read + Send + 'static,
    limit: usize,
) -> (thread::JoinHandle<BoundedOutput>, Arc<AtomicBool>) {
    let overflow_signal = Arc::new(AtomicBool::new(false));
    let reader_overflow_signal = Arc::clone(&overflow_signal);
    let capture = thread::spawn(move || {
        let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
        let mut overflowed = false;
        let mut read_failed = false;
        let mut chunk = [0u8; 8 * 1024];
        loop {
            let read = match stdout.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => read,
                Err(_) => {
                    read_failed = true;
                    break;
                }
            };
            let remaining = limit.saturating_sub(bytes.len());
            let retained = read.min(remaining);
            bytes.extend_from_slice(&chunk[..retained]);
            overflowed |= retained != read;
            if overflowed {
                reader_overflow_signal.store(true, Ordering::Relaxed);
            }
        }
        BoundedOutput {
            bytes,
            overflowed,
            read_failed,
        }
    });
    (capture, overflow_signal)
}

pub(super) fn run_node_process(
    directory: &Path,
    cancellation: Option<&AgentCancellation>,
    output_budget: usize,
) -> Result<String, Diagnostic> {
    if output_budget == 0 || output_budget > MAX_NODE_STDOUT_BYTES {
        return Err(invariant("wasm_executor.process.output_budget"));
    }
    if cancellation.is_some_and(AgentCancellation::is_cancelled) {
        return Err(invariant("wasm_executor.process.cancelled"));
    }
    let child = Command::new("node")
        .arg("observe.mjs")
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| invariant("wasm_executor.tool.node"))?;
    let mut child = ReapedChild {
        child,
        reaped: false,
    };
    let stdout = child
        .child
        .stdout
        .take()
        .ok_or_else(|| invariant("wasm_executor.process.stdout"))?;
    let (capture, overflowed) = capture_bounded(stdout, output_budget);
    let status = loop {
        if cancellation.is_some_and(AgentCancellation::is_cancelled) {
            child.terminate_and_reap();
            let _ = capture.join();
            return Err(invariant("wasm_executor.process.cancelled"));
        }
        if overflowed.load(Ordering::Relaxed) {
            child.terminate_and_reap();
            let _ = capture.join();
            return Err(invariant("wasm_executor.process.output_budget"));
        }
        match child.child.try_wait() {
            Ok(Some(status)) => {
                child.reaped = true;
                break status;
            }
            Ok(None) => thread::sleep(NODE_POLL_INTERVAL),
            Err(_) => {
                child.terminate_and_reap();
                let _ = capture.join();
                return Err(invariant("wasm_executor.process.wait"));
            }
        }
    };
    let captured = capture
        .join()
        .map_err(|_| invariant("wasm_executor.process.capture"))?;
    if !status.success() {
        return Err(invariant("wasm_executor.run"));
    }
    if captured.read_failed {
        return Err(invariant("wasm_executor.process.read"));
    }
    if captured.overflowed {
        return Err(invariant("wasm_executor.process.output_budget"));
    }
    String::from_utf8(captured.bytes).map_err(|_| invariant("wasm_executor.output_utf8"))
}
