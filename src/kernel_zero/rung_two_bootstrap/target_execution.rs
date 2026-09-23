//! Bounded local execution evidence for the five closed Rung-2 renderer lanes.
//!
//! The bootstrap artifact retains both generated C11 and a private scalar-export
//! Wasm companion. Rust remains authoritative: every target observation is
//! converted to a candidate result and passed through [`super::recovery`].

use std::fmt::Write as _;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(unix)]
use rustix::process::{kill_process_group, Pid, Signal};

use super::artifact::{component_defs, Artifact, Component, ComponentDef};
use super::decode::decode_and_replay;
use super::recovery::{recover, CandidateDisposition, CandidateRefusal, TargetFailure};

const REQUIRE_ENV: &str = "SEMAPRAX_REQUIRE_KERNEL_ZERO_RUNG_TWO_TARGETS";
const PROCESS_DEADLINE: Duration = Duration::from_secs(20);
const PROCESS_OUTPUT_CAP: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
enum Input {
    Int(i64),
    Bool(bool),
}

#[derive(Clone, Debug)]
struct Row {
    input: Input,
    rust: Vec<u8>,
}

pub(super) struct Captured {
    pub(super) status: ExitStatus,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

pub(super) struct Scratch(PathBuf);

impl Scratch {
    pub(super) fn create() -> Result<Self, TargetFailure> {
        for _ in 0..8 {
            let mut entropy = [0_u8; 16];
            getrandom::fill(&mut entropy).map_err(|_| TargetFailure::Io)?;
            let suffix = entropy
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let path = std::env::temp_dir().join(format!("semaprax-rung-two-target-{suffix}"));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(TargetFailure::Io),
            }
        }
        Err(TargetFailure::Io)
    }

    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn drain_limited(mut reader: impl Read) -> Vec<u8> {
    let mut retained = Vec::with_capacity(PROCESS_OUTPUT_CAP);
    let mut chunk = [0_u8; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                let remaining = PROCESS_OUTPUT_CAP.saturating_sub(retained.len());
                retained.extend_from_slice(&chunk[..read.min(remaining)]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    retained
}

type PipeReader = (JoinHandle<()>, Receiver<Vec<u8>>);

fn spawn_pipe_reader(reader: impl Read + Send + 'static) -> PipeReader {
    let (sent, received) = mpsc::sync_channel(1);
    let handle = thread::spawn(move || {
        let _ = sent.send(drain_limited(reader));
    });
    (handle, received)
}

fn collect_pipe_reader(reader: PipeReader, deadline: Instant) -> Result<Vec<u8>, TargetFailure> {
    let (handle, received) = reader;
    let remaining = deadline.saturating_duration_since(Instant::now());
    match received.recv_timeout(remaining) {
        Ok(bytes) => {
            handle.join().map_err(|_| TargetFailure::Io)?;
            Ok(bytes)
        }
        Err(mpsc::RecvTimeoutError::Timeout) => Err(TargetFailure::Deadline),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = handle.join();
            Err(TargetFailure::Io)
        }
    }
}

#[cfg(unix)]
fn terminate_child_group(child: &mut Child) {
    // `process_group(0)` below creates a fresh group whose ID is the direct
    // child PID, so the safe rustix wrapper cannot select the caller's group.
    let _ = kill_process_group(Pid::from_child(child), Signal::KILL);
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(not(unix))]
fn terminate_child_group(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Run one local tool under the sole target-evidence process policy. Both
/// pipes are drained concurrently even after their retained transcript cap.
/// Every child enters a fresh Unix process group. Its whole group is killed and
/// the direct child is waited before reader collection, including after a
/// direct child exits, so descendants cannot retain an inherited pipe past the
/// same deadline.
pub(super) fn run_bounded(command: &mut Command) -> Result<Captured, TargetFailure> {
    #[cfg(unix)]
    command.process_group(0);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|_| TargetFailure::Spawn)?;
    let Some(stdout) = child.stdout.take() else {
        terminate_child_group(&mut child);
        return Err(TargetFailure::Io);
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_child_group(&mut child);
        return Err(TargetFailure::Io);
    };
    let stdout_reader = spawn_pipe_reader(stdout);
    let stderr_reader = spawn_pipe_reader(stderr);
    let deadline = Instant::now() + PROCESS_DEADLINE;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) if Instant::now() < deadline => break status,
            Ok(Some(_)) => {
                terminate_child_group(&mut child);
                return Err(TargetFailure::Deadline);
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) => {
                terminate_child_group(&mut child);
                return Err(TargetFailure::Deadline);
            }
            Err(_) => {
                terminate_child_group(&mut child);
                return Err(TargetFailure::Io);
            }
        }
    };
    terminate_child_group(&mut child);
    let stdout = collect_pipe_reader(stdout_reader, deadline)?;
    let stderr = collect_pipe_reader(stderr_reader, deadline)?;
    Ok(Captured {
        status,
        stdout,
        stderr,
    })
}

fn tool_available(name: &str) -> bool {
    let mut command = Command::new(name);
    command.arg("--version");
    run_bounded(&mut command).is_ok_and(|output| output.status.success())
}

fn c_symbol(id: &str) -> String {
    let mut symbol = String::from("spx_decl_");
    for byte in id.bytes() {
        write!(symbol, "{byte:02x}").expect("writing a C symbol cannot fail");
    }
    symbol
}

fn rows(definition: &ComponentDef) -> Vec<Row> {
    let values = match definition.name {
        "char" => [
            Input::Int(u32::from('\n').into()),
            Input::Int(u32::from('\'').into()),
            Input::Int(u32::from('A').into()),
            Input::Int(0x7f),
            Input::Int(0x80),
            Input::Int(0x10ffff),
        ]
        .to_vec(),
        "bool" => vec![Input::Bool(false), Input::Bool(true)],
        "int" => vec![
            Input::Int(i64::MIN),
            Input::Int(-1),
            Input::Int(0),
            Input::Int(1),
            Input::Int(i64::MAX),
        ],
        "operator" => (0..=14).map(Input::Int).collect(),
        "string-scalar" => [
            Input::Int(u32::from('\t').into()),
            Input::Int(u32::from('\n').into()),
            Input::Int(u32::from('"').into()),
            Input::Int(u32::from('\\').into()),
            Input::Int(0x7f),
            Input::Int(0x80),
            Input::Int(u32::from('é').into()),
            Input::Int(u32::from('🦀').into()),
            Input::Int(0x10ffff),
        ]
        .to_vec(),
        other => panic!("unknown closed renderer component {other:?}"),
    };
    values
        .into_iter()
        .map(|input| Row {
            rust: authoritative_bytes(definition.name, input),
            input,
        })
        .collect()
}

fn authoritative_bytes(component: &str, input: Input) -> Vec<u8> {
    match (component, input) {
        ("char", Input::Int(value)) => super::super::canonical_char_renderer::render_bytes(
            u32::try_from(value).expect("char corpus inputs are u32"),
        )
        .expect("authoritative char renderer must accept corpus input"),
        ("bool", Input::Bool(value)) => super::super::canonical_bool_renderer::render_bytes(value)
            .expect("authoritative bool renderer must accept corpus input"),
        ("int", Input::Int(value)) => super::super::canonical_int_renderer::render_bytes(value)
            .expect("authoritative integer renderer must accept corpus input"),
        ("operator", Input::Int(value)) => {
            super::super::canonical_operator_renderer::render_bytes(value)
                .expect("authoritative operator renderer must accept corpus input")
        }
        ("string-scalar", Input::Int(value)) => {
            super::super::canonical_string_renderer::render_bytes(
                u32::try_from(value).expect("string corpus inputs are u32"),
            )
            .expect("authoritative string renderer must accept corpus input")
        }
        (component, input) => panic!("invalid input {input:?} for {component}"),
    }
}

fn c_literal(input: Input) -> String {
    match input {
        Input::Bool(value) => value.to_string(),
        Input::Int(i64::MIN) => "(-INT64_C(9223372036854775807) - 1)".to_owned(),
        Input::Int(value) if value < 0 => format!("(-INT64_C({}))", value.unsigned_abs()),
        Input::Int(value) => format!("INT64_C({value})"),
    }
}

fn js_literal(input: Input) -> String {
    match input {
        Input::Bool(value) => value.to_string(),
        Input::Int(value) => format!("{value}n"),
    }
}

fn native_driver(definition: &ComponentDef, rows: &[Row]) -> Result<String, TargetFailure> {
    let length = c_symbol(definition.length_entry);
    let byte = c_symbol(definition.entry);
    let mut driver = String::from("int main(void) {\n");
    for (index, row) in rows.iter().enumerate() {
        let input = c_literal(row.input);
        writeln!(
            driver,
            "    {{\n\
             \x20       struct spx_status_entry spx_status_entries[UINT32_C(1)];\n\
             \x20       struct spx_context spx_ctx = {{0}};\n\
             \x20       if (!spx_context_init(&spx_ctx, UINT64_C(4096), spx_status_entries, UINT32_C(1), NULL, NULL, NULL)) return 90;\n\
             \x20       int64_t spx_length = 0;\n\
             \x20       if ({length}(&spx_ctx, {input}, &spx_length) != SPX_STATUS_SUCCESS || spx_length < 1 || spx_length > 32) return 91;\n\
             \x20       printf(\"{index} \");\n\
             \x20       for (int64_t spx_index = 0; spx_index < spx_length; ++spx_index) {{\n\
             \x20           int64_t spx_byte = 0;\n\
             \x20           if ({byte}(&spx_ctx, {input}, spx_index, &spx_byte) != SPX_STATUS_SUCCESS || spx_byte < 0 || spx_byte > 255) return 92;\n\
             \x20           printf(\"%02x\", (unsigned int)spx_byte);\n\
             \x20       }}\n\
             \x20       printf(\"\\n\");\n\
             \x20   }}"
        )
        .map_err(|_| TargetFailure::Io)?;
    }
    driver.push_str("    return 0;\n}\n");
    Ok(driver)
}

fn parse_rows(stdout: &[u8], rows: &[Row]) -> Result<Vec<Vec<u8>>, TargetFailure> {
    let stdout = std::str::from_utf8(stdout).map_err(|_| TargetFailure::Parse)?;
    let lines: Vec<_> = stdout.lines().collect();
    if lines.len() != rows.len() {
        return Err(TargetFailure::Parse);
    }
    lines
        .into_iter()
        .enumerate()
        .map(|(index, line)| {
            let (actual_index, hex) = line.split_once(' ').ok_or(TargetFailure::Parse)?;
            if actual_index.parse::<usize>().ok() != Some(index) || hex.len() % 2 != 0 {
                return Err(TargetFailure::Parse);
            }
            (0..hex.len())
                .step_by(2)
                .map(|offset| {
                    u8::from_str_radix(&hex[offset..offset + 2], 16)
                        .map_err(|_| TargetFailure::Parse)
                })
                .collect()
        })
        .collect()
}

fn run_native(
    definition: &ComponentDef,
    component: &Component,
    rows: &[Row],
    root: &Path,
    optimization: &str,
    refusal: fn(TargetFailure) -> CandidateRefusal,
) -> Result<Vec<Vec<u8>>, CandidateRefusal> {
    let source = root.join(format!("{}-{optimization}.c", definition.name));
    let executable = root.join(format!("{}-{optimization}", definition.name));
    let generated =
        std::str::from_utf8(&component.c_source).map_err(|_| refusal(TargetFailure::Parse))?;
    std::fs::write(
        &source,
        format!(
            "{generated}\n{}",
            native_driver(definition, rows).map_err(refusal)?
        ),
    )
    .map_err(|_| refusal(TargetFailure::Io))?;
    let mut compile = Command::new("clang");
    compile
        .args([
            "-std=c11",
            optimization,
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DSPX_NO_ENTRY_WRAPPER",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&executable);
    let output = run_bounded(&mut compile).map_err(refusal)?;
    if !output.status.success() {
        let _ = output.stderr;
        return Err(refusal(TargetFailure::Nonzero));
    }
    let mut execute = Command::new(&executable);
    let output = run_bounded(&mut execute).map_err(refusal)?;
    if !output.status.success() {
        let _ = output.stderr;
        return Err(refusal(TargetFailure::Nonzero));
    }
    parse_rows(&output.stdout, rows).map_err(refusal)
}

fn run_wasm(
    definition: &ComponentDef,
    companion: &[u8],
    rows: &[Row],
    root: &Path,
    run_label: &str,
    refusal: fn(TargetFailure) -> CandidateRefusal,
) -> Result<Vec<Vec<u8>>, CandidateRefusal> {
    let package = root.join(format!("{}-{run_label}-wasm", definition.name));
    let program = crate::parse(definition.source, definition.source_name)
        .map_err(|_| refusal(TargetFailure::Io))?;
    crate::wasm::build_web_with_scalar_exports(
        &program,
        &package,
        &[
            definition.length_entry.to_owned(),
            definition.entry.to_owned(),
        ],
    )
    .map_err(|_| refusal(TargetFailure::Io))?;
    std::fs::write(package.join("app.wasm"), companion).map_err(|_| refusal(TargetFailure::Io))?;
    let mut script = String::from(
        "import { readFile } from \"node:fs/promises\";\n\
         import { pathToFileURL } from \"node:url\";\n\
         import { resolve } from \"node:path\";\n\
         const directory = resolve(process.argv[2]);\n\
         const bindings = await import(pathToFileURL(resolve(directory, \"semaprax.bindings.js\")));\n\
         const runtime = await bindings.instantiateBytes(await readFile(resolve(directory, \"app.wasm\")));\n",
    );
    let length = format!("{:?}", definition.length_entry);
    let byte = format!("{:?}", definition.entry);
    for (index, row) in rows.iter().enumerate() {
        let input = js_literal(row.input);
        writeln!(
            script,
            "{{ const length = runtime.call({length}, {input}); if (!length.ok || typeof length.value !== 'bigint' || length.value < 1n || length.value > 32n) process.exit(41); let output = ''; for (let i = 0n; i < length.value; ++i) {{ const byte = runtime.call({byte}, {input}, i); if (!byte.ok || typeof byte.value !== 'bigint' || byte.value < 0n || byte.value > 255n) process.exit(42); output += Number(byte.value).toString(16).padStart(2, '0'); }} process.stdout.write('{index} ' + output + '\\n'); }}"
        )
        .map_err(|_| refusal(TargetFailure::Io))?;
    }
    let observer = root.join(format!("{}-observe.mjs", definition.name));
    std::fs::write(&observer, script).map_err(|_| refusal(TargetFailure::Io))?;
    let mut execute = Command::new("node");
    execute.arg(&observer).arg(&package);
    let output = run_bounded(&mut execute).map_err(refusal)?;
    if !output.status.success() {
        let _ = output.stderr;
        return Err(refusal(TargetFailure::Nonzero));
    }
    parse_rows(&output.stdout, rows).map_err(refusal)
}

fn candidate(
    observed: Result<Vec<Vec<u8>>, CandidateRefusal>,
    expected: &[Vec<u8>],
    refusal: fn(TargetFailure) -> CandidateRefusal,
) -> Result<Vec<Vec<u8>>, CandidateRefusal> {
    let observed = observed?;
    if observed != expected {
        return Err(refusal(TargetFailure::Mismatch));
    }
    Ok(observed)
}

fn assert_recovered_or_matched(
    expected: &[Vec<u8>],
    candidate: &Result<Vec<Vec<u8>>, CandidateRefusal>,
    expected_disposition: CandidateDisposition,
) {
    let recovery = match candidate {
        Ok(actual) => recover(expected, Ok(actual.as_slice())),
        Err(refusal) => recover(expected, Err(*refusal)),
    };
    assert_eq!(recovery.disposition, expected_disposition);
    assert!(std::ptr::eq(recovery.authoritative, expected));
}

#[test]
fn all_five_retained_targets_recover_to_rust_and_reenter_after_corruption() {
    if !tool_available("clang") || !tool_available("node") {
        assert!(
            std::env::var_os(REQUIRE_ENV).is_none(),
            "{REQUIRE_ENV} requires clang and node on PATH"
        );
        return;
    }
    let artifact = Artifact::derive().expect("closed bootstrap artifact must derive");
    assert_eq!(decode_and_replay(artifact.bytes()), Ok(artifact.digest()));
    let root = Scratch::create().expect("creating private target scratch directory");
    for (definition, component) in component_defs().iter().zip(artifact.components()) {
        let rows = rows(definition);
        let expected = rows.iter().map(|row| row.rust.clone()).collect::<Vec<_>>();
        for (optimization, refusal) in [
            (
                "-O0",
                CandidateRefusal::NativeO0 as fn(TargetFailure) -> CandidateRefusal,
            ),
            (
                "-O2",
                CandidateRefusal::NativeO2 as fn(TargetFailure) -> CandidateRefusal,
            ),
        ] {
            let candidate = candidate(
                run_native(
                    definition,
                    component,
                    &rows,
                    root.path(),
                    optimization,
                    refusal,
                ),
                &expected,
                refusal,
            );
            assert_recovered_or_matched(&expected, &candidate, CandidateDisposition::Matched);
        }
        let candidate = candidate(
            run_wasm(
                definition,
                &component.execution_wasm,
                &rows,
                root.path(),
                "baseline",
                CandidateRefusal::Wasm,
            ),
            &expected,
            CandidateRefusal::Wasm,
        );
        assert_recovered_or_matched(&expected, &candidate, CandidateDisposition::Matched);
    }

    let definition = component_defs()[0];
    let component = &artifact.components()[0];
    let rows = rows(&definition);
    let expected = rows.iter().map(|row| row.rust.clone()).collect::<Vec<_>>();
    let mut corrupted_c = component.clone();
    corrupted_c
        .c_source
        .extend_from_slice(b"\n#error injected target corruption\n");
    let corrupted_native_candidate = candidate(
        run_native(
            &definition,
            &corrupted_c,
            &rows,
            root.path(),
            "-O0",
            CandidateRefusal::NativeO0,
        ),
        &expected,
        CandidateRefusal::NativeO0,
    );
    assert_recovered_or_matched(
        &expected,
        &corrupted_native_candidate,
        CandidateDisposition::Recovered(CandidateRefusal::NativeO0(TargetFailure::Nonzero)),
    );
    let reentry = candidate(
        run_native(
            &definition,
            component,
            &rows,
            root.path(),
            "-O0",
            CandidateRefusal::NativeO0,
        ),
        &expected,
        CandidateRefusal::NativeO0,
    );
    assert_recovered_or_matched(&expected, &reentry, CandidateDisposition::Matched);

    let mut corrupted_wasm = component.execution_wasm.clone();
    corrupted_wasm[0] ^= 1;
    let corrupted_wasm_candidate = candidate(
        run_wasm(
            &definition,
            &corrupted_wasm,
            &rows,
            root.path(),
            "corrupt",
            CandidateRefusal::Wasm,
        ),
        &expected,
        CandidateRefusal::Wasm,
    );
    assert_recovered_or_matched(
        &expected,
        &corrupted_wasm_candidate,
        CandidateDisposition::Recovered(CandidateRefusal::Wasm(TargetFailure::Nonzero)),
    );
    let reentry = candidate(
        run_wasm(
            &definition,
            &component.execution_wasm,
            &rows,
            root.path(),
            "reentry",
            CandidateRefusal::Wasm,
        ),
        &expected,
        CandidateRefusal::Wasm,
    );
    assert_recovered_or_matched(&expected, &reentry, CandidateDisposition::Matched);
}

#[test]
fn malformed_target_output_becomes_a_parse_refusal_before_recovery() {
    let definition = component_defs()[0];
    let rows = rows(&definition);
    let expected = rows.iter().map(|row| row.rust.clone()).collect::<Vec<_>>();
    let candidate = candidate(
        parse_rows(b"not an observation\n", &rows).map_err(CandidateRefusal::Wasm),
        &expected,
        CandidateRefusal::Wasm,
    );
    assert_recovered_or_matched(
        &expected,
        &candidate,
        CandidateDisposition::Recovered(CandidateRefusal::Wasm(TargetFailure::Parse)),
    );
}

#[test]
fn mismatching_target_observation_becomes_a_lane_refusal_before_recovery() {
    let definition = component_defs()[0];
    let rows = rows(&definition);
    let expected = rows.iter().map(|row| row.rust.clone()).collect::<Vec<_>>();
    let candidate = candidate(
        Ok(vec![b"wrong target bytes".to_vec()]),
        &expected,
        CandidateRefusal::NativeO2,
    );
    assert_recovered_or_matched(
        &expected,
        &candidate,
        CandidateDisposition::Recovered(CandidateRefusal::NativeO2(TargetFailure::Mismatch)),
    );
}
