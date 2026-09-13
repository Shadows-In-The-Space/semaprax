//! Checked atomic publication through the authenticated Project v19 route.
use super::{filesystem, project};
use semaprax::filesystem_provider::{CheckedAtomicWriteFault, FixtureFileProvider};
use semaprax::interpreter::CommandEvaluationOutcome;

const CASES: [(&str, &str, Option<CheckedAtomicWriteFault>); 4] = [
    ("std.fs.tests.checked-published", "published", None),
    (
        "std.fs.tests.checked-not-published",
        "not-published",
        Some(CheckedAtomicWriteFault::BeforeCommit),
    ),
    (
        "std.fs.tests.checked-uncertain",
        "uncertain",
        Some(CheckedAtomicWriteFault::CommitOutcomeUnknown),
    ),
    ("std.fs.examples.checked-replace", "example", None),
];

pub(super) const C_PROVIDER: &str = r#"
struct fixture { unsigned calls, settlements; unsigned code; unsigned byte; };
static uint32_t checked(void *ctx, spx_slice_u8_v1 path, uint64_t path_len,
                        spx_slice_u8_v1 data, uint64_t data_len, uint64_t *out) {
 struct fixture *s=ctx; ++s->calls;
 if(data_len!=1||data.len<1||data.ptr[0]!=65||path_len!=(SCENARIO==1?3:1))return 5;
 if(SCENARIO==1 ? memcmp(path.ptr,"d/a",3)!=0 : path.ptr[0]!=99)return 5;
 if(s->code==4)return 0; // Host omitted the result slot.
 if(s->code==5)return 6; // Valid callback failure status.
 if(s->code==6)return 42; // Invalid callback failure status.
 *out=s->code;
 if(s->code==0||s->code==2)s->byte=65;
 return 0;
}
static void settle(void *ctx) { ++((struct fixture*)ctx)->settlements; }
static int checked_carrier_boundaries(void) {
 uint8_t path_byte=99, data_byte=65;
 for(unsigned kind=0;kind<3;++kind) {
  struct fixture state={0};
  struct spx_filesystem_callbacks_v3 callbacks={.context=&state,.write_atomic_checked=checked};
  struct spx_filesystem_command_state_v3 command={.callbacks=&callbacks};
  struct spx_status_entry entries[1];struct spx_context ctx={0};
  if(!spx_context_init(&ctx,1,entries,1,NULL,NULL,&command))return 1;
  spx_slice_u8_v1 path={.ptr=kind==0?NULL:&path_byte,.len=1};
  spx_slice_u8_v1 data={.ptr=kind==1?NULL:&data_byte,.len=1};
  uint64_t result=UINT64_MAX;
  spx_status_token status=spx_host_file_write_atomic_checked_v1(&ctx,path,kind==2?2:1,data,1,&result);
  if(state.calls!=0)return 2;
  if(kind==2) { if(status!=0||result!=1)return 3; }
  else {const struct spx_normalized_status *failure=spx_status_resolve(&ctx,status);if(!failure||failure->code!=5)return 4;}
 }
 return 0;
}
int main(void) {
 if(checked_carrier_boundaries()!=0)return 3;
 for(int i=0;i<2;++i) {
  struct fixture state={.code=SCENARIO==0||SCENARIO==3?0:SCENARIO==1?1:2,.byte=66};
  struct spx_filesystem_callbacks_v3 callbacks={.context=&state,.write_atomic_checked=checked,.settle=settle};
  struct spx_filesystem_command_result_v3 result;
  if(spx_run_filesystem_command_v3(&callbacks,&result)!=1||!result.semantic_success||!result.matched||state.calls!=(SCENARIO==4?0:1)||state.settlements!=1||state.byte!=(SCENARIO==4||state.code==1?66:65))return 1;
 }
 if(SCENARIO==4)return 0;
 // Invalid, unwritten, and nonzero callback outcomes are never source values.
 for(unsigned mode=3;mode<=6;++mode) {
  struct fixture bad={.code=mode,.byte=66};
  struct spx_filesystem_callbacks_v3 callbacks={.context=&bad,.write_atomic_checked=checked,.settle=settle};
  struct spx_filesystem_command_result_v3 result;
  if(spx_run_filesystem_command_v3(&callbacks,&result)!=1||result.semantic_success||bad.calls!=1||bad.settlements!=1||bad.byte!=66||result.status_code!=(mode==5?6:5))return 2;
 }
 return 0;
}
"#;

fn compact_v3_package(label: &str, command: &str) -> std::path::PathBuf {
    let manifest = filesystem::package(label, command, false);
    let text = std::fs::read_to_string(&manifest)
        .unwrap()
        .replace("filesystem-io.v1", "filesystem-io.v3");
    std::fs::write(&manifest, text).unwrap();
    let source_dir = manifest.parent().unwrap().join("src");
    std::fs::write(
        source_dir.join("examples.spx"),
        include_str!("filesystem_v3_sources/examples.spx"),
    )
    .unwrap();
    std::fs::write(
        source_dir.join("tests.spx"),
        include_str!("filesystem_v3_sources/tests.spx"),
    )
    .unwrap();
    manifest
}

#[cfg(unix)]
pub(super) fn run_conformance() {
    for (command, scenario, fault) in CASES {
        let manifest = compact_v3_package("fs-v3", command);
        let mut provider = FixtureFileProvider::new([(b"c".to_vec(), vec![66])], true).unwrap();
        provider.set_checked_atomic_fault(fault);
        project::with_authenticated_project(&manifest, |snapshot| {
            let run = snapshot.execute_filesystem_command(&mut provider, 1_000_000)?;
            assert!(
                matches!(run.outcome, CommandEvaluationOutcome::ReturnedBool(true)),
                "{command}: {run:?}"
            );
            assert_eq!(provider.settlements(), 1);
            assert_eq!(
                provider.files().get(b"c".as_slice()).unwrap(),
                &vec![if scenario != "not-published" { 65 } else { 66 }]
            );
            assert_eq!(provider.files().len(), 1);
            let revision = snapshot.retain_revision();
            let scenario_number = match scenario {
                "published" => 0,
                "not-published" => 1,
                "uncertain" => 2,
                "example" => 3,
                _ => unreachable!(),
            };
            let source = format!(
                "{}\n#define SCENARIO {scenario_number}\n{C_PROVIDER}",
                revision.filesystem_c_source()?
            );
            for optimization in ["-O0", "-O2"] {
                super::compile_and_run_c(&source, manifest.parent().unwrap(), optimization, "");
            }
            let wasm_path = manifest.with_extension("wasm");
            let facade_path = manifest.with_extension("mjs");
            std::fs::write(&wasm_path, revision.filesystem_wasm_module()?).unwrap();
            std::fs::write(&facade_path, include_str!("filesystem_v3_facade.mjs")).unwrap();
            let symbol = format!(
                "spx_data_{}",
                command
                    .bytes()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            let result = std::process::Command::new("node")
                .arg(&facade_path)
                .arg(&wasm_path)
                .arg(symbol)
                .arg(scenario)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(String::from_utf8(result.stdout).unwrap(), "ok\n");
            Ok(())
        })
        .unwrap();
        std::fs::remove_dir_all(manifest.parent().unwrap()).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn filesystem_v3_checked_outcomes_execute_on_all_three_backends() {
    run_conformance();
}

#[cfg(unix)]
#[test]
fn filesystem_v3_invalid_raw_path_is_a_value_inside_nested_blocks() {
    let command = "std.fs.tests.checked-invalid-raw-path";
    let manifest = compact_v3_package("fs-v3-invalid-raw", command);
    let source_path = manifest.parent().unwrap().join("src/tests.spx");
    let mut source = std::fs::read_to_string(&source_path).unwrap();
    source.push_str(r#"
@id("std.fs.tests.checked-invalid-raw-path")
fn checked_invalid_raw_path() -> bool
    uses { fs.write }
{
    let path = [97u8, 47u8, 46u8, 46u8, 47u8, 98u8];
    let data = [65u8];
    let outcome = if true { if true { file_write_atomic_checked(array_as_slice(path), 6usize, array_as_slice(data), 1usize) } else { 0usize } } else { 0usize };
    outcome == 1usize
}
"#);
    let parsed = semaprax::parse(&source, &source_path).unwrap();
    std::fs::write(&source_path, semaprax::format::canonical(&parsed)).unwrap();
    let mut provider = FixtureFileProvider::new([(b"c".to_vec(), vec![66])], true).unwrap();
    project::with_authenticated_project(&manifest, |snapshot| {
        let run = snapshot.execute_filesystem_command(&mut provider, 1_000_000)?;
        assert!(
            matches!(run.outcome, CommandEvaluationOutcome::ReturnedBool(true)),
            "{run:?}"
        );
        assert_eq!(provider.files().get(b"c".as_slice()), Some(&vec![66]));
        assert_eq!(provider.settlements(), 1);
        let revision = snapshot.retain_revision();
        let c_source = format!(
            "{}\n#define SCENARIO 4\n{C_PROVIDER}",
            revision.filesystem_c_source()?
        );
        for optimization in ["-O0", "-O2"] {
            super::compile_and_run_c(&c_source, manifest.parent().unwrap(), optimization, "");
        }
        let wasm_path = manifest.with_extension("wasm");
        let facade_path = manifest.with_extension("mjs");
        std::fs::write(&wasm_path, revision.filesystem_wasm_module()?).unwrap();
        std::fs::write(&facade_path, include_str!("filesystem_v3_facade.mjs")).unwrap();
        let symbol = format!(
            "spx_data_{}",
            command
                .bytes()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let result = std::process::Command::new("node")
            .arg(&facade_path)
            .arg(&wasm_path)
            .arg(symbol)
            .arg("invalid-path")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(String::from_utf8(result.stdout).unwrap(), "ok\n");
        Ok(())
    })
    .unwrap();
    std::fs::remove_dir_all(manifest.parent().unwrap()).unwrap();
}
