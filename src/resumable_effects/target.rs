//! Pure production artifact preparation for the bounded source resumable
//! profile.
//!
//! This is deliberately a byte preparation seam. It writes no files, starts
//! no process, contacts no host, and makes no claim that a prepared artifact
//! has been deployed or can be resumed by an external scheduler. The caller
//! owns any later publication and physical execution authority.

use super::lowering::{
    lower_sequential, ResumablePlanIdentity, ResumableState, SequentialResumablePlan,
    MAX_RESUMABLE_YIELDS,
};
use crate::diagnostic::Diagnostic;
use crate::hir::{ResolvedFunction, ResolvedProgram};
use sha2::{Digest, Sha256};

const INVALID_TARGET_PROFILE: &str = "SPX-H006";
const ARTIFACT_DIGEST_DOMAIN: &[u8] = b"semaprax.resumable-target-artifact.v1\0";
const PROFILE_DIGEST_DOMAIN: &[u8] = b"semaprax.resumable-target-profile.v1\0";

/// One lowered source function has at most its start projection plus eight
/// per-suspension resume projections.
pub const MAX_TARGET_PROFILE_ARTIFACTS: usize = MAX_RESUMABLE_YIELDS + 1;
/// Individual emitted projections are deliberately capped before they enter a
/// typed profile. This caps an authority-free compiler request as well as its
/// later verifier replay.
pub const MAX_TARGET_PROFILE_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;
/// The complete inventory stays bounded even if every admitted projection is
/// near the individual cap.
pub const MAX_TARGET_PROFILE_BYTES: usize = 16 * 1024 * 1024;

/// The two byte-only target seams admitted by the resumable scalar profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResumableArtifactTarget {
    NativeC11,
    CoreWasm,
}

impl ResumableArtifactTarget {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::NativeC11 => b"native-c11",
            Self::CoreWasm => b"core-wasm",
        }
    }
}

/// The exact yield-free projection that supplied an artifact's bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResumableProjectionSite {
    Start,
    Resume { suspension_index: u32 },
}

impl ResumableProjectionSite {
    fn tag(&self) -> &'static [u8] {
        match self {
            Self::Start => b"start",
            Self::Resume { .. } => b"resume",
        }
    }

    fn index(&self) -> u32 {
        match self {
            Self::Start => u32::MAX,
            Self::Resume { suspension_index } => *suspension_index,
        }
    }
}

/// One deterministic byte projection. Its digest commits to its exact plan,
/// selected function, state, target, projection position, selected entry
/// symbol, and emitted bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumableProjectionArtifact {
    target: ResumableArtifactTarget,
    function_id: String,
    plan_identity: [u8; 32],
    site: ResumableProjectionSite,
    state_id: String,
    entry_symbol: String,
    bytes: Vec<u8>,
    digest: [u8; 32],
}

impl ResumableProjectionArtifact {
    pub fn target(&self) -> ResumableArtifactTarget {
        self.target
    }

    pub fn function_id(&self) -> &str {
        &self.function_id
    }

    pub fn plan_identity(&self) -> &[u8; 32] {
        &self.plan_identity
    }

    pub fn site(&self) -> &ResumableProjectionSite {
        &self.site
    }

    pub fn state_id(&self) -> &str {
        &self.state_id
    }

    pub fn entry_symbol(&self) -> &str {
        &self.entry_symbol
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// A bounded, ordered target inventory for one exact sequential plan.
///
/// This is not a serialized manifest. [`Self::verify`] independently lowers
/// and re-emits every projection from a supplied resolved program before it
/// accepts the typed inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumableTargetProfile {
    target: ResumableArtifactTarget,
    function_id: String,
    plan_identity: [u8; 32],
    artifacts: Vec<ResumableProjectionArtifact>,
    digest: [u8; 32],
}

impl ResumableTargetProfile {
    pub fn target(&self) -> ResumableArtifactTarget {
        self.target
    }

    pub fn function_id(&self) -> &str {
        &self.function_id
    }

    pub fn plan_identity(&self) -> &[u8; 32] {
        &self.plan_identity
    }

    pub fn artifacts(&self) -> &[ResumableProjectionArtifact] {
        &self.artifacts
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Re-lower and re-emit the exact target inventory. A source drift, forged
    /// plan, reordered state, changed target, or one-byte artifact mutation
    /// fails closed without granting any physical authority.
    pub fn verify(&self, program: &ResolvedProgram) -> Result<(), Diagnostic> {
        let expected = prepare_target_profile(program, &self.function_id, self.target)?;
        if expected != *self {
            return Err(invalid(
                "resumable target profile disagrees with the exact checked plan and emitted bytes",
            ));
        }
        Ok(())
    }
}

/// Lower one explicitly identified source function and prepare its complete,
/// ordered start/resume target inventory.
pub fn prepare_target_profile(
    program: &ResolvedProgram,
    function_id: &str,
    target: ResumableArtifactTarget,
) -> Result<ResumableTargetProfile, Diagnostic> {
    let function = selected_function(program, function_id)?;
    let plan = lower_sequential(program, function)?;
    prepare_target_profile_with_plan(program, &plan, target)
}

/// The crate-internal variant supports callers that already hold a checked
/// plan. It always rederives that plan first, so an old or modified plan never
/// becomes a bearer for target preparation.
pub(crate) fn prepare_target_profile_with_plan(
    program: &ResolvedProgram,
    plan: &SequentialResumablePlan,
    target: ResumableArtifactTarget,
) -> Result<ResumableTargetProfile, Diagnostic> {
    let function = selected_function(program, plan.function_id.as_str())?;
    let expected_plan = lower_sequential(program, function)?;
    if expected_plan != *plan {
        return Err(invalid(
            "resumable target preparation requires the exact current deterministic plan",
        ));
    }

    let artifact_count = plan
        .suspensions
        .len()
        .checked_add(1)
        .ok_or_else(|| invalid("resumable target artifact inventory overflow"))?;
    if artifact_count > MAX_TARGET_PROFILE_ARTIFACTS {
        return Err(invalid(
            "resumable target artifact inventory exceeds its bound",
        ));
    }

    let function_id = plan.function_id.as_str().to_owned();
    let plan_identity = *plan.identity.as_bytes();
    let mut total_bytes = 0usize;
    let mut artifacts = Vec::with_capacity(artifact_count);

    let start = plan.start_program(program)?;
    let start_site = ResumableProjectionSite::Start;
    let (start_bytes, start_symbol) =
        emit(target, &start, &function_id, &plan.identity, &start_site)?;
    artifacts.push(artifact(
        target,
        &function_id,
        &plan.identity,
        start_site,
        &plan.entry,
        start_symbol,
        start_bytes,
        &mut total_bytes,
    )?);
    for (index, suspension) in plan.suspensions.iter().enumerate() {
        let index = u32::try_from(index)
            .map_err(|_| invalid("resumable target suspension index does not fit u32"))?;
        let projection = plan.resume_program_at(program, index as usize)?;
        let site = ResumableProjectionSite::Resume {
            suspension_index: index,
        };
        let (bytes, entry_symbol) = emit(target, &projection, &function_id, &plan.identity, &site)?;
        artifacts.push(artifact(
            target,
            &function_id,
            &plan.identity,
            site,
            &suspension.state,
            entry_symbol,
            bytes,
            &mut total_bytes,
        )?);
    }

    let digest = profile_digest(target, &function_id, &plan_identity, &artifacts);
    Ok(ResumableTargetProfile {
        target,
        function_id,
        plan_identity,
        artifacts,
        digest,
    })
}

fn selected_function<'a>(
    program: &'a ResolvedProgram,
    function_id: &str,
) -> Result<&'a ResolvedFunction, Diagnostic> {
    program
        .functions
        .iter()
        .find(|function| function.id.as_str() == function_id)
        .ok_or_else(|| invalid("resumable target function is absent from the resolved program"))
}

fn emit(
    target: ResumableArtifactTarget,
    projection: &ResolvedProgram,
    function_id: &str,
    plan_identity: &ResumablePlanIdentity,
    site: &ResumableProjectionSite,
) -> Result<(Vec<u8>, String), Diagnostic> {
    let (emitted, overflowed) =
        crate::bounded_output::with_limit(MAX_TARGET_PROFILE_ARTIFACT_BYTES, || match target {
            ResumableArtifactTarget::NativeC11 => {
                let generated = crate::codegen::emit_hir_c(projection)?;
                let entry_symbol = native_entry_symbol(plan_identity, site);
                let wrapper = native_wrapper(projection, function_id, &entry_symbol)?;
                let prefix = b"#define SPX_NO_ENTRY_WRAPPER 1\n";
                let length = prefix
                    .len()
                    .checked_add(generated.len())
                    .and_then(|length| length.checked_add(wrapper.len()))
                    .ok_or_else(|| invalid("resumable native artifact byte count overflow"))?;
                if length > MAX_TARGET_PROFILE_ARTIFACT_BYTES {
                    return Err(invalid(
                        "resumable target projection bytes exceed their bound",
                    ));
                }
                let mut bytes = Vec::with_capacity(length);
                bytes.extend_from_slice(prefix);
                bytes.extend_from_slice(generated.as_bytes());
                bytes.extend_from_slice(wrapper.as_bytes());
                Ok((bytes, entry_symbol))
            }
            ResumableArtifactTarget::CoreWasm => {
                crate::wasm::emit_resumable_scalar_projection(projection, function_id)
            }
        });
    if overflowed {
        return Err(invalid(
            "resumable target projection exceeded its emission budget",
        ));
    }
    emitted
}

fn native_wrapper(
    projection: &ResolvedProgram,
    function_id: &str,
    entry_symbol: &str,
) -> Result<String, Diagnostic> {
    let function = selected_function(projection, function_id)?;
    let mut parameters = vec!["struct spx_context *spx_ctx".to_owned()];
    let mut arguments = vec!["spx_ctx".to_owned()];
    for (index, parameter) in function.params.iter().enumerate() {
        parameters.push(format!(
            "{} spx_arg_{index}",
            native_scalar_type(&parameter.ty)?
        ));
        arguments.push(format!("spx_arg_{index}"));
    }
    parameters.push(format!(
        "{} *spx_result",
        native_scalar_type(&function.return_type)?
    ));
    arguments.push("spx_result".to_owned());
    Ok(format!(
        "\nspx_status_token {entry_symbol}({}) {{\n    return {}({});\n}}\n",
        parameters.join(", "),
        native_source_symbol(function_id),
        arguments.join(", "),
    ))
}

fn native_scalar_type(ty: &crate::hir::ResolvedType) -> Result<&'static str, Diagnostic> {
    match ty {
        crate::hir::ResolvedType::I64 => Ok("int64_t"),
        crate::hir::ResolvedType::I32 => Ok("int32_t"),
        crate::hir::ResolvedType::U8 => Ok("uint8_t"),
        crate::hir::ResolvedType::Usize => Ok("uint64_t"),
        crate::hir::ResolvedType::Char => Ok("uint32_t"),
        crate::hir::ResolvedType::F32 => Ok("float"),
        crate::hir::ResolvedType::F64 => Ok("double"),
        crate::hir::ResolvedType::Bool => Ok("bool"),
        _ => Err(invalid(
            "resumable native projection type is not a Copy scalar",
        )),
    }
}

fn native_entry_symbol(
    plan_identity: &ResumablePlanIdentity,
    site: &ResumableProjectionSite,
) -> String {
    let mut symbol = String::from("spx_resumable_projection_");
    for byte in plan_identity.as_bytes() {
        symbol.push_str(&format!("{byte:02x}"));
    }
    match site {
        ResumableProjectionSite::Start => symbol.push_str("_start"),
        ResumableProjectionSite::Resume { suspension_index } => {
            symbol.push_str(&format!("_resume_{suspension_index}"));
        }
    }
    symbol
}

fn native_source_symbol(function_id: &str) -> String {
    let mut symbol = String::from("spx_decl_");
    for byte in function_id.bytes() {
        symbol.push_str(&format!("{byte:02x}"));
    }
    symbol
}

fn artifact(
    target: ResumableArtifactTarget,
    function_id: &str,
    plan_identity: &ResumablePlanIdentity,
    site: ResumableProjectionSite,
    state: &ResumableState,
    entry_symbol: String,
    bytes: Vec<u8>,
    total_bytes: &mut usize,
) -> Result<ResumableProjectionArtifact, Diagnostic> {
    if bytes.is_empty() || bytes.len() > MAX_TARGET_PROFILE_ARTIFACT_BYTES {
        return Err(invalid(
            "resumable target projection bytes exceed their bound",
        ));
    }
    *total_bytes = total_bytes
        .checked_add(bytes.len())
        .ok_or_else(|| invalid("resumable target profile byte count overflow"))?;
    if *total_bytes > MAX_TARGET_PROFILE_BYTES {
        return Err(invalid("resumable target profile bytes exceed their bound"));
    }
    let plan_identity = *plan_identity.as_bytes();
    let state_id = state.id.as_str().to_owned();
    let digest = artifact_digest(
        target,
        function_id,
        &plan_identity,
        &site,
        &state_id,
        &entry_symbol,
        &bytes,
    );
    Ok(ResumableProjectionArtifact {
        target,
        function_id: function_id.to_owned(),
        plan_identity,
        site,
        state_id,
        entry_symbol,
        bytes,
        digest,
    })
}

fn artifact_digest(
    target: ResumableArtifactTarget,
    function_id: &str,
    plan_identity: &[u8; 32],
    site: &ResumableProjectionSite,
    state_id: &str,
    entry_symbol: &str,
    bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ARTIFACT_DIGEST_DOMAIN);
    frame(&mut hasher, target.tag());
    frame(&mut hasher, function_id.as_bytes());
    frame(&mut hasher, plan_identity);
    frame(&mut hasher, site.tag());
    hasher.update(site.index().to_le_bytes());
    frame(&mut hasher, state_id.as_bytes());
    frame(&mut hasher, entry_symbol.as_bytes());
    frame(&mut hasher, bytes);
    hasher.finalize().into()
}

fn profile_digest(
    target: ResumableArtifactTarget,
    function_id: &str,
    plan_identity: &[u8; 32],
    artifacts: &[ResumableProjectionArtifact],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROFILE_DIGEST_DOMAIN);
    frame(&mut hasher, target.tag());
    frame(&mut hasher, function_id.as_bytes());
    frame(&mut hasher, plan_identity);
    hasher.update((artifacts.len() as u64).to_le_bytes());
    for artifact in artifacts {
        frame(&mut hasher, &artifact.digest);
    }
    hasher.finalize().into()
}

fn frame(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn invalid(message: impl Into<String>) -> Diagnostic {
    Diagnostic::io(INVALID_TARGET_PROFILE, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use wasmparser::{ExternalKind, Parser, Payload};

    const SOURCE: &str = r#"
module test.target_profile;
@id("app.ask")
fn ask(seed: i64) -> i64
    yields i64 -> i64
{
    let first = yield seed + 1;
    yield first + 2
}
@id("app.main")
fn main() -> i64 { 0 }
"#;

    fn program(source: &str) -> ResolvedProgram {
        let ast = crate::parse(source, Path::new("target-profile.spx")).unwrap();
        crate::hir::resolve(&ast).unwrap()
    }

    #[test]
    fn target_profiles_are_deterministic_and_replayable() {
        let program = program(SOURCE);
        let first = prepare_target_profile(&program, "app.ask", ResumableArtifactTarget::NativeC11)
            .unwrap();
        let second =
            prepare_target_profile(&program, "app.ask", ResumableArtifactTarget::NativeC11)
                .unwrap();
        assert_eq!(first, second);
        first.verify(&program).unwrap();
    }

    #[test]
    fn ordinary_yield_is_refused_but_yield_free_projection_artifacts_emit() {
        let program = program(SOURCE);
        assert_eq!(
            crate::codegen::emit_hir_c(&program).unwrap_err().code,
            "SPX-B116"
        );
        assert_eq!(
            crate::wasm::emit_resolved_module(&program)
                .unwrap_err()
                .code,
            "SPX-W126"
        );
        let profile =
            prepare_target_profile(&program, "app.ask", ResumableArtifactTarget::NativeC11)
                .unwrap();
        for artifact in profile.artifacts() {
            assert!(artifact
                .bytes()
                .starts_with(b"#define SPX_NO_ENTRY_WRAPPER 1\n"));
            let source = std::str::from_utf8(artifact.bytes()).unwrap();
            assert!(source.contains(artifact.entry_symbol()));
            assert!(source.contains(&native_source_symbol("app.ask")));
        }
    }

    #[test]
    fn core_wasm_profile_is_deterministic_without_host_or_publication_work() {
        let program = program(SOURCE);
        let first =
            prepare_target_profile(&program, "app.ask", ResumableArtifactTarget::CoreWasm).unwrap();
        let second =
            prepare_target_profile(&program, "app.ask", ResumableArtifactTarget::CoreWasm).unwrap();
        assert_eq!(first, second);
        let native =
            prepare_target_profile(&program, "app.ask", ResumableArtifactTarget::NativeC11)
                .unwrap();
        assert_ne!(first.digest(), native.digest());
        assert_eq!(first.artifacts().len(), 3);
        assert!(first
            .artifacts()
            .iter()
            .all(|artifact| artifact.bytes().starts_with(b"\0asm")));
        for artifact in first.artifacts() {
            assert_eq!(
                function_exports(artifact.bytes()),
                vec![artifact.entry_symbol().to_owned()]
            );
        }
        first.verify(&program).unwrap();
    }

    #[test]
    fn core_wasm_entry_symbols_execute_each_selected_projection() {
        if std::process::Command::new("node")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let program = program(SOURCE);
        let profile =
            prepare_target_profile(&program, "app.ask", ResumableArtifactTarget::CoreWasm).unwrap();
        let cases: [&[&str]; 3] = [&["4"], &["4", "10"], &["4", "10", "20"]];
        let expected = ["5", "12", "20"];
        let root = NativeTestRoot::new();
        let script = root.0.join("invoke.mjs");
        std::fs::write(
            &script,
            r#"import { readFile } from "node:fs/promises";
const [path, symbol, ...tokens] = process.argv.slice(2);
const min = -(1n << 63n), max = (1n << 63n) - 1n;
const checked = value => { if (value < min || value > max) throw new RangeError("overflow"); return value; };
const env = {
  spx_add: (a, b) => checked(a + b), spx_sub: (a, b) => checked(a - b),
  spx_mul: (a, b) => checked(a * b),
  spx_div: (a, b) => { if (b === 0n || (a === min && b === -1n)) throw new RangeError("division"); return a / b; },
  spx_rem: (a, b) => { if (b === 0n || (a === min && b === -1n)) throw new RangeError("remainder"); return a % b; },
  spx_neg: value => checked(-value), spx_contract_fail: () => { throw new Error("contract"); },
};
const { instance } = await WebAssembly.instantiate(await readFile(path), { env });
const selected = instance.exports[symbol];
if (typeof selected !== "function") throw new Error(`missing export ${symbol}`);
console.log(selected(...tokens.map(BigInt)).toString());
"#,
        )
        .unwrap();
        for (index, artifact) in profile.artifacts().iter().enumerate() {
            let module = root.0.join(format!("projection-{index}.wasm"));
            std::fs::write(&module, artifact.bytes()).unwrap();
            let output = std::process::Command::new("node")
                .arg(&script)
                .arg(&module)
                .arg(artifact.entry_symbol())
                .args(cases[index])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                std::str::from_utf8(&output.stdout).unwrap().trim(),
                expected[index]
            );
        }
    }

    fn function_exports(bytes: &[u8]) -> Vec<String> {
        let mut exports = Vec::new();
        for payload in Parser::new(0).parse_all(bytes) {
            if let Payload::ExportSection(section) = payload.unwrap() {
                for export in section {
                    let export = export.unwrap();
                    if export.kind == ExternalKind::Func {
                        exports.push(export.name.to_owned());
                    }
                }
            }
        }
        exports
    }

    #[test]
    fn native_artifact_entry_symbols_execute_each_selected_projection() {
        if std::process::Command::new("clang")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let program = program(SOURCE);
        let profile =
            prepare_target_profile(&program, "app.ask", ResumableArtifactTarget::NativeC11)
                .unwrap();
        let cases = [
            ("INT64_C(4)", "5"),
            ("INT64_C(4), INT64_C(10)", "12"),
            ("INT64_C(4), INT64_C(10), INT64_C(20)", "20"),
        ];
        let root = NativeTestRoot::new();
        for (index, (artifact, (arguments, expected))) in
            profile.artifacts().iter().zip(cases).enumerate()
        {
            let source = root.0.join(format!("projection-{index}.c"));
            let executable = root.0.join(format!("projection-{index}"));
            let driver = format!(
                "\nint main(void) {{ struct spx_status_entry entries[UINT32_C(32)]; struct spx_context ctx = {{0}}; if (!spx_context_init(&ctx, UINT64_C(1), entries, UINT32_C(32), NULL, NULL, NULL)) return 90; int64_t result = 0; spx_status_token status = {}(&ctx, {}, &result); if (status != SPX_STATUS_SUCCESS) return 91; printf(\"%lld\\n\", (long long)result); return 0; }}\n",
                artifact.entry_symbol(),
                arguments,
            );
            let mut bytes = artifact.bytes().to_vec();
            bytes.extend_from_slice(driver.as_bytes());
            std::fs::write(&source, bytes).unwrap();
            let compiled = std::process::Command::new("clang")
                .args(["-std=c11", "-O0", "-Wall", "-Wextra", "-Werror"])
                .arg(&source)
                .arg("-o")
                .arg(&executable)
                .output()
                .unwrap();
            assert!(
                compiled.status.success(),
                "{}",
                String::from_utf8_lossy(&compiled.stderr)
            );
            let output = std::process::Command::new(&executable).output().unwrap();
            assert!(output.status.success());
            assert_eq!(
                std::str::from_utf8(&output.stdout).unwrap().trim(),
                expected
            );
        }
    }

    struct NativeTestRoot(std::path::PathBuf);
    impl NativeTestRoot {
        fn new() -> Self {
            static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "semaprax-resumable-target-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for NativeTestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn target_inventory_is_exactly_entry_then_each_suspension() {
        let program = program(SOURCE);
        let plan =
            lower_sequential(&program, selected_function(&program, "app.ask").unwrap()).unwrap();
        let profile =
            prepare_target_profile(&program, "app.ask", ResumableArtifactTarget::NativeC11)
                .unwrap();
        assert_eq!(profile.artifacts().len(), 3);
        assert_eq!(
            profile.artifacts()[0].site(),
            &ResumableProjectionSite::Start
        );
        assert_eq!(
            profile.artifacts()[1].site(),
            &ResumableProjectionSite::Resume {
                suspension_index: 0
            }
        );
        assert_eq!(
            profile.artifacts()[2].site(),
            &ResumableProjectionSite::Resume {
                suspension_index: 1
            }
        );
        assert_eq!(profile.artifacts()[0].state_id(), plan.entry.id.as_str());
        assert_eq!(
            profile.artifacts()[1].state_id(),
            plan.suspensions[0].state.id.as_str()
        );
        assert_eq!(
            profile.artifacts()[2].state_id(),
            plan.suspensions[1].state.id.as_str()
        );
    }

    #[test]
    fn stale_source_forged_plan_and_mutated_bytes_fail_closed() {
        let resolved = program(SOURCE);
        let function = selected_function(&resolved, "app.ask").unwrap();
        let plan = lower_sequential(&resolved, function).unwrap();
        let stale = program(&SOURCE.replace("seed + 1", "seed + 9"));
        assert!(prepare_target_profile_with_plan(
            &stale,
            &plan,
            ResumableArtifactTarget::NativeC11
        )
        .is_err());

        let mut forged = plan.clone();
        forged.suspensions.swap(0, 1);
        assert!(prepare_target_profile_with_plan(
            &resolved,
            &forged,
            ResumableArtifactTarget::NativeC11
        )
        .is_err());

        let mut profile =
            prepare_target_profile(&resolved, "app.ask", ResumableArtifactTarget::NativeC11)
                .unwrap();
        profile.artifacts[0].bytes[0] ^= 1;
        assert!(profile.verify(&resolved).is_err());
    }
}
