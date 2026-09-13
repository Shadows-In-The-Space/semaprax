//! Core-Wasm boundary for HTTPS Client I/O v1.
//!
//! The profile appends one synchronous, capability-selected `env` import to
//! the frozen Language Command I/O imports. A host may satisfy it from a
//! deterministic fixture or another explicitly injected HTTPS provider; the
//! module itself receives no ambient fetch, socket, DNS, or TLS authority.
//!
//! `spx_https_get_v1(url_root, url_len, max, out_owned)` and
//! `spx_https_post_v1(url_root, url_len, body_root, body_len, max, out_owned)`
//! return one `semaprax.http.v1` status. On status zero they write exactly one
//! tagged owned-byte carrier to the little-endian i64 out slot.

use crate::diagnostic::Diagnostic;
use crate::hir::ResolvedProgram;

use super::{function_import, intern_type, write_u32, Signature, I32};

pub(super) const IMPORT_COUNT: u32 = 1;
pub(super) const IMPORT_BASE: u32 =
    super::command_io::ARGS_LEN_IMPORT + super::command_io::IMPORT_COUNT;
pub(super) const GET_IMPORT: u32 = IMPORT_BASE;
pub(super) const POST_IMPORT: u32 = IMPORT_BASE + 1;
/// The line, raw-network, and HTTPS profiles are mutually exclusive, so their
/// independently named status markers share the same frozen global slot.
pub(super) const STATUS_GLOBAL: u32 = 15;
pub(super) const STATUS_EXPORT: &str = "__spx_http_status_v1";
pub(super) const IMPORT_NAME: &str = "spx_https_get_v1";
pub(super) const POST_IMPORT_NAME: &str = "spx_https_post_v1";

pub(crate) fn emit_resolved_https_command_io_v1(
    program: &ResolvedProgram,
    command_id: &str,
) -> Result<Vec<u8>, Diagnostic> {
    let plan = prepare(program, command_id)?;
    super::aggregate::emit_language_command_io(program, &plan)
}

pub(super) fn prepare(
    program: &ResolvedProgram,
    command_id: &str,
) -> Result<super::command_io::CommandPlan, Diagnostic> {
    super::command_io::prepare(
        program,
        command_id,
        crate::command_io_ops::CommandOperationProfile::HttpV1,
    )
}

pub(super) fn check_permits(permits: &[String]) -> Result<(), Diagnostic> {
    const ADMITTED: [&str; 5] = [
        crate::network_io_ops::NETWORK_HTTP_EFFECT,
        crate::command_io_ops::ARGS_READ_EFFECT,
        crate::command_io_ops::STDERR_WRITE_EFFECT,
        crate::command_io_ops::STDIN_READ_EFFECT,
        crate::host_io_ops::STDOUT_WRITE_EFFECT,
    ];
    if permits
        .iter()
        .any(|permit| !ADMITTED.contains(&permit.as_str()))
    {
        return Err(Diagnostic::io(
            "SPX-W114",
            "HTTPS Client I/O v1 admits only network.http and process command permits",
        ));
    }
    if !permits
        .iter()
        .any(|permit| permit == crate::network_io_ops::NETWORK_HTTP_EFFECT)
    {
        return Err(Diagnostic::io(
            "SPX-W114",
            "HTTPS Client I/O v1 requires the network.http permit",
        ));
    }
    Ok(())
}

pub(super) fn program_uses_https_post(program: &ResolvedProgram) -> bool {
    program
        .functions
        .iter()
        .chain(
            program
                .function_instances
                .iter()
                .map(|instance| &instance.function),
        )
        .any(|function| {
            let mut found = false;
            crate::hir::function_value::walk(function, |expression| {
                found |= matches!(
                    &expression.kind,
                    crate::hir::ResolvedExprKind::HostCommandCall(call)
                        if call.operation == crate::hir::ResolvedHostCommandOperation::HttpsPost
                );
            });
            found
        })
}

pub(super) fn intern_import_types(
    types: &mut Vec<Signature>,
    type_indexes: &mut std::collections::HashMap<Signature, u32>,
    post: bool,
) -> (u32, Option<u32>) {
    let get = intern_type(
        Signature {
            params: vec![I32, I32, I32, I32],
            results: vec![I32],
        },
        types,
        type_indexes,
    );
    let post = post.then(|| {
        intern_type(
            Signature {
                params: vec![I32, I32, I32, I32, I32, I32],
                results: vec![I32],
            },
            types,
            type_indexes,
        )
    });
    (get, post)
}

pub(super) fn emit_imports(imports: &mut Vec<u8>, types: &(u32, Option<u32>)) {
    function_import(imports, "env", IMPORT_NAME, types.0);
    if let Some(post) = types.1 {
        function_import(imports, "env", POST_IMPORT_NAME, post);
    }
}

pub(super) fn append_export(exports: &mut Vec<u8>) {
    super::write_name(exports, STATUS_EXPORT);
    exports.push(0x03);
    write_u32(exports, STATUS_GLOBAL);
}

pub(super) fn emit_reset(body: &mut Vec<u8>) {
    body.extend([0x41, 0x00, 0x24]);
    write_u32(body, STATUS_GLOBAL);
}

#[cfg(test)]
#[path = "http_io/tests.rs"]
mod tests;
