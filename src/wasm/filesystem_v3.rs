//! Additive filesystem v3 imports after the frozen v1 prefix.
use super::{function_import, intern_type, write_u32, Signature, I32};
use crate::{diagnostic::Diagnostic, hir::ResolvedProgram};
pub(super) const IMPORT_COUNT: u32 = 1;
pub(super) const BASE: u32 = super::filesystem_v2::BASE + super::filesystem_v2::IMPORT_COUNT;
pub(super) const WRITE_ATOMIC_CHECKED: u32 = BASE;
const NAMES: [&str; 1] = ["spx_filesystem_write_atomic_checked_v3"];
pub fn emit_resolved_filesystem_ops_v3(
    program: &ResolvedProgram,
    command_id: &str,
) -> Result<Vec<u8>, Diagnostic> {
    let plan = super::command_io::prepare(
        program,
        command_id,
        crate::command_io_ops::CommandOperationProfile::FilesystemV3,
    )?;
    super::aggregate::emit_language_command_io(program, &plan)
}
pub(super) fn intern_import_types(
    types: &mut Vec<Signature>,
    indexes: &mut std::collections::HashMap<Signature, u32>,
) -> [u32; 1] {
    [7].map(|count| {
        intern_type(
            Signature {
                params: vec![I32; count],
                results: vec![I32],
            },
            types,
            indexes,
        )
    })
}
pub(super) fn emit_imports(imports: &mut Vec<u8>, types: &[u32; 1]) {
    for (name, index) in NAMES.iter().zip(types) {
        function_import(imports, "env", name, *index);
    }
}
pub(super) fn append_export(exports: &mut Vec<u8>) {
    super::write_name(exports, "__spx_filesystem_status_v3");
    exports.push(0x03);
    write_u32(exports, super::filesystem_ops::STATUS_GLOBAL);
}

/// Versioned import planning keeps the frozen V2 prefix in V3 modules.
pub(super) struct ImportTypes {
    v2: Option<[u32; 5]>,
    v3: Option<[u32; 1]>,
}

impl ImportTypes {
    pub(super) fn new(
        command: Option<&super::command_io::CommandPlan>,
        types: &mut Vec<Signature>,
        indexes: &mut std::collections::HashMap<Signature, u32>,
    ) -> Self {
        Self {
            v2: command
                .is_some_and(super::command_io::CommandPlan::is_filesystem_v2)
                .then(|| super::filesystem_v2::intern_import_types(types, indexes)),
            v3: command
                .is_some_and(super::command_io::CommandPlan::is_filesystem_v3)
                .then(|| intern_import_types(types, indexes)),
        }
    }

    pub(super) fn emit(self, imports: &mut Vec<u8>) {
        if let Some(types) = self.v2 {
            super::filesystem_v2::emit_imports(imports, &types);
        }
        if let Some(types) = self.v3 {
            emit_imports(imports, &types);
        }
    }
}
