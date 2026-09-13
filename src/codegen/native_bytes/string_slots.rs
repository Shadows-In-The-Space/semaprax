//! String liveness actions delegated to the canonical native cleanup plan.

use super::{NativeBytesPlan, OwnedLeafKind};

impl NativeBytesPlan {
    pub(in crate::codegen) fn string_initialize(&self, value: &str) -> Option<String> {
        self.slots.values().find(|slot| slot.kind == OwnedLeafKind::String && slot.value == value)
            .map(|slot| format!("if ({}) spx_runtime_invariant_failure(\"String plan initialize liveness\");\n{} = true;", slot.flag, slot.flag))
    }

    pub(in crate::codegen) fn string_drop(&self, value: &str) -> Option<String> {
        self.slots
            .values()
            .find(|slot| slot.kind == OwnedLeafKind::String && slot.value == value)
            .map(|slot| {
                format!(
                    "if ({}) {{ {} = false; spx_string_drop({}); {} = NULL; }}",
                    slot.flag, slot.flag, slot.value, slot.value
                )
            })
    }
}
