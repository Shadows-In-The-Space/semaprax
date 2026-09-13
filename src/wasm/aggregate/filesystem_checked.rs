//! Checked publication outcomes retain ordinary source control flow.
use super::*;

impl Emitter<'_> {
    pub(super) fn emit_checked_atomic_write(
        &mut self,
        expr: &ResolvedExpr,
        arguments: &[Value],
        local: u32,
        pointer: Pointer,
    ) -> Result<Value, Diagnostic> {
        for (argument, ty) in arguments.iter().zip([
            ResolvedType::SliceU8,
            ResolvedType::Usize,
            ResolvedType::SliceU8,
            ResolvedType::Usize,
        ]) {
            self.require_scalar(argument, &ty, "checked atomic write argument")?;
        }
        self.reserve_filesystem_work(&arguments[3], &expr.id)?;

        // A domain refusal exits only this expression's block with outcome 1.
        // Provider/ABI defects still use the function's normal failure cleanup.
        self.output.extend([0x02, 0x40]);
        self.control_depth += 1;
        let exit = (local, self.control_depth);
        self.stage_slice_carrier(&arguments[0], local);
        self.get_scalar(&arguments[1]);
        self.output.push(0x50);
        self.emit_checked_not_published_if(exit)?;
        self.get_scalar(&arguments[1]);
        self.emit_carrier_length(local);
        self.output.push(0x56);
        self.emit_checked_not_published_if(exit)?;
        self.get_scalar(&arguments[1]);
        self.output.push(0x42);
        write_i64(self.output, crate::filesystem_ops::MAX_PATH_BYTES as i64);
        self.output.push(0x56);
        self.emit_checked_not_published_if(exit)?;
        self.emit_filesystem_path_validation(local, &arguments[1], &expr.id, Some(exit))?;
        self.stage_slice_carrier(&arguments[2], local);
        self.get_scalar(&arguments[3]);
        self.emit_carrier_length(local);
        self.output.push(0x56);
        self.emit_checked_not_published_if(exit)?;
        self.get_scalar(&arguments[3]);
        self.output.push(0x42);
        write_i64(self.output, crate::filesystem_ops::MAX_FILE_BYTES as i64);
        self.output.push(0x56);
        self.emit_checked_not_published_if(exit)?;

        self.stage_slice_carrier(&arguments[0], local);
        self.emit_carrier_root_and_length(local);
        self.get_scalar(&arguments[1]);
        self.output.push(0xa7);
        self.stage_slice_carrier(&arguments[2], local);
        self.emit_carrier_root_and_length(local);
        self.get_scalar(&arguments[3]);
        self.output.push(0xa7);
        self.emit_pointer(pointer);
        self.output.push(0x10);
        write_u32(
            self.output,
            super::super::filesystem_v3::WRITE_ATOMIC_CHECKED,
        );
        self.output.push(0x21);
        write_u32(self.output, self.plan.status);
        self.output.push(0x20);
        write_u32(self.output, self.plan.status);
        self.output.push(0x41);
        write_i64(self.output, crate::filesystem_ops::INVALID_FILE_TYPE as i64);
        self.output.push(0x4b);
        self.emit_filesystem_failure_if_code(&expr.id, crate::filesystem_ops::IO_FAILURE as i32)?;
        self.output.push(0x20);
        write_u32(self.output, self.plan.status);
        self.emit_filesystem_failure_if(&expr.id)?;
        self.emit_load_out(pointer);
        self.output.extend([0x42, 0x02, 0x56]);
        self.emit_filesystem_failure_if_code(&expr.id, crate::filesystem_ops::IO_FAILURE as i32)?;
        self.emit_load_out(pointer);
        self.output.push(0x21);
        write_u32(self.output, local);
        self.control_depth -= 1;
        self.output.push(0x0b);
        Ok(Value::Scalar {
            local,
            ty: ResolvedType::Usize,
        })
    }

    pub(super) fn emit_filesystem_path_failure_if(
        &mut self,
        expression: &ExpressionId,
        checked_exit: Option<(u32, u32)>,
    ) -> Result<(), Diagnostic> {
        if let Some(exit) = checked_exit {
            self.emit_checked_not_published_if(exit)
        } else {
            self.emit_filesystem_failure_if_code(
                expression,
                crate::filesystem_ops::INVALID_PATH as i32,
            )
        }
    }

    fn emit_checked_not_published_if(
        &mut self,
        (local, depth): (u32, u32),
    ) -> Result<(), Diagnostic> {
        let branch = self
            .control_depth
            .checked_sub(depth)
            .and_then(|depth| depth.checked_add(1))
            .ok_or_else(|| error("checked filesystem outcome block is absent"))?;
        self.output.extend([0x04, 0x40, 0x42, 0x01, 0x21]);
        write_u32(self.output, local);
        // The path scanner uses status as a byte scratch register. A domain
        // refusal is successful evaluation, so do not publish that scratch byte.
        self.output.extend([0x41, 0x00, 0x21]);
        write_u32(self.output, self.plan.status);
        self.output.push(0x0c);
        write_u32(self.output, branch);
        self.output.push(0x0b);
        Ok(())
    }
}
