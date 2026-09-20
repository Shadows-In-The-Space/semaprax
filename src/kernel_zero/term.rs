//! The Kernel-0 term grammar, as a standalone Rust type.
//!
//! This is a direct transcription of the `Expr`/`Fn`/`Ty` grammar in
//! [`docs/SEMANTIC-KERNEL-V1.md`](../../../docs/SEMANTIC-KERNEL-V1.md)
//! ("Syntax"). It is deliberately **not** `hir::ResolvedExpr`: it has no
//! `ExpressionId`, no `OwnershipMode`, no cleanup/loan plan, and no case for
//! any expression kind Kernel-0's grammar excludes. Its only connection to
//! the real compiler's HIR is the one-directional, total-on-admission
//! translation in `super::reify`.
//!
//! Variable and function identity reuse `hir::ValueId`/`hir::DeclarationId`
//! rather than re-deriving a name-based identity of this module's own: HIR
//! already assigns each binder and each declaration a unique identity (two
//! `let`-bindings named `x` in different scopes get different `ValueId`s),
//! and re-deriving that from source text would risk exactly the shadowing/
//! capture bugs Kernel-0's grammar's simplicity is supposed to avoid. Reusing
//! it does not make this module dependent on interpreter/codegen evaluation
//! logic: `ValueId`/`DeclarationId` are identity types, not evaluators.

use crate::ast::{BinaryOp, UnaryOp};
use crate::hir::{DeclarationId, ValueId};

/// Kernel-0's two scalar types (`Ty` in the grammar).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KernelType {
    I64,
    Bool,
}

/// A Kernel-0 term (`Expr` in the grammar).
///
/// `Let`'s bound name and `Call`'s callee are carried as `ValueId`/
/// `DeclarationId` rather than `String` -- see the module doc.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Term {
    Int(i64),
    Bool(bool),
    /// `x` -- a parameter or `let`-bound name.
    Var(ValueId),
    /// `"-" Expr | "!" Expr`.
    Unary(UnaryOp, Box<Term>),
    /// `Expr BinOp Expr`.
    Binary(BinaryOp, Box<Term>, Box<Term>),
    /// `"if" Expr "{" Expr "}" "else" "{" Expr "}"`.
    If {
        condition: Box<Term>,
        then_branch: Box<Term>,
        else_branch: Box<Term>,
    },
    /// `"let" x "=" Expr ";" Expr`.
    Let {
        bound: ValueId,
        value: Box<Term>,
        body: Box<Term>,
    },
    /// `f "(" Expr,* ")"`. Arguments are stored in the grammar's authored,
    /// left-to-right order; `super::eval` evaluates them in that same order,
    /// never Rust's own argument-evaluation order for some incidental tuple
    /// or struct literal.
    Call {
        callee: DeclarationId,
        args: Vec<Term>,
    },
}

/// One Kernel-0 `Fn` declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KernelFn {
    pub(crate) id: DeclarationId,
    /// Parameter identity and type, in authored, left-to-right order.
    pub(crate) params: Vec<(ValueId, KernelType)>,
    pub(crate) return_type: KernelType,
    pub(crate) body: Term,
}

/// A whole Kernel-0 `Program`: a finite, acyclic (by construction of
/// `super::reify::translate_program`, which only ever walks the reifying,
/// acyclic subgraph `kernel_zero::reifies_into_kernel_zero` already
/// verified) set of `Fn` declarations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KernelProgram {
    pub(crate) functions: Vec<KernelFn>,
}

impl KernelProgram {
    pub(crate) fn function(&self, id: &DeclarationId) -> Option<&KernelFn> {
        self.functions.iter().find(|function| &function.id == id)
    }
}
