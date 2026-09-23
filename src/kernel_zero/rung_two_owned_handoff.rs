//! Ordinary checked ownership around the unchanged scalar renderer. The scalar
//! helpers and host assembly are NOT part of an ownership theorem/profile.
mod binding;

use crate::interpreter::retained_call::owned_handoff::{PreparedOwnedHandoff, MAX_FUEL};
use binding::{checksum, Binding};
use std::sync::OnceLock;

const SOURCE: &str = include_str!("rung_two_owned_handoff/handoff.spx");
const ENTRY: &str = "kernel-zero.owned-handoff.move";
const MAX_BYTES: usize = super::rung_two_authority::MAX_TOKEN_BYTES;

struct Boundary {
    binding: Binding,
    authenticated_bytes: Vec<u8>,
    digest: [u8; 32],
    prepared: PreparedOwnedHandoff,
}

impl Boundary {
    fn derive() -> Result<Self, ()> {
        super::rung_two_authority::in_candidate_scope(|| {
            if SOURCE.len() > 4096 || MAX_BYTES != 20 {
                return Err(());
            }
            let parsed = crate::parse(SOURCE, "kernel-zero-owned-handoff.spx").map_err(|_| ())?;
            let program = crate::hir::resolve(&parsed).map_err(|_| ())?;
            crate::hir::validate(&program).map_err(|_| ())?;
            let binding = Binding::derive(&program)?;
            let authenticated_bytes = binding.bytes()?;
            let digest = checksum(&authenticated_bytes);
            let prepared = PreparedOwnedHandoff::new(program, ENTRY).map_err(|_| ())?;
            Ok(Self {
                binding,
                authenticated_bytes,
                digest,
                prepared,
            })
        })
    }

    fn deliver(
        &self,
        bytes: &[u8],
        digest: [u8; 32],
        input: &[u8],
        fuel: usize,
    ) -> Result<Vec<u8>, ()> {
        if input.len() > MAX_BYTES {
            return Err(());
        }
        Binding::authenticate(bytes, digest, &self.authenticated_bytes)?;
        let settled = self
            .prepared
            .execute(input, fuel)
            .map_err(|_| ())?
            .into_bytes()?;
        if settled != input {
            return Err(());
        }
        record();
        Ok(settled)
    }
}

pub(super) fn handoff(candidate: String) -> Result<String, ()> {
    static BOUNDARY: OnceLock<Result<Boundary, ()>> = OnceLock::new();
    let boundary = BOUNDARY
        .get_or_init(Boundary::derive)
        .as_ref()
        .map_err(|_| ())?;
    // Authenticate the held source/entry/core/target/maximum recipe before any
    // language-owner allocation. This copy is bounded by the private profile.
    let bytes = boundary.binding.bytes()?;
    let settled = boundary.deliver(&bytes, boundary.digest, candidate.as_bytes(), MAX_FUEL)?;
    String::from_utf8(settled).map_err(|_| ())
}

#[cfg(test)]
thread_local! { static HANDOFFS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

fn record() {
    #[cfg(test)]
    HANDOFFS.with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
pub(super) fn handoffs() -> usize {
    HANDOFFS.with(std::cell::Cell::get)
}

#[cfg(test)]
mod targets;
#[cfg(test)]
mod tests;
