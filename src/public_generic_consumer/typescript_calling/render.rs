//! The deterministic string templates [`super::generate_typescript_calling_consumer`]
//! composes. Split from `typescript_calling.rs` itself only to keep that
//! file's own generator-contract logic short; every function here is a pure
//! byte-in/text-out renderer, exercised by [`super::tests`]. Mirrors
//! `rust_calling::render`'s own fixed-template/generated-per-shape split.

use std::fmt::Write as _;

use crate::public_generic_abi::wasm::binding::WasmProviderBindingV1;

use super::{field_name, RecordShape};

/// Line endings are normalized because a checkout may deliver these `.txt`
/// assets with CRLF -- `.gitattributes` pins them to LF, but a generator
/// that is only deterministic because of a checkout setting is not
/// deterministic. Matches `public_generic_consumer::template`'s own
/// convention exactly.
fn template(text: &str) -> String {
    text.replace("\r\n", "\n")
}

pub(super) fn package_json() -> String {
    template(include_str!("render/package.json.txt"))
}

pub(super) fn package_lock_json() -> String {
    template(include_str!("render/package-lock.json.txt"))
}

pub(super) fn tsconfig_json() -> String {
    template(include_str!("render/tsconfig.json.txt"))
}

pub(super) fn errors_ts() -> String {
    template(include_str!("render/errors.ts.txt"))
}

pub(super) fn index_ts() -> String {
    template(include_str!("render/index.ts.txt"))
}

pub(super) fn wasm_provider_ts() -> String {
    template(include_str!("render/wasm-provider.ts.txt"))
}

/// One numeric byte literal per generated file: twelve bytes a line, so a
/// diff of two generated consumers stays readable. Matches
/// `public_generic_consumer::byte_literal`'s and
/// `rust_calling::render::byte_array_literal`'s own convention, rendered as
/// a TypeScript `Uint8Array.from([...])` initializer.
fn uint8_array_literal(bytes: &[u8]) -> String {
    let mut out = String::from("Uint8Array.from([\n");
    for chunk in bytes.chunks(12) {
        out.push_str("  ");
        for byte in chunk {
            let _ = write!(out, "0x{byte:02x}, ");
        }
        out.push('\n');
    }
    out.push_str("])");
    out
}

/// A canonical, escaped TypeScript double-quoted string literal. Every
/// embedded string this generator emits (an export name, a digest) is
/// already-trusted, already-validated UTF-8 from
/// [`WasmProviderBindingV1`]'s own accessors, but this still escapes `\`,
/// `"`, and control characters rather than assuming they cannot occur --
/// the generator's own contract, not a fact about today's fixture values.
fn ts_string_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if (other as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", other as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

const DESCRIPTOR_HEADER: &str = include_str!("render/descriptor_header.ts.txt");

const DESCRIPTOR_VERIFY: &str = include_str!("render/descriptor_verify.ts.txt");

pub(super) fn descriptor_ts(
    descriptor_bytes: &[u8],
    binding_bytes: &[u8],
    binding: &WasmProviderBindingV1,
) -> String {
    let mut out = String::new();
    out.push_str(&template(DESCRIPTOR_HEADER));
    out.push('\n');
    out.push_str(
        "const MODULE_ARTIFACT_DIGEST_DOMAIN = new TextEncoder().encode(\n  \"semaprax.public-generic-wasm-provider.v1.artifact\\0\",\n);\n\n",
    );
    out.push_str("export const TRUSTED_DESCRIPTOR_BYTES: Uint8Array = ");
    out.push_str(&uint8_array_literal(descriptor_bytes));
    out.push_str(";\n\n");
    out.push_str("export const TRUSTED_BINDING_BYTES: Uint8Array = ");
    out.push_str(&uint8_array_literal(binding_bytes));
    out.push_str(";\n\n");
    out.push_str("export const TRUSTED_PROVIDER_ARTIFACT_DIGEST: string = ");
    out.push_str(&ts_string_literal(binding.provider_artifact_digest()));
    out.push_str(";\n");
    out.push_str(&template(DESCRIPTOR_VERIFY));
    out
}

const TYPES_HEADER: &str = include_str!("render/types_header.ts.txt");

fn record_interface(name: &str, shape: &RecordShape) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "export interface {name} {{");
    for field in &shape.fields {
        let _ = writeln!(out, "  /** Field identity: {:?} */", field.identity);
        let _ = writeln!(out, "  readonly {}: Uint8Array;", field_name(field));
    }
    out.push_str("}\n");
    out
}

pub(super) fn types_ts(input: &RecordShape, output: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str(&template(TYPES_HEADER));
    out.push('\n');
    out.push_str(&record_interface("Input", input));
    out.push('\n');
    out.push_str(&record_interface("Output", output));
    out
}

const CARRIER_HEADER: &str = include_str!("render/carrier_header.ts.txt");

fn input_leaves_fn(input: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str("function inputLeaves(value: Input): readonly Uint8Array[] {\n");
    out.push_str("  return readInputFields(value, [\n");
    for field in &input.fields {
        let _ = writeln!(out, "    {:?},", field_name(field));
    }
    out.push_str("  ]);\n");
    out.push_str("}\n");
    out
}

fn output_from_leaves_fn(output: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str("function outputFromLeaves(leaves: readonly Uint8Array[]): Output {\n");
    out.push_str("  return {\n");
    for (index, field) in output.fields.iter().enumerate() {
        let _ = writeln!(
            out,
            "    {}: leaves[{index}] as Uint8Array,",
            field_name(field)
        );
    }
    out.push_str("  };\n");
    out.push_str("}\n");
    out
}

pub(super) fn carrier_ts(input: &RecordShape, output: &RecordShape) -> String {
    let count = input.fields.len();
    let mut out = String::new();
    out.push_str(&template(CARRIER_HEADER));
    out.push('\n');
    let _ = writeln!(out, "export const FIELD_COUNT = {count};");
    out.push('\n');
    out.push_str(&input_leaves_fn(input));
    out.push('\n');
    out.push_str(&output_from_leaves_fn(output));
    out.push('\n');
    out.push_str(
        "export function encodeInput(value: Input): Uint8Array {\n  return encodeLeaves(inputLeaves(value));\n}\n\n",
    );
    out.push_str(
        "export function decodeOutput(bytes: Uint8Array): Output {\n  return outputFromLeaves(decodeLeaves(bytes, FIELD_COUNT));\n}\n",
    );
    out
}

const ROUND_TRIP_HEADER: &str = include_str!("render/round_trip_header.mjs.txt");

fn sample_input_fn(input: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str("function sampleInput() {\n");
    out.push_str("  return {\n");
    for (index, field) in input.fields.iter().enumerate() {
        let _ = writeln!(
            out,
            "    {}: new TextEncoder().encode(\"sample-{index}\"),",
            field_name(field)
        );
    }
    out.push_str("  };\n");
    out.push_str("}\n");
    out
}

fn assert_output_shape_fn(output: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str("function assertOutputShape(output) {\n");
    out.push_str("  assert.deepEqual(Object.keys(output), [\n");
    for field in &output.fields {
        let _ = writeln!(out, "    {:?},", field_name(field));
    }
    out.push_str("  ]);\n");
    for field in &output.fields {
        let name = field_name(field);
        let _ = writeln!(out, "  assert.ok(output.{name} instanceof Uint8Array);");
        let _ = writeln!(
            out,
            "  assert.strictEqual(Object.getPrototypeOf(output.{name}), Uint8Array.prototype);"
        );
        let _ = writeln!(out, "  assert.strictEqual(Object.getPrototypeOf(output.{name}.buffer), ArrayBuffer.prototype);");
        let _ = writeln!(
            out,
            "  assert.strictEqual(output.{name}.buffer.resizable, false);"
        );
    }
    out.push_str("}\n");
    out
}

const ROUND_TRIP_BODY: &str = include_str!("render/round_trip_body.mjs.txt");

pub(super) fn round_trip_mjs(input: &RecordShape, output: &RecordShape) -> String {
    let mut out = String::new();
    out.push_str(&template(ROUND_TRIP_HEADER));
    out.push('\n');
    out.push_str(&sample_input_fn(input));
    out.push('\n');
    out.push_str(&assert_output_shape_fn(output));
    out.push('\n');
    out.push_str(&template(ROUND_TRIP_BODY));
    out
}

#[cfg(test)]
mod template_tests {
    use super::*;

    #[test]
    fn every_fixed_asset_has_lf_crlf_equivalent_rendering() {
        for text in [
            DESCRIPTOR_HEADER,
            DESCRIPTOR_VERIFY,
            TYPES_HEADER,
            CARRIER_HEADER,
            ROUND_TRIP_HEADER,
            ROUND_TRIP_BODY,
            include_str!("render/package.json.txt"),
            include_str!("render/package-lock.json.txt"),
            include_str!("render/tsconfig.json.txt"),
            include_str!("render/errors.ts.txt"),
            include_str!("render/index.ts.txt"),
            include_str!("render/wasm-provider.ts.txt"),
        ] {
            let lf = template(text);
            assert_eq!(template(&lf.replace('\n', "\r\n")), lf);
        }
    }
}
