//! Private Core-Wasm lowering for the canonical Public Generic Carrier v1
//! frame.  This module is deliberately an assembler component rather than a
//! second carrier codec: trusted facts are supplied by the caller from the
//! replayed descriptor, and every byte received from linear memory is still
//! checked here before a payload is copied.
//!
//! The emitted helpers are private.  Their calling convention is stable only
//! inside the compiler-owned provider module:
//!
//! * `sha256(domain_ptr, domain_len, body_ptr, body_len, workspace)` writes
//!   32 raw digest bytes at `workspace + 256`;
//! * `validate(frame_ptr, frame_len) -> i64` returns `(payload_len << 32) |
//!   status`; and
//! * `copy(frame_ptr, frame_len, out_ptr, out_capacity, leaf_table) -> i64`
//!   validates first and copies the canonical leaf payloads only on status
//!   zero, materializing `(ptr,len)` table rows in descriptor order; and
//! * `encode(slice_table, slice_count, out_ptr, out_capacity) -> i64` writes
//!   a self-digested canonical frame. Slice-table rows are little-endian
//!   `(pointer, length)` pairs in trusted descriptor leaf order.
//!
//! `sha256` has no imports and does not materialize a second copy of the
//! frame.  It hashes the repository's exact `digest` preimage:
//! `FRAME_DOMAIN || little_endian_u64(body_len) || body`.

use crate::public_generic_abi::boundary_profile::{
    MAX_BYTES_PER_LEAF, MAX_OWNED_LEAVES_PER_INSTANCE, MAX_TOTAL_PAYLOAD_BYTES,
};
use crate::public_generic_abi::carrier::frame::CarrierFrameBinding;
use crate::public_generic_abi::carrier::trace::Direction;
use crate::public_generic_abi::carrier::CARRIER_SCHEMA;
use crate::public_generic_abi::descriptor::verify::VerifiedPublicGenericDescriptor;

const FRAME_DOMAIN: &[u8] = b"semaprax.public-generic-carrier.v1.frame\0";
const MAX_FRAME_FIELD_BYTES: u32 = 64 * 1024;
pub(crate) const MAX_FRAME_WIRE_BYTES: u32 = MAX_TOTAL_PAYLOAD_BYTES as u32 + 4 * 1024 * 1024;
const DIGEST_TEXT_BYTES: u32 = 71; // `sha256:` plus 32 lowercase hexadecimal bytes.
const SHA256_WORKSPACE_BYTES: u32 = 288; // 64 words plus the final 32-byte digest.

/// Packed-helper status codes.  They mirror Carrier v1's three refusal
/// classes without leaking a host diagnostic transport into Core Wasm.
pub(crate) const STATUS_MALFORMED: u32 = 0x801;
pub(crate) const STATUS_CAPACITY: u32 = 0x802;
pub(crate) const STATUS_REPLAY_MISMATCH: u32 = 0x803;

/// The descriptor-derived facts that a carrier frame must name exactly.
/// `direction` is represented independently so the caller cannot accidentally
/// use result facts while compiling the input parser (or vice versa).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CarrierCodecFacts {
    pub direction: Direction,
    pub descriptor_digest: String,
    pub endpoint_identity_digest: String,
    pub instance_identity_digest: String,
    pub leaf_inventory_digest: String,
    pub leaf_paths: Vec<String>,
}

impl CarrierCodecFacts {
    pub(crate) fn new(
        direction: Direction,
        descriptor_digest: impl Into<String>,
        endpoint_identity_digest: impl Into<String>,
        instance_identity_digest: impl Into<String>,
        leaf_inventory_digest: impl Into<String>,
        leaf_paths: Vec<String>,
    ) -> Result<Self, String> {
        let facts = Self {
            direction,
            descriptor_digest: descriptor_digest.into(),
            endpoint_identity_digest: endpoint_identity_digest.into(),
            instance_identity_digest: instance_identity_digest.into(),
            leaf_inventory_digest: leaf_inventory_digest.into(),
            leaf_paths,
        };
        facts.validate()?;
        Ok(facts)
    }

    /// Extract the exact fixed strings from the existing descriptor-derived
    /// binding rather than reimplementing either private digest domain here.
    /// The temporary empty frame is canonical and contains all six fixed
    /// fields before its count/length/payload tail.
    pub(crate) fn from_verified_descriptor(
        descriptor: &VerifiedPublicGenericDescriptor,
        direction: Direction,
    ) -> Result<Self, String> {
        let binding = CarrierFrameBinding::from_verified_descriptor(descriptor, direction);
        let bytes = binding.frame_with_leaves(Vec::new()).encode();
        let mut offset = 0;
        let next = |offset: &mut usize| -> Result<String, String> {
            let (field, next) = crate::public_generic_abi::read_frame(&bytes, *offset, 64 * 1024)
                .ok_or_else(|| {
                "descriptor-derived carrier binding was not canonically framed".to_owned()
            })?;
            *offset = next;
            String::from_utf8(field.to_vec())
                .map_err(|_| "descriptor-derived carrier binding was not UTF-8".to_owned())
        };
        let schema = next(&mut offset)?;
        let encoded_direction = next(&mut offset)?;
        if schema != CARRIER_SCHEMA
            || encoded_direction
                != match direction {
                    Direction::Input => "input",
                    Direction::Result => "result",
                }
        {
            return Err("descriptor-derived carrier binding disagrees with Carrier v1".to_owned());
        }
        Self::new(
            direction,
            next(&mut offset)?,
            next(&mut offset)?,
            next(&mut offset)?,
            next(&mut offset)?,
            binding.leaf_paths().to_vec(),
        )
    }

    fn validate(&self) -> Result<(), String> {
        if self.leaf_paths.len() > MAX_OWNED_LEAVES_PER_INSTANCE {
            return Err("carrier leaf inventory exceeds the frozen bound".to_owned());
        }
        let fields = self.fixed_fields();
        if fields
            .iter()
            .any(|field| field.len() > MAX_FRAME_FIELD_BYTES as usize)
        {
            return Err("carrier trusted fixed field exceeds the frozen bound".to_owned());
        }
        for (index, path) in self.leaf_paths.iter().enumerate() {
            if path.len() > MAX_FRAME_FIELD_BYTES as usize {
                return Err(format!(
                    "carrier leaf path {index} exceeds the frozen bound"
                ));
            }
            if self.leaf_paths[..index].iter().any(|prior| prior == path) {
                return Err("carrier trusted leaf inventory contains a duplicate path".to_owned());
            }
        }
        Ok(())
    }

    fn fixed_fields(&self) -> [Vec<u8>; 6] {
        [
            CARRIER_SCHEMA.as_bytes().to_vec(),
            match self.direction {
                Direction::Input => b"input".to_vec(),
                Direction::Result => b"result".to_vec(),
            },
            self.descriptor_digest.as_bytes().to_vec(),
            self.endpoint_identity_digest.as_bytes().to_vec(),
            self.instance_identity_digest.as_bytes().to_vec(),
            self.leaf_inventory_digest.as_bytes().to_vec(),
        ]
    }
}

/// Compile-time placement choices owned by the enclosing provider assembler.
/// The workspace must be private writable memory and must not overlap the
/// public frame or output windows for the duration of one helper call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CarrierCodecLayout {
    pub trusted_data_offset: u32,
    pub sha256_workspace_offset: u32,
}

impl CarrierCodecLayout {
    pub(crate) fn validate(self, trusted_data_len: usize) -> Result<(), String> {
        let data_len = u32::try_from(trusted_data_len)
            .map_err(|_| "carrier trusted data length does not fit Core Wasm".to_owned())?;
        let data_end = self
            .trusted_data_offset
            .checked_add(data_len)
            .ok_or_else(|| "carrier trusted data placement overflows Core Wasm".to_owned())?;
        let workspace_end = self
            .sha256_workspace_offset
            .checked_add(SHA256_WORKSPACE_BYTES)
            .ok_or_else(|| "carrier SHA-256 workspace placement overflows Core Wasm".to_owned())?;
        if self.trusted_data_offset < workspace_end && self.sha256_workspace_offset < data_end {
            return Err("carrier SHA-256 workspace overlaps immutable trusted data".to_owned());
        }
        Ok(())
    }
}

/// One active data segment the parent module must add in its deterministic
/// data-section order.  No relocation is hidden in this module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CarrierCodecDataSegment {
    pub offset: u32,
    pub bytes: Vec<u8>,
}

/// Function indices after the enclosing assembler appends the four private
/// codec functions in this exact order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CarrierCodecFunctionIndexes {
    pub sha256: u32,
    pub validate: u32,
    pub copy: u32,
    pub encode: u32,
}

/// Type entries and private bodies to splice into an otherwise import-free
/// Core-Wasm module.  Bodies are raw function bodies (including local
/// declarations, excluding the outer code-section size prefix).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CarrierCodecEmission {
    facts: CarrierCodecFacts,
    layout: CarrierCodecLayout,
    trusted_data: Vec<u8>,
    fixed_offsets: [u32; 6],
    leaf_offsets: Vec<u32>,
}

impl CarrierCodecEmission {
    pub(crate) const TYPE_COUNT: u32 = 4;
    pub(crate) const FUNCTION_COUNT: u32 = 4;

    pub(crate) const fn type_count(&self) -> u32 {
        Self::TYPE_COUNT
    }

    pub(crate) const fn function_count(&self) -> u32 {
        Self::FUNCTION_COUNT
    }

    pub(crate) fn leaf_count(&self) -> usize {
        self.facts.leaf_paths.len()
    }

    pub(crate) fn new(
        facts: CarrierCodecFacts,
        layout: CarrierCodecLayout,
    ) -> Result<Self, String> {
        facts.validate()?;
        let mut trusted_data = FRAME_DOMAIN.to_vec();
        let data_base = layout.trusted_data_offset;
        let mut fixed_offsets = [0; 6];
        for (index, field) in facts.fixed_fields().iter().enumerate() {
            fixed_offsets[index] = data_base
                .checked_add(
                    u32::try_from(trusted_data.len()).map_err(|_| "carrier data is too large")?,
                )
                .ok_or_else(|| "carrier trusted field placement overflows".to_owned())?;
            trusted_data.extend_from_slice(field);
        }
        let mut leaf_offsets = Vec::with_capacity(facts.leaf_paths.len());
        for path in &facts.leaf_paths {
            leaf_offsets.push(
                data_base
                    .checked_add(
                        u32::try_from(trusted_data.len())
                            .map_err(|_| "carrier data is too large")?,
                    )
                    .ok_or_else(|| "carrier leaf placement overflows".to_owned())?,
            );
            trusted_data.extend_from_slice(path.as_bytes());
        }
        layout.validate(trusted_data.len())?;
        Ok(Self {
            facts,
            layout,
            trusted_data,
            fixed_offsets,
            leaf_offsets,
        })
    }

    /// Append exactly four function-type payloads after the caller has
    /// written the enclosing type-section vector length.
    pub(crate) fn append_type_entries(&self, out: &mut Vec<u8>) {
        wasm_function_type(out, &[I32, I32, I32, I32, I32], &[]); // SHA-256
        wasm_function_type(out, &[I32, I32], &[I64]); // validate
        wasm_function_type(out, &[I32, I32, I32, I32, I32], &[I64]); // copy + leaf table
        wasm_function_type(out, &[I32, I32, I32, I32], &[I64]); // encode
    }

    pub(crate) fn append_function_type_indexes(&self, out: &mut Vec<u32>, type_base: u32) {
        out.extend([type_base, type_base + 1, type_base + 2, type_base + 3]);
    }

    pub(crate) fn function_indexes(&self, function_base: u32) -> CarrierCodecFunctionIndexes {
        CarrierCodecFunctionIndexes {
            sha256: function_base,
            validate: function_base + 1,
            copy: function_base + 2,
            encode: function_base + 3,
        }
    }

    pub(crate) fn data_segments(&self) -> [CarrierCodecDataSegment; 1] {
        [CarrierCodecDataSegment {
            offset: self.layout.trusted_data_offset,
            bytes: self.trusted_data.clone(),
        }]
    }

    /// Return bodies in the same order as [`Self::append_function_type_indexes`].
    pub(crate) fn bodies(&self, function_base: u32) -> Vec<Vec<u8>> {
        let indexes = self.function_indexes(function_base);
        vec![
            self.sha256_body(),
            self.validate_body(indexes.sha256),
            self.copy_body(indexes.validate),
            self.encode_body(indexes.sha256),
        ]
    }

    fn sha256_body(&self) -> Vec<u8> {
        // Parameters: domain ptr/len, body ptr/len, workspace ptr. Locals are
        // total, padded, blocks, block, word, byte position, H0..H7, a..h,
        // t1 and t2. The 64-word schedule is the first 256 workspace bytes.
        let mut code = wasm_locals(&[(24, I32)]);
        const TOTAL: u32 = 5;
        const PADDED: u32 = 6;
        const BLOCKS: u32 = 7;
        const BLOCK: u32 = 8;
        const POS: u32 = 10;
        const H0: u32 = 11;
        const A: u32 = 19;
        const T1: u32 = 27;
        const T2: u32 = 28;

        // `domain || le_u64(body_len) || body` is the exact `digest` preimage.
        local_get(&mut code, 1);
        i32_const(&mut code, 8);
        code.push(I32_ADD);
        local_get(&mut code, 3);
        code.push(I32_ADD);
        local_set(&mut code, TOTAL);
        local_get(&mut code, TOTAL);
        i32_const(&mut code, 72); // ceil((n + 9) / 64) * 64
        code.push(I32_ADD);
        i32_const(&mut code, -64);
        code.push(I32_AND);
        local_set(&mut code, PADDED);
        local_get(&mut code, PADDED);
        i32_const(&mut code, 6);
        code.push(I32_SHR_U);
        local_set(&mut code, BLOCKS);
        for (index, value) in SHA256_INITIAL.iter().enumerate() {
            i32_const(&mut code, *value as i32);
            local_set(&mut code, H0 + index as u32);
        }
        i32_const(&mut code, 0);
        local_set(&mut code, BLOCK);
        block(&mut code);
        loop_(&mut code);
        local_get(&mut code, BLOCK);
        local_get(&mut code, BLOCKS);
        code.push(I32_GE_U);
        br_if(&mut code, 1);

        for word in 0..16 {
            local_get(&mut code, 4);
            i32_const(&mut code, (word * 4) as i32);
            code.push(I32_ADD);
            sha_message_word(&mut code, word, BLOCK, POS, TOTAL, PADDED);
            i32_store(&mut code);
        }
        for word in 16..64 {
            local_get(&mut code, 4);
            i32_const(&mut code, (word * 4) as i32);
            code.push(I32_ADD);
            sha_sigma0(&mut code, word - 15);
            sha_load_word(&mut code, word - 16);
            code.push(I32_ADD);
            sha_sigma1(&mut code, word - 2);
            code.push(I32_ADD);
            sha_load_word(&mut code, word - 7);
            code.push(I32_ADD);
            i32_store(&mut code);
        }
        for index in 0..8 {
            local_get(&mut code, H0 + index);
            local_set(&mut code, A + index);
        }
        for (round, constant) in SHA256_K.iter().enumerate() {
            // t1 = h + Sigma1(e) + Ch(e,f,g) + K + w[t]
            local_get(&mut code, A + 7);
            sha_big_sigma1(&mut code, A + 4);
            code.push(I32_ADD);
            local_get(&mut code, A + 4);
            local_get(&mut code, A + 5);
            code.push(I32_AND);
            local_get(&mut code, A + 4);
            i32_const(&mut code, -1);
            code.push(I32_XOR);
            local_get(&mut code, A + 6);
            code.push(I32_AND);
            code.push(I32_XOR);
            code.push(I32_ADD);
            i32_const(&mut code, *constant as i32);
            code.push(I32_ADD);
            sha_load_word(&mut code, round);
            code.push(I32_ADD);
            local_set(&mut code, T1);
            // t2 = Sigma0(a) + Maj(a,b,c)
            sha_big_sigma0(&mut code, A);
            local_get(&mut code, A);
            local_get(&mut code, A + 1);
            code.push(I32_AND);
            local_get(&mut code, A);
            local_get(&mut code, A + 2);
            code.push(I32_AND);
            code.push(I32_XOR);
            local_get(&mut code, A + 1);
            local_get(&mut code, A + 2);
            code.push(I32_AND);
            code.push(I32_XOR);
            code.push(I32_ADD);
            local_set(&mut code, T2);
            // h = g; g = f; f = e must all observe the old round state
            // before e is replaced by d + t1.
            for (to, from) in [(7, 6), (6, 5), (5, 4)] {
                local_get(&mut code, A + from);
                local_set(&mut code, A + to);
            }
            local_get(&mut code, A + 3);
            local_get(&mut code, T1);
            code.push(I32_ADD);
            local_set(&mut code, A + 4);
            for (to, from) in [(3, 2), (2, 1), (1, 0)] {
                local_get(&mut code, A + from);
                local_set(&mut code, A + to);
            }
            local_get(&mut code, T1);
            local_get(&mut code, T2);
            code.push(I32_ADD);
            local_set(&mut code, A);
        }
        for index in 0..8 {
            local_get(&mut code, H0 + index);
            local_get(&mut code, A + index);
            code.push(I32_ADD);
            local_set(&mut code, H0 + index);
        }
        local_get(&mut code, BLOCK);
        i32_const(&mut code, 1);
        code.push(I32_ADD);
        local_set(&mut code, BLOCK);
        br(&mut code, 0);
        end(&mut code);
        end(&mut code);
        for index in 0..8 {
            for (byte, shift) in [0_u32, 1, 2, 3].into_iter().zip([24, 16, 8, 0]) {
                local_get(&mut code, 4);
                i32_const(&mut code, 256 + index as i32 * 4 + byte as i32);
                code.push(I32_ADD);
                local_get(&mut code, H0 + index as u32);
                i32_const(&mut code, shift);
                code.push(I32_SHR_U);
                i32_store8(&mut code);
            }
        }
        end(&mut code);
        code
    }

    fn validate_body(&self, sha256: u32) -> Vec<u8> {
        // Parameters: frame ptr, frame len. Locals: offset/end/field start,
        // field length/sum/leaf length/index/body-end.
        let mut code = wasm_locals(&[(7, I32)]);
        const OFFSET: u32 = 2;
        const END: u32 = 3;
        const FIELD: u32 = 4;
        const SUM: u32 = 5;
        const LEAF_LEN: u32 = 6;
        const INDEX: u32 = 7;
        const BODY_END: u32 = 8;
        local_get(&mut code, 1);
        i32_const(&mut code, MAX_FRAME_WIRE_BYTES as i32);
        code.push(I32_GT_U);
        return_status(&mut code, STATUS_CAPACITY);
        local_get(&mut code, 0);
        local_get(&mut code, 1);
        code.push(I32_ADD);
        local_tee(&mut code, END);
        local_get(&mut code, 0);
        code.push(I32_LT_U);
        return_status(&mut code, STATUS_MALFORMED);
        local_get(&mut code, 0);
        local_set(&mut code, OFFSET);
        for (field, offset) in self.facts.fixed_fields().iter().zip(self.fixed_offsets) {
            exact_field(
                &mut code,
                OFFSET,
                END,
                FIELD,
                INDEX,
                offset,
                field.len() as u32,
            );
        }
        raw_u64_equals(
            &mut code,
            OFFSET,
            END,
            self.facts.leaf_paths.len() as u32,
            STATUS_CAPACITY,
        );
        raw_u64_to_local(&mut code, OFFSET, END, LEAF_LEN, STATUS_CAPACITY);
        local_get(&mut code, LEAF_LEN);
        i32_const(&mut code, MAX_TOTAL_PAYLOAD_BYTES as i32);
        code.push(I32_GT_U);
        return_status(&mut code, STATUS_CAPACITY);
        i32_const(&mut code, 0);
        local_set(&mut code, SUM);
        for (path, offset) in self.facts.leaf_paths.iter().zip(&self.leaf_offsets) {
            exact_field(
                &mut code,
                OFFSET,
                END,
                FIELD,
                INDEX,
                *offset,
                path.len() as u32,
            );
            require_bytes(&mut code, OFFSET, END, 1, STATUS_MALFORMED);
            local_get(&mut code, OFFSET);
            i32_load8(&mut code);
            i32_const(&mut code, 0); // LeafKind::Bytes is the sole v1 tag.
            code.push(I32_NE);
            return_status(&mut code, STATUS_MALFORMED);
            local_get(&mut code, OFFSET);
            i32_const(&mut code, 1);
            code.push(I32_ADD);
            local_set(&mut code, OFFSET);
            raw_u64_to_local(&mut code, OFFSET, END, FIELD, STATUS_MALFORMED);
            local_get(&mut code, FIELD);
            i32_const(&mut code, MAX_BYTES_PER_LEAF as i32);
            code.push(I32_GT_U);
            return_status(&mut code, STATUS_CAPACITY);
            local_get(&mut code, OFFSET);
            local_set(&mut code, BODY_END); // payload starts after its raw frame length.
            require_bytes_dynamic(&mut code, BODY_END, END, FIELD, STATUS_MALFORMED);
            local_get(&mut code, BODY_END);
            local_get(&mut code, FIELD);
            code.push(I32_ADD);
            local_set(&mut code, OFFSET);
            local_get(&mut code, SUM);
            local_get(&mut code, FIELD);
            code.push(I32_ADD);
            local_tee(&mut code, SUM);
            i32_const(&mut code, MAX_TOTAL_PAYLOAD_BYTES as i32);
            code.push(I32_GT_U);
            return_status(&mut code, STATUS_CAPACITY);
        }
        local_get(&mut code, SUM);
        local_get(&mut code, LEAF_LEN);
        code.push(I32_NE);
        return_status(&mut code, STATUS_MALFORMED);
        local_get(&mut code, OFFSET);
        local_set(&mut code, BODY_END);
        raw_u64_to_local(&mut code, OFFSET, END, FIELD, STATUS_MALFORMED);
        local_get(&mut code, FIELD);
        i32_const(&mut code, DIGEST_TEXT_BYTES as i32);
        code.push(I32_NE);
        return_status(&mut code, STATUS_MALFORMED);
        require_bytes_dynamic(&mut code, OFFSET, END, FIELD, STATUS_MALFORMED);
        local_get(&mut code, OFFSET);
        local_get(&mut code, FIELD);
        code.push(I32_ADD);
        local_get(&mut code, END);
        code.push(I32_NE);
        return_status(&mut code, STATUS_MALFORMED);
        for (index, byte) in b"sha256:".iter().enumerate() {
            local_get(&mut code, OFFSET);
            i32_const(&mut code, index as i32);
            code.push(I32_ADD);
            i32_load8(&mut code);
            i32_const(&mut code, i32::from(*byte));
            code.push(I32_NE);
            return_status(&mut code, STATUS_REPLAY_MISMATCH);
        }
        i32_const(&mut code, self.layout.trusted_data_offset as i32);
        i32_const(&mut code, FRAME_DOMAIN.len() as i32);
        local_get(&mut code, 0);
        local_get(&mut code, BODY_END);
        local_get(&mut code, 0);
        code.push(0x6b); // body length is frame-relative, never an address.
        i32_const(&mut code, self.layout.sha256_workspace_offset as i32);
        call(&mut code, sha256);
        i32_const(&mut code, 0);
        local_set(&mut code, INDEX);
        block(&mut code);
        loop_(&mut code);
        local_get(&mut code, INDEX);
        i32_const(&mut code, 32);
        code.push(I32_GE_U);
        br_if(&mut code, 1);
        i32_const(&mut code, self.layout.sha256_workspace_offset as i32 + 256);
        local_get(&mut code, INDEX);
        code.push(I32_ADD);
        i32_load8(&mut code);
        local_set(&mut code, FIELD);
        // Compare the high then low nibble with the submitted lowercase hex.
        local_get(&mut code, FIELD);
        i32_const(&mut code, 4);
        code.push(I32_SHR_U);
        hex_compare(&mut code, OFFSET, INDEX, 0);
        local_get(&mut code, FIELD);
        i32_const(&mut code, 15);
        code.push(I32_AND);
        hex_compare(&mut code, OFFSET, INDEX, 1);
        local_get(&mut code, INDEX);
        i32_const(&mut code, 1);
        code.push(I32_ADD);
        local_set(&mut code, INDEX);
        br(&mut code, 0);
        end(&mut code);
        end(&mut code);
        pack_status(&mut code, STATUS_OK, SUM);
        end(&mut code);
        code
    }

    fn copy_body(&self, validate: u32) -> Vec<u8> {
        // Parameters: frame ptr/len, output ptr/capacity, private leaf-table
        // ptr. Locals are offset, copied bytes, leaf length, byte index, and
        // the packed validation lane. Leaf-table rows are `(ptr,len)` pairs.
        let mut code = wasm_locals(&[(4, I32), (1, I64)]);
        const OFFSET: u32 = 5;
        const COPIED: u32 = 6;
        const LEAF_LEN: u32 = 7;
        const INDEX: u32 = 8;
        const LANE: u32 = 9;
        local_get(&mut code, 0);
        local_get(&mut code, 1);
        call(&mut code, validate);
        local_tee(&mut code, LANE);
        code.push(I32_WRAP_I64);
        code.push(I32_EQZ);
        if_(&mut code);
        local_get(&mut code, LANE);
        i64_const(&mut code, 32);
        code.push(I64_SHR_U);
        code.push(I32_WRAP_I64);
        local_get(&mut code, 3);
        code.push(I32_GT_U);
        return_status(&mut code, STATUS_CAPACITY);
        local_get(&mut code, 0);
        local_set(&mut code, OFFSET);
        for field in self.facts.fixed_fields() {
            local_get(&mut code, OFFSET);
            i32_const(&mut code, 8 + field.len() as i32);
            code.push(I32_ADD);
            local_set(&mut code, OFFSET);
        }
        for _ in 0..2 {
            local_get(&mut code, OFFSET);
            i32_const(&mut code, 8);
            code.push(I32_ADD);
            local_set(&mut code, OFFSET);
        }
        i32_const(&mut code, 0);
        local_set(&mut code, COPIED);
        for (leaf, path) in self.facts.leaf_paths.iter().enumerate() {
            local_get(&mut code, OFFSET);
            i32_const(&mut code, 8 + path.len() as i32 + 1);
            code.push(I32_ADD);
            local_set(&mut code, OFFSET);
            local_get(&mut code, OFFSET);
            i32_load(&mut code);
            local_set(&mut code, LEAF_LEN);
            local_get(&mut code, OFFSET);
            i32_const(&mut code, 8);
            code.push(I32_ADD);
            local_set(&mut code, OFFSET);
            local_get(&mut code, 4);
            i32_const(&mut code, (leaf * 8) as i32);
            code.push(I32_ADD);
            local_get(&mut code, 2);
            local_get(&mut code, COPIED);
            code.push(I32_ADD);
            i32_store(&mut code);
            local_get(&mut code, 4);
            i32_const(&mut code, (leaf * 8 + 4) as i32);
            code.push(I32_ADD);
            local_get(&mut code, LEAF_LEN);
            i32_store(&mut code);
            i32_const(&mut code, 0);
            local_set(&mut code, INDEX);
            block(&mut code);
            loop_(&mut code);
            local_get(&mut code, INDEX);
            local_get(&mut code, LEAF_LEN);
            code.push(I32_GE_U);
            br_if(&mut code, 1);
            local_get(&mut code, 2);
            local_get(&mut code, COPIED);
            code.push(I32_ADD);
            local_get(&mut code, INDEX);
            code.push(I32_ADD);
            local_get(&mut code, OFFSET);
            local_get(&mut code, INDEX);
            code.push(I32_ADD);
            i32_load8(&mut code);
            i32_store8(&mut code);
            local_get(&mut code, INDEX);
            i32_const(&mut code, 1);
            code.push(I32_ADD);
            local_set(&mut code, INDEX);
            br(&mut code, 0);
            end(&mut code);
            end(&mut code);
            local_get(&mut code, OFFSET);
            local_get(&mut code, LEAF_LEN);
            code.push(I32_ADD);
            local_set(&mut code, OFFSET);
            local_get(&mut code, COPIED);
            local_get(&mut code, LEAF_LEN);
            code.push(I32_ADD);
            local_set(&mut code, COPIED);
        }
        local_get(&mut code, LANE);
        code.push(RETURN);
        else_(&mut code);
        local_get(&mut code, LANE);
        code.push(RETURN);
        end(&mut code);
        // Core Wasm validates the outer `if` as potentially falling through
        // even though both arms return. Keep that syntactic fallthrough
        // fail-closed rather than relying on a validator's control-flow
        // inference for the function's required i64 result.
        i64_const(&mut code, STATUS_MALFORMED as i64);
        end(&mut code);
        code
    }

    fn encode_body(&self, sha256: u32) -> Vec<u8> {
        // Parameters: slice-table ptr/count, output ptr/capacity. The table is
        // a private array of little-endian `(pointer,length)` rows, one for
        // each descriptor leaf. It is intentionally not a public ABI layout.
        let mut code = wasm_locals(&[(6, I32)]);
        const TOTAL: u32 = 4;
        const OFFSET: u32 = 5;
        const POINTER: u32 = 6;
        const LENGTH: u32 = 7;
        const INDEX: u32 = 8;
        const REQUIRED: u32 = 9;
        local_get(&mut code, 1);
        i32_const(&mut code, self.facts.leaf_paths.len() as i32);
        code.push(I32_NE);
        return_status(&mut code, STATUS_REPLAY_MISMATCH);
        i32_const(&mut code, 0);
        local_set(&mut code, TOTAL);
        for leaf in 0..self.facts.leaf_paths.len() {
            local_get(&mut code, 0);
            i32_const(&mut code, (leaf * 8 + 4) as i32);
            code.push(I32_ADD);
            i32_load(&mut code);
            local_tee(&mut code, LENGTH);
            i32_const(&mut code, MAX_BYTES_PER_LEAF as i32);
            code.push(I32_GT_U);
            return_status(&mut code, STATUS_CAPACITY);
            local_get(&mut code, TOTAL);
            local_get(&mut code, LENGTH);
            code.push(I32_ADD);
            local_tee(&mut code, TOTAL);
            i32_const(&mut code, MAX_TOTAL_PAYLOAD_BYTES as i32);
            code.push(I32_GT_U);
            return_status(&mut code, STATUS_CAPACITY);
        }
        // Fixed frame bytes, two raw u64s, per-leaf path/tag/payload frames,
        // and the final length-framed `sha256:` digest.
        i32_const(&mut code, self.fixed_wire_bytes() as i32);
        i32_const(&mut code, 16);
        code.push(I32_ADD);
        for path in &self.facts.leaf_paths {
            i32_const(&mut code, (17 + path.len()) as i32);
            code.push(I32_ADD);
        }
        i32_const(&mut code, 8 + DIGEST_TEXT_BYTES as i32);
        code.push(I32_ADD);
        local_get(&mut code, TOTAL);
        code.push(I32_ADD);
        local_tee(&mut code, REQUIRED);
        i32_const(&mut code, MAX_FRAME_WIRE_BYTES as i32);
        code.push(I32_GT_U);
        return_status(&mut code, STATUS_CAPACITY);
        local_get(&mut code, REQUIRED);
        local_get(&mut code, 3);
        code.push(I32_GT_U);
        return_status(&mut code, STATUS_CAPACITY);
        local_get(&mut code, 2);
        local_set(&mut code, OFFSET);
        for (field, data) in self.facts.fixed_fields().iter().zip(self.fixed_offsets) {
            write_u64_low(&mut code, OFFSET, field.len() as u32);
            copy_static(&mut code, OFFSET, data, field.len() as u32, INDEX);
        }
        write_u64_low(&mut code, OFFSET, self.facts.leaf_paths.len() as u32);
        write_u64_local(&mut code, OFFSET, TOTAL);
        for (leaf, (path, data)) in self
            .facts
            .leaf_paths
            .iter()
            .zip(&self.leaf_offsets)
            .enumerate()
        {
            write_u64_low(&mut code, OFFSET, path.len() as u32);
            copy_static(&mut code, OFFSET, *data, path.len() as u32, INDEX);
            local_get(&mut code, OFFSET);
            i32_const(&mut code, 0);
            i32_store8(&mut code);
            local_get(&mut code, OFFSET);
            i32_const(&mut code, 1);
            code.push(I32_ADD);
            local_set(&mut code, OFFSET);
            local_get(&mut code, 0);
            i32_const(&mut code, (leaf * 8) as i32);
            code.push(I32_ADD);
            i32_load(&mut code);
            local_set(&mut code, POINTER);
            local_get(&mut code, 0);
            i32_const(&mut code, (leaf * 8 + 4) as i32);
            code.push(I32_ADD);
            i32_load(&mut code);
            local_set(&mut code, LENGTH);
            write_u64_local(&mut code, OFFSET, LENGTH);
            copy_dynamic(&mut code, OFFSET, POINTER, LENGTH, INDEX);
        }
        // The body ends immediately before the digest's own frame header.
        i32_const(&mut code, self.layout.trusted_data_offset as i32);
        i32_const(&mut code, FRAME_DOMAIN.len() as i32);
        local_get(&mut code, 2);
        local_get(&mut code, OFFSET);
        local_get(&mut code, 2);
        code.push(0x6b); // output body length
        i32_const(&mut code, self.layout.sha256_workspace_offset as i32);
        call(&mut code, sha256);
        write_u64_low(&mut code, OFFSET, DIGEST_TEXT_BYTES);
        for (index, byte) in b"sha256:".iter().enumerate() {
            local_get(&mut code, OFFSET);
            i32_const(&mut code, index as i32);
            code.push(I32_ADD);
            i32_const(&mut code, i32::from(*byte));
            i32_store8(&mut code);
        }
        local_get(&mut code, OFFSET);
        i32_const(&mut code, 7);
        code.push(I32_ADD);
        local_set(&mut code, POINTER);
        i32_const(&mut code, 0);
        local_set(&mut code, INDEX);
        block(&mut code);
        loop_(&mut code);
        local_get(&mut code, INDEX);
        i32_const(&mut code, 32);
        code.push(I32_GE_U);
        br_if(&mut code, 1);
        i32_const(&mut code, self.layout.sha256_workspace_offset as i32 + 256);
        local_get(&mut code, INDEX);
        code.push(I32_ADD);
        i32_load8(&mut code);
        local_set(&mut code, LENGTH);
        local_get(&mut code, POINTER);
        local_get(&mut code, INDEX);
        i32_const(&mut code, 1);
        code.push(0x74);
        code.push(I32_ADD);
        local_get(&mut code, LENGTH);
        i32_const(&mut code, 4);
        code.push(I32_SHR_U);
        hex_ascii(&mut code, TOTAL);
        i32_store8(&mut code);
        local_get(&mut code, POINTER);
        local_get(&mut code, INDEX);
        i32_const(&mut code, 1);
        code.push(0x74);
        code.push(I32_ADD);
        i32_const(&mut code, 1);
        code.push(I32_ADD);
        local_get(&mut code, LENGTH);
        i32_const(&mut code, 15);
        code.push(I32_AND);
        hex_ascii(&mut code, TOTAL);
        i32_store8(&mut code);
        local_get(&mut code, INDEX);
        i32_const(&mut code, 1);
        code.push(I32_ADD);
        local_set(&mut code, INDEX);
        br(&mut code, 0);
        end(&mut code);
        end(&mut code);
        local_get(&mut code, OFFSET);
        i32_const(&mut code, DIGEST_TEXT_BYTES as i32);
        code.push(I32_ADD);
        local_set(&mut code, OFFSET);
        pack_status(&mut code, STATUS_OK, REQUIRED);
        end(&mut code);
        code
    }

    fn fixed_wire_bytes(&self) -> usize {
        self.facts
            .fixed_fields()
            .iter()
            .map(|field| 8 + field.len())
            .sum()
    }
}

const I32: u8 = 0x7f;
const I64: u8 = 0x7e;
const RETURN: u8 = 0x0f;
const I32_EQZ: u8 = 0x45;
const I32_NE: u8 = 0x47;
const I32_LT_U: u8 = 0x49;
const I32_GT_U: u8 = 0x4b;
const I32_GE_U: u8 = 0x4f;
const I32_ADD: u8 = 0x6a;
const I32_AND: u8 = 0x71;
const I32_XOR: u8 = 0x73;
const I32_SHR_U: u8 = 0x76;
const I32_ROTR: u8 = 0x78;
const I64_SHL: u8 = 0x86;
const I64_SHR_U: u8 = 0x88;
const I32_WRAP_I64: u8 = 0xa7;

const STATUS_OK: u32 = 0;
const SHA256_INITIAL: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn exact_field(
    code: &mut Vec<u8>,
    offset: u32,
    end_offset: u32,
    field: u32,
    index: u32,
    expected: u32,
    expected_len: u32,
) {
    require_bytes(code, offset, end_offset, 8, STATUS_MALFORMED);
    local_get(code, offset);
    i32_load(code);
    i32_const(code, expected_len as i32);
    code.push(I32_NE);
    return_status(code, STATUS_REPLAY_MISMATCH);
    local_get(code, offset);
    i32_const(code, 4);
    code.push(I32_ADD);
    i32_load(code);
    code.push(I32_EQZ);
    if_(code);
    else_(code);
    status_return(code, STATUS_REPLAY_MISMATCH);
    end(code);
    local_get(code, offset);
    i32_const(code, 8);
    code.push(I32_ADD);
    local_set(code, field);
    require_bytes(code, field, end_offset, expected_len, STATUS_MALFORMED);
    i32_const(code, 0);
    local_set(code, index);
    block(code);
    loop_(code);
    local_get(code, index);
    i32_const(code, expected_len as i32);
    code.push(I32_GE_U);
    br_if(code, 1);
    local_get(code, field);
    local_get(code, index);
    code.push(I32_ADD);
    i32_load8(code);
    i32_const(code, expected as i32);
    local_get(code, index);
    code.push(I32_ADD);
    i32_load8(code);
    code.push(I32_NE);
    return_status(code, STATUS_REPLAY_MISMATCH);
    local_get(code, index);
    i32_const(code, 1);
    code.push(I32_ADD);
    local_set(code, index);
    br(code, 0);
    end(code);
    end(code);
    local_get(code, field);
    i32_const(code, expected_len as i32);
    code.push(I32_ADD);
    local_set(code, offset);
}

fn raw_u64_equals(code: &mut Vec<u8>, offset: u32, end_offset: u32, expected: u32, status: u32) {
    require_bytes(code, offset, end_offset, 8, STATUS_MALFORMED);
    local_get(code, offset);
    i32_load(code);
    i32_const(code, expected as i32);
    code.push(I32_NE);
    return_status(code, status);
    local_get(code, offset);
    i32_const(code, 4);
    code.push(I32_ADD);
    i32_load(code);
    code.push(I32_EQZ);
    if_(code);
    else_(code);
    status_return(code, status);
    end(code);
    local_get(code, offset);
    i32_const(code, 8);
    code.push(I32_ADD);
    local_set(code, offset);
}

fn raw_u64_to_local(code: &mut Vec<u8>, offset: u32, end_offset: u32, target: u32, status: u32) {
    require_bytes(code, offset, end_offset, 8, STATUS_MALFORMED);
    local_get(code, offset);
    i32_load(code);
    local_set(code, target);
    local_get(code, offset);
    i32_const(code, 4);
    code.push(I32_ADD);
    i32_load(code);
    code.push(I32_EQZ);
    if_(code);
    else_(code);
    status_return(code, status);
    end(code);
    local_get(code, offset);
    i32_const(code, 8);
    code.push(I32_ADD);
    local_set(code, offset);
}

fn require_bytes(code: &mut Vec<u8>, start: u32, end_offset: u32, bytes: u32, status: u32) {
    local_get(code, end_offset);
    local_get(code, start);
    code.push(0x6b); // i32.sub
    i32_const(code, bytes as i32);
    code.push(I32_LT_U);
    return_status(code, status);
}

fn require_bytes_dynamic(code: &mut Vec<u8>, start: u32, end_offset: u32, bytes: u32, status: u32) {
    local_get(code, end_offset);
    local_get(code, start);
    code.push(0x6b); // i32.sub
    local_get(code, bytes);
    code.push(I32_LT_U);
    return_status(code, status);
}

fn hex_compare(code: &mut Vec<u8>, digest_text: u32, index: u32, nibble: i32) {
    // Stack begins with a nibble. Turn it into lowercase ASCII and compare it
    // with byte `7 + index * 2 + nibble` of the transmitted digest field.
    i32_const(code, 10);
    code.push(I32_LT_U);
    if_result_i32(code);
    // The condition consumed the nibble, so reconstruct from the byte held in
    // the caller's FIELD local through the equivalent branch-specific form.
    // This helper is only called by validate_body, whose FIELD local is 4.
    local_get(code, 4);
    if nibble == 0 {
        i32_const(code, 4);
        code.push(I32_SHR_U);
    } else {
        i32_const(code, 15);
        code.push(I32_AND);
    }
    i32_const(code, 48);
    code.push(I32_ADD);
    else_(code);
    local_get(code, 4);
    if nibble == 0 {
        i32_const(code, 4);
        code.push(I32_SHR_U);
    } else {
        i32_const(code, 15);
        code.push(I32_AND);
    }
    i32_const(code, 87);
    code.push(I32_ADD);
    end(code);
    local_get(code, digest_text);
    i32_const(code, 7 + nibble);
    code.push(I32_ADD);
    local_get(code, index);
    i32_const(code, 1);
    code.push(0x74); // i32.shl
    code.push(I32_ADD);
    i32_load8(code);
    code.push(I32_NE);
    return_status(code, STATUS_REPLAY_MISMATCH);
}

fn hex_ascii(code: &mut Vec<u8>, scratch: u32) {
    // Stack begins with one 0..=15 nibble and ends with its lowercase ASCII.
    local_set(code, scratch);
    local_get(code, scratch);
    i32_const(code, 10);
    code.push(I32_LT_U);
    if_result_i32(code);
    local_get(code, scratch);
    i32_const(code, 48);
    code.push(I32_ADD);
    else_(code);
    local_get(code, scratch);
    i32_const(code, 87);
    code.push(I32_ADD);
    end(code);
}

fn write_u64_low(code: &mut Vec<u8>, offset: u32, value: u32) {
    local_get(code, offset);
    i32_const(code, value as i32);
    i32_store(code);
    local_get(code, offset);
    i32_const(code, 4);
    code.push(I32_ADD);
    i32_const(code, 0);
    i32_store(code);
    local_get(code, offset);
    i32_const(code, 8);
    code.push(I32_ADD);
    local_set(code, offset);
}

fn write_u64_local(code: &mut Vec<u8>, offset: u32, value: u32) {
    local_get(code, offset);
    local_get(code, value);
    i32_store(code);
    local_get(code, offset);
    i32_const(code, 4);
    code.push(I32_ADD);
    i32_const(code, 0);
    i32_store(code);
    local_get(code, offset);
    i32_const(code, 8);
    code.push(I32_ADD);
    local_set(code, offset);
}

fn copy_static(code: &mut Vec<u8>, offset: u32, source: u32, len: u32, index: u32) {
    i32_const(code, 0);
    local_set(code, index);
    block(code);
    loop_(code);
    local_get(code, index);
    i32_const(code, len as i32);
    code.push(I32_GE_U);
    br_if(code, 1);
    local_get(code, offset);
    local_get(code, index);
    code.push(I32_ADD);
    i32_const(code, source as i32);
    local_get(code, index);
    code.push(I32_ADD);
    i32_load8(code);
    i32_store8(code);
    local_get(code, index);
    i32_const(code, 1);
    code.push(I32_ADD);
    local_set(code, index);
    br(code, 0);
    end(code);
    end(code);
    local_get(code, offset);
    i32_const(code, len as i32);
    code.push(I32_ADD);
    local_set(code, offset);
}

fn copy_dynamic(code: &mut Vec<u8>, offset: u32, source: u32, len: u32, index: u32) {
    i32_const(code, 0);
    local_set(code, index);
    block(code);
    loop_(code);
    local_get(code, index);
    local_get(code, len);
    code.push(I32_GE_U);
    br_if(code, 1);
    local_get(code, offset);
    local_get(code, index);
    code.push(I32_ADD);
    local_get(code, source);
    local_get(code, index);
    code.push(I32_ADD);
    i32_load8(code);
    i32_store8(code);
    local_get(code, index);
    i32_const(code, 1);
    code.push(I32_ADD);
    local_set(code, index);
    br(code, 0);
    end(code);
    end(code);
    local_get(code, offset);
    local_get(code, len);
    code.push(I32_ADD);
    local_set(code, offset);
}

fn sha_message_word(
    code: &mut Vec<u8>,
    word: usize,
    block: u32,
    pos: u32,
    total: u32,
    padded: u32,
) {
    for byte in 0..4 {
        if byte != 0 {
            i32_const(code, 8);
            code.push(0x74); // i32.shl: make room in the accumulated word.
        }
        local_get(code, block);
        i32_const(code, 64);
        code.push(0x6c); // i32.mul
        i32_const(code, (word * 4 + byte) as i32);
        code.push(I32_ADD);
        local_set(code, pos);
        sha_message_byte(code, pos, total, padded);
        if byte != 0 {
            code.push(I32_ADD);
        }
    }
}

fn sha_message_byte(code: &mut Vec<u8>, pos: u32, total: u32, padded: u32) {
    // Position selects domain, the dynamic little-endian body length, body,
    // the mandatory 0x80 byte, the final big-endian bit length, or zero.
    local_get(code, pos);
    i32_const(code, FRAME_DOMAIN.len() as i32);
    code.push(I32_LT_U);
    if_result_i32(code);
    // The enclosing validator passes the actual data base to SHA; this body
    // only knows the pointer parameter, so retrieve it through local 0.
    local_get(code, 0);
    local_get(code, pos);
    code.push(I32_ADD);
    i32_load8(code);
    else_(code);
    local_get(code, pos);
    i32_const(code, (FRAME_DOMAIN.len() + 8) as i32);
    code.push(I32_LT_U);
    if_result_i32(code);
    local_get(code, 3);
    code.push(0xad); // i64.extend_i32_u
    local_get(code, pos);
    i32_const(code, FRAME_DOMAIN.len() as i32);
    code.push(0x6b);
    code.push(0xad);
    i64_const(code, 3);
    code.push(I64_SHL);
    code.push(I64_SHR_U);
    i64_const(code, 255);
    code.push(0x83); // i64.and
    code.push(I32_WRAP_I64);
    else_(code);
    local_get(code, pos);
    local_get(code, total);
    code.push(I32_LT_U);
    if_result_i32(code);
    local_get(code, 2);
    local_get(code, pos);
    i32_const(code, (FRAME_DOMAIN.len() + 8) as i32);
    code.push(0x6b);
    code.push(I32_ADD);
    i32_load8(code);
    else_(code);
    local_get(code, pos);
    local_get(code, total);
    code.push(I32_NE);
    if_result_i32(code);
    local_get(code, pos);
    local_get(code, padded);
    i32_const(code, 8);
    code.push(0x6b);
    code.push(I32_LT_U);
    if_result_i32(code);
    i32_const(code, 0);
    else_(code);
    local_get(code, total);
    code.push(0xad);
    i64_const(code, 3);
    code.push(I64_SHL);
    local_get(code, padded);
    i32_const(code, 1);
    code.push(0x6b);
    local_get(code, pos);
    code.push(0x6b);
    code.push(0xad);
    i64_const(code, 3);
    code.push(I64_SHL);
    code.push(I64_SHR_U);
    i64_const(code, 255);
    code.push(0x83);
    code.push(I32_WRAP_I64);
    end(code);
    else_(code);
    i32_const(code, 0x80);
    end(code);
    end(code);
    end(code);
    end(code);
}

fn sha_load_word(code: &mut Vec<u8>, word: usize) {
    local_get(code, 4);
    i32_const(code, (word * 4) as i32);
    code.push(I32_ADD);
    i32_load(code);
}

fn sha_sigma0(code: &mut Vec<u8>, word: usize) {
    sha_rot_word(code, word, 7);
    sha_rot_word(code, word, 18);
    code.push(I32_XOR);
    sha_load_word(code, word);
    i32_const(code, 3);
    code.push(I32_SHR_U);
    code.push(I32_XOR);
}

fn sha_sigma1(code: &mut Vec<u8>, word: usize) {
    sha_rot_word(code, word, 17);
    sha_rot_word(code, word, 19);
    code.push(I32_XOR);
    sha_load_word(code, word);
    i32_const(code, 10);
    code.push(I32_SHR_U);
    code.push(I32_XOR);
}

fn sha_rot_word(code: &mut Vec<u8>, word: usize, shift: i32) {
    sha_load_word(code, word);
    i32_const(code, shift);
    code.push(I32_ROTR);
}

fn sha_big_sigma0(code: &mut Vec<u8>, local: u32) {
    sha_rot_local(code, local, 2);
    sha_rot_local(code, local, 13);
    code.push(I32_XOR);
    sha_rot_local(code, local, 22);
    code.push(I32_XOR);
}

fn sha_big_sigma1(code: &mut Vec<u8>, local: u32) {
    sha_rot_local(code, local, 6);
    sha_rot_local(code, local, 11);
    code.push(I32_XOR);
    sha_rot_local(code, local, 25);
    code.push(I32_XOR);
}

fn sha_rot_local(code: &mut Vec<u8>, local: u32, shift: i32) {
    local_get(code, local);
    i32_const(code, shift);
    code.push(I32_ROTR);
}

fn pack_status(code: &mut Vec<u8>, status: u32, payload_local: u32) {
    local_get(code, payload_local);
    code.push(0xad); // i64.extend_i32_u
    i64_const(code, 32);
    code.push(I64_SHL);
    i64_const(code, status as i64);
    code.push(0x84); // i64.or
}

fn return_status(code: &mut Vec<u8>, status: u32) {
    if_(code);
    status_return(code, status);
    end(code);
}

fn status_return(code: &mut Vec<u8>, status: u32) {
    i64_const(code, status as i64);
    code.push(RETURN);
}

fn wasm_function_type(out: &mut Vec<u8>, params: &[u8], results: &[u8]) {
    out.push(0x60);
    wasm_bytes(out, params);
    wasm_bytes(out, results);
}

fn wasm_locals(groups: &[(u32, u8)]) -> Vec<u8> {
    let mut body = Vec::new();
    wasm_u32(&mut body, groups.len() as u32);
    for (count, ty) in groups {
        wasm_u32(&mut body, *count);
        body.push(*ty);
    }
    body
}

fn wasm_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    wasm_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

fn wasm_u32(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        out.push(if value == 0 { byte } else { byte | 0x80 });
        if value == 0 {
            return;
        }
    }
}

fn i32_const(out: &mut Vec<u8>, value: i32) {
    out.push(0x41);
    wasm_i64(out, i64::from(value));
}

fn i64_const(out: &mut Vec<u8>, value: i64) {
    out.push(0x42);
    wasm_i64(out, value);
}

fn wasm_i64(out: &mut Vec<u8>, mut value: i64) {
    loop {
        let byte = (value as u8) & 0x7f;
        value >>= 7;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        out.push(if done { byte } else { byte | 0x80 });
        if done {
            return;
        }
    }
}

fn local_get(out: &mut Vec<u8>, local: u32) {
    out.push(0x20);
    wasm_u32(out, local);
}

fn local_set(out: &mut Vec<u8>, local: u32) {
    out.push(0x21);
    wasm_u32(out, local);
}

fn local_tee(out: &mut Vec<u8>, local: u32) {
    out.push(0x22);
    wasm_u32(out, local);
}

fn block(out: &mut Vec<u8>) {
    out.extend([0x02, 0x40]);
}
fn loop_(out: &mut Vec<u8>) {
    out.extend([0x03, 0x40]);
}
fn if_(out: &mut Vec<u8>) {
    out.extend([0x04, 0x40]);
}
fn if_result_i32(out: &mut Vec<u8>) {
    out.extend([0x04, I32]);
}
fn else_(out: &mut Vec<u8>) {
    out.push(0x05);
}
fn end(out: &mut Vec<u8>) {
    out.push(0x0b);
}
fn br(out: &mut Vec<u8>, depth: u32) {
    out.push(0x0c);
    wasm_u32(out, depth);
}
fn br_if(out: &mut Vec<u8>, depth: u32) {
    out.push(0x0d);
    wasm_u32(out, depth);
}
fn call(out: &mut Vec<u8>, function: u32) {
    out.push(0x10);
    wasm_u32(out, function);
}
fn i32_load(out: &mut Vec<u8>) {
    out.extend([0x28, 2, 0]);
}
fn i32_load8(out: &mut Vec<u8>) {
    out.extend([0x2d, 0, 0]);
}
fn i32_store(out: &mut Vec<u8>) {
    out.extend([0x36, 2, 0]);
}
fn i32_store8(out: &mut Vec<u8>) {
    out.extend([0x3a, 0, 0]);
}
