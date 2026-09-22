#!/usr/bin/env python3
"""Test-only flat-fixture assembly from the production consumer templates.

This is not a descriptor producer/verifier. It substitutes trusted fixture
field lists into the SAME fixed assets used by the Rust generators. The Cargo
harness byte-compares these files to actual generator output before executing
its consumer matrix. Standalone runs report their template-fixture route.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'src/public_generic_consumer'


def frame(data: bytes) -> bytes:
    return struct.pack('<Q', len(data)) + data


def identities(count: int) -> list[str]:
    if type(count) is not int or not 1 <= count <= 256:
        raise ValueError('fixture-shape-bound')
    return [f'settlement.field{index}' for index in range(count)]


def bindings() -> tuple[bytes, bytes]:
    # Same DescriptorV1::new fixture used in the generated-caller harnesses.
    # Canonical framing != compiler-derived authenticity: no PG-7 claim.
    descriptor = b''.join(frame(x.encode('ascii')) for x in [
        'semaprax.public-generic-descriptor.v1', 'semaprax.public-generic-boundary-profile.v1',
        'semaprax.public-generic-type-grammar.v1', 'sample.transform',
        *['sha256:' + str(i) * 64 for i in [1, 2, 3]],
        '@11:sample.pair<bytes,bool>', 'sha256:' + '4' * 64,
        '@11:sample.pair<bytes,i64>', 'sha256:' + '5' * 64, 'transform'])
    carrier = b''.join(frame(x.encode('ascii')) for x in [
        'semaprax.public-generic-carrier.v1', 'sha256:' + '9' * 64,
        'native-c11', 'runtime:native-c11-fixture-issue-158'])
    binding = b''.join(map(frame, [b'semaprax.public-generic-native-adapter.v1', carrier, b'v1',
        b'sha256:' + b'a' * 68, b'spx_pg_endpoint_reverse_bytes_v1', b'semaprax-0.4.1', b'unsupported-unpublished']))
    return descriptor, binding


def asset(family: str, name: str) -> str:
    return (ASSETS / family / 'render' / name).read_text(encoding='utf-8').replace('\r\n', '\n')


def c_bytes(name: str, length_name: str, data: bytes) -> str:
    if not data:
        return f'const uint8_t {name}[] = {{0}};\nconst size_t {length_name} = 0;\n'
    result = f'const uint8_t {name}[] = {{\n'
    for offset in range(0, len(data), 12):
        result += '    ' + ''.join(f'0x{x:02x}, ' for x in data[offset:offset + 12]) + '\n'
    result += '};\n' if data else '0};\n'
    return result + f'const size_t {length_name} = {len(data)};\n'


def render(count: int, *, field_identities: list[str] | None = None,
           descriptor_bytes: bytes | None = None,
           binding_bytes: bytes | None = None) -> dict[str, str]:
    ids = identities(count) if field_identities is None else field_identities
    if (not isinstance(ids, list) or len(ids) != count
            or any(type(value) is not str or not value or len(value.encode('utf-8')) > 256
                   for value in ids)
            or len(set(ids)) != count):
        raise ValueError('fixture-identity-bound')
    fields = ['field_' + name.encode('utf-8').hex() for name in ids]
    default_descriptor, default_binding = bindings()
    descriptor = default_descriptor if descriptor_bytes is None else descriptor_bytes
    binding = default_binding if binding_bytes is None else binding_bytes
    if (type(descriptor) is not bytes or not descriptor or len(descriptor) > 4 * 1024 * 1024
            or type(binding) is not bytes or not binding or len(binding) > 4 * 1024 * 1024):
        raise ValueError('fixture-binding-bound')
    def struct_type(name: str) -> str:
        return (f'typedef struct {name} {{\n' + ''.join(
            f'    /* Field identity: {json.dumps(identity)} */\n    spx_pg_owned_bytes {field};\n'
            for identity, field in zip(ids, fields)) + f'}} {name};\n')
    header = asset('c_calling', 'header_preamble.h.txt') + struct_type('spx_pg_input') + '\n' + struct_type('spx_pg_output') + '\n' + asset('c_calling', 'header_api.h.txt')
    encode = ('static spx_pg_consumer_status spx_pg_ccc_encode_input(const spx_pg_input *input,\n'
              '    uint8_t **out_bytes, size_t *out_len) {\n    const spx_pg_owned_bytes *leaves[FIELD_COUNT] = {\n')
    encode += ''.join(f'        &input->{field},\n' for field in fields)
    encode += '    };\n    return spx_pg_ccc_encode_leaves(leaves, out_bytes, out_len);\n}\n'
    free_input = 'static void spx_pg_ccc_free_input_leaves(spx_pg_input *input) {\n    spx_pg_owned_bytes *leaves[FIELD_COUNT] = {\n'
    free_input += ''.join(f'        &input->{field},\n' for field in fields) + '    };\n    spx_pg_ccc_consume_input(leaves);\n}\n'
    free_output = ('void spx_pg_owned_bytes_free(spx_pg_owned_bytes *bytes) {\n'
        '    if (bytes == NULL) {\n        return;\n    }\n    free(bytes->data);\n    bytes->data = NULL;\n    bytes->len = 0;\n}\n\n'
        'void spx_pg_output_free(spx_pg_output *output) {\n    if (output == NULL) {\n        return;\n    }\n')
    free_output += ''.join(f'    spx_pg_owned_bytes_free(&output->{field});\n' for field in reversed(fields)) + '}\n'
    decode = ('static spx_pg_consumer_status spx_pg_ccc_decode_output(const uint8_t *bytes, size_t len,\n'
        '    spx_pg_output *out) {\n    spx_pg_owned_bytes leaves[FIELD_COUNT];\n    memset(leaves, 0, sizeof(leaves));\n'
        '    spx_pg_consumer_status status = spx_pg_ccc_decode_leaves(bytes, len, leaves);\n    if (status != SPX_PG_CONSUMER_OK) return status;\n')
    decode += ''.join(f'    out->{field} = leaves[{i}];\n' for i, field in enumerate(fields)) + '    return SPX_PG_CONSUMER_OK;\n}\n'
    source = asset('c_calling', 'source_preamble.c.txt') + f'#define FIELD_COUNT {count}\n\n'
    source += '\n'.join([c_bytes('spx_pg_trusted_descriptor_bytes', 'spx_pg_trusted_descriptor_len', descriptor),
        c_bytes('spx_pg_trusted_binding_bytes', 'spx_pg_trusted_binding_len', binding),
        asset('c_calling', 'codec.c.txt'), encode, free_input, free_output, decode,
        asset('c_calling', 'lifecycle.c.txt')])
    inp = asset('cxx_calling', 'input.hpp.txt').replace('@FIELDS@', ''.join(f'    std::vector<std::uint8_t> {field};\n' for field in fields))
    out = asset('cxx_calling', 'output.hpp.txt').replace('@ACCESSORS@', ''.join(
        f'    BytesView {field}() const noexcept {{ return BytesView{{raw_.{field}.data, raw_.{field}.len}}; }}\n' for field in fields))
    preflight = ''.join(f'    if (input.{field}.size() > 65536u || input.{field}.size() > 16777216u - payload) return Error(ErrorKind::CapacityExceeded, 0);\n    payload += input.{field}.size();\n' for field in fields)
    transform = asset('cxx_calling', 'transform.hpp.txt').replace('@PREFLIGHT@', preflight).replace('@STAGE@', ''.join(
        f'    prepared = prepared && detail::make_owned_bytes(input.{field}, c_input.{field});\n' for field in fields)).replace('@ROLLBACK@', ''.join(
        f'        ::spx_pg_owned_bytes_free(&c_input.{field});\n' for field in reversed(fields)))
    cpp = asset('cxx_calling', 'header.hpp.txt') + '\n'.join([inp, out,
        asset('cxx_calling', 'provider.hpp.txt'), asset('cxx_calling', 'owned.hpp.txt'),
        asset('cxx_calling', 'open.hpp.txt'), transform]) + asset('cxx_calling', 'trailer.hpp.txt')
    return {'spx_pg_v1.h': (ROOT / 'src/public_generic_abi/native/spx_pg_v1.h').read_text(),
            'spx_pg_calling_consumer.h': header, 'spx_pg_calling_consumer.c': source,
            'include/semaprax_public_generic_v1.hpp': cpp}


def write(root: Path, count: int) -> None:
    for name, data in render(count).items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding='utf-8', newline='\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fields', type=int, required=True)
    args = parser.parse_args()
    write(args.output, args.fields)
