import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const expected = Number(process.argv[2]);
assert.ok(expected === 0 || expected === 11);
const module = await WebAssembly.compile(readFileSync('provider.wasm'));
assert.equal(WebAssembly.Module.imports(module).length, 0);
const { exports: api } = await WebAssembly.instantiate(module, {});
const lane = raw => ({ status: Number(raw & 0xffffffffn), value: Number((raw >> 32n) & 0xffffffffn) });
const reserved = lane(api.spx_pg_v1_scratch_reserve(16 * 1024 * 1024 + 2056));
assert.equal(reserved.status, 0);
assert.ok(reserved.value > 0);
const scratch = reserved.value;
const descriptor = readFileSync('descriptor.bin'), binding = readFileSync('binding.bin');
let memory = new Uint8Array(api.memory.buffer);
memory.set(descriptor, scratch);
memory.set(binding, scratch + descriptor.length);
const opened = lane(api.spx_pg_v1_open(scratch, descriptor.length, scratch + descriptor.length, binding.length));
assert.equal(opened.status, 0);
assert.ok(opened.value > 0);
const input = readFileSync('input.bin');
memory.set(input, scratch);
const prepared = lane(api.spx_pg_v1_input_prepare(opened.value, scratch, input.length));
assert.equal(prepared.status, 0);
assert.ok(prepared.value > 0);
const called = lane(api.spx_pg_v1_call(opened.value, prepared.value));
assert.equal(called.status, expected);
let bytes = [];
if (expected === 0) {
    assert.ok(called.value > 0);
    const probe = lane(api.spx_pg_v1_result_export(called.value, scratch, 0));
    assert.equal(probe.status, 12);
    assert.ok(probe.value > 0 && probe.value <= 65536);
    const copied = lane(api.spx_pg_v1_result_export(called.value, scratch, probe.value));
    assert.equal(copied.status, 0);
    assert.equal(copied.value, probe.value);
    memory = new Uint8Array(api.memory.buffer);
    bytes = Array.from(memory.slice(scratch, scratch + copied.value));
    assert.equal(api.spx_pg_v1_result_release(called.value), 0);
} else {
    assert.equal(called.value, 0);
    // Wasm preserves the input on checked failure; explicitly settle it.
    assert.equal(api.spx_pg_v1_value_release(prepared.value), 0);
}
assert.equal(api.spx_pg_v1_value_release(prepared.value), 8);
assert.equal(api.spx_pg_v1_provider_close(opened.value), 0);
process.stdout.write(JSON.stringify(bytes));
