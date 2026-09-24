import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const expected = Number(process.argv[2]);
assert.ok(expected === 0 || expected === 11);
const module = await WebAssembly.compile(readFileSync('provider.wasm'));
assert.equal(WebAssembly.Module.imports(module).length, 0);
const { exports: api } = await WebAssembly.instantiate(module, {});
const lane = raw => ({ status: Number(raw & 0xffffffffn), value: Number(raw >> 32n) });
const refused = raw => assert.deepEqual(lane(raw), { status: 8, value: 0 });
const reservation = lane(api.spx_pg_v1_scratch_reserve(65536));
assert.equal(reservation.status, 0);
const scratch = reservation.value;
const descriptor = readFileSync('descriptor.bin'), binding = readFileSync('binding.bin');
const input = readFileSync('input.bin'), results = [];
function absent() {
    refused(api.spx_pg_v1_call(0, 0));
    refused(api.spx_pg_v1_input_prepare(0, scratch, input.length));
    refused(api.spx_pg_v1_result_export(0, scratch, 65536));
    assert.equal(api.spx_pg_v1_value_release(0), 8);
    assert.equal(api.spx_pg_v1_result_release(0), 8);
    assert.equal(api.spx_pg_v1_provider_close(0), 8);
}
for (let cycle = 0; cycle < 2; ++cycle) {
    absent(); // before open, then again after every close/recreation
    let memory = new Uint8Array(api.memory.buffer);
    memory.set(descriptor, scratch); memory.set(binding, scratch + descriptor.length);
    const opened = lane(api.spx_pg_v1_open(scratch, descriptor.length, scratch + descriptor.length, binding.length));
    assert.equal(opened.status, 0); assert.ok(opened.value > 0);
    refused(api.spx_pg_v1_call(opened.value, 0));
    refused(api.spx_pg_v1_result_export(0, scratch, 65536));
    assert.equal(api.spx_pg_v1_value_release(0), 8);
    memory.set(input, scratch);
    const prepared = lane(api.spx_pg_v1_input_prepare(opened.value, scratch, input.length));
    assert.equal(prepared.status, 0); assert.ok(prepared.value > 0);
    assert.equal(api.spx_pg_v1_provider_close(opened.value), 7);
    refused(api.spx_pg_v1_call(0, prepared.value));
    const called = lane(api.spx_pg_v1_call(opened.value, prepared.value));
    assert.equal(called.status, expected);
    let bytes = [];
    if (expected === 0) {
        assert.ok(called.value > 0);
        refused(api.spx_pg_v1_call(opened.value, prepared.value));
        refused(api.spx_pg_v1_call(opened.value, 0));
        assert.equal(api.spx_pg_v1_provider_close(opened.value), 7);
        const query = lane(api.spx_pg_v1_result_export(called.value, scratch, 0));
        assert.equal(query.status, 12); assert.ok(query.value > 1 && query.value < 65536);
        memory = new Uint8Array(api.memory.buffer);
        memory.fill(0xa5, scratch, scratch + query.value);
        const short = lane(api.spx_pg_v1_result_export(called.value, scratch, query.value - 1));
        assert.deepEqual(short, query);
        assert.ok(memory.slice(scratch, scratch + query.value).every(byte => byte === 0xa5));
        const copied = lane(api.spx_pg_v1_result_export(called.value, scratch, query.value));
        assert.deepEqual(copied, { status: 0, value: query.value });
        bytes = Array.from(memory.slice(scratch, scratch + copied.value));
        const retry = lane(api.spx_pg_v1_result_export(called.value, scratch, query.value));
        assert.deepEqual(retry, copied);
        assert.deepEqual(Array.from(memory.slice(scratch, scratch + copied.value)), bytes);
        assert.equal(api.spx_pg_v1_result_release(called.value), 0);
        assert.equal(api.spx_pg_v1_result_release(called.value), 8);
        refused(api.spx_pg_v1_result_export(called.value, scratch, 65536));
    } else {
        assert.equal(called.value, 0);
        // Existing target contract: failed call retains its input until release.
        assert.equal(api.spx_pg_v1_provider_close(opened.value), 7);
        assert.equal(api.spx_pg_v1_value_release(prepared.value), 0);
    }
    assert.equal(api.spx_pg_v1_value_release(prepared.value), 8);
    assert.equal(api.spx_pg_v1_value_release(0), 8);
    assert.equal(api.spx_pg_v1_result_release(0), 8);
    assert.equal(api.spx_pg_v1_provider_close(opened.value), 0);
    assert.equal(api.spx_pg_v1_provider_close(opened.value), 8);
    results.push(bytes);
}
absent();
process.stdout.write(JSON.stringify(results));
