// PRIVATE Node host for a compiled C11 reference provider, not the generated
// TypeScript caller or the Semaprax compiler's Wasm profile. All semantic
// allocations, handles, copy-in, execution, staging and release run in Wasm.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const [modulePath, inputsPath, mode = 'suite'] = process.argv.slice(2);
const input = JSON.parse(readFileSync(inputsPath, 'utf8'));
assert.equal(input.schema, 'semaprax.public-generic-compiled-reference-input.v1');
const module = await WebAssembly.compile(readFileSync(modulePath));
assert.deepEqual(WebAssembly.Module.imports(module), [], 'no host imports or allocator');
const required = ['memory', 'pg_log_pointer', 'pg_log_length', 'pg_heap_live', 'pg_heap_bytes',
    'pg_scratch_pointer', 'pg_scratch_capacity', 'pg_open', 'pg_prepare', 'pg_call', 'pg_export',
    'pg_input_release', 'pg_result_release', 'pg_close', 'pg_inject', 'pg_phase_inject',
    'pg_reset_observations', 'pg_observe', 'pg_trace', 'pg_release_observation', 'pg_cleanup_observation', 'pg_run'];
assert.deepEqual(WebAssembly.Module.exports(module).map(x => x.name).sort(), required.sort(), 'closed export inventory');
const descriptor = Buffer.from(input.descriptor_hex, 'hex');
const binding = Buffer.from(input.binding_hex, 'hex');
const lane = n => ({ status: Number(BigInt.asUintN(64, n) & 0xffffffffn), value: Number(BigInt.asUintN(64, n) >> 32n) });
const FRAME_MAX = 16777216 + 2056;
async function instance() {
    return (await WebAssembly.instantiate(module, {})).exports;
}
function log(x) {
    return Buffer.from(x.memory.buffer, x.pg_log_pointer(), x.pg_log_length()).toString('utf8');
}
function zero(x) {
    for (const key of [0, 1, 2, 10, 11])
        assert.equal(x.pg_observe(key), 0n, `live resource ${key}`);
    assert.equal(x.pg_heap_live(), 0);
    assert.equal(x.pg_heap_bytes(), 0);
}
function put(x, bytes, offset = 0) {
    const p = x.pg_scratch_pointer() + offset;
    assert(offset >= 0 && offset + bytes.length <= x.pg_scratch_capacity());
    // New view for every operation; a memory.grow must never leave a stale view.
    new Uint8Array(x.memory.buffer).set(bytes, p);
    return p;
}
function open(x, d = descriptor, b = binding) {
    put(x, d);
    put(x, b, d.length);
    return lane(x.pg_open(x.pg_scratch_pointer(), d.length, x.pg_scratch_pointer() + d.length, b.length));
}
function trusted(x) {
    const p = open(x);
    assert.equal(p.status, 0);
    assert(p.value > 0);
    return p.value;
}
const ordinary = Buffer.from('0200000000000000020000000000000041420300000000000000430044', 'hex');
const ordinaryResult = Buffer.from('0200000000000000020000000000000042410300000000000000440043', 'hex');
function prepare(x, p, bytes = ordinary) {
    const v = lane(x.pg_prepare(p, put(x, bytes), bytes.length));
    assert.equal(v.status, 0);
    assert(v.value > 0);
    return v.value;
}
function call(x, p, v) {
    const r = lane(x.pg_call(p, v));
    assert.equal(r.status, 0);
    assert(r.value > 0);
    return r.value;
}
const lastExport = new WeakMap();
function exported(x, r, expected = ordinaryResult) {
    const size = lane(x.pg_export(r, 0, 0));
    assert.equal(size.status, 12);
    assert.equal(size.value, expected.length);
    const p = x.pg_scratch_pointer();
    assert.deepEqual(lane(x.pg_export(r, p, size.value)), { status: 0, value: size.value });
    const copy = Buffer.from(new Uint8Array(x.memory.buffer, p, size.value));
    assert.deepEqual(copy, expected, 'exact committed carrier');
    lastExport.set(x, copy.toString('hex'));
    return copy;
}
function closeResult(x, p, r) {
    assert.equal(x.pg_result_release(r), 0);
    assert.equal(x.pg_close(p), 0);
    zero(x);
}
function observation(x) {
    const n = field => Number(x.pg_observe(field));
    const releases = Array.from({ length: n(7) }, (_, i) => {
        const v = BigInt.asUintN(64, x.pg_release_observation(i));
        return [Number(v >> 32n), Number(v & 0xffffffffn)];
    });
    return { endpoint_invoked: n(3), peak_alloc: n(4), peak_bytes: n(5), peak_handles: n(6),
        live_alloc: n(0), live_bytes: n(1), live_handles: n(2), allocator_live: n(10), allocator_bytes: n(11),
        release_order: releases, secondary_cleanup: Array.from({ length: n(8) }, (_, i) => x.pg_cleanup_observation(i)),
        overwrite: n(13), trace: Array.from({ length: n(9) }, (_, i) => x.pg_trace(i)) };
}
const output = { selectors: [], raw: [], host: [] };
if (mode === 'suite') {
    const selectors = input.stress ? 14 : 13;
    for (let selector = 0; selector < selectors; ++selector) {
        const x = await instance();
        try {
            assert.equal(x.pg_run(selector), 0, `in-module selector ${selector}`);
        }
        catch (e) {
            e.message += '\n' + log(x);
            throw e;
        }
        assert.equal(x.pg_heap_live(), 0);
        assert.equal(x.pg_heap_bytes(), 0);
        output.selectors.push({ selector, receipt: log(x) });
    }
}
if (mode === 'suite' || mode === 'raw') {
    const x = await instance();
    for (const c of input.cases) {
        assert.equal(x.pg_reset_observations(), 0);
        const p = trusted(x), bytes = Buffer.from(c.carrier_hex, 'hex');
        for (const label of c.injections)
            assert.equal(x.pg_inject(label), 0);
        let v = lane(x.pg_prepare(p, put(x, bytes), bytes.length));
        let result = { status: v.status, value: 0 };
        if (v.status === 0) {
            // Change ALL ingress bytes after copy-in: execution must use the
            // independently allocated private input, not retained host storage.
            new Uint8Array(x.memory.buffer).fill(0xa5, x.pg_scratch_pointer(), x.pg_scratch_pointer() + bytes.length);
            for (const label of c.injections)
                assert.equal(x.pg_inject(label), 0);
            result = lane(x.pg_call(p, v.value));
        }
        assert.equal(result.status, c.expected_status, `raw ${c.case_id} status`);
        let resultHex = null;
        if (result.status === 0) {
            const expected = Buffer.from(c.result_hex, 'hex');
            const size = lane(x.pg_export(result.value, 0, 0));
            assert.equal(size.status, 12);
            const scratch = x.pg_scratch_pointer();
            new Uint8Array(x.memory.buffer).fill(0xa5, scratch, scratch + size.value);
            assert.deepEqual(lane(x.pg_export(result.value, scratch, size.value - 1)), { status: 12, value: size.value });
            assert(new Uint8Array(x.memory.buffer, scratch, size.value).every(b => b === 0xa5), 'short export is non-writing');
            resultHex = exported(x, result.value, expected).toString('hex');
            assert.equal(x.pg_result_release(result.value), 0);
            assert.equal(x.pg_result_release(0), 0);
            assert.equal(x.pg_result_release(result.value), 8);
        }
        else
            assert.equal(result.value, 0, 'no partial result handle');
        assert.equal(x.pg_close(p), 0);
        zero(x);
        output.raw.push({ case_id: c.case_id, status: result.status, result_hex: resultHex, ...observation(x) });
    }
}
const host = async (name, action) => {
    if (mode.startsWith('host:') && mode.slice(5) !== name)
        return;
    const x = await instance();
    assert.equal(x.pg_reset_observations(), 0);
    let checked;
    try {
        checked = action(x);
        zero(x);
    }
    catch (error) {
        throw new Error(`HOST ${name}: ${error.message}`, { cause: error });
    }
    assert(Array.isArray(checked) && checked.every(Number.isSafeInteger), 'explicit observed statuses');
    output.host.push({ case_id: name, statuses: checked, result_hex: lastExport.get(x) ?? null, ...observation(x) });
};
if (mode === 'suite' || mode.startsWith('host:') || mode === 'host') {
    await host('open_out_of_memory_range', x => {
        const r = lane(x.pg_open(0xfffffff0, 32, 0, 0));
        assert.equal(r.status, 256);
        return [r.status];
    });
    await host('open_private_memory_range', x => {
        const r = lane(x.pg_open(8, descriptor.length, 0, 0));
        assert.equal(r.status, 256);
        return [r.status];
    });
    await host('open_overbound_precedence', x => {
        const r = lane(x.pg_open(0xffffffff, 65537, 0, 0));
        assert.equal(r.status, 6);
        return [r.status];
    });
    await host('descriptor_mismatch', x => {
        const d = Buffer.from(descriptor);
        d[d.length - 1] ^= 1;
        const r = open(x, d);
        assert.equal(r.status, 2);
        return [r.status];
    });
    await host('binding_mismatch', x => {
        const b = Buffer.from(binding);
        b[b.length - 1] ^= 1;
        const r = open(x, descriptor, b);
        assert.equal(r.status, 4);
        return [r.status];
    });
    await host('missing_descriptor', x => {
        const p = put(x, binding);
        const r = lane(x.pg_open(0, 0, p, binding.length));
        assert.equal(r.status, 13);
        return [r.status];
    });
    await host('prepare_overflow_range', x => {
        const p = trusted(x);
        const r = lane(x.pg_prepare(p, 0xfffffff8, 32));
        assert.equal(r.status, 256);
        assert.equal(x.pg_close(p), 0);
        return [r.status];
    });
    await host('prepare_private_memory', x => {
        const p = trusted(x);
        const r = lane(x.pg_prepare(p, 8, ordinary.length));
        assert.equal(r.status, 256);
        assert.equal(x.pg_close(p), 0);
        return [r.status];
    });
    await host('prepare_scratch_end_plus_one', x => {
        const p = trusted(x);
        const r = lane(x.pg_prepare(p, x.pg_scratch_pointer() + x.pg_scratch_capacity(), 1));
        assert.equal(r.status, 256);
        assert.equal(x.pg_close(p), 0);
        return [r.status];
    });
    await host('prepare_total_bound_plus_one', x => {
        const p = trusted(x);
        const r = lane(x.pg_prepare(p, x.pg_scratch_pointer(), FRAME_MAX + 1));
        assert.equal(r.status, 6);
        assert.equal(x.pg_close(p), 0);
        return [r.status];
    });
    await host('prepare_invalid_u32_length', x => {
        const p = trusted(x);
        const r = lane(x.pg_prepare(p, 0, 0xffffffff));
        assert.equal(r.status, 6);
        assert.equal(x.pg_close(p), 0);
        return [r.status];
    });
    await host('trailing_input', x => {
        const p = trusted(x), b = Buffer.concat([ordinary, Buffer.from([0])]);
        const r = lane(x.pg_prepare(p, put(x, b), b.length));
        assert.equal(r.status, 5);
        assert.equal(x.pg_close(p), 0);
        return [r.status];
    });
    await host('truncated_input', x => {
        const p = trusted(x);
        const r = lane(x.pg_prepare(p, put(x, ordinary), ordinary.length - 1));
        assert.equal(r.status, 5);
        assert.equal(x.pg_close(p), 0);
        return [r.status];
    });
    await host('unknown_handles', x => {
        const r = lane(x.pg_call(0xffffffff, 0xffffffff));
        assert.equal(r.status, 8);
        const s = x.pg_result_release(0xffffffff);
        assert.equal(s, 8);
        return [r.status, s];
    });
    await host('wrong_provider_preserves_input', x => {
        const p = trusted(x), q = trusted(x), v = prepare(x, p);
        const r = lane(x.pg_call(q, v));
        assert.equal(r.status, 8);
        const good = call(x, p, v);
        exported(x, good);
        assert.equal(x.pg_close(q), 0);
        closeResult(x, p, good);
        return [r.status, 0];
    });
    await host('input_used_as_result', x => {
        const p = trusted(x), v = prepare(x, p);
        const r = lane(x.pg_export(v, 0, 0));
        assert.equal(r.status, 8);
        assert.equal(x.pg_input_release(v), 0);
        assert.equal(x.pg_close(p), 0);
        return [r.status];
    });
    await host('close_with_live_input', x => {
        const p = trusted(x), v = prepare(x, p);
        const status = x.pg_close(p);
        assert.equal(status, 7);
        assert.equal(x.pg_input_release(v), 0);
        assert.equal(x.pg_close(p), 0);
        return [status];
    });
    await host('stale_input_after_new_prepare', x => {
        const p = trusted(x), old = prepare(x, p);
        assert.equal(x.pg_input_release(old), 0);
        const v = prepare(x, p);
        assert.notEqual(v, old);
        const r = lane(x.pg_call(p, old));
        assert.equal(r.status, 8);
        const good = call(x, p, v);
        exported(x, good);
        closeResult(x, p, good);
        return [r.status, 0];
    });
    await host('stale_child_after_recreation', x => {
        const p = trusted(x), v = prepare(x, p);
        assert.equal(x.pg_input_release(v), 0);
        assert.equal(x.pg_close(p), 0);
        const q = trusted(x);
        const r = lane(x.pg_call(q, v));
        assert.equal(r.status, 8);
        assert.equal(x.pg_close(q), 0);
        return [r.status];
    });
    await host('consumed_input_cannot_execute_twice', x => {
        const p = trusted(x), v = prepare(x, p), r = call(x, p, v);
        const bad = lane(x.pg_call(p, v));
        assert.equal(bad.status, 8);
        assert.equal(x.pg_observe(3), 1n);
        exported(x, r);
        closeResult(x, p, r);
        return [bad.status];
    });
    await host('result_wrong_kind_release', x => {
        const p = trusted(x), r = call(x, p, prepare(x, p));
        const status = x.pg_input_release(r);
        assert.equal(status, 7);
        exported(x, r);
        closeResult(x, p, r);
        return [status];
    });
    await host('result_export_bad_ranges', x => {
        const p = trusted(x), r = call(x, p, prepare(x, p));
        const a = lane(x.pg_export(r, 0xfffffff0, 32)), b = lane(x.pg_export(r, 8, 32)), c = lane(x.pg_export(r, x.pg_scratch_pointer() + x.pg_scratch_capacity(), 1));
        assert.deepEqual([a.status, b.status, c.status], [256, 256, 256]);
        exported(x, r);
        closeResult(x, p, r);
        return [a.status, b.status, c.status];
    });
    await host('result_export_overbound', x => {
        const p = trusted(x), r = call(x, p, prepare(x, p));
        const bad = lane(x.pg_export(r, 0, 0xffffffff));
        assert.equal(bad.status, 6);
        exported(x, r);
        closeResult(x, p, r);
        return [bad.status];
    });
    await host('memory_growth_reacquires_views', x => {
        const p = trusted(x), v = prepare(x, p);
        const old = new Uint8Array(x.memory.buffer);
        x.memory.grow(1);
        assert.equal(old.byteLength, 0);
        const r = call(x, p, v);
        x.memory.grow(1);
        exported(x, r);
        closeResult(x, p, r);
        return [0];
    });
    await host('ingress_mutation_is_not_owned_alias', x => {
        const p = trusted(x), v = prepare(x, p);
        new Uint8Array(x.memory.buffer).fill(0, x.pg_scratch_pointer(), x.pg_scratch_pointer() + ordinary.length);
        const r = call(x, p, v);
        exported(x, r);
        closeResult(x, p, r);
        return [0];
    });
    await host('export_copy_remains_independent', x => {
        const p = trusted(x), r = call(x, p, prepare(x, p));
        const copy = exported(x, r);
        new Uint8Array(x.memory.buffer).fill(0, x.pg_scratch_pointer(), x.pg_scratch_pointer() + copy.length);
        assert.deepEqual(copy, ordinaryResult);
        exported(x, r);
        closeResult(x, p, r);
        return [0];
    });
    await host('export_failure_retry_no_reexecution', x => {
        const p = trusted(x), r = call(x, p, prepare(x, p)), s = x.pg_scratch_pointer();
        new Uint8Array(x.memory.buffer).fill(0xa5, s, s + ordinaryResult.length);
        assert.equal(x.pg_phase_inject(6, 1, 1), 0);
        const bad = lane(x.pg_export(r, s, ordinaryResult.length));
        assert.equal(bad.status, 11);
        assert(new Uint8Array(x.memory.buffer, s, ordinaryResult.length).every(n => n === 0xa5), 'failed export remains atomic');
        exported(x, r);
        assert.equal(x.pg_observe(3), 1n);
        closeResult(x, p, r);
        return [bad.status, 0];
    });
    await host('result_release_failure_still_settles', x => {
        const p = trusted(x), r = call(x, p, prepare(x, p));
        assert.equal(x.pg_phase_inject(7, 1, 1), 0);
        const status = x.pg_result_release(r);
        assert.equal(status, 11, "explicit release status");
        assert.equal(x.pg_result_release(r), 8);
        assert.equal(x.pg_close(p), 0);
        return [status, 8];
    });
    await host('result_staging_failure_no_handle', x => {
        const p = trusted(x), v = prepare(x, p);
        assert.equal(x.pg_phase_inject(0, 1, 1), 0);
        const r = lane(x.pg_call(p, v));
        assert.deepEqual(r, { status: 10, value: 0 });
        assert.equal(x.pg_close(p), 0);
        return [r.status];
    });
    await host('result_failure_plus_cleanup_sticky', x => {
        const p = trusted(x), v = prepare(x, p);
        assert.equal(x.pg_phase_inject(0, 1, 1), 0);
        assert.equal(x.pg_phase_inject(7, 1, 0), 0);
        const r = lane(x.pg_call(p, v));
        assert.equal(r.status, 10, "sticky primary status");
        assert.equal(x.pg_cleanup_observation(0), 11);
        assert.equal(x.pg_close(p), 0);
        return [r.status, 11];
    });
    await host('observation_reset_cannot_hide_live_owner', x => {
        const p = trusted(x);
        const status = x.pg_reset_observations();
        assert.equal(status, 258);
        assert.equal(x.pg_close(p), 0);
        return [status];
    });
    await host('invalid_injection_option', x => {
        const a = x.pg_inject(14), b = x.pg_phase_inject(8, 0, 0);
        assert.deepEqual([a, b], [257, 257]);
        return [a, b];
    });
    await host('test_selector_is_closed', x => {
        const status = x.pg_run(14);
        assert.equal(status, 257);
        return [status];
    });
    await host('memory_growth_bound_refuses', x => {
        assert.throws(() => x.memory.grow(1025), RangeError);
        const p = trusted(x), r = call(x, p, prepare(x, p));
        exported(x, r);
        closeResult(x, p, r);
        return [0];
    });
}
assert(output.selectors.length + output.raw.length + output.host.length > 0, 'requested selector executed');
process.stdout.write(JSON.stringify(output) + '\n');
