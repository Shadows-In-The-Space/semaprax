import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Provider, SemapraxPublicGenericException } from '../dist/index.js';
import { TRUSTED_DESCRIPTOR_BYTES, TRUSTED_BINDING_BYTES } from '../dist/descriptor.js';
const [guard, names, payloads] = JSON.parse(readFileSync('test/subject.json', 'utf8'));
const wasm = readFileSync(process.argv[2]);
const originalInstantiate = WebAssembly.instantiate;
const observed = { instances: 0, calls: 0, valueReleases: 0, resultReleases: 0, closes: 0 };
// Transparent observation only: each invocation reaches the original export
// exactly once and returns its unchanged result. No adapter/codec is replaced.
WebAssembly.instantiate = async (...args) => {
    observed.instances += 1;
    const instance = await Reflect.apply(originalInstantiate, WebAssembly, args);
    const measured = { spx_pg_v1_call: 'calls', spx_pg_v1_value_release: 'valueReleases', spx_pg_v1_result_release: 'resultReleases', spx_pg_v1_provider_close: 'closes' };
    return { exports: new Proxy({}, {
        get(_target, property) {
            const original = Reflect.get(instance.exports, property);
            if (!Object.hasOwn(measured, property)) return original;
            return (...parameters) => {
                observed[measured[property]] += 1;
                const result = Reflect.apply(original, instance.exports, parameters);
                if (property !== 'spx_pg_v1_call') assert.equal(result, 0, 'real physical settlement must succeed');
                return result;
            };
        },
    }) };
};
try {
    const descriptor = TRUSTED_DESCRIPTOR_BYTES.slice(); descriptor[0] ^= 1;
    const binding = TRUSTED_BINDING_BYTES.slice(); binding[binding.length - 1] ^= 1;
    const changedModule = Uint8Array.from(wasm); changedModule[changedModule.length - 1] ^= 1;
    for (const [bytes, options, kind] of [
        [wasm, { descriptorBytes: descriptor }, 'descriptor-rejected'],
        [wasm, { bindingBytes: binding }, 'provider-mismatch'],
        [changedModule, {}, 'provider-mismatch'],
    ]) {
        await assert.rejects(() => Provider.open(bytes, options), error => error instanceof SemapraxPublicGenericException && error.detail.kind === kind);
        assert.deepEqual(observed, { instances: 0, calls: 0, valueReleases: 0, resultReleases: 0, closes: 0 }, 'hostile bytes must be refused before instantiation');
    }
    const provider = await Provider.open(wasm);
    const input = Object.fromEntries(names.map((name, index) => [name, Uint8Array.from(payloads[index])]));
    let output = [];
    if (guard) {
        const result = provider.transform(input);
        output = names.map(name => Array.from(result[name]));
        assert.deepEqual(output, payloads);
    } else {
        assert.throws(() => provider.transform(input), error => error instanceof SemapraxPublicGenericException && error.detail.kind === 'execution-failed' && error.detail.status === 11);
    }
    assert.deepEqual(names.map(name => Array.from(input[name])), payloads, 'host inputs remain snapshots, not transferred host arrays');
    provider.close();
    provider.close();
    assert.deepEqual(observed, { instances: 1, calls: 1, valueReleases: guard ? 0 : 1, resultReleases: guard ? 1 : 0, closes: 1 });
    console.error(`generated TypeScript requires=${guard}: three pre-instantiation refusals; one actual call; value releases=${observed.valueReleases}; result releases=${observed.resultReleases}; close once`);
    process.stdout.write(JSON.stringify([guard ? 0 : 11, output]));
} finally {
    WebAssembly.instantiate = originalInstantiate;
}
