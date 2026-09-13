import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const module = new WebAssembly.Module(readFileSync(process.argv[2]));
const provider = environmentProvider(module);
assert.deepEqual(
  WebAssembly.Module.imports(module).map(item => item.name).sort(),
  ['spx_add', 'spx_sub', 'spx_mul', 'spx_div', 'spx_rem', 'spx_neg',
    'spx_contract_fail', 'spx_bytes_copy', 'spx_bytes_get', 'spx_bytes_drop',
    'spx_bytes_as_slice', 'spx_bytes_zeroed', 'spx_bytes_set'].sort(),
);
const min = -(1n << 63n);
const max = (1n << 63n) - 1n;
const checked = operation => (...args) => {
  const value = operation(...args);
  if (value < min || value > max) throw new RangeError('checked i64 overflow');
  return value;
};
const div = (left, right) => {
  if (right === 0n || (left === min && right === -1n)) throw new RangeError('checked i64 division');
  return left / right;
};
const rem = (left, right) => {
  if (right === 0n || (left === min && right === -1n)) throw new RangeError('checked i64 remainder');
  return left % right;
};
Object.assign(provider.imports.env, {
  spx_add: checked((left, right) => left + right),
  spx_sub: checked((left, right) => left - right),
  spx_mul: checked((left, right) => left * right),
  spx_neg: checked(value => -value),
  spx_div: div,
  spx_rem: rem,
});
const incomplete = { env: { ...provider.imports.env } };
delete incomplete.env.spx_bytes_set;
assert.throws(() => new WebAssembly.Instance(module, incomplete), WebAssembly.LinkError);
const instance = new WebAssembly.Instance(module, provider.imports);
provider.attach(instance);
for (let run = 0; run < 2; run += 1) {
  assert.equal(instance.exports.semaprax_main(), 0n);
  provider.settled();
}
