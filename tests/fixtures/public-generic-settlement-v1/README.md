# Shared settlement fixtures

See [Settlement Corpus v1](../../../docs/PUBLIC-GENERIC-SETTLEMENT-CORPUS-V1.md).

`cases.json` is the canonical shared manifest; `native-expectations.json` pins
native observations against its exact digest. These files are not regenerated
by the test gate. `descriptor.txt` is an exact-byte fixture (intentionally no
trailing newline), not a compiler-verified generic descriptor.

Do not describe the Core-Wasm model as a compiled provider, or these flat owned
byte leaves as nested generic/scalar coverage. Public ownership remains
unsupported and unpublished.
