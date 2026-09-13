# Authentication host v1

Status: private Rust embedding profile for password hashing and session service; local evidence, no network or production deployment claim.
Audience: host integrators and compiler contributors implementing authenticated embedding.

This Rust embedding profile adds actual password hashing and authenticated
sessions alongside the pure `std.auth` predicates specified in
[Authentication and Sessions v1](AUTHENTICATION-SESSIONS-V1.md).
It adds no source-language operation or ambient compiler authority.

The host explicitly supplies entropy, signing key, clock ticks and storage.
`SecretBytes` has redacted debug output, no serialization or clone traits,
and zeroizes owned storage on drop. This does not erase caller-owned copies.
Errors are closed tags and carry no credential or bearer-token contents.

Reference in-memory stores provide bounded process-local storage; they do
not claim database durability, distributed transactions, HTTP middleware,
rate limiting, or production deployment support.

## Signed session service

`authentication::session` provides a host-owned session flow with explicit
entropy, signing key, clock tick, and `SessionStore`. `SessionService` fixes
HS256 at construction. No bearer token selects an algorithm, key, issuer,
audience, or policy identity. `SessionPolicy` binds stable exact policy,
issuer, and audience strings and positive bounded TTLs.

The bearer value is a `semaprax-session-token.v1`, not a JWT: canonical fixed
binary claims and a fixed HMAC-SHA-256 tag are independently base64url-no-pad
encoded and separated by one dot. The authenticated claims carry the schema
magic/version, 32-byte session id, generation, issue and expiry ticks, and the
exact policy, issuer, audience, and subject strings. Parsing is bounded and
canonical; MAC verification uses `hmac`'s `verify_slice` before claims are
accepted. The tag includes a fixed domain separator. Verification rejects a
clock tick before issue time and rechecks the claimed lifetime against the
current server policy.

`SessionToken` owns redacted, zeroized bytes and exposes its value only through
`bearer()` for an explicitly selected transport boundary. It has no `Clone`,
`Debug`, or serialization implementation. `SecretBytes` likewise never exposes
the server signing key outside the authentication module.

`SessionStore` requires atomic `issue_if_absent`,
`compare_and_rotate`, and `compare_and_revoke` operations. Rotation retires the
presented record and creates a fresh random 32-byte id with an incremented
generation in one store operation; revocation and rotation refuse stale,
revoked, and generation-mismatched records. `InMemorySessionStore` is a capped
process-local reference implementation. It is neither a durable database nor a
distributed transaction implementation.

The service has no source-language operation, ambient clock, entropy, key,
filesystem, network, HTTP middleware, authorization policy, rate limit, or
production external-store implementation. A successful authentication result
returns only the subject and public issue/expiry/generation claims; it never
returns a bearer token or signing key.

## Password records

`authentication::password` is a native host service. It admits only RustCrypto
Argon2id version 19 records, gives the KDF a 16-byte host-supplied salt, and
stores a 32-byte output. A password input is at most 1,024 bytes and a PHC
record is at most 512 bytes.

The default policy is 19,456 KiB, two iterations, and parallelism one. The
only accepted resource envelope is 19,456--65,536 KiB, two--four iterations,
and parallelism one. A `PasswordHasherHost` creates hashes with its current
policy and verifies only that policy plus at most four explicit, bounded
migration policies.

`StoredPasswordHash::parse_for_storage` parses the entire PHC envelope before
any KDF work: its algorithm and version are fixed, parameter keys are closed,
salt and digest encodings are canonical and fixed-size, and all resource bounds
are checked. Its debug representation is redacted; storage adapters receive a
record only through `expose_for_storage`. Incorrect passwords and malformed
stored credentials are returned as closed `AuthError` tags. This host API does
not add a source-language secret type, password operation, or authority.


## Account and session composition

`service::AuthService` performs signup by hashing a supplied secret before an
atomic `AccountStore::insert_if_absent`; storage failure never issues a token.
Login verifies the actual stored hash before asking `SessionService` to issue
a token. `protected`, `rotate` and `logout` delegate authenticated session
validation and atomic session transitions. Account identifiers are bounded
ASCII identifiers (letters, digits, `.`, `_`, `-`, `@`), at most 128 bytes.
The reference account store holds at most 4096 entries under a lower explicit
host capacity. The host supplies transaction semantics for its own store.

`OsAuthEntropy` is an explicitly instantiated native capability. Tests inject
deterministic entropy; that fixture is not a deployment random generator.
Clock values are explicit host ticks and must use one consistent trusted clock.
Hosts must bound simultaneous KDF calls and apply login/signup rate limits.
Unknown accounts and wrong passwords share an error tag, but this profile does
not promise indistinguishable response timing or conceal signup conflicts.

The executable composition gate is
`authentication::service::tests::actual_signup_login_rotation_protected_logout`.
It performs real hashing, wrong-password rejection, login, protected access,
rotation, old-token refusal and logout. It is a Rust embedding test, not an
HTTP deployment or a source-language/backend conformance claim.
