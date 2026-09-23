/* Private, unsupported/unpublished additive profile:
 * semaprax.authenticated-native-identity.v1. The predecessor flat preparation
 * operation is disabled in this artifact; its wire bytes are never reinterpreted.
 * Other v1 lifecycle operations retain their explicit ownership rules.
 * Frame/ticket storage must remain immutable for the duration of prepare.
 * Reentrant and foreign-thread calls leave caller outputs unchanged. */
#ifndef SPX_PG_AUTHENTICATED_V1_H
#define SPX_PG_AUTHENTICATED_V1_H
#ifdef __cplusplus
extern "C" {
#endif
/* SPX-PG803, absent from the predecessor physical vocabulary. */
#define SPX_PG_AUTH_STATUS_REPLAY_MISMATCH 14
#define SPX_PG_AUTH_OWNERSHIP_CALLER 0u
#define SPX_PG_AUTH_OWNERSHIP_PROVIDER 1u
/* Provider-unique, non-recycled ticket generation. A successful admission
 * consumes this generation even if subsequent physical preparation fails. */
spx_pg_status_v1 spx_pg_authenticated_generation_v1(spx_pg_provider_v1 *, uint64_t *);
spx_pg_status_v1 spx_pg_authenticated_input_prepare_v1(spx_pg_provider_v1 *,
    uint64_t generation, uint32_t ownership, const uint8_t *cleanup_digest,
    size_t cleanup_digest_len, const uint8_t *frame, size_t frame_len,
    spx_pg_value_v1 **out_input);
#ifdef __cplusplus
}
#endif
#endif
