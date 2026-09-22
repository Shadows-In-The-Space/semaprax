/* No allocation or physical observation occurs until the entire canonical
 * frame and its descriptor-derived plan have been checked. Fixed stack tables
 * retain only bounded slices, never ownership or caller-provided authority. */
static spx_pg_status_v1 spx_pg_auth_field(const uint8_t *p, size_t n, size_t *at,
    const uint8_t **value, size_t *length) {
    if (*at > n || n - *at < 8) return SPX_PG_STATUS_MALFORMED_CARRIER;
    uint64_t size = spx_pg_read_u64le(p + *at); *at += 8;
    if (size > 65536) return SPX_PG_STATUS_CARRIER_CAPACITY;
    if (size > n - *at) return SPX_PG_STATUS_MALFORMED_CARRIER;
    *value = p + *at; *length = (size_t)size; *at += (size_t)size;
    return SPX_PG_STATUS_OK;
}
/* Match Rust str::from_utf8: reject incomplete/overlong sequences, surrogate
 * code points and values beyond U+10FFFF before semantic binding checks. */
static int spx_pg_auth_utf8(const uint8_t *p, size_t n) {
    size_t at=0;
    while (at<n) {
        uint8_t first=p[at++];
        if (first<0x80) continue;
        unsigned remaining;
        uint32_t scalar, minimum;
        if (first>=0xc2 && first<=0xdf) { remaining=1; scalar=first&0x1f; minimum=0x80; }
        else if (first>=0xe0 && first<=0xef) { remaining=2; scalar=first&0x0f; minimum=0x800; }
        else if (first>=0xf0 && first<=0xf4) { remaining=3; scalar=first&0x07; minimum=0x10000; }
        else return 0;
        if (remaining>n-at) return 0;
        while (remaining--) {
            uint8_t next=p[at++];
            if ((next&0xc0)!=0x80) return 0;
            scalar=(scalar<<6)|(next&0x3f);
        }
        if (scalar<minimum || scalar>0x10ffff || (scalar>=0xd800 && scalar<=0xdfff)) return 0;
    }
    return 1;
}
static spx_pg_status_v1 spx_pg_auth_frame(const uint8_t *p, size_t n,
    const uint8_t **payloads, size_t *lengths, size_t *flat_size) {
    if (n > (size_t)20*1024*1024) return SPX_PG_STATUS_CARRIER_CAPACITY;
    size_t at=0, trusted=0, len=0, expected_len=0;
    const uint8_t *value, *expected;
    int binding_mismatch=0;
    for (unsigned field=0; field<6; ++field) {
        spx_pg_status_v1 status = spx_pg_auth_field(p,n,&at,&value,&len);
        if (status) return status;
        if (!spx_pg_auth_utf8(value,len)) return SPX_PG_STATUS_MALFORMED_CARRIER;
        if (field==1 && !spx_pg_bytes_equal(value,len,(const uint8_t *)"input",5)
            && !spx_pg_bytes_equal(value,len,(const uint8_t *)"result",6))
            return SPX_PG_STATUS_MALFORMED_CARRIER;
        status = spx_pg_auth_field(SPX_PG_AUTH_EMPTY_FRAME,SPX_PG_AUTH_EMPTY_FRAME_LEN,&trusted,&expected,&expected_len);
        if (status) return status;
        if (!spx_pg_bytes_equal(value,len,expected,expected_len)) {
            if (field==0) return SPX_PG_STATUS_MALFORMED_CARRIER;
            binding_mismatch=1;
        }
    }
    if (n-at < 16) return SPX_PG_STATUS_MALFORMED_CARRIER;
    uint64_t count=spx_pg_read_u64le(p+at), total=spx_pg_read_u64le(p+at+8); at+=16; trusted+=16;
    if (count>256 || total>SPX_PG_MAX_TOTAL_PAYLOAD_BYTES) return SPX_PG_STATUS_CARRIER_CAPACITY;
    if (count!=SPX_PG_AUTH_LEAF_COUNT) binding_mismatch=1;
    const uint8_t *paths[256]; size_t path_lengths[256];
    size_t sum=0;
    for (size_t leaf=0; leaf<(size_t)count; ++leaf) {
        spx_pg_status_v1 status = spx_pg_auth_field(p,n,&at,&value,&len);
        if (status) return status;
        if (!spx_pg_auth_utf8(value,len)) return SPX_PG_STATUS_MALFORMED_CARRIER;
        for (size_t previous=0; previous<leaf; ++previous) {
            if (spx_pg_bytes_equal(value,len,paths[previous],path_lengths[previous]))
                return SPX_PG_STATUS_MALFORMED_CARRIER;
        }
        paths[leaf]=value; path_lengths[leaf]=len;
        if (leaf<SPX_PG_AUTH_LEAF_COUNT) {
            status=spx_pg_auth_field(SPX_PG_AUTH_EMPTY_FRAME,SPX_PG_AUTH_EMPTY_FRAME_LEN,&trusted,&expected,&expected_len);
            if (status) return status;
            if (!spx_pg_bytes_equal(value,len,expected,expected_len)) binding_mismatch=1;
            trusted+=9; /* trusted Bytes tag and empty payload's length */
        }
        if (at==n || p[at++]!=0) return SPX_PG_STATUS_MALFORMED_CARRIER;
        status=spx_pg_auth_field(p,n,&at,&payloads[leaf],&lengths[leaf]);
        if (status) return status;
        sum+=lengths[leaf];
    }
    if (sum != total) return SPX_PG_STATUS_MALFORMED_CARRIER;
    size_t preimage=at;
    spx_pg_status_v1 status=spx_pg_auth_field(p,n,&at,&value,&len);
    if (status) return status;
    if (!spx_pg_auth_utf8(value,len)) return SPX_PG_STATUS_MALFORMED_CARRIER;
    if (at != n) return SPX_PG_STATUS_MALFORMED_CARRIER;
    uint8_t digest[71]; spx_pg_frame_digest(p,preimage,digest);
    if (!spx_pg_bytes_equal(value,len,digest,sizeof(digest))) return SPX_PG_AUTH_STATUS_REPLAY_MISMATCH;
    /* The shared codec parses all structural facts and checks its digest
     * before CarrierFrameBinding can refuse semantic identity/path claims. */
    if (binding_mismatch) return SPX_PG_AUTH_STATUS_REPLAY_MISMATCH;
    *flat_size=8+8*(size_t)count+sum;
    return SPX_PG_STATUS_OK;
}
static uint64_t spx_pg_auth_generation(size_t slot) {
    /* Identity array positions never recycle. Distinct providers cannot share
     * ticket generations, including after close/reopen. */
    size_t identity=((const unsigned char *)g_spx_pg_providers[slot].identity
        -(const unsigned char *)g_spx_pg_identities)/sizeof(g_spx_pg_identities[0]);
    return ((uint64_t)(identity+1)<<32) | g_spx_pg_providers[slot].object->next_generation;
}
spx_pg_status_v1 spx_pg_authenticated_generation_v1(spx_pg_provider_v1 *provider, uint64_t *out) {
    spx_pg_status_v1 status=spx_pg_enter(); if (status) return status;
    size_t slot=spx_pg_provider_find(provider);
    if (!out) status=SPX_PG_STATUS_NULL_OR_WRONG_KIND;
    else if (slot==SPX_PG_REGISTRY_CAPACITY) status=SPX_PG_STATUS_HANDLE_INVALID;
    else *out=spx_pg_auth_generation(slot);
    spx_pg_leave(); return status;
}
spx_pg_status_v1 spx_pg_authenticated_input_prepare_v1(spx_pg_provider_v1 *provider,
    uint64_t generation, uint32_t ownership, const uint8_t *cleanup, size_t cleanup_len,
    const uint8_t *frame, size_t frame_len, spx_pg_value_v1 **out_input) {
    spx_pg_status_v1 status=spx_pg_enter(); if (status) return status;
    if (!out_input) { spx_pg_leave(); return SPX_PG_STATUS_NULL_OR_WRONG_KIND; }
    *out_input=NULL;
    size_t slot=spx_pg_provider_find(provider);
    spx_pg_reset_call_state();
    const uint8_t *payloads[256]; size_t lengths[256], flat_size=0;
    if (slot==SPX_PG_REGISTRY_CAPACITY) status=SPX_PG_STATUS_HANDLE_INVALID;
    else if (generation!=spx_pg_auth_generation(slot)) status=SPX_PG_STATUS_HANDLE_INVALID;
    else if (ownership!=SPX_PG_AUTH_OWNERSHIP_CALLER) status=SPX_PG_STATUS_ILLEGAL_TRANSITION;
    else if ((!cleanup && cleanup_len) || (!frame && frame_len)) status=SPX_PG_STATUS_NULL_OR_WRONG_KIND;
    else if (!spx_pg_bytes_equal(cleanup,cleanup_len,SPX_PG_AUTH_CLEANUP,SPX_PG_AUTH_CLEANUP_LEN)) status=SPX_PG_AUTH_STATUS_REPLAY_MISMATCH;
    else status=spx_pg_auth_frame(frame,frame_len,payloads,lengths,&flat_size);
    if (!status && g_spx_pg_providers[slot].object->next_generation==UINT32_MAX) status=SPX_PG_STATUS_CARRIER_CAPACITY;
    if (status) { status=spx_pg_settle(status); spx_pg_leave(); return status; }
    ++g_spx_pg_providers[slot].object->next_generation;
    uint8_t *flat=(uint8_t *)spx_pg_alloc(flat_size);
    if (!flat) { status=spx_pg_settle(SPX_PG_STATUS_ALLOCATION_FAILURE); spx_pg_leave(); return status; }
    spx_pg_write_u64le(flat,SPX_PG_AUTH_LEAF_COUNT); size_t at=8;
    for (size_t i=0; i<SPX_PG_AUTH_LEAF_COUNT; ++i) {
        spx_pg_write_u64le(flat+at,lengths[i]); at+=8;
        if (lengths[i]) memcpy(flat+at,payloads[i],lengths[i]); at+=lengths[i];
    }
    status=spx_pg_input_prepare_v1_impl(provider,flat,flat_size,out_input);
    spx_pg_dealloc(flat,flat_size);
    spx_pg_leave(); return status;
}
