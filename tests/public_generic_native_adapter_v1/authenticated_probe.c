#ifdef __cplusplus
extern "C" {
#endif
size_t auth_allocations(void);
size_t auth_live(void);
size_t auth_calls(void);
#ifdef __cplusplus
}
#endif
static void refused(spx_pg_provider_v1 *provider, uint64_t generation, uint32_t ownership,
    const uint8_t *plan, size_t plan_len, const uint8_t *frame, size_t len, int expected) {
    size_t allocations=auth_allocations(), calls=auth_calls(), live=auth_live();
    spx_pg_value_v1 *input=NULL;
    assert(spx_pg_authenticated_input_prepare_v1(provider,generation,ownership,plan,plan_len,frame,len,&input)==expected);
    assert(input==NULL);
    assert(auth_allocations()==allocations && auth_calls()==calls && auth_live()==live);
    assert(spx_pg_test_live_handles_v1(provider)==0);
}
int main(void) {
    spx_pg_provider_v1 *provider=NULL;
    assert(spx_pg_provider_open_v1(descriptor,sizeof(descriptor),binding,sizeof(binding),&provider)==0);
    uint64_t generation=0;
    assert(spx_pg_authenticated_generation_v1(provider,&generation)==0 && generation!=0);
    refused(provider,generation+1,0,cleanup,sizeof(cleanup),canonical,sizeof(canonical),8);
    refused(provider,generation,1,cleanup,sizeof(cleanup),canonical,sizeof(canonical),7);
    refused(provider,generation,0,descriptor,sizeof(descriptor),canonical,sizeof(canonical),14);
    refused(provider,generation,0,cleanup,sizeof(cleanup),wrong_path,sizeof(wrong_path),14);
    refused(provider,generation,0,cleanup,sizeof(cleanup),unknown_direction,sizeof(unknown_direction),5);
    refused(provider,generation,0,cleanup,sizeof(cleanup),duplicate_path,sizeof(duplicate_path),5);
    refused(provider,generation,0,cleanup,sizeof(cleanup),invalid_utf8,sizeof(invalid_utf8),5);
    refused(provider,generation,0,cleanup,sizeof(cleanup),oversized_metadata,sizeof(oversized_metadata),5);
    refused(provider,generation,0,cleanup,sizeof(cleanup),wrong_tag,sizeof(wrong_tag),5);
    refused(provider,generation,0,cleanup,sizeof(cleanup),corrupt,sizeof(corrupt),14);
    refused(provider,generation,0,cleanup,sizeof(cleanup),oversized,sizeof(oversized),6);
    for (size_t n=0;n<sizeof(canonical);++n) {
        refused(provider,generation,0,cleanup,sizeof(cleanup),canonical,n,5);
    }
    uint8_t flat[30]={2,0,0,0,0,0,0,0,3,0,0,0,0,0,0,0,1,7,13,3,0,0,0,0,0,0,0,2,7,13};
    refused(provider,generation,0,cleanup,sizeof(cleanup),flat,sizeof(flat),5);
    size_t allocations=auth_allocations();
    spx_pg_value_v1 *input=NULL;
    assert(spx_pg_input_prepare_v1(provider,flat,sizeof(flat),&input)==5);
    assert(input==NULL && auth_allocations()==allocations && auth_calls()==0);
    assert(spx_pg_authenticated_input_prepare_v1(provider,generation,0,cleanup,sizeof(cleanup),canonical,sizeof(canonical),&input)==0);
    assert(input!=NULL && auth_calls()==0);
    spx_pg_result_v1 *result=NULL;
    assert(spx_pg_call_v1(provider,input,&result)==EXPECT_CALL_STATUS);
    assert(auth_calls()==1);
    spx_pg_result_v1 *duplicate=NULL;
    assert(spx_pg_call_v1(provider,input,&duplicate)==8);
    assert(auth_calls()==1);
    if (EXPECT_CALL_STATUS==0) {
        uint8_t out[30]; size_t required=0;
        assert(result!=NULL);
        assert(spx_pg_result_export_v1(result,out,sizeof(out),&required)==0);
        assert(required==sizeof(flat) && memcmp(out,flat,sizeof(flat))==0);
        assert(spx_pg_result_release_v1(&result)==0);
    }
    assert(result==NULL);
    refused(provider,generation,0,cleanup,sizeof(cleanup),canonical,sizeof(canonical),8);
    assert(spx_pg_provider_close_v1(&provider)==0);
    assert(auth_live()==0);
    puts("authenticated-native-handoff-settled");
    return 0;
}
