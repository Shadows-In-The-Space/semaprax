#include <assert.h>
#include <stdio.h>
size_t auth_live(void);
size_t auth_calls(void);
int main(void) {
    spx_pg_provider_v1 *provider=NULL;
    assert(spx_pg_provider_open_v1(descriptor,sizeof(descriptor),binding,sizeof(binding),&provider)==0);
    uint64_t generation=0;
    assert(spx_pg_authenticated_generation_v1(provider,&generation)==0 && generation!=0);
    spx_pg_value_v1 *input=NULL;
    assert(spx_pg_authenticated_input_prepare_v1(provider,generation,0,cleanup,sizeof(cleanup),canonical,sizeof(canonical),&input)==0);
    assert(input!=NULL && auth_calls()==0);
    spx_pg_result_v1 *result=NULL;
    if (spx_pg_call_v1(provider,input,&result)!=EXPECT_CALL_STATUS) {
        fputs("checked-status-divergence\n",stderr);
        return 42;
    }
    assert(auth_calls()==1);
    spx_pg_result_v1 *duplicate=NULL;
    assert(spx_pg_call_v1(provider,input,&duplicate)==8 && duplicate==NULL);
    assert(auth_calls()==1); /* Native consumes the input even on status 11. */
    uint8_t out[31]; size_t required=0;
    if (EXPECT_CALL_STATUS==0) {
        assert(result!=NULL);
        assert(spx_pg_result_export_v1(result,out,sizeof(out),&required)==0);
        assert(required==sizeof(out));
        assert(spx_pg_result_release_v1(&result)==0);
    }
    assert(result==NULL && spx_pg_test_live_handles_v1(provider)==0);
    assert(spx_pg_provider_close_v1(&provider)==0 && provider==NULL);
    assert(auth_live()==0);
    /* ASCII hex avoids platform stdout text-mode byte rewriting. */
    for (size_t i=0;i<required;++i) assert(printf("%02x",(unsigned)out[i])==2);
    return 0;
}
