//! Physical wrapper-boundary evidence, not a Kernel-0 ownership theorem or a
//! production target runtime. Existing scalar-target gates remain independent.
use super::*;
use crate::kernel_zero::rung_two_bootstrap::{run_target, with_target_scratch};
use std::process::Command;

fn run(command: &mut Command) -> Vec<u8> {
    let (success, stdout, stderr) = run_target(command).expect("bounded target process");
    assert!(success, "{}", String::from_utf8_lossy(&stderr));
    stdout
}

fn rows() -> Vec<Vec<u8>> {
    use crate::kernel_zero::{
        canonical_bool_renderer as boolean, canonical_char_renderer as character,
        canonical_int_renderer as integer, canonical_operator_renderer as operator,
        canonical_string_renderer as string,
    };
    let pairs = [
        (character::render(u32::from('\n')).unwrap(), "'\\n'"),
        (character::render(u32::from('A')).unwrap(), "'A'"),
        (boolean::render(true).unwrap(), "true"),
        (boolean::render(false).unwrap(), "false"),
        (integer::render(i64::MIN).unwrap(), "-9223372036854775808"),
        (integer::render(123456789).unwrap(), "123456789"),
        (
            operator::render_binary(crate::ast::BinaryOp::Ne).unwrap(),
            "!=",
        ),
        (
            operator::render_unary(crate::ast::UnaryOp::Neg).unwrap(),
            "-",
        ),
        (string::render(u32::from('🦀')).unwrap(), "🦀"),
        (string::render(u32::from('\n')).unwrap(), "\\n"),
    ];
    let mut rows = vec![Vec::new(), vec![0], vec![0, 255, 23]];
    for (candidate, rust) in pairs {
        assert_eq!(candidate, rust);
        rows.push(candidate.into_bytes());
    }
    assert_eq!(rows.len(), 13);
    rows
}

#[test]
fn owned_handoff_native_and_wasm_settle_refuse_and_reenter() {
    for tool in ["clang", "node"] {
        let mut command = Command::new(tool);
        command.arg("--version");
        if !run_target(&mut command).is_ok_and(|result| result.0) {
            assert!(
                std::env::var_os("SEMAPRAX_REQUIRE_KERNEL_ZERO_RUNG_TWO_TARGETS").is_none(),
                "required owned handoff target tool missing: {tool}"
            );
            eprintln!("SKIP owned handoff physical targets: {tool} unavailable");
            return;
        }
    }
    let boundary = Boundary::derive().unwrap();
    Binding::authenticate(
        &boundary.authenticated_bytes,
        boundary.digest,
        &boundary.authenticated_bytes,
    )
    .unwrap();
    let rows = super::super::rung_two_authority::in_candidate_scope(rows);
    with_target_scratch(|root| {
        let mut calls = String::new();
        for (index, row) in rows.iter().enumerate() {
            use std::fmt::Write as _;
            let values = if row.is_empty() {
                "0".to_owned()
            } else {
                row.iter().map(u8::to_string).collect::<Vec<_>>().join(",")
            };
            write!(
                calls,
                "const uint8_t row_{index}[] = {{{values}}}; run_case(row_{index}, {});",
                row.len()
            )
            .unwrap();
        }
        let native = format!("{}\n{}\n#define SPX_OWNED_DATA_TESTING 1\n{}\n#define HANDOFF {}\n#define CASES() do {{ {} }} while (0)\n{}",
            include_str!("../../../tests/support/native_fixture_stdio.c"),
            include_str!("../../../tests/native_owned_tuple_admission_v1/allocations.c"),
            String::from_utf8(boundary.binding.c_source.clone()).unwrap(),
            boundary.binding.c_symbol, calls, NATIVE);
        std::fs::write(root.join("wrapper.c"), native).unwrap();
        for optimization in ["-O0", "-O2"] {
            let executable = root.join(format!(
                "wrapper{optimization}{}",
                std::env::consts::EXE_SUFFIX
            ));
            run(Command::new("clang")
                .args(["-std=c11", optimization, "-Wall", "-Wextra", "-Werror"])
                .arg(root.join("wrapper.c"))
                .arg("-o")
                .arg(&executable));
            assert_eq!(
                run(&mut Command::new(executable)),
                b"owned-handoff-native-ok\n"
            );
            eprintln!("owned wrapper {optimization}: 13 rows, exact dispatch/settlement, hostile handle/copy refusal and reentry");
        }
        std::fs::write(root.join("wrapper.wasm"), &boundary.binding.wasm).unwrap();
        std::fs::write(root.join("rows.json"), serde_json::to_vec(&rows).unwrap()).unwrap();
        std::fs::write(root.join("probe.mjs"), WASM).unwrap();
        assert_eq!(
            run(Command::new("node")
                .arg(root.join("probe.mjs"))
                .current_dir(root)),
            b"owned-handoff-wasm-ok\n"
        );
        eprintln!("owned wrapper Wasm: 13 rows, real arena mint/consume/drop, stale/range/copy refusal and reentry");
    });
}

const NATIVE: &str = r#"
#undef malloc
#undef calloc
#undef free
static spx_context_v1 context;
static size_t dispatches;
static uint32_t checked_call(const uint8_t *input, uint64_t length,
    uint32_t *tag, uint64_t *handle, int64_t *error) {
    if(length > 20) return SPX_OWNED_DATA_ADAPTER_FAILURE;
    ++dispatches;
    return HANDOFF(&context,input,length,tag,handle,error);
}
static void run_case(const uint8_t *input, uint64_t length) {
    REQUIRE(fixture_live == 0 && context.live_slots == 0);
    size_t allocations = fixture_malloc_calls, releases = fixture_free_calls;
    uint64_t invocation = context.invocation;
    size_t before_dispatch = dispatches;
    uint32_t tag = UINT32_MAX; uint64_t handle = 0; int64_t error = INT64_MIN;
    REQUIRE(checked_call(input,length,&tag,&handle,&error) == 0);
    REQUIRE(dispatches == before_dispatch + 1 && context.invocation == invocation + 1);
    REQUIRE(tag == 0 && error == 0 && handle != 0 && context.live_slots == 1);
    REQUIRE(fixture_malloc_calls == allocations + (length != 0));
    REQUIRE(fixture_live == (length != 0));
    uint64_t actual = UINT64_MAX;
    REQUIRE(spx_owned_bytes_len_v1(&context,handle,&actual) == 0 && actual == length);
    uint8_t copied[20] = {0};
    spx_owned_data_test_fault_v1(&context,1);
    REQUIRE(spx_owned_bytes_copy_v1(&context,handle,copied,length) == SPX_OWNED_DATA_COPY_FAILURE);
    REQUIRE(context.live_slots == 1 && fixture_live == (length != 0));
    REQUIRE(spx_owned_bytes_copy_v1(&context,handle,copied,length) == 0);
    REQUIRE(memcmp(copied,input,(size_t)length) == 0);
    REQUIRE(fixture_free_calls == releases);
    REQUIRE(spx_owned_bytes_drop_v1(&context,handle) == 0);
    REQUIRE(fixture_live == 0 && context.live_slots == 0);
    /* The drop calls free(NULL) for empty Bytes; live counts real payloads. */
    REQUIRE(fixture_free_calls == releases + 1);
    REQUIRE(spx_owned_bytes_drop_v1(&context,handle) == SPX_OWNED_DATA_INVALID_HANDLE);
    REQUIRE(fixture_live == 0 && context.live_slots == 0);
    REQUIRE(fixture_free_calls == releases + 1);
}
int main(void) {
    REQUIRE(fixture_binary_stdout());
    fixture_calibrate();
    REQUIRE(spx_owned_data_context_init_v1(&context,sizeof(context)) == 0);
    uint8_t input[21] = {0}; uint32_t tag = UINT32_MAX; uint64_t handle = 0; int64_t error = INT64_MIN;
    size_t allocations = fixture_malloc_calls;
    REQUIRE(checked_call(input,21,&tag,&handle,&error) == SPX_OWNED_DATA_ADAPTER_FAILURE);
    REQUIRE(dispatches == 0 && fixture_malloc_calls == allocations && context.invocation == 0);
    REQUIRE(tag == UINT32_MAX && handle == 0 && error == INT64_MIN);
    CASES();
    REQUIRE(dispatches == 13 && fixture_live == 0 && context.live_slots == 0);
    REQUIRE(spx_owned_data_context_drop_v1(&context) == 0);
    puts("owned-handoff-native-ok");
    return 0;
}
"#;

const WASM: &str = r#"
import assert from 'node:assert/strict';
import fs from 'node:fs';
const bytes=fs.readFileSync('wrapper.wasm'),rows=JSON.parse(fs.readFileSync('rows.json','utf8'));
let instance,next=1,mints=0,drops=0,dispatches=0;
const entries=new Map();
function decode(c){const w=BigInt.asUintN(64,c);return {root:Number(w>>32n),length:Number(w&0xffffffffn)}}
function owned(c){const v=decode(c),token=v.root&0x7fffffff,b=entries.get(token);
    assert(v.root>>>31===1 && token!==0 && b instanceof Uint8Array && b.length===v.length);return {token,b};}
function read(c){const v=decode(c);if(v.root>>>31)return owned(c).b;
    assert(instance && v.root<=instance.exports.memory.buffer.byteLength-v.length);
    return new Uint8Array(instance.exports.memory.buffer,v.root,v.length);}
function allocate(c){const b=Uint8Array.from(read(c));assert(b.length<=20 && entries.size===0 && next<0x80000000);
    const token=next++;entries.set(token,b);mints++;return BigInt.asIntN(64,((0x80000000n|BigInt(token))<<32n)|BigInt(b.length));}
function drop(c){const {token}=owned(c);assert(entries.delete(token));drops++;}
let published,copyReads=0;
function copyAndSettle(c,refuse=false){
    const copied=Uint8Array.from(owned(c).b);copyReads++;
    if(refuse)throw Error('injected copy refusal before publication');
    drop(c);published=copied;
}
const unreachable=()=>{throw Error('unexpected scalar/contract import in ownership wrapper')};
const env={spx_add:unreachable,spx_sub:unreachable,spx_mul:unreachable,spx_div:unreachable,
    spx_rem:unreachable,spx_neg:unreachable,spx_contract_fail:unreachable,
    spx_bytes_copy:allocate,spx_bytes_get:(c,i)=>{const b=read(c);return i<0n||i>=BigInt(b.length)?-1:b[Number(i)]},
    spx_bytes_drop:drop,spx_bytes_as_slice:c=>{read(c);return c},spx_owned_utf8_validate_v1:unreachable};
instance=(await WebAssembly.instantiate(bytes,{env})).instance;
const e=instance.exports,mem=new Uint8Array(e.memory.buffer),view=new DataView(e.memory.buffer);
const entry='spx_owned_v1_'+Buffer.from('kernel-zero.owned-handoff.export').toString('hex');
const out=65536;
function call(input,output=out){assert(input.length<=20);dispatches++;mem.set(input,0);return e[entry](0,input.length,output);}
assert.throws(()=>call(new Uint8Array(21)));assert.equal(dispatches,0);assert.equal(mints,0);
mem.fill(0xa5,out,out+16);
assert.equal(call(new Uint8Array(),out+1),11);assert.equal(mints,0);assert.equal(entries.size,0);
assert(mem.slice(out,out+16).every(x=>x===0xa5));
assert.equal(rows.length,13);
for(const row of rows){const input=Uint8Array.from(row),before=mints,priorDrops=drops,priorDispatch=dispatches;
    assert.equal(entries.size,0);assert.equal(call(input),0);assert.equal(dispatches,priorDispatch+1);
    const carrier=view.getBigInt64(out,true);assert.equal(mints,before+1);assert.equal(entries.size,1);
    assert.throws(()=>owned(carrier^1n));assert.equal(entries.size,1);
    published=undefined;const priorReads=copyReads;
    assert.throws(()=>copyAndSettle(carrier,true),/injected copy refusal before publication/);
    assert.equal(copyReads,priorReads+1);assert.equal(published,undefined);
    assert.equal(entries.size,1);assert.equal(drops,priorDrops);
    copyAndSettle(carrier);
    assert.equal(copyReads,priorReads+2);assert.deepEqual(published,input);
    assert.equal(entries.size,0);assert.equal(drops,priorDrops+1);
    assert.throws(()=>drop(carrier));assert.equal(drops,priorDrops+1);
}
assert.equal(mints,13);assert.equal(drops,13);assert.equal(entries.size,0);assert.equal(dispatches,14);
console.log('owned-handoff-wasm-ok');
"#;
