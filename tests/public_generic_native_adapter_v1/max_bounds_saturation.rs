//! Issue #140's "max bounds" callable cell: a *saturating* owned payload —
//! [`MAX_OWNED_LEAVES_PER_INSTANCE`] leaves of exactly
//! [`MAX_BYTES_PER_LEAF`] bytes, i.e. exactly [`MAX_TOTAL_PAYLOAD_BYTES`] —
//! driven through each really compiled generated calling consumer against
//! the real compiled native provider, plus a per-language negative control
//! proving what that cell is actually sensitive to.
//!
//! Why nothing that already exists covers this, stated once here rather
//! than implied:
//!
//! * Every other calling-consumer harness in this directory generates its
//!   consumers from a one- or two-field [`RecordShape`]. With one leaf,
//!   `payload` is always zero when the capacity guard runs, so the second
//!   half of that guard — `leaf.len() > MAX_TOTAL_BYTES - payload` in
//!   `rust_calling/render/carrier_rs.txt`, `SPX_PG_CCC_MAX_TOTAL_BYTES -
//!   payload` in `c_calling/render/codec.c.txt`, `16777216u - payload` in
//!   `cxx_calling/render.rs` — can never fire: a leaf that satisfies the
//!   64 KiB per-leaf bound trivially satisfies a 16 MiB budget nothing has
//!   spent from. **Before this module, no test in the repository spent that
//!   budget at all.** The negative controls below are the proof: each moves
//!   exactly one byte of that budget and nothing else, and only this
//!   module's cases notice.
//! * `probe.c::test_total_payload_boundary_and_full_result_overlap` proves
//!   a payload bound at the *raw provider* layer with a hand-built carrier.
//!   It never goes through a generated consumer, so it says nothing about
//!   the three generators' own restatements of the bound.
//! * The numbers this case lands on are exact, not approximate: 256 leaves
//!   is exactly `MAX_OWNED_LEAVES_PER_INSTANCE`; 16 MiB is exactly
//!   `MAX_TOTAL_PAYLOAD_BYTES`; the provider's exported result is
//!   `8 + 256 * (8 + 65536)` = 16 779 272 bytes, exactly each consumer's own
//!   `MAX_FRAME_BYTES` (`MIN_FRAME_BYTES + MAX_TOTAL_BYTES`); and the native
//!   provider holds a full input alive while it builds a full result, which
//!   is exactly what `SPX_PG_MAX_PHYSICAL_LIVE_BYTES`'s
//!   `2 * SPX_PG_MAX_TOTAL_PAYLOAD_BYTES` term budgets for
//!   (`src/public_generic_abi/native/provider_body.c`). `probe.c` pins that
//!   allowance's *formula*; nothing before this module made a legal maximal
//!   call that actually needs it.
//!
//! What this module deliberately does NOT claim. An *unmutated* over-bound
//! cell ("one byte past the total-payload bound with every per-leaf bound
//! satisfied") is structurally unreachable through a generated consumer, so
//! none is manufactured: `MAX_OWNED_LEAVES_PER_INSTANCE * MAX_BYTES_PER_LEAF
//! == MAX_TOTAL_PAYLOAD_BYTES` exactly (asserted in every test below), and
//! every generator refuses a shape outside `1..=256` leaves before emitting
//! anything, so a document whose per-leaf bounds all hold can at most
//! saturate the total and can never exceed it. The refusal half of the
//! branch is therefore reached the only honest way available — by moving
//! the generated consumer's own budget down by one byte in the negative
//! controls. Over-bound behaviour where it *is* reachable stays covered
//! where it already is: per-leaf in the shared hostile corpus, leaf-count
//! in the generators' own `LeafCountOutOfBounds` unit tests.
//!
//! Every mutation below is applied to the *generated artifact on disk*
//! inside this test's own scratch directory, never to this repository's
//! sources, so a concurrent build in the same checkout never sees a mutated
//! compiler.
//!
//! Like every sibling module here, the trusted descriptor bytes are a
//! FIXTURE placeholder (#229 still blocks deriving one from a real checked
//! generic export), and this harness assumes a Unix-like host with `clang`
//! (or `$CLANG`), `clang++` (or `$CLANGXX`), `cargo` and `ar` (or `$AR`).
//! There is no `command_available`-style guard anywhere in this module: a
//! missing toolchain panics, it never skips.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use semaprax::public_generic_abi::boundary_profile::{
    MAX_BYTES_PER_LEAF, MAX_OWNED_LEAVES_PER_INSTANCE, MAX_TOTAL_PAYLOAD_BYTES,
};
use semaprax::public_generic_abi::carrier::{CarrierBindingV1, TargetProfile};
use semaprax::public_generic_abi::descriptor::{DescriptorV1, InstanceBinding};
use semaprax::public_generic_abi::native::binding::NativeProviderBindingV1;
use semaprax::public_generic_abi::native::template::render_reference_provider;
use semaprax::public_generic_consumer::c_calling::generate_c_calling_consumer;
use semaprax::public_generic_consumer::cxx_calling::generate_cxx_calling_consumer;
use semaprax::public_generic_consumer::rust_calling::{
    generate_rust_calling_consumer, OwnedByteField, RecordShape,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// The one marker every route prints, parsed by [`assert_outcome_line`].
const MARKER: &str = "MAX_BOUNDS ";

/// The single case id in this module's (deliberately one-entry) manifest.
const CASE: &str = "saturating_total_payload";

/// The outcome an unmutated consumer must report for the saturating case.
const ACCEPTED: &str = "ACCEPTED";

/// The outcome the negative controls must report: the consumer's own closed
/// capacity status, never a generic failure. A route that refuses for any
/// other reason prints `OTHER_<exact status>` and fails the exact-line
/// assertion with that status visible.
const CAPACITY_EXCEEDED: &str = "CAPACITY_EXCEEDED";

fn descriptor_bytes() -> Vec<u8> {
    DescriptorV1::new(
        "issue140.max.bounds",
        "saturating_transform",
        format!("sha256:{}", "1".repeat(64)),
        format!("sha256:{}", "2".repeat(64)),
        format!("sha256:{}", "3".repeat(64)),
        InstanceBinding {
            term: "@14:issue140.pair<bytes,bool>".to_owned(),
            instance_digest: format!("sha256:{}", "4".repeat(64)),
        },
        InstanceBinding {
            term: "@14:issue140.pair<bytes,i64>".to_owned(),
            instance_digest: format!("sha256:{}", "5".repeat(64)),
        },
    )
    .encode()
}

fn fixture_binding() -> NativeProviderBindingV1 {
    NativeProviderBindingV1::new(
        CarrierBindingV1::new(
            format!("sha256:{}", "6".repeat(64)),
            TargetProfile::NativeC11,
            "runtime:native-c11-fixture-issue-140-max-bounds",
        ),
        format!("sha256:{}", "7".repeat(64)),
        "spx_pg_endpoint_reverse_bytes_v1",
        "semaprax-0.4.1",
    )
}

/// The generated field name for one leaf identity, in every one of the
/// three native generators: `field_` followed by the identity's bytes in
/// lowercase hex (`public_generic_consumer::identifier`, which is
/// `pub(crate)` and so cannot be called from here). Restated rather than
/// imported, then checked against the generators' actual output in
/// [`assert_field_names_present`] so a scheme change fails loudly here
/// instead of producing source that silently does not compile.
fn field_name(identity: &str) -> String {
    let mut out = String::from("field_");
    for byte in identity.bytes() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// One leaf identity per owned leaf, exactly [`MAX_OWNED_LEAVES_PER_INSTANCE`]
/// of them. Kept four bytes long so a 256-field generated artifact stays
/// readable when a failure needs reading.
fn leaf_identities() -> Vec<String> {
    (0..MAX_OWNED_LEAVES_PER_INSTANCE)
        .map(|index| format!("m{index:03}"))
        .collect()
}

fn shapes() -> (RecordShape, RecordShape) {
    let input = RecordShape::new(
        leaf_identities()
            .into_iter()
            .map(OwnedByteField::new)
            .collect(),
    );
    let output = input.clone();
    (input, output)
}

/// Fail closed if the generated artifact does not actually declare every
/// field name this module's spliced driver assigns to.
fn assert_field_names_present(language: &str, files: &[(String, String)], relative: &str) {
    let contents = files
        .iter()
        .find(|(path, _)| path == relative)
        .map(|(_, contents)| contents.as_str())
        .unwrap_or_else(|| panic!("{language}: generated artifact has no {relative}"));
    for identity in leaf_identities() {
        let name = field_name(&identity);
        assert!(
            contents.contains(&name),
            "{language}: {relative} does not declare the expected generated field {name:?}; the \
             generators' field-naming scheme has drifted from this module's restatement"
        );
    }
}

/// One negative control: the exact text to rewrite in one generated file,
/// and how many occurrences must be there.
struct Mutation {
    relative: &'static str,
    from: &'static str,
    to: &'static str,
    occurrences: usize,
}

impl Mutation {
    fn apply(&self, root: &Path) {
        let path = root.join(self.relative);
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let found = contents.matches(self.from).count();
        assert_eq!(
            found, self.occurrences,
            "negative control: {} contains {found} occurrences of {:?}, expected {}; the \
             generator's own restatement of the total-payload bound has moved and this control \
             must be re-synced rather than silently weakened",
            self.relative, self.from, self.occurrences
        );
        fs::write(&path, contents.replace(self.from, self.to)).unwrap();
    }
}

/// The Rust consumer's own `MAX_TOTAL_BYTES`, one byte short.
fn rust_mutation() -> Mutation {
    Mutation {
        relative: "src/carrier.rs",
        from: "pub(crate) const MAX_TOTAL_BYTES: usize = 16_777_216;",
        to: "pub(crate) const MAX_TOTAL_BYTES: usize = 16_777_215;",
        occurrences: 1,
    }
}

/// The C11 consumer's own `SPX_PG_CCC_MAX_TOTAL_BYTES`, one byte short.
fn c_mutation() -> Mutation {
    Mutation {
        relative: "spx_pg_calling_consumer.c",
        from: "#define SPX_PG_CCC_MAX_TOTAL_BYTES 16777216u",
        to: "#define SPX_PG_CCC_MAX_TOTAL_BYTES 16777215u",
        occurrences: 1,
    }
}

/// The C++17 wrapper's own per-field preflight budget, one byte short. The
/// C++ generator inlines the literal once per leaf rather than naming a
/// constant, so this control asserts it finds exactly one per owned leaf —
/// a generator that started skipping the check for some fields fails here.
fn cxx_mutation() -> Mutation {
    Mutation {
        relative: "include/semaprax_public_generic_v1.hpp",
        from: "16777216u - payload",
        to: "16777215u - payload",
        occurrences: MAX_OWNED_LEAVES_PER_INSTANCE,
    }
}

struct Workspace(PathBuf);

impl Workspace {
    fn new(label: &str) -> Self {
        let root = env::temp_dir().join(format!(
            "spx-pg-max-bounds-{}-{}-{label}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        // Do not canonicalize: on Windows this adds a `\\?\` prefix the
        // native toolchain does not expect.
        Self(root)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn tool(variable: &str, fallback: &str) -> PathBuf {
    env::var_os(variable).map_or_else(|| PathBuf::from(fallback), PathBuf::from)
}

fn run(command: &mut Command, label: &str) -> Output {
    command
        .output()
        .unwrap_or_else(|error| panic!("run {label}: {error}"))
}

fn compile_provider_object(root: &Path, clang: &Path) -> PathBuf {
    let provider_source = render_reference_provider(&descriptor_bytes(), &fixture_binding());
    let source_path = root.join("provider.c");
    fs::write(&source_path, &provider_source).unwrap();
    let object_path = root.join("provider.o");
    let compiled = run(
        Command::new(clang)
            .current_dir(root)
            .args(["-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", "-c"])
            .arg(&source_path)
            .arg("-o")
            .arg(&object_path),
        "compile provider.c",
    );
    assert!(
        compiled.status.success(),
        "compiling the native provider failed: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    assert!(object_path.is_file());
    object_path
}

fn write_generated_files(root: &Path, files: &[(String, String)]) {
    for (relative, contents) in files {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, contents).unwrap();
    }
}

/// Locate the exact anchor text and splice in front of it. Panics loudly
/// (never silently no-ops) when an anchor is missing: a missing anchor means
/// this splice has drifted from the generator's actual output and must be
/// re-synced, never silently skipped.
fn splice_before(contents: &mut String, anchor: &str, inserted: &str) {
    let position = contents
        .find(anchor)
        .unwrap_or_else(|| panic!("splice anchor {anchor:?} not found in generated source"));
    contents.insert_str(position, inserted);
}

/// Exactly one `MAX_BOUNDS <case> <status>` line, matching `expected`
/// exactly, must have been printed by the route. A route that prints
/// nothing — a silently skipped leg — fails here rather than passing
/// vacuously, and a route that refused for the wrong reason fails with its
/// exact observed status in the message.
fn assert_outcome_line(route: &str, stdout: &str, expected: &str) {
    let observed: Vec<&str> = stdout
        .lines()
        .filter_map(|line| line.find(MARKER).map(|at| line[at + MARKER.len()..].trim()))
        .collect();
    assert_eq!(
        observed,
        vec![format!("{CASE} {expected}").as_str()],
        "{route}: unexpected saturating-payload outcome; full stdout:\n{stdout}"
    );
    // Echoed so a `--nocapture` run shows, per route, that this leg really
    // executed.
    eprintln!("{MARKER}{route} {CASE} {expected}");
}

/// The bound relationship every claim in this module rests on. Asserted in
/// each test rather than in a comment: if a future profile change makes the
/// total bound smaller than leaves times per-leaf, an *unmutated* over-bound
/// cell becomes reachable and must be written.
fn assert_bounds_are_exactly_saturable() {
    assert_eq!(
        MAX_OWNED_LEAVES_PER_INSTANCE * MAX_BYTES_PER_LEAF,
        MAX_TOTAL_PAYLOAD_BYTES,
        "the boundary profile's three bounds are no longer exactly saturable; an unmutated \
         total-payload REJECTION cell is now reachable through a generated consumer and must be \
         added here"
    );
}

// ---------------------------------------------------------------------------
// Rust
// ---------------------------------------------------------------------------

/// Appended verbatim to the end of the generated `tests/round_trip.rs`,
/// using only that file's own already-in-scope items (`Provider`, `Error`,
/// `Input`, `diagnostics`, `reversed`, the trusted byte constants).
const RUST_APPENDIX: &str = r#"

// ---- issue #140: saturating owned payload ----
const SPX140_LEAF_BYTES: usize = 64 * 1024;
const SPX140_LEAF_COUNT: usize = 256;
const SPX140_TOTAL_BYTES: usize = SPX140_LEAF_BYTES * SPX140_LEAF_COUNT;

/// A per-(leaf, offset) byte no two leaves share a prefix of, so a swapped,
/// duplicated or truncated leaf cannot pass the checks below.
fn spx140_pattern(leaf: usize, at: usize) -> u8 {
    (((leaf * 31 + at * 7) % 251) + 1) as u8
}

fn spx140_leaf(leaf: usize) -> Vec<u8> {
    (0..SPX140_LEAF_BYTES)
        .map(|at| spx140_pattern(leaf, at))
        .collect()
}

fn spx140_check(leaf: usize, actual: &[u8], total: &mut usize) {
    assert_eq!(
        actual.len(),
        SPX140_LEAF_BYTES,
        "leaf {leaf}: result leaf is not exactly the per-leaf bound"
    );
    // Whole-buffer equality on the two extreme leaves, sampled positions on
    // the rest: 16 MiB of element-wise comparison in an unoptimized build
    // would dominate this test's runtime without proving more about the
    // bound than the ends and midpoint of every leaf already do.
    if leaf == 0 || leaf == SPX140_LEAF_COUNT - 1 {
        assert_eq!(
            actual,
            reversed(&spx140_leaf(leaf)).as_slice(),
            "leaf {leaf}: result is not this leaf's full reversal"
        );
    } else {
        for at in [
            0usize,
            1,
            SPX140_LEAF_BYTES / 2,
            SPX140_LEAF_BYTES - 2,
            SPX140_LEAF_BYTES - 1,
        ] {
            assert_eq!(
                actual[at],
                spx140_pattern(leaf, SPX140_LEAF_BYTES - 1 - at),
                "leaf {leaf} position {at}: result is not this leaf's reversal"
            );
        }
    }
    *total += actual.len();
}

#[test]
fn spx140_saturating_total_payload_round_trip() {
    let mut provider =
        Provider::open(TRUSTED_DESCRIPTOR_BYTES, TRUSTED_BINDING_BYTES).expect("open");
    let input = Input {
__INPUT_FIELDS__
    };
    let allocations_before = diagnostics::live_allocations();
    match provider.transform(input) {
        Ok(output) => {
            let mut total = 0usize;
__OUTPUT_CHECKS__
            assert_eq!(
                total, SPX140_TOTAL_BYTES,
                "the settled result did not carry exactly the total-payload bound"
            );
            println!("MAX_BOUNDS saturating_total_payload ACCEPTED");
        }
        Err(Error::CapacityExceeded(_)) => {
            assert_eq!(
                diagnostics::live_allocations(),
                allocations_before,
                "a capacity refusal must precede every native allocation"
            );
            println!("MAX_BOUNDS saturating_total_payload CAPACITY_EXCEEDED");
        }
        Err(other) => println!("MAX_BOUNDS saturating_total_payload OTHER_{other:?}"),
    }
    drop(provider);
    assert_eq!(
        diagnostics::live_allocations(),
        0,
        "zero live native allocations after this case settles, either way"
    );
}
"#;

fn rust_appendix() -> String {
    let mut input_fields = String::new();
    let mut output_checks = String::new();
    for (index, identity) in leaf_identities().iter().enumerate() {
        let name = field_name(identity);
        let _ = writeln!(input_fields, "        {name}: spx140_leaf({index}),");
        let _ = writeln!(
            output_checks,
            "            spx140_check({index}, &output.{name}, &mut total);"
        );
    }
    RUST_APPENDIX
        .replace("__INPUT_FIELDS__", input_fields.trim_end())
        .replace("__OUTPUT_CHECKS__", output_checks.trim_end())
}

// ---------------------------------------------------------------------------
// C11
// ---------------------------------------------------------------------------

const C_APPENDIX_FN: &str = r#"/* ---- issue #140: saturating owned payload ---- */
#define SPX140_LEAF_BYTES 65536u
#define SPX140_TOTAL_BYTES 16777216u

static uint8_t spx140_pattern(size_t leaf, size_t at) {
    return (uint8_t)(((leaf * 31u + at * 7u) % 251u) + 1u);
}

static uint8_t *spx140_leaf(size_t leaf) {
    uint8_t *data = (uint8_t *)malloc(SPX140_LEAF_BYTES);
    REQUIRE(data != NULL);
    for (size_t at = 0; at < (size_t)SPX140_LEAF_BYTES; ++at) {
        data[at] = spx140_pattern(leaf, at);
    }
    return data;
}

static void spx140_check(size_t leaf, const spx_pg_owned_bytes *actual, size_t *total) {
    REQUIRE(actual->len == (size_t)SPX140_LEAF_BYTES);
    REQUIRE(actual->data != NULL);
    for (size_t at = 0; at < actual->len; ++at) {
        REQUIRE(actual->data[at] == spx140_pattern(leaf, actual->len - 1u - at));
    }
    *total += actual->len;
}

static void test_spx140_saturating_total_payload(void) {
    spx_pg_calling_consumer *consumer = NULL;
    REQUIRE(spx_pg_consumer_open(spx_pg_trusted_descriptor_bytes, spx_pg_trusted_descriptor_len,
                                 spx_pg_trusted_binding_bytes, spx_pg_trusted_binding_len,
                                 &consumer) == SPX_PG_CONSUMER_OK);
    spx_pg_input input;
    memset(&input, 0, sizeof(input));
__INPUT_FIELDS__
    spx_pg_output output;
    int native_status = -1;
    size_t allocations_before = spx_pg_consumer_test_live_allocations();
    spx_pg_consumer_status transformed =
        spx_pg_consumer_transform(consumer, &input, &output, &native_status);
    if (transformed == SPX_PG_CONSUMER_OK) {
        REQUIRE(native_status == 0);
        size_t total = 0;
__OUTPUT_CHECKS__
        REQUIRE(total == (size_t)SPX140_TOTAL_BYTES);
        spx_pg_output_free(&output);
        (void)printf("MAX_BOUNDS saturating_total_payload ACCEPTED\n");
    } else if (transformed == SPX_PG_CONSUMER_CAPACITY_EXCEEDED) {
        REQUIRE(spx_pg_consumer_test_live_allocations() == allocations_before);
        (void)printf("MAX_BOUNDS saturating_total_payload CAPACITY_EXCEEDED\n");
    } else {
        (void)printf("MAX_BOUNDS saturating_total_payload OTHER_%d\n", (int)transformed);
    }
    spx_pg_consumer_close(&consumer);
    REQUIRE(spx_pg_consumer_test_live_allocations() == 0);
}

"#;

fn c_appendix() -> String {
    let mut input_fields = String::new();
    let mut output_checks = String::new();
    for (index, identity) in leaf_identities().iter().enumerate() {
        let name = field_name(identity);
        let _ = writeln!(
            input_fields,
            "    input.{name}.data = spx140_leaf({index});\n    input.{name}.len = \
             (size_t)SPX140_LEAF_BYTES;"
        );
        let _ = writeln!(
            output_checks,
            "        spx140_check({index}, &output.{name}, &total);"
        );
    }
    C_APPENDIX_FN
        .replace("__INPUT_FIELDS__", input_fields.trim_end())
        .replace("__OUTPUT_CHECKS__", output_checks.trim_end())
}

// ---------------------------------------------------------------------------
// C++17
// ---------------------------------------------------------------------------

const CXX_APPENDIX_FN: &str = r#"/* ---- issue #140: saturating owned payload ---- */
static std::uint8_t spx140_pattern(std::size_t leaf, std::size_t at) {
    return static_cast<std::uint8_t>(((leaf * 31u + at * 7u) % 251u) + 1u);
}

static std::vector<std::uint8_t> spx140_leaf(std::size_t leaf) {
    std::vector<std::uint8_t> data(65536u);
    for (std::size_t at = 0; at < data.size(); ++at) {
        data[at] = spx140_pattern(leaf, at);
    }
    return data;
}

static void spx140_check(std::size_t leaf, const BytesView &actual, std::size_t *total) {
    REQUIRE(actual.size == 65536u);
    REQUIRE(actual.data != nullptr);
    for (std::size_t at = 0; at < actual.size; ++at) {
        REQUIRE(actual.data[at] == spx140_pattern(leaf, actual.size - 1u - at));
    }
    *total += actual.size;
}

static void test_spx140_saturating_total_payload() {
    auto opened = Provider::open();
    REQUIRE(opened.has_value());
    Provider provider = std::move(opened).value();
    Input input{};
__INPUT_FIELDS__
    std::size_t allocations_before = ::spx_pg_consumer_test_live_allocations();
    auto result = provider.transform(std::move(input));
    if (result.has_value()) {
        const auto &output = result.value();
        std::size_t total = 0;
__OUTPUT_CHECKS__
        REQUIRE(total == 16777216u);
        (void)std::printf("MAX_BOUNDS saturating_total_payload ACCEPTED\n");
    } else if (result.error().kind() == ErrorKind::CapacityExceeded) {
        REQUIRE(::spx_pg_consumer_test_live_allocations() == allocations_before);
        (void)std::printf("MAX_BOUNDS saturating_total_payload CAPACITY_EXCEEDED\n");
    } else {
        (void)std::printf("MAX_BOUNDS saturating_total_payload OTHER_%d\n",
                          static_cast<int>(result.error().kind()));
    }
    provider.close();
    REQUIRE(::spx_pg_consumer_test_live_allocations() == 0);
}

"#;

fn cxx_appendix() -> String {
    let mut input_fields = String::new();
    let mut output_checks = String::new();
    for (index, identity) in leaf_identities().iter().enumerate() {
        let name = field_name(identity);
        let _ = writeln!(input_fields, "    input.{name} = spx140_leaf({index});");
        let _ = writeln!(
            output_checks,
            "        spx140_check({index}, output.{name}(), &total);"
        );
    }
    CXX_APPENDIX_FN
        .replace("__INPUT_FIELDS__", input_fields.trim_end())
        .replace("__OUTPUT_CHECKS__", output_checks.trim_end())
}

// ---------------------------------------------------------------------------
// The three routes, each run twice: unmutated, and with its own bound moved
// ---------------------------------------------------------------------------

fn exercise_rust_route(label: &str, mutation: Option<Mutation>, expected: &str) {
    assert_bounds_are_exactly_saturable();
    let clang = tool("CLANG", "clang");
    let (input, output) = shapes();
    let binding = fixture_binding();
    let consumer = generate_rust_calling_consumer(&descriptor_bytes(), &binding, &input, &output)
        .expect("a 256-leaf shape is within the generator's declared 1..=256 bound");
    assert_field_names_present("rust", consumer.files(), "src/types.rs");

    let workspace = Workspace::new(label);
    eprintln!("max-bounds Rust workspace: {}", workspace.0.display());
    let provider_object = compile_provider_object(&workspace.0, &clang);

    let root = workspace.path("rust-consumer");
    let appendix = rust_appendix();
    for (relative, contents) in consumer.files() {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut contents = contents.clone();
        if relative == "tests/round_trip.rs" {
            contents.push_str(&appendix);
        }
        fs::write(&path, &contents).unwrap();
    }
    if let Some(mutation) = &mutation {
        mutation.apply(&root);
    }

    let lib_dir = workspace.path("provider-lib");
    fs::create_dir_all(&lib_dir).unwrap();
    let archive_path = lib_dir.join("libspx_pg_reference_provider.a");
    let archived = run(
        Command::new(tool("AR", "ar"))
            .arg("rcs")
            .arg(&archive_path)
            .arg(&provider_object),
        "archive the native provider object",
    );
    assert!(
        archived.status.success(),
        "archiving the native provider failed: {}",
        String::from_utf8_lossy(&archived.stderr)
    );

    let target_dir = workspace.path("rust-cargo-target");
    let lockfile = run(
        Command::new(tool("CARGO", "cargo"))
            .current_dir(&root)
            .env("CARGO_TARGET_DIR", &target_dir)
            .arg("generate-lockfile"),
        "cargo generate-lockfile",
    );
    assert!(
        lockfile.status.success(),
        "generate-lockfile: {}",
        String::from_utf8_lossy(&lockfile.stderr)
    );
    let tested = run(
        Command::new(tool("CARGO", "cargo"))
            .current_dir(&root)
            .env("CARGO_TARGET_DIR", &target_dir)
            .env("SPX_PG_PROVIDER_LIB_DIR", &lib_dir)
            .env("SPX_PG_PROVIDER_LIB_NAME", "spx_pg_reference_provider")
            .env_remove("RUSTC_WRAPPER")
            .args([
                "test",
                "--locked",
                "--test",
                "round_trip",
                "spx140_saturating_total_payload_round_trip",
                "--",
                "--test-threads=1",
                "--nocapture",
            ]),
        "cargo test (max bounds)",
    );
    let stdout = String::from_utf8_lossy(&tested.stdout).into_owned();
    assert!(
        tested.status.success(),
        "the generated Rust consumer's saturating case failed:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&tested.stderr)
    );
    assert_outcome_line("rust_calling_consumer", &stdout, expected);
}

fn exercise_c_route(label: &str, mutation: Option<Mutation>, expected: &str) {
    assert_bounds_are_exactly_saturable();
    let clang = tool("CLANG", "clang");
    let (input, output) = shapes();
    let binding = fixture_binding();
    let consumer = generate_c_calling_consumer(&descriptor_bytes(), &binding, &input, &output)
        .expect("a 256-leaf shape is within the generator's declared 1..=256 bound");
    assert_field_names_present("c11", consumer.files(), "spx_pg_calling_consumer.h");

    let workspace = Workspace::new(label);
    eprintln!("max-bounds C11 workspace: {}", workspace.0.display());
    let provider_object = compile_provider_object(&workspace.0, &clang);

    let root = workspace.path("c-consumer");
    write_generated_files(&root, consumer.files());
    let round_trip = root.join("round_trip.c");
    let mut contents = fs::read_to_string(&round_trip).unwrap();
    splice_before(&mut contents, "int main(void) {", &c_appendix());
    splice_before(
        &mut contents,
        "(void)puts(\"c-calling-consumer-settled\");",
        "test_spx140_saturating_total_payload();\n    ",
    );
    fs::write(&round_trip, &contents).unwrap();
    if let Some(mutation) = &mutation {
        mutation.apply(&root);
    }

    let executable = root.join("max_bounds_probe");
    let built = run(
        Command::new(&clang)
            .current_dir(&root)
            .args(["-std=c11", "-O0", "-Wall", "-Wextra", "-Werror"])
            .arg("spx_pg_calling_consumer.c")
            .arg("round_trip.c")
            .arg(&provider_object)
            .arg("-o")
            .arg(&executable),
        "compile the C11 max-bounds probe",
    );
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    assert!(
        built.stderr.is_empty(),
        "warning-free build required: {}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executed = run(
        Command::new(&executable).current_dir(&root),
        "run the C11 max-bounds probe",
    );
    let stdout = String::from_utf8_lossy(&executed.stdout).into_owned();
    assert!(
        executed.status.success(),
        "the generated C11 consumer's saturating case failed:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    assert_outcome_line("c_calling_consumer", &stdout, expected);
}

fn exercise_cxx_route(label: &str, mutation: Option<Mutation>, expected: &str) {
    assert_bounds_are_exactly_saturable();
    let clang = tool("CLANG", "clang");
    let clangxx = tool("CLANGXX", "clang++");
    let (input, output) = shapes();
    let binding = fixture_binding();
    let consumer = generate_cxx_calling_consumer(&descriptor_bytes(), &binding, &input, &output)
        .expect("a 256-leaf shape is within the generator's declared 1..=256 bound");
    assert_field_names_present(
        "cxx17",
        consumer.files(),
        "include/semaprax_public_generic_v1.hpp",
    );

    let workspace = Workspace::new(label);
    eprintln!("max-bounds C++17 workspace: {}", workspace.0.display());
    let provider_object = compile_provider_object(&workspace.0, &clang);

    let root = workspace.path("cxx-consumer");
    write_generated_files(&root, consumer.files());
    let round_trip = root.join("test/round_trip.cpp");
    let mut contents = fs::read_to_string(&round_trip).unwrap();
    splice_before(&mut contents, "int main() {", &cxx_appendix());
    splice_before(
        &mut contents,
        "std::puts(\"cxx-calling-consumer-settled\");",
        "test_spx140_saturating_total_payload();\n    ",
    );
    fs::write(&round_trip, &contents).unwrap();
    if let Some(mutation) = &mutation {
        mutation.apply(&root);
    }

    let consumer_object = root.join("spx_pg_calling_consumer.o");
    let c_built = run(
        Command::new(&clang)
            .current_dir(&root)
            .args(["-std=c11", "-O0", "-Wall", "-Wextra", "-Werror", "-c"])
            .arg("spx_pg_calling_consumer.c")
            .arg("-o")
            .arg(&consumer_object),
        "compile the C11 consumer object for the C++17 max-bounds probe",
    );
    assert!(
        c_built.status.success(),
        "{}",
        String::from_utf8_lossy(&c_built.stderr)
    );

    let executable = root.join("max_bounds_probe");
    let built = run(
        Command::new(&clangxx)
            .current_dir(&root)
            .args([
                "-std=c++17",
                "-O0",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Iinclude",
                "-I.",
            ])
            .arg("test/round_trip.cpp")
            .arg(&consumer_object)
            .arg(&provider_object)
            .arg("-o")
            .arg(&executable),
        "compile the C++17 max-bounds probe",
    );
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    assert!(
        built.stderr.is_empty(),
        "warning-free build required: {}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executed = run(
        Command::new(&executable).current_dir(&root),
        "run the C++17 max-bounds probe",
    );
    let stdout = String::from_utf8_lossy(&executed.stdout).into_owned();
    assert!(
        executed.status.success(),
        "the generated C++17 consumer's saturating case failed:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    assert_outcome_line("cxx_calling_consumer", &stdout, expected);
}

/// The generated Rust calling consumer, built as its own crate and linked
/// against the real compiled native provider, transferring exactly
/// [`MAX_TOTAL_PAYLOAD_BYTES`] of owned bytes across 256 leaves and settling
/// with zero live native allocations.
#[test]
fn saturating_total_payload_round_trips_through_the_generated_rust_consumer() {
    exercise_rust_route("rust", None, ACCEPTED);
}

/// The generated C11 calling consumer, compiled by a real C compiler and
/// linked directly against the real compiled native provider's object file.
#[test]
fn saturating_total_payload_round_trips_through_the_generated_c11_consumer() {
    exercise_c_route("c11", None, ACCEPTED);
}

/// The generated C++17 calling consumer, compiled by a real C++ compiler
/// over the generated C11 consumer object and the real native provider.
#[test]
fn saturating_total_payload_round_trips_through_the_generated_cxx17_consumer() {
    exercise_cxx_route("cxx17", None, ACCEPTED);
}

/// Negative control for the Rust cell: with the generated crate's own
/// `MAX_TOTAL_BYTES` one byte short — and nothing else changed — the same
/// payload must be refused with the consumer's own `CapacityExceeded`,
/// before any native allocation. This is what makes the accepting cell
/// above a real check rather than a payload nothing looks at: the two
/// differ by one byte of budget.
#[test]
fn a_one_byte_smaller_total_budget_makes_the_rust_consumer_refuse_the_same_payload() {
    exercise_rust_route("rust-mutated", Some(rust_mutation()), CAPACITY_EXCEEDED);
}

/// Negative control for the C11 cell. See the Rust control above.
#[test]
fn a_one_byte_smaller_total_budget_makes_the_c11_consumer_refuse_the_same_payload() {
    exercise_c_route("c11-mutated", Some(c_mutation()), CAPACITY_EXCEEDED);
}

/// Negative control for the C++17 cell, which additionally asserts the
/// generator emitted the per-leaf total-payload preflight exactly once per
/// owned leaf. See the Rust control above.
#[test]
fn a_one_byte_smaller_total_budget_makes_the_cxx17_consumer_refuse_the_same_payload() {
    exercise_cxx_route("cxx17-mutated", Some(cxx_mutation()), CAPACITY_EXCEEDED);
}
