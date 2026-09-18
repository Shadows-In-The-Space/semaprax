//! Semantic Task Context v1 (issue #197): a goal-aware, token-budgeted
//! compilation over the existing bounded Agent Context v2 engine
//! ([`crate::graph::agent_context_v2_json`]).
//!
//! # What already existed before this module
//!
//! `semaprax context` already compiles one deterministic, byte- and
//! node-bounded semantic closure for exactly **one** seed identity, with
//! per-item omission reasons (`depth`, `max_nodes`, `max_bytes`,
//! `unavailable_filters`), a resumable frontier, and mandatory
//! contracts/ownership/effects/types facets. That engine owns every closure
//! rule (callers, callees, types, effects, ownership, contracts) and this
//! module never reimplements, relaxes, or re-derives any of it: every seed
//! is compiled by calling that exact function unchanged.
//!
//! # What this module adds
//!
//! 1. **A goal**: an explicit, ordered set of seeds
//!    ([`CompilationGoal`]/[`CompilationSeed`]), each an explicit stable ID
//!    plus an integer priority and an opaque `reason` string. The `reason`
//!    is untrusted, caller-supplied data -- exactly like natural-language
//!    goal text in issue #197's failure list -- and is carried through only
//!    for human explainability. It never participates in seed resolution,
//!    ranking, or budget selection; see
//!    `tests::seed_reason_text_never_influences_selection_or_budget` for a
//!    hostile-input regression proving an injection-shaped reason string
//!    changes nothing but the echoed text.
//! 2. **A token budget in an explicit, honestly named unit**
//!    ([`CompilationBudget`], [`TokenizerId`]) instead of only a byte
//!    budget. Two units are supported, and both say plainly what they are:
//!    - `byte-v1`: one budget unit per UTF-8 byte of a seed's compiled
//!      context. Exact, but explicitly not a model token.
//!    - `lexical-v1`: [`crate::agent_economics::lexical_tokens`], this
//!      repository's existing non-model lexical counter (already documented
//!      there as "deliberately not a model tokenizer"). Every output marks
//!      this unit `"exactness":"approximate"`; it is never reported or
//!      claimed as an exact model-token count.
//!
//!    Any other tokenizer identity is refused with `SPX-Z803` rather than
//!    silently downgraded to one of the two above -- a caller can never
//!    receive output that silently claims a tokenizer it did not ask for.
//! 3. **Deterministic multi-seed selection under that shared budget.** Each
//!    seed is compiled independently, then seeds are ordered by descending
//!    priority and, to break ties, ascending stable ID -- never by the
//!    order the caller listed them in, so re-listing one goal's seeds in a
//!    different order produces byte-identical output
//!    (`tests::seed_list_order_does_not_affect_output`). Seeds are then
//!    walked in that order and a seed is included exactly when the running
//!    used-token total plus its own token count does not exceed the budget;
//!    a seed that does not fit is omitted **whole** and the walk continues
//!    to the next (lower-priority) seed, so a small low-priority seed can
//!    still fill space a larger higher-priority seed left unusable. A
//!    seed's compiled JSON is never truncated mid-document: it is either
//!    included complete or omitted complete, and every omitted seed is
//!    reported with its exact token cost and the reason
//!    `"omitted_budget_exhausted"`, never silently dropped.
//! 4. **A deterministic digest** ([`compile`]'s `goal_digest` output field)
//!    binding schema, tokenizer (including its [`TokenizerId::algorithm_digest`],
//!    not only its short name), budget, and every seed's exact compiled
//!    content. It changes whenever the source revision, tokenizer, budget,
//!    or goal changes (`tests::digest_changes_with_revision`,
//!    `tests::digest_changes_with_tokenizer`,
//!    `tests::digest_changes_with_budget`).
//! 5. **An explicit tokenizer algorithm identity** ([`TokenizerId::algorithm_digest`]),
//!    separate from and stricter than the short unit name. If a tokenizer's
//!    *counting behavior* ever changes without its short name changing --
//!    "tokenizer version drift changes the budget" in issue #197's failure
//!    list -- this digest is the thing a future change is obligated to bump,
//!    and every [`cache_key`] folds it in, so an unnoticed drift cannot
//!    silently reuse a stale cache entry keyed only by name.
//! 6. **A pre-compile cache key** ([`cache_key`], [`TaskContextCache`],
//!    [`compile_cached`]): an input-only digest over the source revision,
//!    the goal's seeds (order-independent, like [`compile`]'s own merge), the
//!    shared per-seed policy (`AgentContextV2Options`'s `Debug` projection --
//!    exposed accessors don't cover every field, and this module does not
//!    duplicate the underlying engine's private representation to get one),
//!    the tokenizer and budget, and a caller-declared `access_scope` string
//!    naming the caller's own authorization boundary (the security list's
//!    "context caching can leak source across authorization boundaries").
//!    [`TaskContextCache`] is a plain in-memory key-value store: no eviction,
//!    no expiry, no persistence. It stores exactly the bytes `compile` would
//!    have produced for that exact key and never returns a value for a key
//!    it was not explicitly given.
//! 7. **A lexical seed suggestion** ([`suggest_seeds`]), deterministic
//!    word-overlap ranking over each declaration's plain name and leading doc
//!    comment lines (`crate::doc::document`'s `Entry::name`/`description`)
//!    against a caller-supplied, untrusted `query` string. It is a pure,
//!    side-effect-free function returning suggestions for a human or calling
//!    tool to review; nothing in this module calls it, and it never builds,
//!    mutates, or feeds a [`CompilationGoal`] on its own --
//!    `tests::suggest_seeds_never_influences_a_goal_that_does_not_explicitly_include_it`
//!    proves calling it changes nothing about a subsequent unrelated
//!    [`compile`] call.
//! 8. **An explicit inclusion-policy summary** in every [`compile`] bundle's
//!    top-level `policy` field (`depth`, `max_bytes`, `max_nodes`,
//!    `direction`) -- the shared `AgentContextV2Options` this call used,
//!    surfaced once at the bundle level rather than only inside each seed's
//!    own embedded `query` object. `filters` is deliberately absent from this
//!    summary: `AgentContextV2Options` exposes no public accessor for it, and
//!    it remains visible per seed inside that seed's own compiled content.
//!
//! # Deliberately out of scope here
//!
//! Issue #197 asks for a much larger surface this module still does not
//! cover: requirement/test/diagnostic/candidate-diff seeds integrated into
//! the semantic closure itself (a seed is still exactly one stable
//! declaration id), real content summarization of a distant or omitted item
//! (this module and the engine it composes only ever include or omit a whole
//! typed unit, never a compressed substitute for one), and CLI/MCP/SDK
//! exposure of the cache and suggestion additions (the existing `compact
//! task-context` CLI route, documented in
//! `docs/SEMANTIC-TASK-CONTEXT-V1.md`, wires the goal/budget surface only).
//! This is still one honestly-scoped slice, matching the precedent
//! `semantic_embedding` set for shipping one narrow slice of a large issue
//! rather than an unverifiable broader claim (see
//! `docs/SEMANTIC-EMBEDDING-V1.md`).
//!
//! # No cross-seed deduplication
//!
//! Two seeds whose closures overlap (for example, two functions that share
//! a common callee) each compile their **own** independent context; a
//! shared declaration's facts appear once per seed that reaches it, and its
//! token cost is charged once per seed. This module does not merge or
//! deduplicate declaration facts across seeds -- doing so would require
//! re-deriving the single-seed engine's own per-declaration facet rules,
//! which this module is designed specifically not to duplicate. A caller
//! that wants only the smallest possible closure over many related seeds
//! should still call the existing multi-seed-unaware engine directly with
//! the union of call sites as its one root, when that shape fits.
//!
//! # No ambient authority
//!
//! [`compile`] takes an already-parsed `&Program` and calls only
//! [`crate::graph::agent_context_v2_json`] and
//! [`crate::agent_economics::lexical_tokens`]. It opens no file, spawns no
//! process, and contacts no network. [`suggest_seeds`] additionally calls
//! [`crate::doc::document`] on the same already-parsed `&Program` plus a
//! caller-supplied `&Comments` -- it does not lex or read anything itself.
//! [`TaskContextCache`] holds compiled bytes only in process memory; it
//! opens no file and outlives nothing beyond the caller's own process.
//!
//! # Honesty bar
//!
//! This module claims exactly seven things: an explicit multi-seed goal
//! representation, an explicit and honestly labeled token-accounting unit
//! carrying its own algorithm-identity digest, deterministic whole-seed
//! selection under a real budget enforced (not advisory) at an exact
//! boundary, a cache-key digest sensitive to every field that determines the
//! output, a working (if unbounded, unevicting) in-memory cache keyed by
//! that digest and separated by caller-declared access scope, a
//! deterministic lexical seed *suggestion* that never influences selection
//! on its own, and a top-level summary of the shared inclusion policy's
//! exposable fields. It does not claim natural-language goal
//! *understanding*, cross-seed semantic deduplication, real content
//! summarization of an omitted or distant item, requirement/test/diagnostic
//! seed integration, cache eviction or persistence, or any CLI/MCP/SDK
//! surface for the cache and suggestion additions specifically (the existing
//! `compact task-context` route, described in
//! `docs/SEMANTIC-TASK-CONTEXT-V1.md`, covers goal/budget only).

use std::collections::{BTreeSet, HashMap};

use sha2::{Digest, Sha256};

use crate::agent_economics::lexical_tokens;
use crate::ast::Program;
use crate::diagnostic::{quote_json, Diagnostic};
use crate::digest_hex::LowerHex;
use crate::doc;
use crate::format::comments::Comments;
use crate::graph::{self, AgentContextV2Options};

/// Schema identity of the compiled goal-aware bundle this module renders.
pub const SCHEMA: &str = "semaprax.semantic-task-context.v1";
/// Smallest accepted token budget.
pub const MIN_MAX_TOKENS: usize = 1;
/// Largest accepted token budget. Generous on purpose: the unit-dependent
/// ceiling is enforced per seed by the underlying byte-bounded engine, not
/// here.
pub const MAX_MAX_TOKENS: usize = 64 * 1024 * 1024;

const DIGEST_DOMAIN: &[u8] = b"semaprax.semantic-task-context.goal-digest.v1\0";
/// Domain separator for [`cache_key`]'s input-only digest. Distinct from
/// [`DIGEST_DOMAIN`] on purpose: the two digests are never comparable, and a
/// value produced under one must never be mistaken for the other.
const CACHE_KEY_DOMAIN: &[u8] = b"semaprax.semantic-task-context.cache-key.v1\0";
/// Domain separator for each [`TokenizerId`]'s `byte-v1` algorithm identity.
const TOKENIZER_ALGORITHM_DOMAIN_BYTE: &[u8] =
    b"semaprax.semantic-task-context.tokenizer.byte-v1.utf8-byte-count.v1\0";
/// Domain separator for each [`TokenizerId`]'s `lexical-v1` algorithm
/// identity.
const TOKENIZER_ALGORITHM_DOMAIN_LEXICAL: &[u8] =
    b"semaprax.semantic-task-context.tokenizer.lexical-v1.agent-economics-lexical-tokens.v1\0";

fn option_error(message: String) -> Diagnostic {
    Diagnostic::io("SPX-Z801", message)
}

fn seed_error(message: String) -> Diagnostic {
    Diagnostic::io("SPX-Z802", message)
}

fn tokenizer_error(message: String) -> Diagnostic {
    Diagnostic::io("SPX-Z803", message)
}

fn seed_not_found(id: &str) -> Diagnostic {
    Diagnostic::io(
        "SPX-Z804",
        format!("goal seed `{id}` does not resolve to a context root"),
    )
}

/// One caller-declared contribution to a [`CompilationGoal`].
///
/// `reason` is untrusted, caller-supplied explanatory text (it may hold
/// natural language). It is echoed back in [`compile`]'s output for human
/// readers and never inspected by this module's selection logic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompilationSeed {
    id: String,
    priority: u32,
    reason: String,
}

impl CompilationSeed {
    #[must_use]
    pub fn new(id: impl Into<String>, priority: u32, reason: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            priority,
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// A structured goal: an explicit, deduplicated set of seeds. See the module
/// docs for why no natural-language text drives selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompilationGoal {
    seeds: Vec<CompilationSeed>,
}

impl CompilationGoal {
    pub fn new(seeds: Vec<CompilationSeed>) -> Result<Self, Diagnostic> {
        if seeds.is_empty() {
            return Err(seed_error(
                "a compilation goal requires at least one seed".to_owned(),
            ));
        }
        let mut ids = BTreeSet::new();
        for seed in &seeds {
            if seed.id.is_empty() {
                return Err(seed_error(
                    "a compilation seed id must be nonempty".to_owned(),
                ));
            }
            if !ids.insert(seed.id.as_str()) {
                return Err(seed_error(format!(
                    "seed `{}` is duplicated in this goal",
                    seed.id
                )));
            }
        }
        Ok(Self { seeds })
    }
}

/// One explicit, honestly labeled token-accounting unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenizerId {
    /// One unit per UTF-8 byte. Exact, but plainly not a model token.
    Byte,
    /// `agent_economics::lexical_tokens`. Always reported `"approximate"`.
    LexicalApprox,
}

impl TokenizerId {
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "byte-v1" => Some(Self::Byte),
            "lexical-v1" => Some(Self::LexicalApprox),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Byte => "byte-v1",
            Self::LexicalApprox => "lexical-v1",
        }
    }

    /// `"exact"` for `byte-v1` (an exact byte count, never claimed to be a
    /// model token), `"approximate"` for `lexical-v1` (a non-model lexical
    /// estimate). Neither claims a real model tokenizer's exact count.
    #[must_use]
    pub const fn exactness(self) -> &'static str {
        match self {
            Self::Byte => "exact",
            Self::LexicalApprox => "approximate",
        }
    }

    fn count(self, text: &str) -> usize {
        match self {
            Self::Byte => text.len(),
            Self::LexicalApprox => lexical_tokens(text),
        }
    }

    /// An explicit content digest of this tokenizer's exact counting
    /// algorithm, independent of and stricter than its short [`Self::name`].
    /// Folded into every [`compile`] bundle's `budget.tokenizer_digest` field
    /// and into every [`cache_key`]. Issue #197's failure list names
    /// "tokenizer version drift" -- a counting algorithm's behavior changing
    /// without its short name changing -- as a risk; this digest is the
    /// value a future change to either counting algorithm is obligated to
    /// bump, so a drift that forgets to also change `name()` still changes
    /// this digest and therefore still invalidates a cache keyed on it. This
    /// module cannot detect an undeclared drift by itself -- only a
    /// discipline of bumping the domain string below when behavior changes.
    #[must_use]
    pub fn algorithm_digest(self) -> String {
        let domain: &[u8] = match self {
            Self::Byte => TOKENIZER_ALGORITHM_DOMAIN_BYTE,
            Self::LexicalApprox => TOKENIZER_ALGORITHM_DOMAIN_LEXICAL,
        };
        let mut hasher = Sha256::new();
        hasher.update(domain);
        format!("sha256:{:x}", LowerHex(hasher.finalize()))
    }
}

/// Validated token budget for one [`compile`] call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompilationBudget {
    max_tokens: usize,
    tokenizer: TokenizerId,
}

impl CompilationBudget {
    /// Refuses an unsupported `tokenizer_name` (`SPX-Z803`) instead of
    /// silently falling back to a different unit, and refuses a `max_tokens`
    /// outside `MIN_MAX_TOKENS..=MAX_MAX_TOKENS` (`SPX-Z801`).
    pub fn new(max_tokens: usize, tokenizer_name: &str) -> Result<Self, Diagnostic> {
        let Some(tokenizer) = TokenizerId::parse(tokenizer_name) else {
            return Err(tokenizer_error(format!(
                "tokenizer `{tokenizer_name}` is unavailable; exact-token mode is refused rather \
                 than approximated. Use `byte-v1` (exact byte accounting, not a model token) or \
                 `lexical-v1` (approximate lexical-unit accounting, never reported as exact)"
            )));
        };
        if !(MIN_MAX_TOKENS..=MAX_MAX_TOKENS).contains(&max_tokens) {
            return Err(option_error(format!(
                "semantic task context max_tokens {max_tokens} is outside \
                 {MIN_MAX_TOKENS}..={MAX_MAX_TOKENS}"
            )));
        }
        Ok(Self {
            max_tokens,
            tokenizer,
        })
    }
}

struct CompiledSeed<'a> {
    seed: &'a CompilationSeed,
    json: String,
    tokens: usize,
}

/// The one deterministic seed order this module ever uses: descending
/// priority, then ascending stable ID. Shared by [`compile`]'s merge and
/// [`cache_key`]'s seed hashing so the two agree on what "the same goal"
/// means regardless of the caller's original list order.
fn seed_order_key(seed: &CompilationSeed) -> (std::cmp::Reverse<u32>, &str) {
    (std::cmp::Reverse(seed.priority), seed.id.as_str())
}

/// Compile one goal-aware, token-budgeted [`SCHEMA`] bundle.
///
/// Every seed is resolved by calling
/// [`crate::graph::agent_context_v2_json`] unchanged with `per_seed_options`
/// shared across every seed; an unresolved seed id fails the whole call
/// closed (`SPX-Z804`) rather than silently dropping it, because a goal's
/// seeds are explicit stable IDs the caller is expected to have already
/// resolved. See the module docs for the deterministic merge and budget
/// rules.
pub fn compile(
    program: &Program,
    goal: &CompilationGoal,
    per_seed_options: &AgentContextV2Options,
    budget: CompilationBudget,
) -> Result<String, Vec<Diagnostic>> {
    let source_revision = graph::revision(program);

    let mut compiled = Vec::with_capacity(goal.seeds.len());
    for seed in &goal.seeds {
        let json = graph::agent_context_v2_json(program, &seed.id, per_seed_options)?
            .ok_or_else(|| vec![seed_not_found(&seed.id)])?;
        let tokens = budget.tokenizer.count(&json);
        compiled.push(CompiledSeed { seed, json, tokens });
    }

    // Deterministic merge order: descending priority, then ascending stable
    // ID. Never the caller's list order or any hash-map iteration order.
    compiled.sort_by(|a, b| seed_order_key(a.seed).cmp(&seed_order_key(b.seed)));

    let mut used_tokens = 0usize;
    let mut entries = Vec::with_capacity(compiled.len());
    for item in &compiled {
        let included = used_tokens.saturating_add(item.tokens) <= budget.max_tokens;
        if included {
            used_tokens += item.tokens;
        }
        entries.push(render_entry(item, included));
    }

    let goal_digest = digest(&source_revision, budget, &compiled);

    Ok(format!(
        "{{\"schema\":{schema},\"source_revision\":{revision},\"goal_digest\":{digest},\
         \"budget\":{{\"tokenizer\":{tokenizer},\"tokenizer_digest\":{tokenizer_digest},\
         \"exactness\":{exactness},\"max_tokens\":{max_tokens},\
         \"used_tokens\":{used_tokens}}},\"policy\":{{\"depth\":{depth},\"max_bytes\":{max_bytes},\
         \"max_nodes\":{max_nodes},\"direction\":{direction}}},\"seeds\":[{entries}]}}",
        schema = quote_json(SCHEMA),
        revision = quote_json(&source_revision),
        digest = quote_json(&goal_digest),
        tokenizer = quote_json(budget.tokenizer.name()),
        tokenizer_digest = quote_json(&budget.tokenizer.algorithm_digest()),
        exactness = quote_json(budget.tokenizer.exactness()),
        max_tokens = budget.max_tokens,
        used_tokens = used_tokens,
        depth = per_seed_options.depth(),
        max_bytes = per_seed_options.max_bytes(),
        max_nodes = per_seed_options.max_nodes(),
        direction = quote_json(per_seed_options.direction().name()),
        entries = entries.join(","),
    ))
}

fn render_entry(item: &CompiledSeed<'_>, included: bool) -> String {
    if included {
        format!(
            "{{\"id\":{id},\"priority\":{priority},\"reason\":{reason},\"tokens\":{tokens},\
             \"status\":\"included\",\"context\":{context}}}",
            id = quote_json(&item.seed.id),
            priority = item.seed.priority,
            reason = quote_json(&item.seed.reason),
            tokens = item.tokens,
            context = item.json,
        )
    } else {
        format!(
            "{{\"id\":{id},\"priority\":{priority},\"reason\":{reason},\"tokens\":{tokens},\
             \"status\":\"omitted_budget_exhausted\"}}",
            id = quote_json(&item.seed.id),
            priority = item.seed.priority,
            reason = quote_json(&item.seed.reason),
            tokens = item.tokens,
        )
    }
}

/// A digest sensitive to every field that determines `compile`'s exact
/// output byte-for-byte: the source revision, the tokenizer and budget, and
/// each seed's identity, priority, reason, and exact compiled content -- in
/// the same order `compile` renders them in, so it is insensitive to the
/// order the caller originally listed seeds in, exactly like the rendered
/// output itself.
fn digest(
    source_revision: &str,
    budget: CompilationBudget,
    compiled: &[CompiledSeed<'_>],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    update_field(&mut hasher, SCHEMA.as_bytes());
    update_field(&mut hasher, source_revision.as_bytes());
    update_field(&mut hasher, budget.tokenizer.name().as_bytes());
    update_field(&mut hasher, budget.tokenizer.algorithm_digest().as_bytes());
    update_field(&mut hasher, &budget.max_tokens.to_le_bytes());
    for item in compiled {
        update_field(&mut hasher, item.seed.id.as_bytes());
        update_field(&mut hasher, &item.seed.priority.to_le_bytes());
        update_field(&mut hasher, item.seed.reason.as_bytes());
        update_field(&mut hasher, item.json.as_bytes());
    }
    format!("sha256:{:x}", LowerHex(hasher.finalize()))
}

fn update_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// An opaque, input-only cache key from [`cache_key`]. Unlike `compile`'s
/// `goal_digest` (which is computed *from* the compiled output and therefore
/// cannot be known before compiling), this key is computed entirely from the
/// declared inputs, so a caller -- or [`compile_cached`] -- can check for a
/// cache hit without paying for a fresh compile first.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CacheKey(String);

/// Compute the pre-compile cache key for one `(source_revision, goal,
/// per_seed_options, budget, access_scope)` input tuple.
///
/// Folds in, in order: the schema, the exact source revision, the tokenizer's
/// name and [`TokenizerId::algorithm_digest`], the budget's `max_tokens`, the
/// caller-declared `access_scope` (the security list's "context caching can
/// leak source across authorization boundaries" -- two calls with the same
/// revision/goal/policy/tokenizer/budget but different `access_scope` never
/// collide), the shared per-seed policy's `Debug` projection (this module has
/// no public accessor for every `AgentContextV2Options` field -- notably
/// `filters` -- so it hashes the same `Debug` text the engine itself would
/// print rather than re-deriving a private representation), and every seed's
/// identity/priority/reason in the same order-independent sequence
/// [`compile`] itself merges by (see [`seed_order_key`]), so listing one
/// goal's seeds in a different order yields the same key.
///
/// `access_scope` is opaque, caller-declared data (for example a workspace
/// or session id already established by the caller's own authorization
/// layer). This function does not itself perform or verify access control;
/// it only ensures two different scopes are never keyed identically.
#[must_use]
pub fn cache_key(
    source_revision: &str,
    goal: &CompilationGoal,
    per_seed_options: &AgentContextV2Options,
    budget: CompilationBudget,
    access_scope: &str,
) -> CacheKey {
    let mut hasher = Sha256::new();
    hasher.update(CACHE_KEY_DOMAIN);
    update_field(&mut hasher, SCHEMA.as_bytes());
    update_field(&mut hasher, source_revision.as_bytes());
    update_field(&mut hasher, budget.tokenizer.name().as_bytes());
    update_field(&mut hasher, budget.tokenizer.algorithm_digest().as_bytes());
    update_field(&mut hasher, &budget.max_tokens.to_le_bytes());
    update_field(&mut hasher, access_scope.as_bytes());
    update_field(&mut hasher, format!("{per_seed_options:?}").as_bytes());
    let mut ordered_seeds: Vec<&CompilationSeed> = goal.seeds.iter().collect();
    ordered_seeds.sort_by(|a, b| seed_order_key(a).cmp(&seed_order_key(b)));
    for seed in ordered_seeds {
        update_field(&mut hasher, seed.id.as_bytes());
        update_field(&mut hasher, &seed.priority.to_le_bytes());
        update_field(&mut hasher, seed.reason.as_bytes());
    }
    CacheKey(format!("sha256:{:x}", LowerHex(hasher.finalize())))
}

/// A plain in-memory replay cache for [`compile`]'s output, keyed by
/// [`CacheKey`].
///
/// This is intentionally minimal: no eviction, no expiry, no size bound, no
/// persistence across process restarts. It stores exactly the bytes
/// [`compile`] produced for a key and returns them only for that exact key --
/// it never repairs, merges, or reinterprets a stored value, and never
/// returns a value for a key it was never given (see `tests::` for the
/// invalidation properties this yields for a changed revision, tokenizer,
/// budget, policy, goal, or access scope).
#[derive(Debug, Default)]
pub struct TaskContextCache {
    entries: HashMap<String, String>,
}

impl TaskContextCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn get(&self, key: &CacheKey) -> Option<&str> {
        self.entries.get(&key.0).map(String::as_str)
    }

    pub fn insert(&mut self, key: CacheKey, value: String) {
        self.entries.insert(key.0, value);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// [`compile`], but through a [`TaskContextCache`]: on a cache hit, returns
/// the previously stored bytes without recompiling and reports `true`; on a
/// miss, compiles fresh, stores the result under this call's [`cache_key`],
/// and reports `false`. The source revision is read from `program` (via
/// [`crate::graph::revision`]) independently inside both this function and
/// `compile` itself; this function does not trust or accept a caller-supplied
/// revision, so a cache hit can only ever occur for the exact source this
/// call actually rechecked.
pub fn compile_cached(
    cache: &mut TaskContextCache,
    program: &Program,
    goal: &CompilationGoal,
    per_seed_options: &AgentContextV2Options,
    budget: CompilationBudget,
    access_scope: &str,
) -> Result<(String, bool), Vec<Diagnostic>> {
    let source_revision = graph::revision(program);
    let key = cache_key(
        &source_revision,
        goal,
        per_seed_options,
        budget,
        access_scope,
    );
    if let Some(cached) = cache.get(&key) {
        return Ok((cached.to_owned(), true));
    }
    let compiled = compile(program, goal, per_seed_options, budget)?;
    cache.insert(key, compiled.clone());
    Ok((compiled, false))
}

/// One deterministic lexical suggestion from [`suggest_seeds`]: a candidate
/// stable id and plain name, and the word-overlap score that ranked it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeedSuggestion {
    id: String,
    name: String,
    score: u32,
}

impl SeedSuggestion {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn score(&self) -> u32 {
        self.score
    }
}

/// Deterministic lexical seed *suggestion* over a module's declaration names
/// and leading doc comments (issue #197 step 2: "deterministic lexical
/// matching over names/docs" as "a seed suggestion, never a replacement for
/// semantic resolution"). `query` is untrusted, caller-supplied text -- like
/// a goal's natural-language description -- and is only ever split into
/// lowercase ASCII-alphanumeric words for a plain overlap count; it is never
/// parsed as a command, never executed, and never mutates `program` or
/// anything else. This function is pure and side-effect-free: nothing in
/// this module calls it, and it never builds, mutates, or feeds a
/// [`CompilationGoal`] on its own. A caller who wants a suggested id to
/// participate in [`compile`] must explicitly wrap it in
/// [`CompilationSeed::new`] and add it to a goal.
///
/// Ranked by descending overlap score, then ascending stable id to break
/// ties, so the result is deterministic for one `(program, comments, query)`
/// triple. A declaration matching no query word is omitted entirely (never
/// reported with a zero score). An empty or all-punctuation `query` yields
/// an empty result rather than matching everything.
#[must_use]
pub fn suggest_seeds(program: &Program, comments: &Comments, query: &str) -> Vec<SeedSuggestion> {
    let query_words = lexical_words(query);
    if query_words.is_empty() {
        return Vec::new();
    }
    let document = doc::document(program, comments);
    let mut suggestions: Vec<SeedSuggestion> = document
        .entries
        .iter()
        .filter_map(|entry| {
            let mut entry_words = lexical_words(&entry.name);
            for line in &entry.description {
                entry_words.extend(lexical_words(line));
            }
            let score = query_words.intersection(&entry_words).count();
            (score > 0).then(|| SeedSuggestion {
                id: entry.id.clone(),
                name: entry.name.clone(),
                score: score as u32,
            })
        })
        .collect();
    suggestions.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
    suggestions
}

/// Split `text` into a deduplicated set of lowercase ASCII-alphanumeric
/// words, on any non-alphanumeric ASCII boundary. Deliberately simple and
/// deterministic: this is a suggestion heuristic, never a claim of natural-
/// language understanding.
fn lexical_words(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

#[cfg(test)]
mod tests;
