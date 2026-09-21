use sha2::{Digest as _, Sha256};

use super::*;

fn hash(seed: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    format!(
        "sha256:{:x}",
        crate::digest_hex::LowerHex(hasher.finalize())
    )
}

pub(crate) fn fixture(seed: &str) -> PackageArtifactManifestInput {
    PackageArtifactManifestInput {
        package: "examples.meaning".to_owned(),
        version: "1.0.0".to_owned(),
        capsule_digest: hash(&format!("capsule:{seed}")),
        content_digest: hash(&format!("content:{seed}")),
        api_abi_digest: hash(&format!("api-abi:{seed}")),
        target_profile: TARGET_PROFILE.to_owned(),
        features: FEATURES.map(str::to_owned).to_vec(),
        effects: Vec::new(),
        capabilities: Vec::new(),
        artifacts: [
            ("core-wasm-module", "module.wasm"),
            ("build-evidence", "semaprax.package-build.evidence.json"),
            ("build-manifest", "semaprax.package-build.json"),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (role, path))| ArtifactRow {
            role: role.to_owned(),
            path: path.to_owned(),
            bytes: index + 1,
            sha256: hash(&format!("{seed}:{path}")),
            profile: TARGET_PROFILE.to_owned(),
        })
        .collect(),
    }
}

fn canonical() -> PackageArtifactManifest {
    create(fixture("alpha")).expect("canonical package artifact manifest")
}

#[test]
fn canonical_manifest_independently_replays() {
    let manifest = canonical();
    let decoded = decode(manifest.bytes()).expect("decode canonical bytes");
    assert_eq!(decoded, manifest);
    assert_eq!(
        verify(manifest.bytes(), manifest.digest()).expect("digest replay"),
        manifest
    );
}

#[test]
fn digest_is_domain_separated_from_plain_sha256() {
    let manifest = canonical();
    assert_ne!(manifest.digest(), hash(manifest.bytes()));
    assert_eq!(manifest.digest(), canonical().digest());
}

#[test]
fn unknown_missing_duplicate_and_reordered_fields_are_refused() {
    let bytes = canonical().bytes().to_owned();
    let unknown = bytes.replacen("\"schema\":", "\"unknown\":0,\"schema\":", 1);
    let missing = bytes.replacen("\"effects\":[],", "", 1);
    let duplicate = bytes.replacen(
        "\"schema\":",
        &format!("\"schema\":{},\"schema\":", quote_json(SCHEMA)),
        1,
    );
    let reordered = bytes.replacen(
        &format!(
            "\"package\":{},\"version\":{}",
            quote_json("examples.meaning"),
            quote_json("1.0.0")
        ),
        &format!(
            "\"version\":{},\"package\":{}",
            quote_json("1.0.0"),
            quote_json("examples.meaning")
        ),
        1,
    );
    for hostile in [unknown, missing, duplicate, reordered] {
        assert_eq!(decode(&hostile).unwrap_err().code, "SPX-PKR614");
    }
}

#[test]
fn noncanonical_trailing_depth_work_and_byte_hostiles_are_bounded() {
    let bytes = canonical().bytes().to_owned();
    for hostile in [
        format!(" {bytes}"),
        format!("{bytes}\n"),
        format!("{bytes}null"),
    ] {
        assert_eq!(decode(&hostile).unwrap_err().code, "SPX-PKR614");
    }
    let deep = format!("{}0{}", "[".repeat(40), "]".repeat(40));
    assert_eq!(decode(&deep).unwrap_err().code, "SPX-PKR614");
    let work = format!(
        "[{}]",
        std::iter::repeat_n("0", 4_100)
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(decode(&work).unwrap_err().code, "SPX-PKR614");
    let oversized = "x".repeat(MAX_MANIFEST_BYTES + 1);
    assert_eq!(decode(&oversized).unwrap_err().code, "SPX-PKR614");
}

#[test]
fn cross_profile_and_digest_substitution_are_refused() {
    let mut wrong_profile = fixture("alpha");
    wrong_profile.target_profile = "native64".to_owned();
    assert_eq!(create(wrong_profile).unwrap_err().code, "SPX-PKR616");

    let manifest = canonical();
    assert_eq!(
        verify(manifest.bytes(), &hash("another manifest"))
            .unwrap_err()
            .code,
        "SPX-PKR615"
    );
}

#[test]
fn inventories_refuse_traversal_control_duplicates_reordering_missing_extra_and_splices() {
    let mutate = |f: fn(&mut PackageArtifactManifestInput)| {
        let mut input = fixture("alpha");
        f(&mut input);
        create(input).unwrap_err().code
    };
    assert_eq!(
        mutate(|input| input.artifacts[0].path = "../module.wasm".to_owned()),
        "SPX-PKR616"
    );
    assert_eq!(
        mutate(|input| input.artifacts[0].path = "module\n.wasm".to_owned()),
        "SPX-PKR616"
    );
    assert_eq!(
        mutate(|input| input.features.push("scalar-exports".to_owned())),
        "SPX-PKR616"
    );
    assert_eq!(mutate(|input| input.features.reverse()), "SPX-PKR616");
    assert_eq!(
        mutate(|input| {
            input.features.pop();
        }),
        "SPX-PKR616"
    );
    assert_eq!(
        mutate(|input| input.features.push("wasi".to_owned())),
        "SPX-PKR616"
    );
    assert_eq!(mutate(|input| input.artifacts.swap(0, 1)), "SPX-PKR616");
    assert_eq!(
        mutate(|input| {
            input.artifacts.pop();
        }),
        "SPX-PKR616"
    );
    assert_eq!(
        mutate(|input| input.artifacts.push(input.artifacts[0].clone())),
        "SPX-PKR616"
    );
    assert_eq!(
        mutate(|input| input.artifacts[1] = fixture("beta").artifacts[0].clone()),
        "SPX-PKR616"
    );
    assert_eq!(
        mutate(|input| input.effects.push("filesystem.read".to_owned())),
        "SPX-PKR616"
    );
    assert_eq!(
        mutate(|input| input.capabilities.push("network".to_owned())),
        "SPX-PKR616"
    );
}

#[test]
fn decoder_source_has_no_authority_surface() {
    let source = include_str!("../artifact_manifest.rs");
    for forbidden in [
        "std::fs",
        "std::process",
        "std::net",
        "Command::new",
        "File::open",
        "TcpStream",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden authority: {forbidden}"
        );
    }
}

#[test]
fn cumulative_artifact_bound_accepts_boundary_and_refuses_plus_one() {
    assert_eq!(
        checked_artifact_total(crate::package_build_v2::MAX_ARTIFACT_BYTES - 2, 1, 1)
            .expect("exact boundary"),
        crate::package_build_v2::MAX_ARTIFACT_BYTES
    );
    assert_eq!(
        checked_artifact_total(crate::package_build_v2::MAX_ARTIFACT_BYTES - 1, 1, 1)
            .unwrap_err()
            .code,
        "SPX-PKR617"
    );

    let mut boundary = fixture("boundary");
    boundary.artifacts[0].bytes = crate::package_build_v2::MAX_ARTIFACT_BYTES - 2;
    boundary.artifacts[1].bytes = 1;
    boundary.artifacts[2].bytes = 1;
    let canonical = create(boundary).expect("canonical exact-boundary manifest");
    assert!(decode(canonical.bytes()).is_ok());

    let mut plus_one = fixture("plus-one");
    plus_one.artifacts[0].bytes = crate::package_build_v2::MAX_ARTIFACT_BYTES - 1;
    plus_one.artifacts[1].bytes = 1;
    plus_one.artifacts[2].bytes = 1;
    let hostile = render(&plus_one);
    assert_eq!(decode(&hostile).unwrap_err().code, "SPX-PKR617");

    let mut forty_eight_mib = fixture("forty-eight-mib");
    for row in &mut forty_eight_mib.artifacts {
        row.bytes = crate::package_build_v2::MAX_ARTIFACT_BYTES;
    }
    let hostile = render(&forty_eight_mib);
    assert_eq!(decode(&hostile).unwrap_err().code, "SPX-PKR617");
}
