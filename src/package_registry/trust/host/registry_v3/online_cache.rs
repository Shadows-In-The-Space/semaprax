//! Local composition from mirror proof through a held generation to an
//! ordinary resolver cache and deterministic Lock-v3 replay. The cache path
//! is explicit; neither cache bytes nor resolution evidence grant authority.

use super::*;
use crate::diagnostic::Diagnostic;
use crate::package_registry::mirror_transport::{MirrorNetworkAuthority, MirrorTransport};
use crate::package_resolver_v2 as resolver;
use std::path::Path;

/// Caller-selected deterministic resolution inputs other than the signed
/// subjects, which are recovered only from the authenticated cache receipt.
pub struct MirrorResolutionTemplate<'input> {
    pub requirements: &'input [resolver::Requirement],
    pub target: &'input str,
    pub allowed_capabilities: &'input [String],
    pub options: resolver::ResolutionOptions,
}

/// One explicit local composition. The mirror portion retains all of the
/// sealed metadata, lock and logical artifact bindings of `MirrorFlowRequest`.
/// The cache path is ordinary destination authority, not a discovery route.
pub struct MirrorCacheFlowRequest<'registry, 'input> {
    pub mirror: MirrorFlowRequest<'registry, 'input>,
    pub cache_path: &'input Path,
    /// Fixed cache verification time. It cannot predate the final held read.
    pub cache_time: u64,
    pub resolution: MirrorResolutionTemplate<'input>,
}

/// The full evidence from a completed local mirror-to-cache resolution.
pub struct MirrorCacheFlowResult {
    pub checkpoint: crate::package_registry::trust::registry_v3::MirrorCheckpoint,
    pub commit: CommitReceipt,
    pub artifact: VerifiedArtifact,
    pub cache: CacheFillReceipt,
    pub resolution_evidence: String,
    pub resolved: resolver::VerifiedResolution,
}

/// Failure routing for the composed route. `Mirror` retains the original
/// no-effect/uncertain/post-commit distinction. Cache publication has no
/// cross-store rollback, so every cache failure is conservatively a possible
/// retained-prefix outcome and never returns a cache receipt.
pub enum MirrorCacheFlowError {
    Mirror(MirrorFlowError),
    CachePartial {
        checkpoint: crate::package_registry::trust::registry_v3::MirrorCheckpoint,
        commit: CommitReceipt,
        errors: Vec<Diagnostic>,
    },
    /// Cache publication settled and supplied its receipt, but deterministic
    /// cache-file replay, resolver evidence, or root/leaf Lock-v3 association
    /// did not. The cache receipt is evidence only, not read authority.
    Resolution {
        checkpoint: crate::package_registry::trust::registry_v3::MirrorCheckpoint,
        commit: CommitReceipt,
        cache: CacheFillReceipt,
        errors: Vec<Diagnostic>,
    },
}

impl std::fmt::Debug for MirrorCacheFlowError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mirror(error) => formatter.debug_tuple("Mirror").field(error).finish(),
            Self::CachePartial { commit, errors, .. } => formatter
                .debug_struct("CachePartial")
                .field("generation_digest", &commit.generation_digest)
                .field("errors", errors)
                .finish(),
            Self::Resolution {
                commit,
                cache,
                errors,
                ..
            } => formatter
                .debug_struct("Resolution")
                .field("generation_digest", &commit.generation_digest)
                .field("cache_generation_digest", &cache.generation_digest)
                .field("errors", errors)
                .finish(),
        }
    }
}

fn error(message: &str) -> Diagnostic {
    Diagnostic::io("SPX-PKR626", message)
}

fn copy_receipt(receipt: &CommitReceipt) -> CommitReceipt {
    CommitReceipt {
        generation_digest: receipt.generation_digest.clone(),
        checkpoint_digest: receipt.checkpoint_digest.clone(),
    }
}

fn names(receipt: &CacheFillReceipt) -> std::result::Result<Vec<String>, Diagnostic> {
    if receipt.subjects.is_empty()
        || receipt.subjects.len() > crate::package_resolver_v2::MAX_SUBJECTS
    {
        return Err(error(
            "cache receipt subject count is outside the resolver bound",
        ));
    }
    receipt
        .subjects
        .iter()
        .map(|subject| {
            let hex = subject
                .subject_digest
                .strip_prefix("sha256:")
                .filter(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
                .ok_or_else(|| error("cache receipt subject digest is not canonical"))?;
            Ok(format!("{hex}.json"))
        })
        .collect()
}

fn authenticate_receipt_subjects(
    receipt: &CacheFillReceipt,
    subjects: &[String],
) -> std::result::Result<(), Diagnostic> {
    if receipt.subjects.len() != subjects.len() {
        return Err(error("cache receipt and subject inventory disagree"));
    }
    for (receipt, bytes) in receipt.subjects.iter().zip(subjects) {
        let subject = crate::package_lock_v3::verify_dependency_subject(bytes)?;
        if subject.coordinate.package != receipt.package
            || subject.coordinate.version != receipt.version
            || subject.subject_digest != receipt.subject_digest
        {
            return Err(error("cache subject does not match its receipt inventory"));
        }
    }
    Ok(())
}

/// Acquires exact mirror bytes, commits an authenticated held generation,
/// publishes the exact selected Subject-v3 inventory to one caller-selected
/// cache, then independently recreates and verifies Resolver-v2/Lock-v3
/// evidence from bounded nofollow cache reads. It never discovers a mirror,
/// root, cache or resolver input, and it executes no returned bytes.
pub fn acquire_commit_cache_and_resolve<'registry, T: MirrorTransport>(
    authority: &MirrorNetworkAuthority,
    transport: &mut T,
    store: &mut HeldTrustStore,
    request: &MirrorCacheFlowRequest<'registry, '_>,
) -> std::result::Result<MirrorCacheFlowResult, MirrorCacheFlowError> {
    if request.cache_time < request.mirror.read_time {
        return Err(MirrorCacheFlowError::Mirror(MirrorFlowError::Proof(
            Diagnostic::io(
                "SPX-PKR623",
                "cache time precedes the required held artifact read",
            ),
        )));
    }
    let flow = acquire_commit_and_read(authority, transport, store, &request.mirror)
        .map_err(MirrorCacheFlowError::Mirror)?;
    let checkpoint = flow.checkpoint;
    let commit = flow.commit;
    let artifact = flow.artifact;
    let cache = store
        .populate_resolver_cache(
            request.cache_path,
            &CacheFill {
                expected_generation_digest: &commit.generation_digest,
                lock: request.mirror.lock,
                registry: request.mirror.metadata_paths.registry,
                trusted_time: request.cache_time,
            },
        )
        .map_err(|errors| MirrorCacheFlowError::CachePartial {
            checkpoint: checkpoint.clone(),
            commit: copy_receipt(&commit),
            errors,
        })?;
    let resolve =
        || -> std::result::Result<(String, resolver::VerifiedResolution), Vec<Diagnostic>> {
            if cache.generation_digest != commit.generation_digest
                || cache.lock_digest != super::hash(request.mirror.lock.as_bytes())
            {
                return Err(vec![error(
                    "cache receipt does not bind the committed generation and lock",
                )]);
            }
            let names = names(&cache).map_err(|error| vec![error])?;
            let subjects = crate::package_cache_host::read_bound(request.cache_path, &names)?;
            authenticate_receipt_subjects(&cache, &subjects).map_err(|error| vec![error])?;
            let input = resolver::ResolutionInput {
                requirements: request.resolution.requirements.to_vec(),
                subjects,
                target: request.resolution.target.to_owned(),
                allowed_capabilities: request.resolution.allowed_capabilities.to_vec(),
            };
            let evidence = resolver::generate(&input, &request.resolution.options)?;
            let verified = resolver::verify(&evidence, &input, &request.resolution.options)
                .map_err(|error| vec![error])?;
            if verified.lock != request.mirror.lock {
                return Err(vec![error(
                    "resolver Lock-v3 differs from the sealed mirror lock",
                )]);
            }
            crate::package_registry::registry_v3::verify_lock_selection(
                request.mirror.metadata_paths.registry,
                &verified.lock,
                &input.subjects,
            )
            .map_err(|error| vec![error])?;
            Ok((evidence, verified))
        };
    let (resolution_evidence, resolved) = match resolve() {
        Ok(resolved) => resolved,
        Err(errors) => {
            return Err(MirrorCacheFlowError::Resolution {
                checkpoint,
                commit,
                cache,
                errors,
            });
        }
    };
    Ok(MirrorCacheFlowResult {
        checkpoint,
        commit,
        artifact,
        cache,
        resolution_evidence,
        resolved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package_registry::mirror_transport::{
        MirrorError, MirrorGet, MirrorObject, MirrorObjectKind, MirrorOrigin, MirrorResponse,
    };
    use crate::package_registry::trust::registry_v3::{
        tests::host_fixture, MirrorMetadataPaths, MirrorPublisherPath,
    };
    use std::collections::VecDeque;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    static SERIAL: AtomicU64 = AtomicU64::new(0);

    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "semaprax-registry-v3-online-cache-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct ScriptedMirror {
        replies: VecDeque<MirrorResponse>,
        calls: usize,
    }
    impl MirrorTransport for ScriptedMirror {
        fn get(
            &mut self,
            request: MirrorGet<'_>,
        ) -> std::result::Result<MirrorResponse, MirrorError> {
            assert!(request.url().starts_with("https://mirror.example.test/"));
            self.calls += 1;
            self.replies.pop_front().ok_or(MirrorError::TransportFailed)
        }
    }

    fn object<'a>(
        kind: MirrorObjectKind,
        path: &'a str,
        digest: &'a str,
        bytes: &[u8],
    ) -> MirrorObject<'a> {
        MirrorObject {
            kind,
            path,
            digest,
            max_bytes: bytes.len(),
        }
    }
    fn response(path: &str, bytes: &[u8]) -> MirrorResponse {
        MirrorResponse {
            status: 200,
            final_url: format!("https://mirror.example.test{path}"),
            body: bytes.to_vec(),
        }
    }
    fn authority() -> MirrorNetworkAuthority {
        MirrorNetworkAuthority::new(
            MirrorOrigin::parse("https://mirror.example.test/").unwrap(),
            Duration::from_secs(1),
        )
        .unwrap()
    }

    fn run(
        cache: &Path,
        target: &str,
    ) -> (
        std::result::Result<MirrorCacheFlowResult, MirrorCacheFlowError>,
        usize,
        String,
    ) {
        let (root_bytes, timestamp, snapshot, publishers, admitted) = host_fixture(false, 1);
        let source = Temp::new();
        let pin = crate::audit_capsule::sha256_digest(root_bytes.as_bytes());
        let mut store = HeldTrustStore::install(&source.0, &root_bytes, &pin, 90).unwrap();
        let before = store.receipt().generation_digest;
        let metadata_digests = [
            crate::audit_capsule::sha256_digest(timestamp.as_bytes()),
            crate::audit_capsule::sha256_digest(snapshot.as_bytes()),
            crate::audit_capsule::sha256_digest(publishers[0].as_bytes()),
            crate::audit_capsule::sha256_digest(publishers[1].as_bytes()),
        ];
        let artifact_digests = [
            crate::audit_capsule::sha256_digest(&admitted.3),
            crate::audit_capsule::sha256_digest(&admitted.4),
        ];
        let metadata = [
            object(
                MirrorObjectKind::Metadata,
                "/metadata/timestamp.json",
                &metadata_digests[0],
                timestamp.as_bytes(),
            ),
            object(
                MirrorObjectKind::Metadata,
                "/metadata/snapshot.json",
                &metadata_digests[1],
                snapshot.as_bytes(),
            ),
            object(
                MirrorObjectKind::Metadata,
                "/metadata/publisher-app.json",
                &metadata_digests[2],
                publishers[0].as_bytes(),
            ),
            object(
                MirrorObjectKind::Metadata,
                "/metadata/publisher-lib.json",
                &metadata_digests[3],
                publishers[1].as_bytes(),
            ),
        ];
        let artifacts = [
            MirrorArtifact {
                object: object(
                    MirrorObjectKind::Artifact,
                    "/artifacts/app-root.wasm",
                    &artifact_digests[0],
                    &admitted.3,
                ),
                package: "app.root",
                version: "1.0.0",
                path: "module.wasm",
            },
            MirrorArtifact {
                object: object(
                    MirrorObjectKind::Artifact,
                    "/artifacts/lib-leaf.wasm",
                    &artifact_digests[1],
                    &admitted.4,
                ),
                package: "lib.leaf",
                version: "1.0.0",
                path: "module.wasm",
            },
        ];
        let publisher_paths = [
            MirrorPublisherPath {
                role: "publisher-app",
                path: "/metadata/publisher-app.json",
            },
            MirrorPublisherPath {
                role: "publisher-lib",
                path: "/metadata/publisher-lib.json",
            },
        ];
        let metadata_paths = MirrorMetadataPaths {
            timestamp_path: "/metadata/timestamp.json",
            snapshot_path: "/metadata/snapshot.json",
            publishers: &publisher_paths,
            registry: &admitted.0,
        };
        let mut mirror = ScriptedMirror {
            replies: VecDeque::from([
                response("/metadata/timestamp.json", timestamp.as_bytes()),
                response("/metadata/snapshot.json", snapshot.as_bytes()),
                response("/metadata/publisher-app.json", publishers[0].as_bytes()),
                response("/metadata/publisher-lib.json", publishers[1].as_bytes()),
                response("/artifacts/app-root.wasm", &admitted.3),
                response("/artifacts/lib-leaf.wasm", &admitted.4),
            ]),
            calls: 0,
        };
        let result = acquire_commit_cache_and_resolve(
            &authority(),
            &mut mirror,
            &mut store,
            &MirrorCacheFlowRequest {
                mirror: MirrorFlowRequest {
                    metadata_paths: &metadata_paths,
                    metadata_objects: &metadata,
                    artifacts: &artifacts,
                    lock: &admitted.2,
                    subjects: &admitted.1,
                    read: MirrorArtifactSelection {
                        package: "app.root",
                        version: "1.0.0",
                        path: "module.wasm",
                    },
                    update_time: 100,
                    read_time: 100,
                },
                cache_path: cache,
                cache_time: 100,
                resolution: MirrorResolutionTemplate {
                    requirements: &[resolver::Requirement {
                        package: "app.root".into(),
                        range: "=1.0.0".into(),
                    }],
                    target,
                    allowed_capabilities: &[],
                    options: Default::default(),
                },
            },
        );
        (result, mirror.calls, before)
    }

    #[test]
    fn cache_path_refusal_after_mirror_commit_is_partial_without_outside_effects() {
        let destination = Temp::new();
        let outside = Temp::new();
        let cache = destination.0.join("cache");
        symlink(&outside.0, &cache).unwrap();
        let (result, calls, before) = run(&cache, "wasm32");
        match result {
            Err(MirrorCacheFlowError::CachePartial {
                checkpoint,
                commit,
                errors,
            }) => {
                assert_ne!(commit.generation_digest, before);
                assert_eq!(
                    crate::audit_capsule::sha256_digest(
                        checkpoint
                            .registry_checkpoint()
                            .canonical_bytes()
                            .as_bytes()
                    ),
                    commit.checkpoint_digest
                );
                assert!(format!("{errors:?}").contains("SPX-J128"));
            }
            Err(other) => panic!("cache refusal took wrong outcome: {other:?}"),
            Ok(_) => panic!("symlink cache path unexpectedly returned a receipt"),
        }
        assert_eq!(calls, 6);
        assert_eq!(std::fs::read_dir(&outside.0).unwrap().count(), 0);
    }

    #[test]
    fn post_cache_resolution_failure_retains_cache_receipt_without_outside_effects() {
        let destination = Temp::new();
        let outside = Temp::new();
        let cache = destination.0.join("cache");
        let (result, calls, before) = run(&cache, "unknown-target");
        match result {
            Err(MirrorCacheFlowError::Resolution {
                checkpoint,
                commit,
                cache: receipt,
                errors,
            }) => {
                assert_ne!(commit.generation_digest, before);
                assert_eq!(receipt.generation_digest, commit.generation_digest);
                assert_eq!(receipt.subjects.len(), 2);
                assert_eq!(
                    crate::audit_capsule::sha256_digest(
                        checkpoint
                            .registry_checkpoint()
                            .canonical_bytes()
                            .as_bytes()
                    ),
                    commit.checkpoint_digest
                );
                assert!(!errors.is_empty());
            }
            Err(other) => panic!("post-cache resolver failure took wrong outcome: {other:?}"),
            Ok(_) => panic!("unknown target unexpectedly resolved"),
        }
        assert_eq!(calls, 6);
        assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 2);
        assert_eq!(std::fs::read_dir(&outside.0).unwrap().count(), 0);
    }
}
