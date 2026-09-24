//! One bounded local composition of mirror byte acquisition, signed proof,
//! held generation commit, and a live lock-bound artifact read. This module
//! grants no durable network or store capability beyond the authorities its
//! caller already holds.

use super::*;
use crate::diagnostic::Diagnostic;
use crate::package_registry::mirror_transport::{
    MirrorError, MirrorNetworkAuthority, MirrorObject, MirrorObjectKind, MirrorRequest,
    MirrorTransport,
};
use crate::package_registry::trust::registry_v3::{
    verify_mirror_update, verify_update, MirrorCheckpoint, MirrorMetadataPaths, UpdateInputs,
};
use crate::package_registry::trust::InstalledRoot;

/// One exact remote artifact object and its separately signed logical
/// coordinate. Remote paths do not become local filesystem paths.
pub struct MirrorArtifact<'a> {
    pub object: MirrorObject<'a>,
    pub package: &'a str,
    pub version: &'a str,
    pub path: &'a str,
}

/// The one lock-selected artifact returned after the held generation commits.
pub struct MirrorArtifactSelection<'a> {
    pub package: &'a str,
    pub version: &'a str,
    pub path: &'a str,
}

/// All caller-owned inputs for one local mirror-to-held-store transaction.
/// The root, sealed registry, lock and trusted times remain explicit; remote
/// bytes cannot supply or replace any of them.
pub struct MirrorFlowRequest<'registry, 'input> {
    pub root: &'input InstalledRoot,
    pub checkpoint: &'input MirrorCheckpoint,
    pub metadata_paths: &'input MirrorMetadataPaths<'registry, 'input>,
    pub metadata_objects: &'input [MirrorObject<'input>],
    pub artifacts: &'input [MirrorArtifact<'input>],
    pub lock: &'input str,
    pub subjects: &'input [String],
    pub read: MirrorArtifactSelection<'input>,
    pub update_time: u64,
    pub read_time: u64,
}

/// Closed error routing. Acquired response bodies and native error text never
/// escape this boundary.
pub enum MirrorFlowError {
    Acquisition(MirrorError),
    Proof(Diagnostic),
    /// The generation pivot succeeded, but the required final live read did
    /// not. The caller must retain this evidence and use normal held-store
    /// recovery/revalidation rather than treating the result as no-effect.
    PostCommit {
        checkpoint: MirrorCheckpoint,
        commit: CommitReceipt,
        error: Diagnostic,
    },
}
impl std::fmt::Debug for MirrorFlowError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Acquisition(error) => formatter.debug_tuple("Acquisition").field(error).finish(),
            Self::Proof(error) => formatter.debug_tuple("Proof").field(error).finish(),
            Self::PostCommit { commit, error, .. } => formatter
                .debug_struct("PostCommit")
                .field("generation_digest", &commit.generation_digest)
                .field("checkpoint_digest", &commit.checkpoint_digest)
                .field("error", error)
                .finish(),
        }
    }
}

/// Evidence from one completed local flow. `checkpoint` is bridge-local state
/// for a later mirror verification; neither it nor the receipt restores held
/// store or network authority.
pub struct MirrorFlowResult {
    pub checkpoint: MirrorCheckpoint,
    pub commit: CommitReceipt,
    pub artifact: VerifiedArtifact,
}

/// Acquires caller-named immutable bytes, proves their signed metadata against
/// independently held facts, commits the existing Host-v2 generation, then
/// performs one live lock-bound artifact read. It intentionally does not
/// discover objects, select versions, install roots, populate a resolver cache
/// or execute returned bytes.
pub fn acquire_commit_and_read<'registry, T: MirrorTransport>(
    authority: &MirrorNetworkAuthority,
    transport: &mut T,
    store: &mut HeldTrustStore,
    request: &MirrorFlowRequest<'registry, '_>,
) -> std::result::Result<MirrorFlowResult, MirrorFlowError> {
    if !request.checkpoint.is_initial()
        || crate::audit_capsule::sha256_digest(
            request
                .checkpoint
                .registry_checkpoint()
                .canonical_bytes()
                .as_bytes(),
        ) != store.receipt().checkpoint_digest
    {
        return Err(MirrorFlowError::Proof(Diagnostic::io(
            "SPX-PKR623",
            "mirror flow only admits the matching held bootstrap checkpoint",
        )));
    }
    if request
        .metadata_objects
        .iter()
        .any(|object| object.kind != MirrorObjectKind::Metadata)
        || request
            .artifacts
            .iter()
            .any(|artifact| artifact.object.kind != MirrorObjectKind::Artifact)
        || request
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.package == request.read.package
                    && artifact.version == request.read.version
                    && artifact.path == request.read.path
            })
            .count()
            != 1
    {
        return Err(MirrorFlowError::Acquisition(MirrorError::InvalidRequest));
    }
    if request.read_time < request.update_time {
        return Err(MirrorFlowError::Proof(Diagnostic::io(
            "SPX-PKR623",
            "mirror flow read time precedes its update time",
        )));
    }

    let objects = request
        .metadata_objects
        .iter()
        .copied()
        .chain(request.artifacts.iter().map(|artifact| artifact.object))
        .collect::<Vec<_>>();
    let downloaded = authority
        .acquire(transport, &MirrorRequest { objects: &objects })
        .map_err(MirrorFlowError::Acquisition)?;
    let metadata_count = request.metadata_objects.len();
    let (metadata, artifact_bytes) = downloaded.split_at(metadata_count);
    let candidate = verify_mirror_update(
        request.root,
        request.checkpoint,
        request.update_time,
        request.metadata_paths,
        metadata,
    )
    .map_err(MirrorFlowError::Proof)?;
    candidate
        .check_lock(request.lock, request.subjects)
        .map_err(MirrorFlowError::Proof)?;
    for (artifact, bytes) in request.artifacts.iter().zip(artifact_bytes) {
        candidate
            .check_artifact(
                artifact.package,
                artifact.version,
                artifact.path,
                bytes.bytes(),
            )
            .map_err(MirrorFlowError::Proof)?;
    }

    let metadata = |path| {
        metadata
            .iter()
            .find(|bytes| bytes.path == path)
            .and_then(|bytes| std::str::from_utf8(bytes.bytes()).ok())
            .ok_or_else(|| {
                MirrorFlowError::Proof(Diagnostic::io(
                    "SPX-PKR621",
                    "proved mirror metadata could not be recovered",
                ))
            })
    };
    let timestamp = metadata(request.metadata_paths.timestamp_path)?;
    let snapshot = metadata(request.metadata_paths.snapshot_path)?;
    let publishers = request
        .metadata_paths
        .publishers
        .iter()
        .map(|publisher| Ok((publisher.role, metadata(publisher.path)?)))
        .collect::<std::result::Result<Vec<_>, MirrorFlowError>>()?;
    let artifacts = request
        .artifacts
        .iter()
        .zip(artifact_bytes)
        .map(|(artifact, bytes)| Artifact {
            package: artifact.package,
            version: artifact.version,
            path: artifact.path,
            bytes: bytes.bytes(),
        })
        .collect::<Vec<_>>();
    // Preflight the exact later read time before the held commit. This keeps
    // an expired or otherwise non-readable caller request from producing a
    // durable generation that cannot satisfy this flow's promised live read.
    let read_candidate = verify_update(
        request.root,
        candidate.checkpoint().registry_checkpoint(),
        request.read_time,
        &UpdateInputs {
            timestamp,
            snapshot,
            publishers: &publishers,
            registry: request.metadata_paths.registry,
        },
    )
    .map_err(MirrorFlowError::Proof)?;
    read_candidate
        .check_lock(request.lock, request.subjects)
        .map_err(MirrorFlowError::Proof)?;
    let selected = request
        .artifacts
        .iter()
        .zip(artifact_bytes)
        .find(|(artifact, _)| {
            artifact.package == request.read.package
                && artifact.version == request.read.version
                && artifact.path == request.read.path
        })
        .ok_or_else(|| {
            MirrorFlowError::Proof(Diagnostic::io(
                "SPX-PKR624",
                "selected mirror artifact disappeared before preflight",
            ))
        })?;
    read_candidate
        .check_artifact(
            request.read.package,
            request.read.version,
            request.read.path,
            selected.1.bytes(),
        )
        .map_err(MirrorFlowError::Proof)?;
    let update = Update {
        metadata: UpdateInputs {
            timestamp,
            snapshot,
            publishers: &publishers,
            registry: request.metadata_paths.registry,
        },
        rotation: None,
        lock: request.lock,
        subjects: request.subjects,
        artifacts: &artifacts,
        trusted_time: request.update_time,
    };
    let commit = store
        .commit_update(&update)
        .map_err(MirrorFlowError::Proof)?;
    let checkpoint = candidate.checkpoint().clone();
    let artifact = match store.read_artifact(&ArtifactRead {
        expected_generation_digest: &commit.generation_digest,
        lock: request.lock,
        registry: request.metadata_paths.registry,
        package: request.read.package,
        version: request.read.version,
        path: request.read.path,
        trusted_time: request.read_time,
    }) {
        Ok(artifact) => artifact,
        Err(error) => {
            return Err(MirrorFlowError::PostCommit {
                checkpoint,
                commit,
                error,
            });
        }
    };
    Ok(MirrorFlowResult {
        checkpoint,
        commit,
        artifact,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package_registry::mirror_transport::{MirrorGet, MirrorOrigin, MirrorResponse};
    use crate::package_registry::trust::registry_v3::tests::host_fixture;
    use std::collections::VecDeque;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    static SERIAL: AtomicU64 = AtomicU64::new(0);

    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "semaprax-registry-v3-online-{}-{}",
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
    fn corrupt_signature(metadata: &str) -> String {
        let mut bytes = metadata.as_bytes().to_vec();
        let offset = bytes
            .windows(7)
            .position(|window| window == b"\"sig\":\"")
            .unwrap()
            + 7;
        bytes[offset] = if bytes[offset] == b'a' { b'b' } else { b'a' };
        String::from_utf8(bytes).unwrap()
    }
    fn authority() -> MirrorNetworkAuthority {
        MirrorNetworkAuthority::new(
            MirrorOrigin::parse("https://mirror.example.test/").unwrap(),
            Duration::from_secs(1),
        )
        .unwrap()
    }

    #[test]
    fn acquired_signed_metadata_commits_then_returns_live_lock_bound_artifact() {
        let (root_bytes, timestamp, snapshot, publishers, admitted) = host_fixture(false, 1);
        let root = InstalledRoot::from_independently_installed_bytes(&root_bytes).unwrap();
        let checkpoint = MirrorCheckpoint::initial_at(&root, 90);
        let temp = Temp::new();
        let pin = crate::audit_capsule::sha256_digest(root_bytes.as_bytes());
        let mut store = HeldTrustStore::install(&temp.0, &root_bytes, &pin, 90).unwrap();
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
        let publishers_paths = [
            crate::package_registry::trust::registry_v3::MirrorPublisherPath {
                role: "publisher-app",
                path: "/metadata/publisher-app.json",
            },
            crate::package_registry::trust::registry_v3::MirrorPublisherPath {
                role: "publisher-lib",
                path: "/metadata/publisher-lib.json",
            },
        ];
        let metadata_paths = MirrorMetadataPaths {
            timestamp_path: "/metadata/timestamp.json",
            snapshot_path: "/metadata/snapshot.json",
            publishers: &publishers_paths,
            registry: &admitted.0,
        };
        let fault_temp = Temp::new();
        let mut fault_store =
            HeldTrustStore::install(&fault_temp.0, &root_bytes, &pin, 90).unwrap();
        let old_active = std::fs::read(fault_temp.0.join("ACTIVE")).unwrap();
        let fault_directory = fault_temp.0.clone();
        super::super::read::BEFORE_RELEASE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::write(fault_directory.join("ACTIVE"), old_active).unwrap();
            }))
        });
        let mut fault_mirror = ScriptedMirror {
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
        let fault = match acquire_commit_and_read(
            &authority(),
            &mut fault_mirror,
            &mut fault_store,
            &MirrorFlowRequest {
                root: &root,
                checkpoint: &checkpoint,
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
        ) {
            Ok(_) => panic!("post-commit read fault unexpectedly accepted"),
            Err(error) => error,
        };
        match fault {
            MirrorFlowError::PostCommit {
                checkpoint,
                commit,
                error,
            } => {
                assert_eq!(error.code, "SPX-PKR626");
                assert_eq!(
                    crate::audit_capsule::sha256_digest(
                        checkpoint
                            .registry_checkpoint()
                            .canonical_bytes()
                            .as_bytes()
                    ),
                    commit.checkpoint_digest
                );
            }
            other => panic!("post-commit read fault failed through wrong path: {other:?}"),
        }
        assert_eq!(fault_mirror.calls, 6);
        let tampered_timestamp = corrupt_signature(&timestamp);
        let tampered_digest = crate::audit_capsule::sha256_digest(tampered_timestamp.as_bytes());
        let mut tampered_metadata = metadata;
        tampered_metadata[0].digest = &tampered_digest;
        let mut tampered_mirror = ScriptedMirror {
            replies: VecDeque::from([
                response("/metadata/timestamp.json", tampered_timestamp.as_bytes()),
                response("/metadata/snapshot.json", snapshot.as_bytes()),
                response("/metadata/publisher-app.json", publishers[0].as_bytes()),
                response("/metadata/publisher-lib.json", publishers[1].as_bytes()),
                response("/artifacts/app-root.wasm", &admitted.3),
                response("/artifacts/lib-leaf.wasm", &admitted.4),
            ]),
            calls: 0,
        };
        let error = match acquire_commit_and_read(
            &authority(),
            &mut tampered_mirror,
            &mut store,
            &MirrorFlowRequest {
                root: &root,
                checkpoint: &checkpoint,
                metadata_paths: &metadata_paths,
                metadata_objects: &tampered_metadata,
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
        ) {
            Ok(_) => panic!("tampered timestamp unexpectedly accepted"),
            Err(error) => error,
        };
        match error {
            MirrorFlowError::Proof(error) => assert_eq!(error.code, "SPX-PKR622"),
            MirrorFlowError::Acquisition(error) => {
                panic!("timestamp mutation unexpectedly failed acquisition: {error:?}")
            }
            other => panic!("timestamp mutation failed through wrong path: {other:?}"),
        }
        assert_eq!(tampered_mirror.calls, 6);
        assert_eq!(store.receipt().generation_digest, before);
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
        let result = acquire_commit_and_read(
            &authority(),
            &mut mirror,
            &mut store,
            &MirrorFlowRequest {
                root: &root,
                checkpoint: &checkpoint,
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
        )
        .unwrap();
        assert_eq!(mirror.calls, 6);
        assert_ne!(result.commit.generation_digest, before);
        assert_eq!(result.artifact.bytes(), admitted.3);
        assert_eq!(result.artifact.package(), "app.root");
        assert_eq!(
            result.artifact.lock_digest(),
            crate::audit_capsule::sha256_digest(admitted.2.as_bytes())
        );
        assert_eq!(
            crate::audit_capsule::sha256_digest(
                result
                    .checkpoint
                    .registry_checkpoint()
                    .canonical_bytes()
                    .as_bytes()
            ),
            store.receipt().checkpoint_digest
        );
        let committed_generation = result.commit.generation_digest.clone();
        let reset = MirrorCheckpoint::initial_at(&root, 90);
        let mut reset_mirror = ScriptedMirror {
            replies: VecDeque::new(),
            calls: 0,
        };
        let reset_error = match acquire_commit_and_read(
            &authority(),
            &mut reset_mirror,
            &mut store,
            &MirrorFlowRequest {
                root: &root,
                checkpoint: &reset,
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
                update_time: 100
                    + crate::package_registry::trust::registry_v3::MAX_MIRROR_OFFLINE_SECONDS
                    + 1,
                read_time: 100
                    + crate::package_registry::trust::registry_v3::MAX_MIRROR_OFFLINE_SECONDS
                    + 1,
            },
        ) {
            Ok(_) => panic!("initial checkpoint reset unexpectedly accepted"),
            Err(error) => error,
        };
        match reset_error {
            MirrorFlowError::Proof(error) => assert_eq!(error.code, "SPX-PKR623"),
            other => panic!("initial checkpoint reset failed through wrong path: {other:?}"),
        }
        assert_eq!(reset_mirror.calls, 0);
        assert_eq!(store.receipt().generation_digest, committed_generation);
        let mut resume_mirror = ScriptedMirror {
            replies: VecDeque::new(),
            calls: 0,
        };
        let resume_error = match acquire_commit_and_read(
            &authority(),
            &mut resume_mirror,
            &mut store,
            &MirrorFlowRequest {
                root: &root,
                checkpoint: &result.checkpoint,
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
                update_time: 101,
                read_time: 101,
            },
        ) {
            Ok(_) => panic!("mirror refresh unexpectedly accepted"),
            Err(error) => error,
        };
        match resume_error {
            MirrorFlowError::Proof(error) => assert_eq!(error.code, "SPX-PKR623"),
            other => panic!("mirror refresh failed through wrong path: {other:?}"),
        }
        assert_eq!(resume_mirror.calls, 0);
        assert_eq!(store.receipt().generation_digest, committed_generation);
    }

    #[test]
    fn unselected_artifact_refuses_before_network_or_held_generation_effects() {
        let (root_bytes, _, _, _, admitted) = host_fixture(false, 1);
        let root = InstalledRoot::from_independently_installed_bytes(&root_bytes).unwrap();
        let checkpoint = MirrorCheckpoint::initial_at(&root, 90);
        let temp = Temp::new();
        let pin = crate::audit_capsule::sha256_digest(root_bytes.as_bytes());
        let mut store = HeldTrustStore::install(&temp.0, &root_bytes, &pin, 90).unwrap();
        let before = store.receipt().generation_digest;
        let paths = MirrorMetadataPaths {
            timestamp_path: "/metadata/timestamp.json",
            snapshot_path: "/metadata/snapshot.json",
            publishers: &[],
            registry: &admitted.0,
        };
        let mut mirror = ScriptedMirror {
            replies: VecDeque::new(),
            calls: 0,
        };
        let wrong_time = MirrorCheckpoint::initial_at(&root, 89);
        let wrong_time_error = match acquire_commit_and_read(
            &authority(),
            &mut mirror,
            &mut store,
            &MirrorFlowRequest {
                root: &root,
                checkpoint: &wrong_time,
                metadata_paths: &paths,
                metadata_objects: &[],
                artifacts: &[],
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
        ) {
            Ok(_) => panic!("wrong bootstrap time unexpectedly accepted"),
            Err(error) => error,
        };
        match wrong_time_error {
            MirrorFlowError::Proof(error) => assert_eq!(error.code, "SPX-PKR623"),
            other => panic!("wrong bootstrap time failed through wrong path: {other:?}"),
        }
        assert_eq!(mirror.calls, 0);
        assert_eq!(store.receipt().generation_digest, before);
        let error = match acquire_commit_and_read(
            &authority(),
            &mut mirror,
            &mut store,
            &MirrorFlowRequest {
                root: &root,
                checkpoint: &checkpoint,
                metadata_paths: &paths,
                metadata_objects: &[],
                artifacts: &[],
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
        ) {
            Ok(_) => panic!("unselected artifact unexpectedly accepted"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            MirrorFlowError::Acquisition(MirrorError::InvalidRequest)
        ));
        assert_eq!(mirror.calls, 0);
        assert_eq!(store.receipt().generation_digest, before);
    }
}
