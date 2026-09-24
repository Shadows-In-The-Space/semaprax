//! No-clobber local filesystem writer for one OCI Image Layout directory.
//!
//! This module has exactly one effect: create a fresh directory tree at a
//! caller-chosen path and fill it with the bytes [`super::render`] already
//! computed. It never overwrites an existing path, never deletes anything,
//! never contacts a network, and never invokes another process.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use super::{validation, OciError};

pub(crate) struct RenderedLayout {
    pub(crate) oci_layout: Vec<u8>,
    pub(crate) config_bytes: Vec<u8>,
    pub(crate) config_digest_hex: String,
    pub(crate) layer_bytes: Vec<u8>,
    pub(crate) layer_digest_hex: String,
    pub(crate) manifest_bytes: Vec<u8>,
    pub(crate) manifest_digest_hex: String,
    pub(crate) index_bytes: Vec<u8>,
}

/// Write one content-addressed blob. Content-addressed storage legitimately
/// deduplicates: if two distinct logical blobs happen to hash identically
/// (only possible if their bytes are also identical), the second write finds
/// the first blob already sitting at the digest name it would have written
/// itself, so this only re-verifies the existing bytes rather than treating
/// the coincidence as a clobber. Any other pre-existing content, or any
/// non-`AlreadyExists` I/O failure, still fails the publication.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), OciError> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(bytes).map_err(OciError::publication_io)?;
            file.flush().map_err(OciError::publication_io)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if fs::read(path).map_err(OciError::publication_io)? == bytes {
                Ok(())
            } else {
                Err(OciError::publication_verification())
            }
        }
        Err(error) => Err(OciError::publication_io(error)),
    }
}

fn read_back(path: &Path) -> Result<Vec<u8>, OciError> {
    fs::read(path).map_err(OciError::publication_io)
}

/// Create the output directory (refusing an existing path outright) and
/// write every layout file, then read every file back and reject the whole
/// publication if anything on disk disagrees with what was just rendered.
pub(crate) fn publish(output: &Path, layout: &RenderedLayout) -> Result<(), OciError> {
    if !validation::path_is_free_of_nul_bytes(output) {
        return Err(OciError::identity("output path contains a NUL byte"));
    }
    if output.as_os_str().is_empty() {
        return Err(OciError::identity("output path is empty"));
    }
    fs::create_dir(output).map_err(OciError::publication_io)?;
    let blobs_root: PathBuf = output.join("blobs").join("sha256");
    fs::create_dir(output.join("blobs")).map_err(OciError::publication_io)?;
    fs::create_dir(&blobs_root).map_err(OciError::publication_io)?;

    write_new(&output.join("oci-layout"), &layout.oci_layout)?;
    write_new(
        &blobs_root.join(&layout.config_digest_hex),
        &layout.config_bytes,
    )?;
    write_new(
        &blobs_root.join(&layout.layer_digest_hex),
        &layout.layer_bytes,
    )?;
    write_new(
        &blobs_root.join(&layout.manifest_digest_hex),
        &layout.manifest_bytes,
    )?;
    write_new(&output.join("index.json"), &layout.index_bytes)?;

    // Read every file back rather than trusting the write path succeeded
    // silently: a short write or a concurrent actor replacing a just-created
    // file must fail this publication, not return a bundle whose digests
    // disagree with what is actually on disk.
    if read_back(&output.join("oci-layout"))? != layout.oci_layout
        || read_back(&blobs_root.join(&layout.config_digest_hex))? != layout.config_bytes
        || read_back(&blobs_root.join(&layout.layer_digest_hex))? != layout.layer_bytes
        || read_back(&blobs_root.join(&layout.manifest_digest_hex))? != layout.manifest_bytes
        || read_back(&output.join("index.json"))? != layout.index_bytes
    {
        return Err(OciError::publication_verification());
    }
    Ok(())
}
