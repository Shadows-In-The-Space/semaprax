//! Closed one-shot binding data. Neither requests nor replies confer authority.
use super::super::{
    DoctorOfflineArchitecture, DoctorOfflineTool, ProbeError, DOCTOR_OFFLINE_INPUT_MAX_BYTES,
};
use super::Error;
use sha2::{Digest, Sha256};

pub(in crate::doctor) const MAX_REQUEST_BYTES: usize = 149;
pub(in crate::doctor) const MAX_REPLY_BYTES: usize = 3 * 65_536 + 128;
const REQUEST_MAGIC: &[u8; 8] = b"SPXDWK1\0";
const REPLY_MAGIC: &[u8; 8] = b"SPXDWR1\0";
const REPLY_HEADER: usize = 77;
// The wire status byte an `Exit` row carries, and the fixed trailer size a
// worker may attach to that one status. No other status may carry a trailer;
// `validate_reply` enforces that below. This is diagnostic-only: `ReplyRow`'s
// `Err` arm stays the bare `ProbeError` it always was, so nothing here changes
// what a collector or the contracted `semaprax.doctor.v1` report can observe.
const EXIT_STATUS_CODE: u8 = 4;
const EXIT_DETAIL_BYTES: usize = 2;
const EXIT_DETAIL_FLAGS_BYTES: usize = 1;
pub(super) const MAX_EXIT_STDERR_BYTES: usize = 4096;

/// How the confined tool child actually terminated, observed by the worker's
/// own `waitpid` on its exact owned PID. This is strictly richer than the
/// `ProbeError::Exit` it accompanies; it never travels through `ReplyRow`,
/// `SettledDoctorTool::output`, or the settled report -- only through the
/// `Exit` row's optional trailer, decoded solely by `decode_exit_detail` for
/// diagnostic callers (tests, hostile fixtures).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::doctor) enum Termination {
    /// The child called `_exit`/`exit` (or ran off the end of `main`) with
    /// this `WEXITSTATUS` code. Codes 10..=23 are this worker's own
    /// pre-`execve` `fail_stop_with` markers (see `child.rs`); any other
    /// value is the real tool's own exit code.
    Exited(u8),
    /// The child was killed by this `WTERMSIG` signal before it could exit.
    Signaled(i32),
}

impl Termination {
    pub(in crate::doctor) fn success(self) -> bool {
        matches!(self, Termination::Exited(0))
    }
}

/// Bounded diagnostic information carried only by an `Exit` row. It is not
/// tool stdout and never reaches `ReplyRow` or a settled doctor report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ExitDetail {
    pub(super) termination: Termination,
    pub(super) stderr: Vec<u8>,
    pub(super) stderr_truncated: bool,
}

fn encode_termination(value: Termination) -> Option<[u8; EXIT_DETAIL_BYTES]> {
    match value {
        Termination::Exited(code) => Some([0, code]),
        Termination::Signaled(signal) => u8::try_from(signal)
            .ok()
            .filter(|signal| *signal != 0)
            .map(|signal| [1, signal]),
    }
}

fn encode_exit_detail(detail: &ExitDetail) -> Result<Vec<u8>, Error> {
    if detail.stderr.len() > MAX_EXIT_STDERR_BYTES
        || (detail.stderr_truncated && detail.stderr.len() != MAX_EXIT_STDERR_BYTES)
    {
        return Err(Error::Limit);
    }
    let termination = encode_termination(detail.termination).ok_or(Error::Invalid)?;
    if detail.stderr.is_empty() && !detail.stderr_truncated {
        return Ok(termination.to_vec());
    }
    let length = EXIT_DETAIL_BYTES
        .checked_add(EXIT_DETAIL_FLAGS_BYTES)
        .and_then(|length| length.checked_add(detail.stderr.len()))
        .ok_or(Error::Limit)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::Allocation)?;
    bytes.extend_from_slice(&termination);
    bytes.push(u8::from(detail.stderr_truncated));
    bytes.extend_from_slice(&detail.stderr);
    Ok(bytes)
}

fn validate_exit_detail(bytes: &[u8]) -> Result<(), Error> {
    match bytes.len() {
        0 => Ok(()),
        // Preserve already-published termination-only diagnostic frames.
        EXIT_DETAIL_BYTES => decode_termination(bytes).ok_or(Error::Invalid).map(|_| ()),
        length
            if (EXIT_DETAIL_BYTES + EXIT_DETAIL_FLAGS_BYTES
                ..=EXIT_DETAIL_BYTES + EXIT_DETAIL_FLAGS_BYTES + MAX_EXIT_STDERR_BYTES)
                .contains(&length) =>
        {
            let _ = decode_termination(&bytes[..EXIT_DETAIL_BYTES]).ok_or(Error::Invalid)?;
            let truncated = match bytes[EXIT_DETAIL_BYTES] {
                0 => false,
                1 => true,
                _ => return Err(Error::Invalid),
            };
            if truncated
                && length != EXIT_DETAIL_BYTES + EXIT_DETAIL_FLAGS_BYTES + MAX_EXIT_STDERR_BYTES
            {
                return Err(Error::Invalid);
            }
            Ok(())
        }
        _ => Err(Error::Invalid),
    }
}

fn decode_termination(bytes: &[u8]) -> Option<Termination> {
    match *bytes {
        [0, code] => Some(Termination::Exited(code)),
        // `waitpid` never reports signal zero as a terminating signal. Reject
        // it in the diagnostic trailer too, so hostile bytes cannot invent a
        // physically impossible "signaled(0)" observation. This trailer is
        // diagnostic-only, but it must still be a faithful projection of the
        // worker's exact wait status.
        [1, signal] if signal != 0 => Some(Termination::Signaled(i32::from(signal))),
        _ => None,
    }
}

/// Diagnostic-only companion to `validate_reply`, for a reply already known to
/// be well-formed. Recovers the fixed `Termination` an `Exit` row's trailer
/// carries, if the worker attached one. Never consulted by `ReplyRow`, the
/// production collector, or anything reaching the contracted
/// `semaprax.doctor.v1` report -- exclusively for tests and hostile fixtures
/// composing a richer panic message than the bare `ProbeError` variant. Its
/// only callers are `#[cfg(test)]` code (this crate's own wire tests and the
/// hostile `offline_worker::tests`), so it is compiled only for `cfg(test)`.
#[cfg(test)]
pub(super) fn decode_exit_detail(bytes: &[u8], role: u8) -> Option<ExitDetail> {
    let mut cursor = REPLY_HEADER;
    loop {
        let current_role = *bytes.get(cursor)?;
        let status = *bytes.get(cursor + 1)?;
        let length = usize::try_from(u32::from_le_bytes(
            bytes.get(cursor + 2..cursor + 6)?.try_into().ok()?,
        ))
        .ok()?;
        let payload_start = cursor + 6;
        let payload = bytes.get(payload_start..payload_start.checked_add(length)?)?;
        if current_role == role {
            if status != EXIT_STATUS_CODE
                || validate_exit_detail(payload).is_err()
                || payload.is_empty()
            {
                return None;
            }
            let termination = decode_termination(&payload[..EXIT_DETAIL_BYTES])?;
            let (stderr_truncated, stderr) = if payload.len() == EXIT_DETAIL_BYTES {
                (false, Vec::new())
            } else {
                (
                    payload[EXIT_DETAIL_BYTES] == 1,
                    payload[EXIT_DETAIL_BYTES + 1..].to_vec(),
                )
            };
            return Some(ExitDetail {
                termination,
                stderr,
                stderr_truncated,
            });
        }
        cursor = payload_start + length;
    }
}

#[derive(Debug)]
pub(in crate::doctor) struct Request {
    pub(super) nonce: [u8; 32],
    pub(super) digest: [u8; 32],
    pub(in crate::doctor) bundle_digest: [u8; 32],
    pub(in crate::doctor) bundle_len: usize,
    pub(in crate::doctor) architecture: DoctorOfflineArchitecture,
    pub(in crate::doctor) target: u8,
    pub(super) roles: u8,
    pub(in crate::doctor) selector: String,
}

impl Request {
    pub(in crate::doctor) fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(Error::Limit);
        }
        let mut cursor = 0;
        if take(bytes, &mut cursor, 8)? != REQUEST_MAGIC || byte(bytes, &mut cursor)? != 1 {
            return Err(Error::Invalid);
        }
        let architecture = match byte(bytes, &mut cursor)? {
            1 => DoctorOfflineArchitecture::LinuxX86_64,
            2 => DoctorOfflineArchitecture::LinuxAarch64,
            _ => return Err(Error::Invalid),
        };
        let target = byte(bytes, &mut cursor)?;
        let expected_roles = match target {
            0 => 4,
            1 => 1,
            2 => 2,
            3 => 7,
            _ => return Err(Error::Invalid),
        };
        let roles = byte(bytes, &mut cursor)?;
        if roles != expected_roles {
            return Err(Error::Invalid);
        }
        let nonce = array(bytes, &mut cursor)?;
        if nonce == [0; 32] {
            return Err(Error::Invalid);
        }
        let length = u64::from_le_bytes(array(bytes, &mut cursor)?);
        let bundle_len = usize::try_from(length).map_err(|_| Error::Limit)?;
        if bundle_len == 0 {
            return Err(Error::Invalid);
        }
        if bundle_len > DOCTOR_OFFLINE_INPUT_MAX_BYTES {
            return Err(Error::Limit);
        }
        let bundle_digest = array(bytes, &mut cursor)?;
        let selector_len = usize::from(byte(bytes, &mut cursor)?);
        if selector_len > 64 {
            return Err(Error::Limit);
        }
        let selector_bytes = take(bytes, &mut cursor, selector_len)?;
        if cursor != bytes.len()
            || selector_bytes.is_empty()
            || !selector_bytes[0].is_ascii_lowercase()
            || !selector_bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        {
            return Err(Error::Invalid);
        }
        let mut selector = String::new();
        selector
            .try_reserve_exact(selector_len)
            .map_err(|_| Error::Allocation)?;
        selector.push_str(std::str::from_utf8(selector_bytes).map_err(|_| Error::Invalid)?);
        Ok(Self {
            nonce,
            digest: Sha256::digest(bytes).into(),
            bundle_digest,
            bundle_len,
            architecture,
            target,
            roles,
            selector,
        })
    }

    pub(in crate::doctor) fn roles(&self) -> impl Iterator<Item = (u8, DoctorOfflineTool)> + '_ {
        [
            (1, DoctorOfflineTool::Clang),
            (2, DoctorOfflineTool::Node),
            (4, DoctorOfflineTool::Rustc),
        ]
        .into_iter()
        .filter(|(role, _)| self.roles & role != 0)
    }

    fn platform(&self) -> [u8; 4] {
        let architecture = match self.architecture {
            DoctorOfflineArchitecture::LinuxX86_64 => 1,
            DoctorOfflineArchitecture::LinuxAarch64 => 2,
        };
        [1, architecture, self.target, self.roles]
    }
}

pub(in crate::doctor) type ReplyRow = (u8, Result<Vec<u8>, ProbeError>);

// `exit_detail` is a diagnostic-only, purely additive supplement for a role
// whose row is `Err(ProbeError::Exit)`. A role with no matching entry (or
// whose row is not `Exit`) gets the exact zero-length trailer this function
// always emitted; an empty slice reproduces prior byte-for-byte output.
pub(super) fn encode_reply(
    request: &Request,
    rows: &[ReplyRow],
    exit_detail: &[(u8, ExitDetail)],
) -> Result<Vec<u8>, Error> {
    if rows.len() != request.roles().count() {
        return Err(Error::Invalid);
    }
    let trailer_for = |role: u8, value: &Result<Vec<u8>, ProbeError>| {
        if !matches!(value, Err(ProbeError::Exit)) {
            return Ok(Vec::new());
        }
        exit_detail
            .iter()
            .find(|(candidate, _)| *candidate == role)
            .map_or_else(|| Ok(Vec::new()), |(_, detail)| encode_exit_detail(detail))
    };
    let mut length = REPLY_HEADER;
    for ((role, value), (expected, _)) in rows.iter().zip(request.roles()) {
        if *role != expected {
            return Err(Error::Invalid);
        }
        let payload_len = value.as_ref().map_or(0, Vec::len);
        if payload_len > 65_536 {
            return Err(Error::Limit);
        }
        let trailer_len = trailer_for(*role, value)?.len();
        length = length
            .checked_add(6 + payload_len + trailer_len)
            .filter(|length| *length <= MAX_REPLY_BYTES)
            .ok_or(Error::Limit)?;
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| Error::Allocation)?;
    output.extend_from_slice(REPLY_MAGIC);
    output.extend_from_slice(&request.digest);
    output.extend_from_slice(&request.nonce);
    output.extend_from_slice(&request.platform());
    output.push(u8::try_from(rows.len()).map_err(|_| Error::Limit)?);
    for (role, value) in rows {
        output.push(*role);
        match value {
            Ok(payload) => {
                output.push(0);
                output.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                output.extend_from_slice(payload);
            }
            Err(error) => {
                output.push(encode_error(*error));
                let trailer = trailer_for(*role, value)?;
                output.extend_from_slice(&(trailer.len() as u32).to_le_bytes());
                output.extend_from_slice(&trailer);
            }
        }
    }
    Ok(output)
}

/// Validate only byte binding and shape. The collector separately owns the live
/// worker, endpoint, successful termination and descendant-settlement proof.
pub(in crate::doctor) fn validate_reply(
    request: &Request,
    bytes: &[u8],
) -> Result<Vec<ReplyRow>, Error> {
    if bytes.len() > MAX_REPLY_BYTES {
        return Err(Error::Limit);
    }
    let mut cursor = 0;
    if take(bytes, &mut cursor, 8)? != REPLY_MAGIC
        || take(bytes, &mut cursor, 32)? != request.digest
        || take(bytes, &mut cursor, 32)? != request.nonce
        || take(bytes, &mut cursor, 4)? != request.platform()
        || usize::from(byte(bytes, &mut cursor)?) != request.roles().count()
    {
        return Err(Error::Invalid);
    }
    // Validate the complete frame before allocating any returned payload.
    let rows_start = cursor;
    for (expected_role, _) in request.roles() {
        if byte(bytes, &mut cursor)? != expected_role {
            return Err(Error::Invalid);
        }
        let status = byte(bytes, &mut cursor)?;
        let length = usize::try_from(u32::from_le_bytes(array(bytes, &mut cursor)?))
            .map_err(|_| Error::Limit)?;
        if length > 65_536 {
            return Err(Error::Limit);
        }
        // Every status keeps its prior exact-zero-length rule except `Exit`,
        // which may additionally carry the fixed diagnostic trailer decoded
        // by `decode_exit_detail`. `ReplyRow`'s value is unaffected either
        // way: the trailer bytes are consumed below and never returned.
        if status > 7 || (status != 0 && status != EXIT_STATUS_CODE && length != 0) {
            return Err(Error::Invalid);
        }
        let payload = take(bytes, &mut cursor, length)?;
        if status == EXIT_STATUS_CODE && validate_exit_detail(payload).is_err() {
            return Err(Error::Invalid);
        }
    }
    if cursor != bytes.len() {
        return Err(Error::Invalid);
    }
    let mut rows = Vec::new();
    rows.try_reserve_exact(request.roles().count())
        .map_err(|_| Error::Allocation)?;
    cursor = rows_start;
    for _ in request.roles() {
        let role = byte(bytes, &mut cursor)?;
        let status = byte(bytes, &mut cursor)?;
        let length = usize::try_from(u32::from_le_bytes(array(bytes, &mut cursor)?))
            .map_err(|_| Error::Limit)?;
        let payload = take(bytes, &mut cursor, length)?;
        let value = if status == 0 {
            let mut output = Vec::new();
            output
                .try_reserve_exact(length)
                .map_err(|_| Error::Allocation)?;
            output.extend_from_slice(payload);
            Ok(output)
        } else {
            Err(decode_error(status)?)
        };
        rows.push((role, value));
    }
    Ok(rows)
}

fn encode_error(error: ProbeError) -> u8 {
    match error {
        ProbeError::Invalid => 1,
        ProbeError::Unsupported => 2,
        ProbeError::Spawn => 3,
        ProbeError::Exit => EXIT_STATUS_CODE,
        ProbeError::OutputLimit => 5,
        ProbeError::Timeout => 6,
        ProbeError::Io => 7,
    }
}

fn decode_error(status: u8) -> Result<ProbeError, Error> {
    match status {
        1 => Ok(ProbeError::Invalid),
        2 => Ok(ProbeError::Unsupported),
        3 => Ok(ProbeError::Spawn),
        EXIT_STATUS_CODE => Ok(ProbeError::Exit),
        5 => Ok(ProbeError::OutputLimit),
        6 => Ok(ProbeError::Timeout),
        7 => Ok(ProbeError::Io),
        _ => Err(Error::Invalid),
    }
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], Error> {
    let end = cursor.checked_add(length).ok_or(Error::Invalid)?;
    let slice = bytes.get(*cursor..end).ok_or(Error::Invalid)?;
    *cursor = end;
    Ok(slice)
}

fn byte(bytes: &[u8], cursor: &mut usize) -> Result<u8, Error> {
    Ok(take(bytes, cursor, 1)?[0])
}

fn array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], Error> {
    take(bytes, cursor, N)?
        .try_into()
        .map_err(|_| Error::Invalid)
}

#[cfg(test)]
mod tests;
