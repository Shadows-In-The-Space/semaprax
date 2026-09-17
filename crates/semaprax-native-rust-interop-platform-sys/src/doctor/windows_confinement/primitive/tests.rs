//! These tests exercise only the pure, syscall-free helpers in
//! [`super`] (`wide`, `forced_environment`, the UI-limit bitmask). They are
//! real `#[test]` functions that a Windows-capable session's `cargo test`
//! will run under this crate's `--lib doctor::windows_confinement` filter
//! (see the proposed gate in `DOCTOR-PRODUCTION-PROVISIONER-WINDOWS-V1.md`);
//! this whole file is `#[cfg(windows)]` by virtue of `super`'s module
//! declaration, so it has never been compiled or run on this authoring host
//! (macOS arm64, no Windows toolchain). The full spawn/settle path
//! (`confined_spawn`, `settle`) needs a live process and a real job object
//! and is intentionally not exercised here at all -- it belongs in the
//! hostile-input corpus a Windows-capable session adds once this primitive
//! has real execution evidence, analogous to
//! `doctor::darwin_confinement::tests`.
use super::*;

#[test]
fn wide_rejects_empty_oversized_and_interior_nul() {
    assert_eq!(wide(OsStr::new("")), Err(()));
    assert!(wide(OsStr::new("plain")).is_ok());
    let with_nul: std::ffi::OsString = {
        use std::os::windows::ffi::OsStringExt;
        std::ffi::OsString::from_wide(&[u16::from(b'a'), 0, u16::from(b'b')])
    };
    assert_eq!(wide(&with_nul), Err(()));
    let oversized: std::ffi::OsString = {
        use std::os::windows::ffi::OsStringExt;
        std::ffi::OsString::from_wide(&vec![u16::from(b'x'); MAX_WIDE])
    };
    assert_eq!(wide(&oversized), Err(()));
    let at_the_edge: std::ffi::OsString = {
        use std::os::windows::ffi::OsStringExt;
        std::ffi::OsString::from_wide(&vec![u16::from(b'x'); MAX_WIDE - 1])
    };
    assert!(wide(&at_the_edge).is_ok());
}

#[test]
fn wide_appends_exactly_one_terminating_nul() {
    let encoded = wide(OsStr::new("ok")).unwrap();
    assert_eq!(encoded.last(), Some(&0));
    assert_eq!(encoded.iter().filter(|unit| **unit == 0).count(), 1);
}

#[test]
fn forced_environment_pins_temp_and_tmp_to_the_scratch_dir_sorted_and_double_nul_terminated() {
    let scratch = Path::new(r"C:\scratch\dir");
    let block = forced_environment(scratch).unwrap();
    let text = String::from_utf16(&block[..block.len() - 1]).unwrap();
    let rows: Vec<&str> = text.trim_end_matches('\0').split('\0').collect();
    assert_eq!(rows, vec![r"TEMP=C:\scratch\dir", r"TMP=C:\scratch\dir"]);
    assert_eq!(&block[block.len() - 2..], &[0, 0]);
}

#[test]
fn denied_ui_limits_covers_every_documented_flag_exactly_once() {
    let expected = JOB_OBJECT_UILIMIT_HANDLES
        | JOB_OBJECT_UILIMIT_READCLIPBOARD
        | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
        | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
        | JOB_OBJECT_UILIMIT_DESKTOP
        | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
        | JOB_OBJECT_UILIMIT_GLOBALATOMS
        | JOB_OBJECT_UILIMIT_EXITWINDOWS;
    assert_eq!(DENIED_UI_LIMITS, expected);
    // Each flag is a distinct bit: OR-ing them all must not lose any bit to
    // an accidental duplicate value.
    let bits = [
        JOB_OBJECT_UILIMIT_HANDLES,
        JOB_OBJECT_UILIMIT_READCLIPBOARD,
        JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
        JOB_OBJECT_UILIMIT_DESKTOP,
        JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
        JOB_OBJECT_UILIMIT_GLOBALATOMS,
        JOB_OBJECT_UILIMIT_EXITWINDOWS,
    ];
    assert_eq!(
        bits.iter().fold(0u32, |acc, bit| acc | bit).count_ones() as usize,
        bits.len()
    );
}
