//! These tests exercise the pure helpers and the live Win32 spawn/settle seam.
//! The live cases require the gate's explicit
//! `SEMAPRAX_WINDOWS_CONFINEMENT_TEST_PARENT`; absent or unusable provisioning
//! is a test failure. Their capsule bytes are structurally valid test input
//! with an unverified signature because this primitive currently performs
//! body decoding only. They exercise no signed-capsule trust decision.
use super::*;
use std::ffi::OsString;

const TEST_PARENT_ENV: &str = "SEMAPRAX_WINDOWS_CONFINEMENT_TEST_PARENT";
const TEST_MARKER: &str = "runtime-child-started.bin";
const DESCENDANT_PERMIT: &str = "runtime-descendant-permit.bin";

fn runtime_parent() -> PathBuf {
    let parent = std::env::var_os(TEST_PARENT_ENV)
        .unwrap_or_else(|| panic!("{TEST_PARENT_ENV} must be provisioned by the Windows gate"));
    let parent = PathBuf::from(parent);
    assert!(parent.is_absolute(), "runtime parent must be absolute");
    let metadata = std::fs::symlink_metadata(&parent).expect("provisioned runtime parent exists");
    assert!(metadata.is_dir(), "runtime parent is a directory");
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        assert_eq!(
            metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
            0,
            "runtime parent must not be a reparse point"
        );
    }
    assert_parent_empty(&parent);
    parent
}

fn assert_parent_empty(parent: &Path) {
    assert!(
        std::fs::read_dir(parent)
            .expect("provisioned runtime parent can be enumerated")
            .next()
            .is_none(),
        "owned runtime scratch was removed from the explicit parent"
    );
}

fn test_capsule_body() -> Vec<u8> {
    // This only satisfies parse_capsule_body's structural contract. The
    // runtime primitive does not verify these placeholder signature bytes.
    let selector = b"runtime-test";
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"SPXDPC1\0");
    bytes.extend_from_slice(&[1, 1, 0, 4, selector.len() as u8]);
    bytes.extend_from_slice(selector);
    for _ in 0..super::super::capsule::ARTIFACT_COUNT {
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&[0x42; 32]);
    }
    bytes.extend_from_slice(&[0; 64]);
    bytes
}

fn child_test_args(name: &str) -> Vec<OsString> {
    let child_filter = format!("doctor::windows_confinement::primitive::tests::{name}");
    ["--ignored", "--exact", child_filter.as_str(), "--nocapture"]
        .into_iter()
        .map(OsString::from)
        .collect()
}

fn wait_for_marker(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if path.is_file() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "confined child did not create its start marker: {}",
        path.display()
    );
}

fn publish_child_marker(contents: &[u8]) {
    let directory = std::env::current_dir().expect("confined current directory");
    let marker = directory.join(TEST_MARKER);
    let temporary = directory.join(format!("{TEST_MARKER}.tmp"));
    let publish = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        std::io::Write::write_all(&mut file, contents)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, &marker)
    })();
    if publish.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    publish.expect("child atomically publishes a complete start marker");
}

#[test]
#[ignore = "spawned only by the live confinement runtime tests"]
fn runtime_child_checks_descendant_job_limit() {
    let current_exe = std::env::current_exe().expect("confined executable path");
    let descendant = std::process::Command::new(current_exe)
        .arg("--list")
        .output();
    let quota_status = windows_sys::Win32::Foundation::ERROR_NOT_ENOUGH_QUOTA as i32;
    let active_process_limit_refused = match descendant {
        Err(error) => error.raw_os_error() == Some(quota_status),
        Ok(output) => {
            output.status.code() == Some(quota_status)
                && output.stdout.is_empty()
                && output.stderr.is_empty()
        }
    };
    let observation: &[u8] = if active_process_limit_refused {
        b"active-process-limit-refused"
    } else {
        b"descendant-created-or-refused-for-another-reason"
    };
    publish_child_marker(observation);
}

#[test]
#[ignore = "spawned only by the live confinement runtime tests"]
fn runtime_child_marks_start_then_waits_for_job_termination() {
    publish_child_marker(b"started");
    loop {
        std::thread::sleep(Duration::from_secs(30));
    }
}

#[test]
#[ignore = "spawned only by the live confinement runtime tests"]
fn runtime_child_exits_with_nonzero_status() {
    publish_child_marker(b"exit-37");
    std::process::exit(37);
}

#[test]
#[ignore = "spawned only by the live confinement runtime tests"]
fn runtime_child_launches_descendant_after_parent_permit() {
    let directory = std::env::current_dir().expect("confined current directory");
    publish_child_marker(b"ready-for-descendant");
    let permit = directory.join(DESCENDANT_PERMIT);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !permit.is_file() {
        assert!(
            Instant::now() < deadline,
            "parent did not permit descendant launch"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let executable = std::env::current_exe().expect("confined executable path");
    let args = child_test_args("runtime_child_waits_for_job_termination");
    match std::process::Command::new(executable).args(args).spawn() {
        Ok(descendant) => {
            drop(descendant);
            publish_child_marker(b"descendant-started");
            loop {
                std::thread::sleep(Duration::from_secs(30));
            }
        }
        Err(_) => publish_child_marker(b"descendant-spawn-refused"),
    }
}

#[test]
#[ignore = "spawned only by the live confinement runtime tests"]
fn runtime_child_waits_for_job_termination() {
    loop {
        std::thread::sleep(Duration::from_secs(30));
    }
}

fn current_process_handle_count() -> u32 {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};

    let mut count = 0;
    assert_ne!(
        unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) },
        0,
        "query the current process's live handle count"
    );
    count
}

struct RuntimeChildCleanupGuard {
    process: windows_sys::Win32::Foundation::HANDLE,
    job: windows_sys::Win32::Foundation::HANDLE,
    scratch_dir: PathBuf,
    armed: bool,
}

impl RuntimeChildCleanupGuard {
    fn new(child: &ConfinedProcess) -> Self {
        Self {
            process: child.process.raw(),
            job: child.job.raw(),
            scratch_dir: child._scratch.dir.clone(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RuntimeChildCleanupGuard {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicAccountingInformation, QueryInformationJobObject, TerminateJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        };
        use windows_sys::Win32::System::Threading::WaitForSingleObject;

        if !self.armed {
            return;
        }

        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let mut queried = unsafe {
            QueryInformationJobObject(
                self.job,
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&accounting) as u32,
                std::ptr::null_mut(),
            )
        } != 0;
        if queried && accounting.ActiveProcesses != 0 {
            if unsafe { TerminateJobObject(self.job, 126) } == 0 {
                eprintln!("runtime-test cleanup could not terminate its exact confined job");
                return;
            }
            if unsafe { WaitForSingleObject(self.process, 5_000) } != WAIT_OBJECT_0 {
                eprintln!("runtime-test cleanup could not reap its confined leader");
                return;
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
                queried = unsafe {
                    QueryInformationJobObject(
                        self.job,
                        JobObjectBasicAccountingInformation,
                        (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                        std::mem::size_of_val(&accounting) as u32,
                        std::ptr::null_mut(),
                    )
                } != 0;
                if !queried {
                    eprintln!("runtime-test cleanup could not query its confined job");
                    return;
                }
                if accounting.ActiveProcesses == 0 {
                    break;
                }
                if Instant::now() >= deadline {
                    eprintln!("runtime-test cleanup could not prove its job empty");
                    return;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        if !queried
            || accounting.ActiveProcesses != 0
            || unsafe { WaitForSingleObject(self.process, 0) } != WAIT_OBJECT_0
        {
            eprintln!("runtime-test cleanup will not remove files before process settlement");
            return;
        }

        for name in [
            TEST_MARKER,
            "runtime-child-started.bin.tmp",
            DESCENDANT_PERMIT,
        ] {
            match std::fs::remove_file(self.scratch_dir.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => eprintln!("runtime-test cleanup could not remove {name}: {error}"),
            }
        }
    }
}

#[test]
#[ignore = "requires the explicitly provisioned Windows runtime gate"]
fn windows_runtime_launches_restricted_child_inside_acl_scratch_and_settles_it() {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        EqualSid, GetSecurityDescriptorControl, GetTokenInformation, LookupPrivilegeValueW,
        TokenPrivileges, ACCESS_ALLOWED_ACE, DACL_SECURITY_INFORMATION, SE_CHANGE_NOTIFY_NAME,
        SE_DACL_PROTECTED, SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{DELETE, FILE_GENERIC_READ, FILE_GENERIC_WRITE};
    use windows_sys::Win32::System::JobObjects::{
        IsProcessInJob, JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation,
        QueryInformationJobObject, JOBOBJECT_BASIC_UI_RESTRICTIONS,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Threading::OpenProcessToken;

    let parent = runtime_parent();
    let executable = std::env::current_exe().expect("current test executable exists");
    let args = child_test_args("runtime_child_checks_descendant_job_limit");
    let borrowed_args: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    let child = confined_spawn(&executable, &borrowed_args, &parent, &test_capsule_body())
        .expect("restricted-token child launch, job assignment, and ACL scratch setup succeed");
    let mut cleanup_guard = RuntimeChildCleanupGuard::new(&child);
    let marker = child._scratch.dir.join(TEST_MARKER);
    let scratch_dir = child._scratch.dir.clone();
    wait_for_marker(&marker);

    let mut restricted_token = std::ptr::null_mut();
    assert_ne!(
        unsafe { OpenProcessToken(child.process.raw(), TOKEN_QUERY, &mut restricted_token) },
        0,
        "the launched process exposes a queryable token"
    );
    let restricted_token = Handle::new(restricted_token);
    let mut privileges_length = 0u32;
    unsafe {
        GetTokenInformation(
            restricted_token.raw(),
            TokenPrivileges,
            std::ptr::null_mut(),
            0,
            &mut privileges_length,
        );
    }
    assert!(privileges_length >= std::mem::size_of::<TOKEN_PRIVILEGES>() as u32);
    let mut privilege_storage = vec![0u64; privileges_length.div_ceil(8) as usize];
    assert_ne!(
        unsafe {
            GetTokenInformation(
                restricted_token.raw(),
                TokenPrivileges,
                privilege_storage.as_mut_ptr().cast(),
                privileges_length,
                &mut privileges_length,
            )
        },
        0,
        "read the launched process's effective privilege set"
    );
    let privileges = unsafe { &*privilege_storage.as_ptr().cast::<TOKEN_PRIVILEGES>() };
    let privilege_bytes = privileges_length as usize;
    let privilege_offset = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
    let privilege_capacity = privilege_bytes.saturating_sub(privilege_offset)
        / std::mem::size_of::<windows_sys::Win32::Security::LUID_AND_ATTRIBUTES>();
    assert!(privileges.PrivilegeCount as usize <= privilege_capacity);
    let privilege_entries = unsafe {
        std::slice::from_raw_parts(
            privileges.Privileges.as_ptr(),
            privileges.PrivilegeCount as usize,
        )
    };
    let mut change_notify = windows_sys::Win32::Foundation::LUID::default();
    assert_ne!(
        unsafe {
            LookupPrivilegeValueW(std::ptr::null(), SE_CHANGE_NOTIFY_NAME, &mut change_notify)
        },
        0
    );
    assert!(
        privilege_entries.iter().all(|entry| {
            entry.Attributes & SE_PRIVILEGE_ENABLED == 0
                || (entry.Luid.LowPart == change_notify.LowPart
                    && entry.Luid.HighPart == change_notify.HighPart)
        }),
        "CreateRestrictedToken disabled every privilege except SeChangeNotifyPrivilege"
    );

    let mut in_job = 0;
    assert_ne!(
        unsafe { IsProcessInJob(child.process.raw(), child.job.raw(), &mut in_job) },
        0
    );
    assert_ne!(in_job, 0, "the child is assigned to its owned job object");

    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    assert_ne!(
        unsafe {
            QueryInformationJobObject(
                child.job.raw(),
                JobObjectExtendedLimitInformation,
                (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
                std::ptr::null_mut(),
            )
        },
        0
    );
    let required_limits = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    assert_eq!(
        limits.BasicLimitInformation.LimitFlags & required_limits,
        required_limits
    );
    assert_eq!(limits.BasicLimitInformation.ActiveProcessLimit, 1);
    let mut ui = JOBOBJECT_BASIC_UI_RESTRICTIONS::default();
    assert_ne!(
        unsafe {
            QueryInformationJobObject(
                child.job.raw(),
                JobObjectBasicUIRestrictions,
                (&mut ui as *mut JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
                std::mem::size_of_val(&ui) as u32,
                std::ptr::null_mut(),
            )
        },
        0
    );
    assert_eq!(ui.UIRestrictionsClass, DENIED_UI_LIMITS);

    let mut security_descriptor = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let scratch_wide = wide(child._scratch.dir.as_os_str()).unwrap();
    let security_result = unsafe {
        GetNamedSecurityInfoW(
            scratch_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    assert_eq!(security_result, 0, "read back the created scratch DACL");
    assert!(!dacl.is_null());
    let mut descriptor_control = 0u16;
    let mut descriptor_revision = 0u32;
    assert_ne!(
        unsafe {
            GetSecurityDescriptorControl(
                security_descriptor,
                &mut descriptor_control,
                &mut descriptor_revision,
            )
        },
        0
    );
    assert_ne!(
        descriptor_control & SE_DACL_PROTECTED,
        0,
        "scratch DACL protection blocks inherited ACEs"
    );
    let acl = unsafe { &*dacl };
    assert_eq!(acl.AceCount, 1, "scratch DACL contains one explicit ACE");
    let mut ace = std::ptr::null_mut();
    assert_ne!(
        unsafe { windows_sys::Win32::Security::GetAce(dacl, 0, &mut ace) },
        0
    );
    let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    assert_eq!(
        ace.Header.AceType, 0,
        "the sole ACE is an access-allowed ACE"
    );
    assert_eq!(
        ace.Mask,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
        "scratch grants only the primitive's explicit read/write/delete mask"
    );
    let mut token_user = [0u8; 256];
    read_token_user_sid(&child._token, &mut token_user).unwrap();
    let expected_sid = unsafe { (*token_user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let ace_sid = (&ace.SidStart as *const u32).cast_mut().cast();
    assert_ne!(unsafe { EqualSid(expected_sid, ace_sid) }, 0);
    assert_eq!(
        unsafe { LocalFree(security_descriptor.cast()) },
        std::ptr::null_mut()
    );

    let marker_contents = std::fs::read(&marker).unwrap();
    std::fs::remove_file(&marker).expect("remove exact child marker before scratch settlement");
    cleanup_guard.disarm();
    let settled = settle(child, Duration::from_secs(30));
    assert_eq!(settled.status, Settlement::Completed);
    assert_eq!(
        marker_contents, b"active-process-limit-refused",
        "the one-process job limit refuses a launched child's descendant"
    );
    assert!(
        !scratch_dir.exists(),
        "settlement removes the now-empty per-child scratch directory"
    );
    assert_parent_empty(&parent);
}

#[test]
#[ignore = "requires the explicitly provisioned Windows runtime gate"]
fn windows_runtime_timeout_terminates_the_confined_job_and_settles_cancellation() {
    let parent = runtime_parent();
    let executable = std::env::current_exe().expect("current test executable exists");
    let args = child_test_args("runtime_child_marks_start_then_waits_for_job_termination");
    let borrowed_args: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    let child = confined_spawn(&executable, &borrowed_args, &parent, &test_capsule_body())
        .expect("restricted-token child launch, job assignment, and ACL scratch setup succeed");
    let mut cleanup_guard = RuntimeChildCleanupGuard::new(&child);
    let marker = child._scratch.dir.join(TEST_MARKER);
    let scratch_dir = child._scratch.dir.clone();
    wait_for_marker(&marker);
    assert_eq!(std::fs::read(&marker).unwrap(), b"started");
    std::fs::remove_file(&marker).expect("remove exact child marker before scratch settlement");
    cleanup_guard.disarm();
    let settled = settle(child, Duration::from_millis(100));
    assert_eq!(settled.status, Settlement::Cancelled);
    assert!(
        !scratch_dir.exists(),
        "settlement removes the now-empty per-child scratch directory"
    );
    assert_parent_empty(&parent);
}

#[test]
#[ignore = "requires the explicitly provisioned Windows runtime gate"]
fn windows_runtime_timeout_terminates_an_actual_job_descendant() {
    use windows_sys::Win32::System::JobObjects::{
        JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    };

    let parent = runtime_parent();
    let executable = std::env::current_exe().expect("current test executable exists");
    let args = child_test_args("runtime_child_launches_descendant_after_parent_permit");
    let borrowed_args: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    let child = confined_spawn(&executable, &borrowed_args, &parent, &test_capsule_body())
        .expect("restricted-token child launch, job assignment, and ACL scratch setup succeed");
    let mut cleanup_guard = RuntimeChildCleanupGuard::new(&child);
    let marker = child._scratch.dir.join(TEST_MARKER);
    let scratch_dir = child._scratch.dir.clone();
    wait_for_marker(&marker);
    assert_eq!(std::fs::read(&marker).unwrap(), b"ready-for-descendant");

    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    assert_ne!(
        unsafe {
            QueryInformationJobObject(
                child.job.raw(),
                JobObjectExtendedLimitInformation,
                (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
                std::ptr::null_mut(),
            )
        },
        0
    );
    assert_ne!(
        limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        0
    );
    assert_eq!(limits.BasicLimitInformation.ActiveProcessLimit, 1);
    // This isolated test relaxes only its own job after confirming production's
    // configured one-process cap; the separate success test proves that cap.
    limits.BasicLimitInformation.ActiveProcessLimit = 2;
    assert_ne!(
        unsafe {
            SetInformationJobObject(
                child.job.raw(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        },
        0,
        "test-owned job admits one descendant solely to exercise tree timeout"
    );

    std::fs::remove_file(&marker).expect("remove readiness marker before signaling child");
    std::fs::write(child._scratch.dir.join(DESCENDANT_PERMIT), b"go")
        .expect("permit exact confined child to launch one descendant");
    wait_for_marker(&marker);
    assert_eq!(std::fs::read(&marker).unwrap(), b"descendant-started");

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut accounting =
            windows_sys::Win32::System::JobObjects::JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default(
            );
        assert_ne!(
            unsafe {
                windows_sys::Win32::System::JobObjects::QueryInformationJobObject(
                    child.job.raw(),
                    windows_sys::Win32::System::JobObjects::JobObjectBasicAccountingInformation,
                    (&mut accounting as *mut windows_sys::Win32::System::JobObjects::JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    std::mem::size_of_val(&accounting) as u32,
                    std::ptr::null_mut(),
                )
            },
            0,
            "observe live job membership before timed cancellation"
        );
        if accounting.ActiveProcesses == 2 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "job never contained leader and descendant"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    std::fs::remove_file(&marker).expect("remove descendant marker before job settlement");
    std::fs::remove_file(child._scratch.dir.join(DESCENDANT_PERMIT))
        .expect("remove exact descendant permit before job settlement");
    cleanup_guard.disarm();
    let settled = settle(child, Duration::from_millis(100));
    assert_eq!(settled.status, Settlement::Cancelled);
    assert!(
        !scratch_dir.exists(),
        "empty-job settlement closes both processes before scratch cleanup"
    );
    assert_parent_empty(&parent);
}

#[test]
#[ignore = "requires the explicitly provisioned Windows runtime gate"]
fn windows_runtime_nonzero_exit_settles_failed_and_cleans_resources() {
    let parent = runtime_parent();
    let executable = std::env::current_exe().expect("current test executable exists");
    let args = child_test_args("runtime_child_exits_with_nonzero_status");
    let borrowed_args: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    let child = confined_spawn(&executable, &borrowed_args, &parent, &test_capsule_body())
        .expect("restricted-token child launch, job assignment, and ACL scratch setup succeed");
    let mut cleanup_guard = RuntimeChildCleanupGuard::new(&child);
    let marker = child._scratch.dir.join(TEST_MARKER);
    let scratch_dir = child._scratch.dir.clone();
    wait_for_marker(&marker);
    assert_eq!(std::fs::read(&marker).unwrap(), b"exit-37");
    std::fs::remove_file(&marker).expect("remove exact child marker before scratch settlement");
    cleanup_guard.disarm();
    let settled = settle(child, Duration::from_secs(30));
    assert_eq!(
        settled.status,
        Settlement::Failed(FailureReason::ExitCode(37))
    );
    assert!(
        !scratch_dir.exists(),
        "settlement removes the now-empty per-child scratch directory"
    );
    assert_parent_empty(&parent);
}

#[test]
#[ignore = "requires the explicitly provisioned Windows runtime gate"]
fn windows_runtime_scratch_refusal_closes_setup_handles() {
    let parent = runtime_parent();
    let missing_parent = parent.join(format!("missing-scratch-parent-{}", std::process::id()));
    assert!(!missing_parent.exists());
    let executable = std::env::current_exe().expect("current test executable exists");
    let args = child_test_args("runtime_child_marks_start_then_waits_for_job_termination");
    let borrowed_args: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    let capsule = test_capsule_body();

    // Warm dynamic Windows call paths before taking the handle baseline, then
    // require repeated real token/job/ACL-stage refusal to settle all handles.
    for _ in 0..2 {
        assert_eq!(
            confined_spawn(&executable, &borrowed_args, &missing_parent, &capsule).err(),
            Some(Refusal::FilesystemConfinement)
        );
    }
    let baseline = current_process_handle_count();
    for _ in 0..4 {
        assert_eq!(
            confined_spawn(&executable, &borrowed_args, &missing_parent, &capsule).err(),
            Some(Refusal::FilesystemConfinement)
        );
        assert_eq!(
            current_process_handle_count(),
            baseline,
            "token, job, and filesystem-stage failure handles are settled"
        );
    }
    assert!(
        !missing_parent.exists(),
        "refusal does not create the absent parent"
    );
    assert_parent_empty(&parent);
}

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
