#[cfg(unix)]
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
#[cfg(unix)]
use std::os::unix::io::{AsFd as _, OwnedFd};

use crate::bin_error::{self, ContextExt as _};

#[cfg(unix)]
pub struct StartupAck {
    writer: OwnedFd,
}

#[cfg(windows)]
pub struct StartupAck;

#[cfg(unix)]
impl StartupAck {
    pub fn ack(self) -> bin_error::Result<()> {
        rustix::io::write(&self.writer, &[0])?;
        Ok(())
    }
}

#[cfg(windows)]
impl StartupAck {
    pub fn ack(self) -> bin_error::Result<()> {
        Ok(())
    }
}

/// Open + flock the pidfile. If another agent holds the lock, exit with
/// code 23 — the same "already running" signal the daemonized parent
/// uses. Applied uniformly so the `--no-daemonize` path (used by the
/// launchd keepalive plist) doesn't spam its log every time launchd
/// respawns into a still-occupied slot.
#[cfg(unix)]
fn lock_pidfile_or_exit_if_running() -> bin_error::Result<std::fs::File> {
    match open_and_lock_pidfile() {
        Ok(f) => Ok(f),
        Err(e) => {
            let mut cur: Option<&(dyn std::error::Error + 'static)> =
                std::error::Error::source(&e);
            while let Some(c) = cur {
                if let Some(errno) = c.downcast_ref::<rustix::io::Errno>() {
                    if *errno == rustix::io::Errno::WOULDBLOCK
                        || *errno == rustix::io::Errno::AGAIN
                    {
                        std::process::exit(23);
                    }
                    break;
                }
                cur = c.source();
            }
            Err(e)
        }
    }
}

#[cfg(unix)]
fn open_and_lock_pidfile() -> bin_error::Result<std::fs::File> {
    let pidfile = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(bwx::dirs::pid_file())
        .context("failed to open pid file")?;
    rustix::fs::flock(
        &pidfile,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .context("failed to lock pid file")?;
    Ok(pidfile)
}

#[cfg(unix)]
fn redirect_fd_to<Fd: std::os::unix::io::AsFd>(
    src: Fd,
    target_raw: std::os::unix::io::RawFd,
) -> bin_error::Result<()> {
    // SAFETY: we are reconstructing an OwnedFd from a well-known standard fd
    // (0/1/2) purely so that `dup2` can overwrite it; we then forget it to
    // avoid closing the fd we just installed.
    let mut target = unsafe {
        <OwnedFd as std::os::unix::io::FromRawFd>::from_raw_fd(target_raw)
    };
    let res = rustix::io::dup2(src, &mut target);
    std::mem::forget(target);
    res.context("failed to dup2")?;
    Ok(())
}

#[cfg(unix)]
pub fn daemonize(
    no_daemonize: bool,
) -> bin_error::Result<Option<StartupAck>> {
    if no_daemonize {
        let pidfile = lock_pidfile_or_exit_if_running()?;
        writeln!(&pidfile, "{}", std::process::id())
            .context("failed to write pid file")?;
        // don't close the pidfile until the process exits, to ensure it
        // stays locked
        std::mem::forget(pidfile);

        return Ok(None);
    }

    // Lock the pidfile in the original (pre-fork) process so that the
    // "already running" condition is visible to the user-facing parent via
    // its exit code, instead of only being observable in the detached
    // grandchild.
    let pidfile = lock_pidfile_or_exit_if_running()?;

    let stdout = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(bwx::dirs::agent_stdout_file())?;
    let stderr = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(bwx::dirs::agent_stderr_file())?;
    let devnull_in = rustix::fs::open(
        "/dev/null",
        rustix::fs::OFlags::RDONLY,
        rustix::fs::Mode::empty(),
    )
    .context("failed to open /dev/null")?;

    let (r, w) = rustix::pipe::pipe()?;

    // SAFETY: fork is called before any tokio runtime or other threads are
    // started (see real_main in main.rs). The parent returns without
    // touching global state beyond reading the pipe and exiting; the
    // children only call async-signal-safe rustix/libc wrappers plus
    // std::fs open/write before the final return into tokio.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error())
            .context("first fork failed");
    }
    if pid > 0 {
        // original parent: wait for ack from grandchild, then exit
        drop(w);
        let mut buf = [0u8; 1];
        match rustix::io::read(&r, &mut buf) {
            Ok(1) => std::process::exit(0),
            // EOF before ack means the daemon child died without signaling
            // success; propagate a generic failure exit code.
            _ => std::process::exit(1),
        }
    }

    // first child (session leader candidate)
    drop(r);
    rustix::process::setsid().context("setsid failed")?;

    // SAFETY: same invariants as the first fork; no runtime has been
    // started in this process.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error())
            .context("second fork failed");
    }
    if pid > 0 {
        // intermediate exits immediately so the grandchild is reparented
        // to init and cannot reacquire a controlling terminal.
        // SAFETY: _exit is async-signal-safe and avoids running atexit
        // handlers inherited from the parent.
        unsafe { libc::_exit(0) };
    }

    // grandchild: finalize daemon state
    rustix::process::chdir("/").context("chdir / failed")?;

    redirect_fd_to(devnull_in.as_fd(), libc::STDIN_FILENO)?;
    redirect_fd_to(stdout.as_fd(), libc::STDOUT_FILENO)?;
    redirect_fd_to(stderr.as_fd(), libc::STDERR_FILENO)?;
    drop(devnull_in);
    drop(stdout);
    drop(stderr);

    writeln!(&pidfile, "{}", std::process::id())
        .context("failed to write pid file")?;
    // keep the pidfile fd open for the life of the process so the advisory
    // lock is held until exit
    std::mem::forget(pidfile);

    Ok(Some(StartupAck { writer: w }))
}

/// Windows daemon-detach. When invoked without `--no-daemonize`, the
/// parent respawns `current_exe()` with `--no-daemonize` appended,
/// using `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW`
/// so the child has no console attached, and redirects stdout/stderr
/// to the agent log files. The parent exits immediately on success;
/// no StartupAck round-trip is performed (PROC_THREAD_ATTRIBUTE_HANDLE_LIST
/// is left as a follow-up — Unix's pipe-based ack doesn't transfer
/// directly and the simplified flow matches the documented UX gap).
#[cfg(windows)]
pub fn daemonize(
    no_daemonize: bool,
) -> bin_error::Result<Option<StartupAck>> {
    if no_daemonize {
        return Ok(None);
    }
    spawn_detached_child().context("failed to spawn detached agent")?;
    std::process::exit(0);
}

#[cfg(windows)]
fn spawn_detached_child() -> bin_error::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, TRUE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW,
        DETACHED_PROCESS, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
        STARTUPINFOW,
    };

    // Open log files inheritable so the child can dup them as stdout/stderr.
    let stdout = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(bwx::dirs::agent_stdout_file())?;
    let stderr = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(bwx::dirs::agent_stderr_file())?;

    // Mark both handles inheritable.
    let stdout_h: HANDLE = stdout.as_raw_handle().cast();
    let stderr_h: HANDLE = stderr.as_raw_handle().cast();
    set_handle_inheritable(stdout_h)?;
    set_handle_inheritable(stderr_h)?;

    // Build command line: "<exe>" --no-daemonize plus original extra args.
    let exe = std::env::current_exe()
        .context("failed to resolve current_exe for daemon respawn")?;
    let mut cmdline = std::ffi::OsString::new();
    cmdline.push("\"");
    cmdline.push(exe.as_os_str());
    cmdline.push("\" --no-daemonize");
    // Forward any extra args after argv[1] (argv[1] is `--no-daemonize`
    // marker for the unix path; on Windows we just append everything past
    // argv[0] verbatim, deduplicating the daemonize flag we just added).
    for arg in std::env::args().skip(1) {
        if arg == "--no-daemonize" {
            continue;
        }
        cmdline.push(" ");
        cmdline.push(quote_arg(&arg));
    }
    let mut wide = bwx::win::wide::os_str_to_utf16_nul(&cmdline);

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = u32::try_from(std::mem::size_of::<STARTUPINFOW>())
        .expect("STARTUPINFOW fits in u32");
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = std::ptr::null_mut();
    si.hStdOutput = stdout_h;
    si.hStdError = stderr_h;

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // SAFETY: wide is a NUL-terminated, mutable command-line buffer
    // (CreateProcessW requires writable storage); STARTUPINFOW and
    // PROCESS_INFORMATION are stack-locals of the documented sizes;
    // inheritable=TRUE so the child receives the redirected stdio.
    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            wide.as_mut_ptr(),
            std::ptr::null::<SECURITY_ATTRIBUTES>(),
            std::ptr::null::<SECURITY_ATTRIBUTES>(),
            TRUE,
            DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
            std::ptr::null(),
            std::ptr::null(),
            &mut si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(bin_error::Error::with_context(
            std::io::Error::last_os_error(),
            "CreateProcessW",
        ));
    }
    // SAFETY: hProcess and hThread are owned by us; close exactly once.
    unsafe {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    Ok(())
}

#[cfg(windows)]
fn set_handle_inheritable(
    h: windows_sys::Win32::Foundation::HANDLE,
) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::{
        SetHandleInformation, HANDLE_FLAG_INHERIT,
    };
    // SAFETY: caller passes a valid handle; flags are documented.
    let ok = unsafe {
        SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn quote_arg(arg: &str) -> std::ffi::OsString {
    // CommandLineToArgvW round-trip: wrap in quotes, escape inner
    // backslashes-before-quote and embedded quotes per the documented
    // rules. Sufficient for forwarding arbitrary user-supplied args.
    let mut out = std::ffi::OsString::new();
    out.push("\"");
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => {
                backslashes += 1;
                out.push("\\");
            }
            '"' => {
                for _ in 0..=backslashes {
                    out.push("\\");
                }
                backslashes = 0;
                out.push("\"");
            }
            _ => {
                backslashes = 0;
                let mut tmp = [0u8; 4];
                out.push(ch.encode_utf8(&mut tmp));
            }
        }
    }
    for _ in 0..backslashes {
        out.push("\\");
    }
    out.push("\"");
    out
}
