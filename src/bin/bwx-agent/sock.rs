use crate::bin_error::{self, ContextExt as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Cap on the size of a single framed message from the CLI. Blocks a
/// misbehaving (or malicious, if the 0o700-dir / DACL assumption is
/// violated) client from pushing the agent into unbounded heap
/// growth via an oversized length prefix.
const MAX_MESSAGE: u32 = 16 * 1024 * 1024;

#[cfg(unix)]
pub struct Sock(tokio::net::UnixStream);

#[cfg(windows)]
pub struct Sock(tokio::net::windows::named_pipe::NamedPipeServer);

#[cfg(unix)]
impl Sock {
    pub fn new(s: tokio::net::UnixStream) -> Self {
        Self(s)
    }

    pub async fn send(
        &mut self,
        res: &bwx::protocol::Response,
    ) -> bin_error::Result<()> {
        if let bwx::protocol::Response::Error { error } = res {
            log::warn!("{error}");
        }

        let Self(sock) = self;
        let payload =
            rmp_serde::to_vec(res).context("failed to serialize message")?;
        let len = u32::try_from(payload.len()).map_err(|_| {
            bin_error::Error::msg(format!(
                "outgoing message exceeds {MAX_MESSAGE}-byte cap"
            ))
        })?;
        if len > MAX_MESSAGE {
            return Err(bin_error::Error::msg(format!(
                "outgoing message exceeds {MAX_MESSAGE}-byte cap"
            )));
        }
        sock.write_all(&len.to_be_bytes())
            .await
            .context("failed to write message to socket")?;
        sock.write_all(&payload)
            .await
            .context("failed to write message to socket")?;
        Ok(())
    }

    pub async fn recv(
        &mut self,
    ) -> bin_error::Result<std::result::Result<bwx::protocol::Request, String>>
    {
        let Self(sock) = self;
        let mut len_buf = [0u8; 4];
        match sock.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(Err("connection closed".to_string()));
            }
            Err(e) => {
                return Err(bin_error::Error::with_context(
                    e,
                    "failed to read message from socket",
                ));
            }
        }
        let len = u32::from_be_bytes(len_buf);
        if len > MAX_MESSAGE {
            return Ok(Err(format!(
                "message exceeds {MAX_MESSAGE}-byte cap"
            )));
        }
        let mut payload = vec![
            0u8;
            usize::try_from(len)
                .expect("16 MiB-capped u32 fits in usize")
        ];
        sock.read_exact(&mut payload)
            .await
            .context("failed to read message from socket")?;
        Ok(rmp_serde::from_slice(&payload)
            .map_err(|e| format!("failed to parse message: {e}")))
    }
}

#[cfg(windows)]
impl Sock {
    pub fn new(s: tokio::net::windows::named_pipe::NamedPipeServer) -> Self {
        Self(s)
    }

    pub async fn send(
        &mut self,
        res: &bwx::protocol::Response,
    ) -> bin_error::Result<()> {
        if let bwx::protocol::Response::Error { error } = res {
            log::warn!("{error}");
        }

        let Self(sock) = self;
        let payload =
            rmp_serde::to_vec(res).context("failed to serialize message")?;
        let len = u32::try_from(payload.len()).map_err(|_| {
            bin_error::Error::msg(format!(
                "outgoing message exceeds {MAX_MESSAGE}-byte cap"
            ))
        })?;
        if len > MAX_MESSAGE {
            return Err(bin_error::Error::msg(format!(
                "outgoing message exceeds {MAX_MESSAGE}-byte cap"
            )));
        }
        sock.write_all(&len.to_be_bytes())
            .await
            .context("failed to write message to pipe")?;
        sock.write_all(&payload)
            .await
            .context("failed to write message to pipe")?;
        Ok(())
    }

    pub async fn recv(
        &mut self,
    ) -> bin_error::Result<std::result::Result<bwx::protocol::Request, String>>
    {
        let Self(sock) = self;
        let mut len_buf = [0u8; 4];
        match sock.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(Err("connection closed".to_string()));
            }
            Err(e) => {
                return Err(bin_error::Error::with_context(
                    e,
                    "failed to read message from pipe",
                ));
            }
        }
        let len = u32::from_be_bytes(len_buf);
        if len > MAX_MESSAGE {
            return Ok(Err(format!(
                "message exceeds {MAX_MESSAGE}-byte cap"
            )));
        }
        let mut payload = vec![
            0u8;
            usize::try_from(len)
                .expect("16 MiB-capped u32 fits in usize")
        ];
        sock.read_exact(&mut payload)
            .await
            .context("failed to read message from pipe")?;
        Ok(rmp_serde::from_slice(&payload)
            .map_err(|e| format!("failed to parse message: {e}")))
    }
}

/// Best-effort lookup of the peer's pid from a connected `UnixStream`.
/// Wraps `peer_pid` for callers that work with the typed stream.
#[cfg(unix)]
pub fn peer_pid_of(stream: &tokio::net::UnixStream) -> Option<i32> {
    use std::os::unix::io::AsRawFd as _;
    peer_pid(stream.as_raw_fd())
}

/// Verify that the peer connected to `stream` is running as the same
/// uid as this process. The 0o700 runtime dir already blocks cross-user
/// access at the filesystem layer; this catches the case where someone
/// loosens those dir permissions, mounts the path into a sandbox, or
/// passes the connected fd across a privilege boundary. Rejects with an
/// error rather than panicking so the accept loop stays up.
#[cfg(unix)]
pub fn check_peer_uid(
    stream: &tokio::net::UnixStream,
) -> bin_error::Result<()> {
    use std::os::unix::io::AsRawFd as _;
    let fd = stream.as_raw_fd();
    let peer_uid = peer_uid(fd).context("failed to read peer uid")?;
    // SAFETY: getuid is infallible.
    let self_uid = unsafe { libc::getuid() };
    if peer_uid != self_uid {
        return Err(bin_error::Error::msg(format!(
            "peer uid {peer_uid} does not match agent uid {self_uid}; \
             refusing connection"
        )));
    }
    Ok(())
}

/// Read the uid of the process on the other end of a Unix socket fd.
/// `SO_PEERCRED` is the Linux idiom; called directly because musl omits
/// the `getpeereid` wrapper and the libc crate follows suit.
/// `getpeereid` is the BSD / macOS idiom.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_ucred(fd: std::os::unix::io::RawFd) -> std::io::Result<libc::ucred> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = u32::try_from(std::mem::size_of::<libc::ucred>())
        .expect("ucred size fits in socklen_t");
    // SAFETY: `fd` is a valid Unix-socket fd owned by the caller;
    // `cred` and `len` are stack-local outs of the correct types.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut::<libc::ucred>(&mut cred).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_uid(fd: std::os::unix::io::RawFd) -> std::io::Result<u32> {
    peer_ucred(fd).map(|c| c.uid)
}

/// Peer PID of a Unix-socket fd. Best effort — returns `None` if the
/// platform doesn't expose it or if the syscall fails. Used only for
/// human-readable client descriptions; never for authorization.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn peer_pid(fd: std::os::unix::io::RawFd) -> Option<i32> {
    peer_ucred(fd).ok().map(|c| c.pid)
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn peer_uid(fd: std::os::unix::io::RawFd) -> std::io::Result<u32> {
    let mut uid: libc::uid_t = u32::MAX;
    let mut gid: libc::gid_t = u32::MAX;
    // SAFETY: `fd` is a valid Unix-socket fd owned by the caller;
    // getpeereid writes only to the two u32 out-params.
    let rc = unsafe { libc::getpeereid(fd, &raw mut uid, &raw mut gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid)
}

/// macOS exposes the peer pid via `LOCAL_PEERPID` (level `SOL_LOCAL`,
/// which is `0` for `AF_UNIX`). Both constants are stable in Darwin's
/// `sys/un.h`. Best effort — returns `None` on error.
#[cfg(target_os = "macos")]
pub fn peer_pid(fd: std::os::unix::io::RawFd) -> Option<i32> {
    // From <sys/un.h>: #define LOCAL_PEERPID 2, SOL_LOCAL = 0.
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERPID: libc::c_int = 2;
    let mut pid: libc::pid_t = 0;
    let mut len = u32::try_from(std::mem::size_of::<libc::pid_t>())
        .expect("pid_t fits in socklen_t");
    // SAFETY: `fd` is a valid Unix-socket fd; pid/len are stack-local.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            std::ptr::from_mut::<libc::pid_t>(&mut pid).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    Some(pid)
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos"
    ))
))]
pub fn peer_pid(_fd: std::os::unix::io::RawFd) -> Option<i32> {
    None
}

#[cfg(unix)]
pub fn listen() -> bin_error::Result<tokio::net::UnixListener> {
    let path = bwx::dirs::socket_file();
    let sock = bind_atomic(&path).context("failed to listen on socket")?;
    log::debug!("listening on socket {}", path.to_string_lossy());
    Ok(sock)
}

/// Server-end of a Windows named pipe, plus the pipe name needed to
/// pre-create the next instance after each accept.
#[cfg(windows)]
pub struct PipeListener {
    pub name: String,
    pub server: tokio::net::windows::named_pipe::NamedPipeServer,
}

#[cfg(windows)]
impl PipeListener {
    /// Hand off the current pre-created server to the caller and
    /// pre-create a fresh instance bound to the same name. The named
    /// pipe API requires a server handle to exist before a client can
    /// connect, so each accept must be followed by a new instance.
    pub fn rotate(
        &mut self,
    ) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer>
    {
        let next = create_pipe_instance(&self.name, false)?;
        Ok(std::mem::replace(&mut self.server, next))
    }
}

#[cfg(windows)]
pub fn listen() -> bin_error::Result<PipeListener> {
    let name = bwx::dirs::pipe_name();
    let server = create_pipe_instance(&name, true)
        .context("failed to create initial named-pipe instance")?;
    log::debug!("listening on named pipe {name}");
    Ok(PipeListener { name, server })
}

/// Build a `SECURITY_ATTRIBUTES` whose DACL grants `GENERIC_ALL` to
/// the owner of the resource (this process's user) and nobody else,
/// then create a new server instance for `name`. `first_instance`
/// controls the `FILE_FLAG_FIRST_PIPE_INSTANCE` flag — set on the
/// initial bind so a stale agent's pipe doesn't get silently joined.
#[cfg(windows)]
pub(crate) fn create_pipe_instance_for_ssh(
    name: &str,
    first_instance: bool,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    create_pipe_instance(name, first_instance)
}

#[cfg(windows)]
fn create_pipe_instance(
    name: &str,
    first_instance: bool,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    // SDDL: D = DACL; one ACE granting (A)llow / (GA = GENERIC_ALL)
    // to (OW = Owner Rights, i.e. the resource owner). The pipe is
    // created owned by the current user, so OW resolves to that user
    // and only that user.
    let sddl = bwx::win::wide::str_to_utf16_nul("D:(A;;GA;;;OW)");
    let mut psd: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: sddl is NUL-terminated; psd receives a LocalAlloc'd SD
    // freed below.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut psd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    struct LocalFreeOnDrop(*mut core::ffi::c_void);
    impl Drop for LocalFreeOnDrop {
        fn drop(&mut self) {
            // SAFETY: pointer originated from
            // ConvertStringSecurityDescriptorToSecurityDescriptorW which
            // documents LocalFree as the matching deallocator.
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(self.0.cast());
            }
        }
    }
    let _free = LocalFreeOnDrop(psd);

    let mut sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .expect("SECURITY_ATTRIBUTES size fits in u32"),
        lpSecurityDescriptor: psd,
        bInheritHandle: 0,
    };

    let mut opts = tokio::net::windows::named_pipe::ServerOptions::new();
    opts.access_inbound(true)
        .access_outbound(true)
        .pipe_mode(tokio::net::windows::named_pipe::PipeMode::Byte)
        .first_pipe_instance(first_instance);
    let sa_ptr: *mut SECURITY_ATTRIBUTES = &mut sa;
    // SAFETY: `name` is a valid pipe path; sa is well-formed and
    // lives for the duration of this call. tokio's named-pipe API
    // documents this entry point for custom security attributes.
    unsafe {
        opts.create_with_security_attributes_raw(name, sa_ptr.cast())
    }
}

/// Bind a `UnixListener` at `path` without a remove-then-bind TOCTOU
/// window. Binds to a unique sibling path and then `rename(2)`s it onto
/// `path`. `rename` is atomic within a filesystem and clobbers any
/// existing file at the destination, so a racing same-user process can't
/// slip a symlink or regular file in between an unlink and a bind.
#[cfg(unix)]
pub fn bind_atomic(
    path: &std::path::Path,
) -> std::io::Result<tokio::net::UnixListener> {
    // If the atomic path fails for any reason — including Darwin's
    // ~104-byte `sockaddr_un.sun_path` limit once the tmp suffix is
    // appended — fall back to unlink-then-bind so the agent still
    // starts. The fallback has a tiny same-user TOCTOU window, blocked
    // in practice by the 0o700 runtime dir; logged so it's observable.
    match bind_atomic_inner(path) {
        Ok(l) => Ok(l),
        Err(e) => {
            log::warn!(
                "bind_atomic failed ({e}); falling back to unlink-then-bind \
                 on {}. TOCTOU mitigation partially degraded; socket is \
                 still protected by its 0o700 parent dir.",
                path.display()
            );
            let _ = std::fs::remove_file(path);
            tokio::net::UnixListener::bind(path)
        }
    }
}

#[cfg(unix)]
fn bind_atomic_inner(
    path: &std::path::Path,
) -> std::io::Result<tokio::net::UnixListener> {
    use rand::RngCore as _;
    use std::fmt::Write as _;

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socket path has no parent directory",
        )
    })?;
    // Minimal tmp name: 4 random bytes of hex with a tiny prefix. Keeps
    // the total tmp path under Darwin's 104-byte `sun_path` limit in
    // almost all layouts. The filename doesn't need to resemble the
    // target — rename(2) replaces it below.
    let mut nonce = [0u8; 4];
    rand::rng().fill_bytes(&mut nonce);
    let mut nonce_hex = String::with_capacity(nonce.len() * 2 + 2);
    nonce_hex.push_str(".t");
    for b in &nonce {
        write!(&mut nonce_hex, "{b:02x}").unwrap();
    }
    let tmp = parent.join(nonce_hex);

    // Best-effort cleanup in case a prior crashed agent left a tmp
    // behind. Nonce collision is vanishingly unlikely but harmless to
    // clean.
    let _ = std::fs::remove_file(&tmp);

    let listener = tokio::net::UnixListener::bind(&tmp)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        // Don't leak the tmp socket if rename somehow fails.
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(listener)
}

// Note: there is no Windows `bind_atomic`. Atomic-rename matters only
// for filesystem-backed sockets; named pipes use a name only, and the
// `first_pipe_instance` flag in `create_pipe_instance` already rejects
// stale-server collisions. `ssh_agent.rs` calls into the per-listener
// helpers directly instead.

/// Peer process id of a connected named-pipe server. Best-effort —
/// returns `None` if the client has already disconnected. Used both
/// by the Authenticode peer check and by human-readable client
/// descriptions in pinentry / Touch-equivalent prompts.
#[cfg(windows)]
pub fn peer_pid_of(
    server: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> Option<i32> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

    let mut pid: u32 = 0;
    // SAFETY: AsRawHandle returns a valid handle owned by `server`;
    // GetNamedPipeClientProcessId writes only to `pid`.
    let ok = unsafe {
        GetNamedPipeClientProcessId(server.as_raw_handle().cast(), &mut pid)
    };
    if ok == 0 {
        return None;
    }
    i32::try_from(pid).ok()
}

/// Verify that the peer connected to `server` is running as the same
/// authenticated user as this process. The pipe DACL already restricts
/// access to the current user; this defence-in-depth check catches
/// the case where the DACL was widened or the pipe handle was passed
/// across a token / integrity boundary.
#[cfg(windows)]
pub fn check_peer_uid(
    server: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> bin_error::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{EqualSid, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let mut pid: u32 = 0;
    // SAFETY: server handle is valid; pid is a stack out.
    let ok = unsafe {
        GetNamedPipeClientProcessId(server.as_raw_handle().cast(), &mut pid)
    };
    if ok == 0 {
        return Err(bin_error::Error::with_context(
            std::io::Error::last_os_error(),
            "GetNamedPipeClientProcessId",
        ));
    }

    // Open peer process + its token.
    // SAFETY: pid is a u32 from the OS; PROCESS_QUERY_LIMITED_INFORMATION
    // is sufficient to call OpenProcessToken on a same-user process.
    let peer_proc = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    };
    if peer_proc.is_null() {
        return Err(bin_error::Error::with_context(
            std::io::Error::last_os_error(),
            format!("OpenProcess(pid={pid}) for peer-uid check"),
        ));
    }
    let mut peer_token: HANDLE = std::ptr::null_mut();
    // SAFETY: peer_proc is valid; peer_token is a stack out.
    let ok = unsafe {
        OpenProcessToken(peer_proc, TOKEN_QUERY, &mut peer_token)
    };
    // SAFETY: peer_proc is closed exactly once.
    unsafe {
        CloseHandle(peer_proc);
    }
    if ok == 0 {
        return Err(bin_error::Error::with_context(
            std::io::Error::last_os_error(),
            "OpenProcessToken(peer)",
        ));
    }
    let peer_buf_res = bwx::win::sid::token_user_sid_buf(peer_token);
    // SAFETY: peer_token is closed exactly once.
    unsafe {
        CloseHandle(peer_token);
    }
    let peer_buf = peer_buf_res
        .map_err(|e| bin_error::Error::with_context(e, "peer token"))?;

    let self_buf = bwx::win::sid::current_user_sid_buf()
        .map_err(|e| bin_error::Error::with_context(e, "self token"))?;

    // SAFETY: each buf holds a TOKEN_USER followed by SID bytes.
    let peer_sid = unsafe { (*peer_buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let self_sid = unsafe { (*self_buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: both SIDs point into their respective buffers, valid
    // for the duration of this call.
    let eq = unsafe { EqualSid(peer_sid, self_sid) };
    if eq == 0 {
        return Err(bin_error::Error::msg(format!(
            "peer pid {pid} does not match agent's user SID; \
             refusing connection"
        )));
    }
    Ok(())
}

/// Best-effort peer-pid lookup by raw handle, parallel to the unix
/// `peer_pid(fd)` helper. Used by the ssh-agent describer.
#[cfg(windows)]
pub fn peer_pid(
    handle: std::os::windows::io::RawHandle,
) -> Option<i32> {
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    let mut pid: u32 = 0;
    // SAFETY: caller passes a valid pipe-server handle; pid is a stack out.
    let ok = unsafe { GetNamedPipeClientProcessId(handle.cast(), &mut pid) };
    if ok == 0 {
        return None;
    }
    i32::try_from(pid).ok()
}
