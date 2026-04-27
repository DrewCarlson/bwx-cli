#[cfg(unix)]
use std::io::{Read as _, Write as _};
use std::sync::Mutex;

use crate::bin_error::{self, ContextExt as _};

/// Cap on the size of a single framed message from the agent. Blocks a
/// runaway or malicious agent from pushing the CLI into unbounded heap
/// growth via an oversized length prefix.
const MAX_MESSAGE: u32 = 16 * 1024 * 1024;

/// Process-local cached connection. Reused across IPC calls in the same
/// `bwx` invocation so we don't pay a fresh connect()/handshake on every
/// `actions::decrypt`/`encrypt`/etc. Cleared on any send/recv error and
/// when `Quit` is sent.
static CACHED: Mutex<Option<Sock>> = Mutex::new(None);

#[cfg(unix)]
pub struct Sock(std::os::unix::net::UnixStream);

/// Windows IPC transport. Goes straight through Win32
/// `CreateFileW` / `ReadFile` / `WriteFile` against the agent's named
/// pipe, keeping the CLI's `Sock` API synchronous (the rest of the
/// CLI is sync). Avoids spinning up a tokio runtime just for IPC.
#[cfg(windows)]
pub struct Sock {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
// SAFETY: the handle is owned exclusively by this Sock and we never
// alias it across threads without the &mut receiver of send/recv.
unsafe impl Send for Sock {}

#[cfg(unix)]
impl Sock {
    // not returning bin_error::Result here because we want to be able to handle
    // specific kinds of std::io::Results differently
    pub fn connect() -> std::io::Result<Self> {
        Ok(Self(std::os::unix::net::UnixStream::connect(
            bwx::dirs::socket_file(),
        )?))
    }

    /// Drop the cached connection. Call after sending `Quit` (the agent
    /// is on its way out) or before any operation that wants to start
    /// from a fresh socket.
    pub fn invalidate_cached() {
        let mut guard = CACHED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = None;
    }

    pub fn send(
        &mut self,
        msg: &bwx::protocol::Request,
    ) -> bin_error::Result<()> {
        let Self(sock) = self;
        let payload = rmp_serde::to_vec(msg)
            .context("failed to serialize message to agent")?;
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
            .context("failed to send message to agent")?;
        sock.write_all(&payload)
            .context("failed to send message to agent")?;
        Ok(())
    }

    pub fn recv(&mut self) -> bin_error::Result<bwx::protocol::Response> {
        let Self(sock) = self;
        let mut len_buf = [0u8; 4];
        sock.read_exact(&mut len_buf)
            .context("failed to read message from agent")?;
        let len = u32::from_be_bytes(len_buf);
        if len > MAX_MESSAGE {
            return Err(bin_error::Error::msg(format!(
                "agent response exceeds {MAX_MESSAGE}-byte cap"
            )));
        }
        let mut payload = vec![
            0u8;
            usize::try_from(len)
                .expect("16 MiB-capped u32 fits in usize")
        ];
        sock.read_exact(&mut payload)
            .context("failed to read message from agent")?;
        rmp_serde::from_slice(&payload)
            .context("failed to parse message from agent")
    }
}

#[cfg(windows)]
impl Sock {
    pub fn connect() -> std::io::Result<Self> {
        use windows_sys::Win32::Foundation::{
            ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, OPEN_EXISTING,
        };
        use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

        let name = bwx::dirs::pipe_name();
        let wide = bwx::win::wide::str_to_utf16_nul(&name);

        // Retry briefly if all server instances are busy. Server pre-creates
        // a fresh instance on every accept, so this is rare in practice.
        for attempt in 0..5 {
            // SAFETY: wide is NUL-terminated; remaining args are documented
            // ints/handles. Returns INVALID_HANDLE_VALUE on failure.
            let h = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null_mut(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if h != INVALID_HANDLE_VALUE {
                return Ok(Self { handle: h });
            }
            let err = std::io::Error::last_os_error();
            #[allow(clippy::as_conversions)]
            let pipe_busy = ERROR_PIPE_BUSY as i32;
            if err.raw_os_error() != Some(pipe_busy) {
                return Err(err);
            }
            // SAFETY: wide is NUL-terminated; documented blocking wait.
            let _ = unsafe { WaitNamedPipeW(wide.as_ptr(), 1000) };
            if attempt == 4 {
                return Err(err);
            }
        }
        unreachable!()
    }

    pub fn invalidate_cached() {
        let mut guard = CACHED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = None;
    }

    pub fn send(
        &mut self,
        msg: &bwx::protocol::Request,
    ) -> bin_error::Result<()> {
        let payload = rmp_serde::to_vec(msg)
            .context("failed to serialize message to agent")?;
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
        write_all(self.handle, &len.to_be_bytes())
            .context("failed to send message to agent")?;
        write_all(self.handle, &payload)
            .context("failed to send message to agent")?;
        Ok(())
    }

    pub fn recv(&mut self) -> bin_error::Result<bwx::protocol::Response> {
        let mut len_buf = [0u8; 4];
        read_exact(self.handle, &mut len_buf)
            .context("failed to read message from agent")?;
        let len = u32::from_be_bytes(len_buf);
        if len > MAX_MESSAGE {
            return Err(bin_error::Error::msg(format!(
                "agent response exceeds {MAX_MESSAGE}-byte cap"
            )));
        }
        let mut payload = vec![
            0u8;
            usize::try_from(len)
                .expect("16 MiB-capped u32 fits in usize")
        ];
        read_exact(self.handle, &mut payload)
            .context("failed to read message from agent")?;
        rmp_serde::from_slice(&payload)
            .context("failed to parse message from agent")
    }
}

#[cfg(windows)]
impl Drop for Sock {
    fn drop(&mut self) {
        // SAFETY: handle came from CreateFileW; close exactly once.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

#[cfg(windows)]
fn write_all(
    handle: windows_sys::Win32::Foundation::HANDLE,
    mut buf: &[u8],
) -> std::io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    while !buf.is_empty() {
        let mut written: u32 = 0;
        let chunk = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: handle is a valid pipe handle owned by the caller;
        // buf points at `chunk` valid bytes; written is a stack out.
        let ok = unsafe {
            WriteFile(
                handle,
                buf.as_ptr(),
                chunk,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "WriteFile wrote 0 bytes",
            ));
        }
        buf = &buf[written as usize..];
    }
    Ok(())
}

#[cfg(windows)]
fn read_exact(
    handle: windows_sys::Win32::Foundation::HANDLE,
    mut buf: &mut [u8],
) -> std::io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    while !buf.is_empty() {
        let mut got: u32 = 0;
        let chunk = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: handle is a valid pipe handle owned by the caller;
        // buf points at `chunk` writable bytes; got is a stack out.
        let ok = unsafe {
            ReadFile(
                handle,
                buf.as_mut_ptr(),
                chunk,
                &mut got,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if got == 0 {
            return Err(std::io::Error::from(
                std::io::ErrorKind::UnexpectedEof,
            ));
        }
        buf = &mut buf[got as usize..];
    }
    Ok(())
}

#[cfg(test)]
pub fn cached_is_some() -> bool {
    CACHED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_some()
}

/// Round-trip a request/response pair on the cached socket. Reconnects
/// once if the cached socket fails (e.g. agent restarted between calls
/// in the same process).
pub fn request(
    msg: &bwx::protocol::Request,
) -> bin_error::Result<bwx::protocol::Response> {
    let mut guard = CACHED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    if let Some(sock) = guard.as_mut() {
        match sock.send(msg).and_then(|()| sock.recv()) {
            Ok(res) => return Ok(res),
            Err(_) => {
                *guard = None;
            }
        }
    }

    let mut sock = Sock::connect().with_context(|| {
        let log = bwx::dirs::agent_stderr_file();
        format!(
            "failed to connect to bwx-agent \
            (this often means that the agent failed to start; \
            check {} for agent logs)",
            log.display()
        )
    })?;
    sock.send(msg)?;
    let res = sock.recv()?;
    *guard = Some(sock);
    Ok(res)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn framed_send_writes_length_prefix_then_msgpack() {
        let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut sock = Sock(a);

        let req = bwx::protocol::Request::new(
            bwx::protocol::Environment::default(),
            bwx::protocol::Action::Version,
        );
        sock.send(&req).unwrap();

        let mut len_buf = [0u8; 4];
        std::io::Read::read_exact(&mut b, &mut len_buf).unwrap();
        let len = u32::from_be_bytes(len_buf);
        assert!(len > 0 && len <= MAX_MESSAGE);

        let mut payload = vec![0u8; usize::try_from(len).unwrap()];
        std::io::Read::read_exact(&mut b, &mut payload).unwrap();

        let decoded: bwx::protocol::Request =
            rmp_serde::from_slice(&payload).unwrap();
        let (action, _, _, _) = decoded.into_parts();
        assert!(matches!(action, bwx::protocol::Action::Version));
    }

    #[test]
    fn framed_recv_rejects_oversized_length() {
        let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut sock = Sock(a);

        let bogus_len: u32 = MAX_MESSAGE + 1;
        std::io::Write::write_all(&mut b, &bogus_len.to_be_bytes()).unwrap();
        // Don't bother sending payload; recv must reject before reading it.
        let res = sock.recv();
        let err = res.unwrap_err();
        assert!(format!("{err}").contains("cap"), "got: {err}");
    }

    #[test]
    fn framed_recv_rejects_truncated_payload() {
        let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut sock = Sock(a);

        // Length prefix says 64 bytes, peer sends 4 bytes then closes.
        std::io::Write::write_all(&mut b, &64u32.to_be_bytes()).unwrap();
        std::io::Write::write_all(&mut b, &[0xc0, 0xc1, 0xc2, 0xc3]).unwrap();
        drop(b);

        let err = sock.recv().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("read message"),
            "expected read error, got: {msg}"
        );
    }

    #[test]
    fn framed_recv_rejects_malformed_msgpack() {
        let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut sock = Sock(a);

        // Valid 4-byte frame of garbage that isn't a valid Response.
        let payload = b"\xc1\xc1\xc1\xc1";
        let len = u32::try_from(payload.len()).unwrap();
        std::io::Write::write_all(&mut b, &len.to_be_bytes()).unwrap();
        std::io::Write::write_all(&mut b, payload).unwrap();

        let err = sock.recv().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("parse"), "expected parse error, got: {msg}");
    }

    #[test]
    fn framed_recv_rejects_zero_length_frame() {
        let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut sock = Sock(a);

        std::io::Write::write_all(&mut b, &0u32.to_be_bytes()).unwrap();
        // No payload follows; rmp-serde over an empty slice must fail.
        let err = sock.recv().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("parse"), "expected parse error, got: {msg}");
    }

    #[test]
    fn framed_send_recv_roundtrip_via_sock_pair() {
        // Full client/server framing on both sides: encode a Response on
        // one Sock and decode it via the other Sock's recv path.
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();

        // Hand-encode the response on `b` using the same wire layout as
        // Sock::send so the test pins the framing contract.
        let resp = bwx::protocol::Response::Version { version: 42 };
        let payload = rmp_serde::to_vec(&resp).unwrap();
        let len = u32::try_from(payload.len()).unwrap();
        let mut b = b;
        std::io::Write::write_all(&mut b, &len.to_be_bytes()).unwrap();
        std::io::Write::write_all(&mut b, &payload).unwrap();

        let mut sock = Sock(a);
        match sock.recv().unwrap() {
            bwx::protocol::Response::Version { version } => {
                assert_eq!(version, 42);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn invalidate_cached_clears_slot() {
        // Plant a value in the cache then confirm invalidate_cached drops
        // it. We can't easily fabricate a Sock without a live agent, so
        // assert via the test-only inspector.
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        {
            let mut guard = CACHED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard = Some(Sock(a));
        }
        assert!(cached_is_some());
        Sock::invalidate_cached();
        assert!(!cached_is_some());
    }
}
