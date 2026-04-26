use std::io::{BufRead as _, Write as _};
use std::sync::Mutex;

use crate::bin_error::{self, ContextExt as _};

/// Cap on the size of a single JSON-line response from the agent. Blocks
/// a runaway or malicious agent from pushing the CLI into unbounded heap
/// growth.
const MAX_MESSAGE: u64 = 16 * 1024 * 1024;

/// Process-local cached connection. Reused across IPC calls in the same
/// `bwx` invocation so we don't pay a fresh connect()/handshake on every
/// `actions::decrypt`/`encrypt`/etc. Cleared on any send/recv error and
/// when `Quit` is sent.
static CACHED: Mutex<Option<Sock>> = Mutex::new(None);

pub struct Sock(std::os::unix::net::UnixStream);

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
        sock.write_all(
            serde_json::to_string(msg)
                .context("failed to serialize message to agent")?
                .as_bytes(),
        )
        .context("failed to send message to agent")?;
        sock.write_all(b"\n")
            .context("failed to send message to agent")?;
        Ok(())
    }

    pub fn recv(&mut self) -> bin_error::Result<bwx::protocol::Response> {
        let Self(sock) = self;
        let limited = std::io::Read::take(&mut *sock, MAX_MESSAGE);
        let mut buf = std::io::BufReader::new(limited);
        let mut line = String::new();
        buf.read_line(&mut line)
            .context("failed to read message from agent")?;
        if !line.ends_with('\n') {
            return Err(bin_error::Error::msg(format!(
                "agent response exceeds {MAX_MESSAGE}-byte cap"
            )));
        }
        serde_json::from_str(&line)
            .context("failed to parse message from agent")
    }
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
    let mut guard = CACHED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

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

#[cfg(test)]
mod tests {
    use super::*;

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
