use signature::{RandomizedSigner as _, SignatureEncoding as _, Signer as _};

const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

#[derive(Clone)]
pub struct SshAgent {
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
}

impl SshAgent {
    pub fn new(
        state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    ) -> Self {
        Self { state }
    }

    #[cfg(unix)]
    pub async fn run(self) -> crate::bin_error::Result<()> {
        let socket = bwx::dirs::ssh_agent_socket_file();
        let listener = crate::sock::bind_atomic(&socket)?;
        ssh_agent_lib::agent::listen(UidFilteredUnixListener(listener), self)
            .await
            .map_err(|e| crate::bin_error::Error::Boxed(Box::new(e)))?;

        Ok(())
    }

    #[cfg(windows)]
    pub async fn run(self) -> crate::bin_error::Result<()> {
        let pipe = bwx::dirs::ssh_agent_pipe_name();
        let listener = OwnerFilteredPipeListener::bind(&pipe)?;
        ssh_agent_lib::agent::listen(listener, self)
            .await
            .map_err(|e| crate::bin_error::Error::Boxed(Box::new(e)))?;
        Ok(())
    }
}

/// Per-connection ssh-agent session. Carries a human-readable `peer`
/// description (program name + pid) shown in Touch ID / pinentry prompts
/// so the user sees which local client is requesting a signature. Never
/// used for authorization.
#[derive(Clone)]
pub struct SshSession {
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    peer: String,
}

// The blanket `Agent<UnixListener> for T: Session + Clone` shipped by
// ssh-agent-lib only covers the concrete `UnixListener` type, so it has
// to be restated here for the filtered wrapper — otherwise `listen`
// can't resolve a session factory.
#[cfg(unix)]
impl ssh_agent_lib::agent::Agent<UidFilteredUnixListener> for SshAgent {
    fn new_session(
        &mut self,
        socket: &tokio::net::UnixStream,
    ) -> impl ssh_agent_lib::agent::Session {
        use std::os::unix::io::AsRawFd as _;
        let peer = describe_peer(socket.as_raw_fd());
        log::debug!("ssh-agent: accepted connection from {peer}");
        SshSession {
            state: self.state.clone(),
            peer,
        }
    }
}

/// Build a "`<program>` (pid `<pid>`)" description of the peer on a
/// connected Unix-socket fd. Best-effort: substitutes an "unknown"
/// placeholder if any lookup fails.
#[cfg(unix)]
fn describe_peer(fd: std::os::unix::io::RawFd) -> String {
    let Some(pid) = crate::sock::peer_pid(fd) else {
        return "unknown client".to_string();
    };
    let name = peer_program_name(pid).unwrap_or_else(|| "<unknown>".into());
    format!("{name} (pid {pid})")
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_program_name(pid: i32) -> Option<String> {
    // /proc/<pid>/comm holds the `TASK_COMM_LEN`-truncated program
    // name (no path). Good enough for a prompt.
    let raw = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(target_os = "macos")]
fn peer_program_name(pid: i32) -> Option<String> {
    // `PROC_PIDPATHINFO_MAXSIZE` is Darwin-defined as 4 * `MAXPATHLEN`
    // (= 4096); typed `c_int`, so the widening to `usize` needs an
    // explicit allow for the `as_conversions` lint.
    #[allow(clippy::as_conversions)]
    const BUF_LEN: usize = libc::PROC_PIDPATHINFO_MAXSIZE as usize;
    let mut buf = [0u8; BUF_LEN];
    // SAFETY: buf is stack-allocated of the documented size;
    // proc_pidpath writes at most `buf.len()` bytes.
    let written = unsafe {
        libc::proc_pidpath(
            pid,
            buf.as_mut_ptr().cast(),
            u32::try_from(buf.len()).ok()?,
        )
    };
    if written <= 0 {
        return None;
    }
    let n = usize::try_from(written).ok()?;
    let path = std::str::from_utf8(&buf[..n]).ok()?;
    Some(
        std::path::Path::new(path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(path)
            .to_string(),
    )
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos"
    ))
))]
fn peer_program_name(_pid: i32) -> Option<String> {
    None
}

#[cfg(unix)]
#[derive(Debug)]
struct UidFilteredUnixListener(tokio::net::UnixListener);

#[cfg(unix)]
#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::ListeningSocket for UidFilteredUnixListener {
    type Stream = tokio::net::UnixStream;
    async fn accept(&mut self) -> std::io::Result<Self::Stream> {
        loop {
            let (stream, _addr) = self.0.accept().await?;
            match crate::sock::check_peer_uid(&stream) {
                Ok(()) => return Ok(stream),
                Err(e) => {
                    log::warn!("ssh-agent: rejecting connection: {e:#}");
                }
            }
        }
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct OwnerFilteredPipeListener {
    server: tokio::net::windows::named_pipe::NamedPipeServer,
    name: String,
}

#[cfg(windows)]
impl OwnerFilteredPipeListener {
    fn bind(name: &str) -> crate::bin_error::Result<Self> {
        use crate::bin_error::ContextExt as _;
        let server = crate::sock::create_pipe_instance_for_ssh(name, true)
            .context("failed to create initial ssh-agent pipe instance")?;
        Ok(Self {
            server,
            name: name.to_string(),
        })
    }
}

#[cfg(windows)]
#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::ListeningSocket for OwnerFilteredPipeListener {
    type Stream = tokio::net::windows::named_pipe::NamedPipeServer;
    async fn accept(&mut self) -> std::io::Result<Self::Stream> {
        loop {
            self.server.connect().await?;
            let next =
                crate::sock::create_pipe_instance_for_ssh(&self.name, false)?;
            let stream = std::mem::replace(&mut self.server, next);
            match crate::sock::check_peer_uid(&stream) {
                Ok(()) => return Ok(stream),
                Err(e) => {
                    log::warn!("ssh-agent: rejecting connection: {e:#}");
                }
            }
        }
    }
}

#[cfg(windows)]
impl ssh_agent_lib::agent::Agent<OwnerFilteredPipeListener> for SshAgent {
    fn new_session(
        &mut self,
        socket: &tokio::net::windows::named_pipe::NamedPipeServer,
    ) -> impl ssh_agent_lib::agent::Session {
        use std::os::windows::io::AsRawHandle as _;
        let peer = describe_peer_handle(socket.as_raw_handle());
        log::debug!("ssh-agent: accepted connection from {peer}");
        SshSession {
            state: self.state.clone(),
            peer,
        }
    }
}

#[cfg(windows)]
fn describe_peer_handle(
    handle: std::os::windows::io::RawHandle,
) -> String {
    let Some(pid) = crate::sock::peer_pid(handle) else {
        return "unknown client".to_string();
    };
    let name = peer_program_name_win(pid)
        .unwrap_or_else(|| "<unknown>".into());
    format!("{name} (pid {pid})")
}

#[cfg(windows)]
fn peer_program_name_win(pid: i32) -> Option<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, MAX_PATH};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let pid_u = u32::try_from(pid).ok()?;
    // SAFETY: PROCESS_QUERY_LIMITED_INFORMATION is sufficient for
    // QueryFullProcessImageNameW; pid is a u32 from the OS.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid_u) };
    if h.is_null() {
        return None;
    }
    #[allow(clippy::as_conversions)]
    const BUF: usize = MAX_PATH as usize;
    let mut buf = [0u16; BUF];
    let mut size = u32::try_from(buf.len()).expect("MAX_PATH fits in u32");
    // SAFETY: h is a valid process handle; buf is sized via size in/out.
    let ok = unsafe {
        QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size)
    };
    // SAFETY: h is closed exactly once.
    unsafe {
        CloseHandle(h);
    }
    if ok == 0 || size == 0 {
        return None;
    }
    use std::os::windows::ffi::OsStringExt as _;
    let path = std::ffi::OsString::from_wide(&buf[..size as usize]);
    std::path::PathBuf::from(path)
        .file_name()
        .and_then(|s| s.to_str())
        .map(str::to_string)
}

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for SshSession {
    async fn request_identities(
        &mut self,
    ) -> Result<
        Vec<ssh_agent_lib::proto::Identity>,
        ssh_agent_lib::error::AgentError,
    > {
        crate::actions::get_ssh_public_keys(self.state.clone())
            .await
            .map_err(|e| ssh_agent_lib::error::AgentError::Other(e.into()))?
            .into_iter()
            .map(|p| {
                p.parse::<ssh_agent_lib::ssh_key::PublicKey>()
                    .map(|pk| ssh_agent_lib::proto::Identity {
                        pubkey: pk.key_data().clone(),
                        comment: String::new(),
                    })
                    .map_err(ssh_agent_lib::error::AgentError::other)
            })
            .collect()
    }

    async fn sign(
        &mut self,
        request: ssh_agent_lib::proto::SignRequest,
    ) -> Result<
        ssh_agent_lib::ssh_key::Signature,
        ssh_agent_lib::error::AgentError,
    > {
        let pubkey =
            ssh_agent_lib::ssh_key::PublicKey::new(request.pubkey, "");

        // Phase 1: locate the matching entry and decrypt only the public
        // key + entry name (enough for a named prompt) while leaving the
        // *private* key cipherstring encrypted. If the user cancels
        // Touch ID or pinentry CONFIRM below, no plaintext private key
        // material ever sits on the heap.
        let located = crate::actions::locate_ssh_private_key(
            self.state.clone(),
            pubkey,
        )
        .await
        .map_err(|e| ssh_agent_lib::error::AgentError::Other(e.into()))?;

        let gate = bwx::config::Config::load()
            .map_or(bwx::biometric::Gate::Off, |c| c.biometric_gate);
        let biometric_gated_this_sign =
            bwx::biometric::gate_applies(gate, bwx::biometric::Kind::SshSign);
        if biometric_gated_this_sign {
            let ok = bwx::biometric::require_presence(&format!(
                "{peer} wants to sign with SSH key {name:?}",
                peer = self.peer,
                name = located.name,
            ))
            .await
            .map_err(|e| ssh_agent_lib::error::AgentError::Other(e.into()))?;
            if !ok {
                return Err(ssh_agent_lib::error::AgentError::Other(
                    "signature declined by Touch ID".into(),
                ));
            }
        }

        // Optional confirm-on-sign via pinentry. Skipped when the
        // biometric gate already prompted for this sign — the biometric
        // tap is the confirmation, and pinentry isn't guaranteed to be
        // installed on macOS.
        let (confirm_required, pinentry, environment) = {
            let state = self.state.lock().await;
            let config = bwx::config::Config::load().map_err(|e| {
                ssh_agent_lib::error::AgentError::Other(e.into())
            })?;
            (
                config.ssh_confirm_sign && !biometric_gated_this_sign,
                config.pinentry,
                state.last_environment().clone(),
            )
        };
        if confirm_required {
            let ok = bwx::pinentry::confirm(
                &pinentry,
                "Sign",
                &format!(
                    "{peer} wants to sign with key {name:?}",
                    peer = self.peer,
                    name = located.name,
                ),
                &environment,
            )
            .await
            .map_err(|e| ssh_agent_lib::error::AgentError::Other(e.into()))?;
            if !ok {
                return Err(ssh_agent_lib::error::AgentError::Other(
                    "signature declined by user".into(),
                ));
            }
        }

        // Decrypt the private key now, sign, and drop at end-of-scope —
        // plaintext key material is alive only for the signing window.
        let private_key = crate::actions::decrypt_located_ssh_private_key(
            self.state.clone(),
            &located,
        )
        .await
        .map_err(|e| ssh_agent_lib::error::AgentError::Other(e.into()))?;

        match private_key.key_data() {
            ssh_agent_lib::ssh_key::private::KeypairData::Ed25519(key) => key
                .try_sign(&request.data)
                .map_err(ssh_agent_lib::error::AgentError::other),

            ssh_agent_lib::ssh_key::private::KeypairData::Rsa(key) => {
                let p = rsa::BigUint::from_bytes_be(key.private.p.as_bytes());
                let q = rsa::BigUint::from_bytes_be(key.private.q.as_bytes());
                let e = rsa::BigUint::from_bytes_be(key.public.e.as_bytes());
                let rsa_key = rsa::RsaPrivateKey::from_p_q(p, q, e)
                    .map_err(ssh_agent_lib::error::AgentError::other)?;

                let mut rng = rand_8::rngs::OsRng;

                let (algorithm, sig_bytes) = if request.flags
                    & SSH_AGENT_RSA_SHA2_512
                    != 0
                {
                    let signing_key =
                        rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(
                            rsa_key,
                        );
                    let signature = signing_key
                        .try_sign_with_rng(&mut rng, &request.data)
                        .map_err(ssh_agent_lib::error::AgentError::other)?;

                    ("rsa-sha2-512", signature.to_bytes())
                } else if request.flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                    let signing_key =
                        rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(
                            rsa_key,
                        );
                    let signature = signing_key
                        .try_sign_with_rng(&mut rng, &request.data)
                        .map_err(ssh_agent_lib::error::AgentError::other)?;

                    ("rsa-sha2-256", signature.to_bytes())
                } else {
                    let signing_key = rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new_unprefixed(rsa_key);
                    let signature = signing_key
                        .try_sign_with_rng(&mut rng, &request.data)
                        .map_err(ssh_agent_lib::error::AgentError::other)?;

                    ("ssh-rsa", signature.to_bytes())
                };

                Ok(ssh_agent_lib::ssh_key::Signature::new(
                    ssh_agent_lib::ssh_key::Algorithm::new(algorithm)
                        .map_err(ssh_agent_lib::error::AgentError::other)?,
                    sig_bytes,
                )
                .map_err(ssh_agent_lib::error::AgentError::other)?)
            }

            // TODO: Check which other key types are supported by bitwarden
            other => Err(ssh_agent_lib::error::AgentError::Other(
                format!("Unsupported key type: {other:?}").into(),
            )),
        }
    }
}
