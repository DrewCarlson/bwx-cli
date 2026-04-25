use super::auth::unlock_state;
use super::sync::decrypt_cipher;
use super::util::load_db;
use crate::bin_error;

pub async fn get_ssh_public_keys(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> bin_error::Result<Vec<String>> {
    let environment = {
        let state = state.lock().await;
        state.set_timeout();
        state.last_environment().clone()
    };
    unlock_state(state.clone(), &environment).await?;

    let db = load_db().await?;
    let mut pubkeys = Vec::new();

    for entry in db.entries {
        if let bwx::db::EntryData::SshKey {
            public_key: Some(encrypted),
            ..
        } = &entry.data
        {
            let plaintext = decrypt_cipher(
                state.clone(),
                &environment,
                encrypted,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .await?;

            pubkeys.push(plaintext);
        }
    }

    Ok(pubkeys)
}

/// Encrypted handle to an SSH entry matching the requested pubkey. The
/// plaintext private key is intentionally not pulled into memory here,
/// so a cancelled user confirm leaves no key material on the heap.
pub struct LocatedSshEntry {
    pub private_key_enc: String,
    pub entry_key: Option<String>,
    pub org_id: Option<String>,
    pub name: String,
}

pub async fn locate_ssh_private_key(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    request_public_key: ssh_agent_lib::ssh_key::PublicKey,
) -> bin_error::Result<LocatedSshEntry> {
    let environment = {
        let state = state.lock().await;
        state.set_timeout();
        state.last_environment().clone()
    };
    unlock_state(state.clone(), &environment).await?;

    let request_bytes = request_public_key.to_bytes();

    let db = load_db().await?;

    for entry in db.entries {
        if let bwx::db::EntryData::SshKey {
            private_key,
            public_key,
            ..
        } = &entry.data
        {
            let Some(public_key_enc) = public_key else {
                continue;
            };
            let public_key_plaintext = decrypt_cipher(
                state.clone(),
                &environment,
                public_key_enc,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .await?;
            let public_key_bytes =
                ssh_agent_lib::ssh_key::PublicKey::from_openssh(
                    &public_key_plaintext,
                )
                .map_err(|e| bin_error::Error::Boxed(Box::new(e)))?
                .to_bytes();

            if public_key_bytes == request_bytes {
                let private_key_enc =
                    private_key.as_ref().ok_or_else(|| {
                        bin_error::Error::msg(
                            "Matching entry has no private key",
                        )
                    })?;

                let name_plaintext = decrypt_cipher(
                    state.clone(),
                    &environment,
                    &entry.name,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
                .await
                .unwrap_or_else(|_| "<unknown>".to_string());

                return Ok(LocatedSshEntry {
                    private_key_enc: private_key_enc.clone(),
                    entry_key: entry.key.clone(),
                    org_id: entry.org_id.clone(),
                    name: name_plaintext,
                });
            }
        }
    }

    Err(bin_error::Error::msg("No matching private key found"))
}

/// Second phase of the split SSH-sign flow: decrypt the private key
/// cipherstring located by `locate_ssh_private_key`. Only call after the
/// user has confirmed Touch ID / pinentry CONFIRM. Callers must drop the
/// returned `PrivateKey` as soon as signing completes.
pub async fn decrypt_located_ssh_private_key(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    located: &LocatedSshEntry,
) -> bin_error::Result<ssh_agent_lib::ssh_key::PrivateKey> {
    let environment = {
        let state = state.lock().await;
        state.last_environment().clone()
    };
    let plaintext = decrypt_cipher(
        state,
        &environment,
        &located.private_key_enc,
        located.entry_key.as_deref(),
        located.org_id.as_deref(),
    )
    .await?;
    ssh_agent_lib::ssh_key::PrivateKey::from_openssh(plaintext)
        .map_err(|e| bin_error::Error::Boxed(Box::new(e)))
}
