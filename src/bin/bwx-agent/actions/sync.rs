use sha2::Digest as _;

use super::auth::prompt_master_password;
use super::util::{
    config_email, load_db, respond_ack, save_db, subscribe_to_notifications,
};
use crate::bin_error::{self, ContextExt as _};

pub async fn sync(
    sock: Option<&mut crate::sock::Sock>,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> bin_error::Result<()> {
    let mut db = load_db().await?;

    let access_token = if let Some(access_token) = &db.access_token {
        access_token.clone()
    } else {
        return Err(bin_error::Error::msg(
            "failed to find access token in db",
        ));
    };
    let refresh_token = if let Some(refresh_token) = &db.refresh_token {
        refresh_token.clone()
    } else {
        return Err(bin_error::Error::msg(
            "failed to find refresh token in db",
        ));
    };
    let (
        access_token,
        (protected_key, protected_private_key, protected_org_keys, entries),
    ) = bwx::actions::sync(&access_token, &refresh_token)
        .await
        .context("failed to sync database from server")?;
    state.lock().await.set_master_password_reprompt(&entries);
    if let Some(access_token) = access_token {
        db.access_token = Some(access_token);
    }
    db.protected_key = Some(protected_key);
    db.protected_private_key = Some(protected_private_key);
    db.protected_org_keys = protected_org_keys;
    db.entries = entries;
    save_db(&db).await?;

    if let Err(e) = subscribe_to_notifications(state.clone()).await {
        eprintln!("failed to subscribe to notifications: {e}");
    }

    if let Some(sock) = sock {
        respond_ack(sock).await?;
    }

    Ok(())
}

pub(super) async fn decrypt_cipher(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &bwx::protocol::Environment,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> bin_error::Result<String> {
    let mut state = state.lock().await;
    if !state.master_password_reprompt_initialized() {
        let db = load_db().await?;
        state.set_master_password_reprompt(&db.entries);
    }
    let Some(keys) = state.key(org_id) else {
        return Err(bin_error::Error::msg(
            "failed to find decryption keys in in-memory state",
        ));
    };
    let entry_key = if let Some(entry_key) = entry_key {
        let key_cipherstring =
            bwx::cipherstring::CipherString::new(entry_key)
                .context("failed to parse individual item encryption key")?;
        Some(bwx::locked::Keys::new(
            key_cipherstring.decrypt_locked_symmetric(keys).context(
                "failed to decrypt individual item encryption key",
            )?,
        ))
    } else {
        None
    };

    let mut sha256 = sha2::Sha256::new();
    sha256.update(cipherstring);
    let master_password_reprompt: [u8; 32] = sha256.finalize().into();
    if state
        .master_password_reprompt
        .contains(&master_password_reprompt)
    {
        let db = load_db().await?;

        let Some(kdf) = db.kdf else {
            return Err(bin_error::Error::msg(
                "failed to find kdf type in db",
            ));
        };

        let Some(iterations) = db.iterations else {
            return Err(bin_error::Error::msg(
                "failed to find number of iterations in db",
            ));
        };

        let memory = db.memory;
        let parallelism = db.parallelism;

        let Some(protected_key) = db.protected_key else {
            return Err(bin_error::Error::msg(
                "failed to find protected key in db",
            ));
        };
        let Some(protected_private_key) = db.protected_private_key else {
            return Err(bin_error::Error::msg(
                "failed to find protected private key in db",
            ));
        };

        let email = config_email().await?;

        let mut err_msg = None;
        for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let password = prompt_master_password(
                "Master Password",
                "Accessing this entry requires the master password",
                environment,
                err.as_deref(),
            )
            .await
            .context("failed to read master password")?;
            match bwx::actions::unlock(
                &email,
                &password,
                kdf,
                iterations,
                memory,
                parallelism,
                &protected_key,
                &protected_private_key,
                &db.protected_org_keys,
            ) {
                Ok(_) => {
                    break;
                }
                Err(bwx::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(bwx::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to unlock database");
                    }
                    err_msg = Some(message);
                }
                Err(e) => return Err(e).context("failed to unlock database"),
            }
        }
    }

    let cipherstring = bwx::cipherstring::CipherString::new(cipherstring)
        .context("failed to parse encrypted secret")?;
    let plaintext = String::from_utf8(
        cipherstring
            .decrypt_symmetric(keys, entry_key.as_ref())
            .context("failed to decrypt encrypted secret")?,
    )
    .context("failed to parse decrypted secret")?;

    Ok(plaintext)
}
