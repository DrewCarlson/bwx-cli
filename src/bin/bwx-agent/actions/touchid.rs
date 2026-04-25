use super::util::respond_ack;
use crate::bin_error::{self, ContextExt as _};

#[cfg(target_os = "macos")]
pub async fn touchid_enroll(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> bin_error::Result<()> {
    use rand::RngCore as _;

    // Require an unlocked vault so there are keys to wrap.
    {
        let s = state.lock().await;
        if s.needs_unlock() {
            return Err(bin_error::Error::msg(
                "cannot enroll Touch ID while vault is locked; \
                 run `bwx unlock` first",
            ));
        }
    }

    // Random 64-byte wrapper seed in a `locked::Vec` (mlocked + zeroized
    // on drop) so it never sits in ordinary heap/stack pages that could
    // be recovered from a core dump or swap.
    let mut seed = bwx::locked::Vec::new();
    seed.extend(std::iter::repeat_n(0u8, 64));
    rand::rng().fill_bytes(seed.data_mut());
    let wrapper_keys =
        bwx::touchid::blob::keys_from_wrapper_seed(seed.data());

    let label = format!("bwx-touchid-{}", bwx::uuid::new_v4());

    let (wrapped_priv_key, wrapped_org_keys) = {
        let s = state.lock().await;
        let priv_key = s.priv_key.as_ref().ok_or_else(|| {
            bin_error::Error::msg("priv_key missing post-unlock")
        })?;
        let org_keys = s.org_keys.as_ref().ok_or_else(|| {
            bin_error::Error::msg("org_keys missing post-unlock")
        })?;
        let wrapped_priv =
            bwx::cipherstring::CipherString::encrypt_symmetric(
                &wrapper_keys,
                priv_key.as_bytes(),
            )
            .context("wrap priv_key")?
            .to_string();
        let mut wrapped_org = std::collections::BTreeMap::new();
        for (oid, k) in org_keys {
            wrapped_org.insert(
                oid.clone(),
                bwx::cipherstring::CipherString::encrypt_symmetric(
                    &wrapper_keys,
                    k.as_bytes(),
                )
                .with_context(|| format!("wrap org key {oid}"))?
                .to_string(),
            );
        }
        (wrapped_priv, wrapped_org)
    };

    // If a prior enrollment exists, remove it first (rotating).
    if let Ok(existing) = bwx::touchid::blob::Blob::load() {
        if let Err(e) =
            bwx::touchid::keychain::delete(&existing.keychain_label)
        {
            log::warn!(
                "touchid: failed to delete previous Keychain item \
                 {label}: {e} (enrollment will continue; the old item \
                 is now orphaned)",
                label = existing.keychain_label,
            );
        }
    }
    bwx::touchid::keychain::store(&label, seed.data())
        .map_err(|e| bin_error::Error::msg(e.to_string()))?;

    let blob = bwx::touchid::blob::Blob {
        keychain_label: label,
        wrapped_priv_key,
        wrapped_org_keys,
    };
    blob.save().context("write touchid blob")?;

    respond_ack(sock).await?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::unused_async)]
pub async fn touchid_enroll(
    _sock: &mut crate::sock::Sock,
    _state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> bin_error::Result<()> {
    Err(bin_error::Error::msg(
        "touchid enroll is only supported on macOS",
    ))
}

pub async fn touchid_disable(
    sock: &mut crate::sock::Sock,
) -> bin_error::Result<()> {
    #[cfg(target_os = "macos")]
    if let Ok(blob) = bwx::touchid::blob::Blob::load() {
        if let Err(e) = bwx::touchid::keychain::delete(&blob.keychain_label) {
            log::warn!(
                "touchid: failed to delete Keychain item {label}: {e} \
                 (blob will still be removed; Keychain item may be \
                 orphaned — clear manually in Keychain Access if \
                 desired)",
                label = blob.keychain_label,
            );
        }
    }
    bwx::touchid::blob::Blob::remove().context("remove touchid blob")?;
    respond_ack(sock).await?;
    Ok(())
}

pub async fn touchid_status(
    sock: &mut crate::sock::Sock,
) -> bin_error::Result<()> {
    let config = bwx::config::Config::load()
        .unwrap_or_else(|_| bwx::config::Config::new());
    let (enrolled, label) = match bwx::touchid::blob::Blob::load() {
        Ok(blob) => (true, Some(blob.keychain_label)),
        Err(_) => (false, None),
    };
    sock.send(&bwx::protocol::Response::TouchIdStatus {
        enrolled,
        gate: config.touchid_gate.to_string(),
        keychain_label: label,
    })
    .await?;
    Ok(())
}
