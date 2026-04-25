use crate::bin_error::{self, ContextExt as _};

pub(super) async fn respond_ack(
    sock: &mut crate::sock::Sock,
) -> bin_error::Result<()> {
    sock.send(&bwx::protocol::Response::Ack).await?;

    Ok(())
}

pub(super) async fn respond_decrypt(
    sock: &mut crate::sock::Sock,
    plaintext: String,
) -> bin_error::Result<()> {
    sock.send(&bwx::protocol::Response::Decrypt { plaintext })
        .await?;

    Ok(())
}

pub(super) async fn respond_encrypt(
    sock: &mut crate::sock::Sock,
    cipherstring: String,
) -> bin_error::Result<()> {
    sock.send(&bwx::protocol::Response::Encrypt { cipherstring })
        .await?;

    Ok(())
}

pub(super) async fn config_email() -> bin_error::Result<String> {
    let config = bwx::config::Config::load_async().await?;
    config.email.map_or_else(
        || {
            Err(bin_error::Error::msg(
                "failed to find email address in config",
            ))
        },
        Ok,
    )
}

pub(super) async fn load_db() -> bin_error::Result<bwx::db::Db> {
    let config = bwx::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        Ok(bwx::db::Db::load_async(&config.server_name(), email).await?)
    } else {
        Err(bin_error::Error::msg(
            "failed to find email address in config",
        ))
    }
}

pub(super) async fn save_db(db: &bwx::db::Db) -> bin_error::Result<()> {
    let config = bwx::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        db.save_async(&config.server_name(), email).await?;
        Ok(())
    } else {
        Err(bin_error::Error::msg(
            "failed to find email address in config",
        ))
    }
}

pub(super) async fn config_base_url() -> bin_error::Result<String> {
    let config = bwx::config::Config::load_async().await?;
    Ok(config.base_url())
}

pub(super) async fn config_pinentry() -> bin_error::Result<String> {
    let config = bwx::config::Config::load_async().await?;
    Ok(config.pinentry)
}

pub(super) async fn subscribe_to_notifications(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> bin_error::Result<()> {
    if state.lock().await.notifications_handler.is_connected() {
        return Ok(());
    }

    let config = bwx::config::Config::load_async()
        .await
        .context("Config is missing")?;
    let email = config.email.clone().context("Config is missing email")?;
    let db = bwx::db::Db::load_async(config.server_name().as_str(), &email)
        .await?;
    let access_token =
        db.access_token.context("Error getting access token")?;

    let websocket_url = format!(
        "{}/hub?access_token={}",
        config.notifications_url(),
        access_token
    )
    .replace("https://", "wss://");

    let mut state = state.lock().await;
    state
        .notifications_handler
        .connect(websocket_url)
        .await
        .err()
        .map_or_else(
            || Ok(()),
            |err| Err(bin_error::Error::msg(err.to_string())),
        )
}
