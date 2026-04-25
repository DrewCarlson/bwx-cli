use super::auth::unlock;
use super::cipher::DecryptedData;
use super::find::{find_entry, Needle};
use super::util::load_db;
use crate::bin_error::{self, ContextExt as _};

pub fn ssh_public_key(
    name: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> bin_error::Result<()> {
    unlock()?;
    let db = load_db()?;
    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        name
    );
    let (_, decrypted) = find_entry(&db, name, username, folder, ignore_case)
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    match decrypted.data {
        DecryptedData::SshKey {
            public_key: Some(pk),
            ..
        } => {
            println!("{pk}");
            Ok(())
        }
        DecryptedData::SshKey {
            public_key: None, ..
        } => Err(bin_error::Error::msg(format!(
            "entry '{desc}' has no stored public key"
        ))),
        _ => Err(bin_error::Error::msg(format!(
            "entry '{desc}' is not an SSH key"
        ))),
    }
}

pub fn ssh_socket() {
    println!("{}", bwx::dirs::ssh_agent_socket_file().display());
}

pub fn ssh_allowed_signers() -> bin_error::Result<()> {
    unlock()?;
    let db = load_db()?;
    let config = bwx::config::Config::load()?;
    let email = config.email.as_deref().ok_or_else(|| {
        bin_error::Error::msg(
            "no email configured; run `bwx config set email`",
        )
    })?;
    for entry in &db.entries {
        let bwx::db::EntryData::SshKey {
            public_key: Some(pk_enc),
            ..
        } = &entry.data
        else {
            continue;
        };
        let pk = crate::actions::decrypt(
            pk_enc,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?;
        println!("{email} {}", pk.trim());
    }
    Ok(())
}
