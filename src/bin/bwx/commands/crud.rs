use std::fmt::Write as _;

use super::auth::unlock;
use super::cipher::DecryptedData;
use super::find::{find_entry, Needle};
use super::util::{
    format_rfc3339, load_db, parse_editor, save_db, HELP_NOTES, HELP_PW,
};
use crate::bin_error::{self, ContextExt as _};

pub fn add(
    name: &str,
    username: Option<&str>,
    uris: &[(String, Option<bwx::api::UriMatchType>)],
    folder: Option<&str>,
) -> bin_error::Result<()> {
    unlock()?;

    let mut db = load_db()?;
    // unwrap is safe here because the call to unlock above is guaranteed to
    // populate these or error
    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let name = crate::actions::encrypt(name, None)?;

    let username = username
        .map(|username| crate::actions::encrypt(username, None))
        .transpose()?;

    let contents = bwx::edit::edit("", HELP_PW)?;

    let (password, notes) = parse_editor(&contents);
    let password = password
        .map(|password| crate::actions::encrypt(&password, None))
        .transpose()?;
    let notes = notes
        .map(|notes| crate::actions::encrypt(&notes, None))
        .transpose()?;
    let uris: Vec<_> = uris
        .iter()
        .map(|uri| {
            Ok(bwx::db::Uri {
                uri: crate::actions::encrypt(&uri.0, None)?,
                match_type: uri.1,
            })
        })
        .collect::<bin_error::Result<_>>()?;

    let mut folder_id = None;
    if let Some(folder_name) = folder {
        let (new_access_token, folders) =
            bwx::actions::list_folders(&access_token, refresh_token)?;
        if let Some(new_access_token) = new_access_token {
            access_token.clone_from(&new_access_token);
            db.access_token = Some(new_access_token);
            save_db(&db)?;
        }

        let folders: Vec<(String, String)> = folders
            .iter()
            .cloned()
            .map(|(id, name)| {
                Ok((id, crate::actions::decrypt(&name, None, None)?))
            })
            .collect::<bin_error::Result<_>>()?;

        for (id, name) in folders {
            if name == folder_name {
                folder_id = Some(id);
            }
        }
        if folder_id.is_none() {
            let (new_access_token, id) = bwx::actions::create_folder(
                &access_token,
                refresh_token,
                &crate::actions::encrypt(folder_name, None)?,
            )?;
            if let Some(new_access_token) = new_access_token {
                access_token.clone_from(&new_access_token);
                db.access_token = Some(new_access_token);
                save_db(&db)?;
            }
            folder_id = Some(id);
        }
    }

    if let (Some(access_token), ()) = bwx::actions::add(
        &access_token,
        refresh_token,
        &name,
        &bwx::db::EntryData::Login {
            username,
            password,
            uris,
            totp: None,
        },
        notes.as_deref(),
        folder_id.as_deref(),
    )? {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

pub fn generate(
    name: Option<&str>,
    username: Option<&str>,
    uris: &[(String, Option<bwx::api::UriMatchType>)],
    folder: Option<&str>,
    len: usize,
    ty: bwx::pwgen::Type,
) -> bin_error::Result<()> {
    let password = bwx::pwgen::pwgen(ty, len);
    // pwgen guarantees valid UTF-8 (ASCII alphabet + space-joined
    // diceware words), so this unwrap can't fail.
    let password_str = std::str::from_utf8(password.password()).unwrap();
    println!("{password_str}");

    if let Some(name) = name {
        unlock()?;

        let mut db = load_db()?;
        // unwrap is safe here because the call to unlock above is guaranteed
        // to populate these or error
        let mut access_token = db.access_token.as_ref().unwrap().clone();
        let refresh_token = db.refresh_token.as_ref().unwrap();

        let name = crate::actions::encrypt(name, None)?;
        let username = username
            .map(|username| crate::actions::encrypt(username, None))
            .transpose()?;
        let password = crate::actions::encrypt(password_str, None)?;
        let uris: Vec<_> = uris
            .iter()
            .map(|uri| {
                Ok(bwx::db::Uri {
                    uri: crate::actions::encrypt(&uri.0, None)?,
                    match_type: uri.1,
                })
            })
            .collect::<bin_error::Result<_>>()?;

        let mut folder_id = None;
        if let Some(folder_name) = folder {
            let (new_access_token, folders) =
                bwx::actions::list_folders(&access_token, refresh_token)?;
            if let Some(new_access_token) = new_access_token {
                access_token.clone_from(&new_access_token);
                db.access_token = Some(new_access_token);
                save_db(&db)?;
            }

            let folders: Vec<(String, String)> = folders
                .iter()
                .cloned()
                .map(|(id, name)| {
                    Ok((id, crate::actions::decrypt(&name, None, None)?))
                })
                .collect::<bin_error::Result<_>>()?;

            for (id, name) in folders {
                if name == folder_name {
                    folder_id = Some(id);
                }
            }
            if folder_id.is_none() {
                let (new_access_token, id) = bwx::actions::create_folder(
                    &access_token,
                    refresh_token,
                    &crate::actions::encrypt(folder_name, None)?,
                )?;
                if let Some(new_access_token) = new_access_token {
                    access_token.clone_from(&new_access_token);
                    db.access_token = Some(new_access_token);
                    save_db(&db)?;
                }
                folder_id = Some(id);
            }
        }

        if let (Some(access_token), ()) = bwx::actions::add(
            &access_token,
            refresh_token,
            &name,
            &bwx::db::EntryData::Login {
                username,
                password: Some(password),
                uris,
                totp: None,
            },
            None,
            folder_id.as_deref(),
        )? {
            db.access_token = Some(access_token);
            save_db(&db)?;
        }

        crate::actions::sync()?;
    }

    Ok(())
}

pub fn edit(
    name: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> bin_error::Result<()> {
    unlock()?;

    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        name
    );

    let (entry, decrypted) =
        find_entry(&db, name, username, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    let (data, fields, notes, history) = match &decrypted.data {
        DecryptedData::Login { password, .. } => {
            let mut contents =
                format!("{}\n", password.as_deref().unwrap_or(""));
            if let Some(notes) = decrypted.notes {
                write!(contents, "\n{notes}\n").unwrap();
            }

            let contents = bwx::edit::edit(&contents, HELP_PW)?;

            let (password, notes) = parse_editor(&contents);
            let password = password
                .map(|password| {
                    crate::actions::encrypt(
                        &password,
                        entry.org_id.as_deref(),
                    )
                })
                .transpose()?;
            let notes = notes
                .map(|notes| {
                    crate::actions::encrypt(&notes, entry.org_id.as_deref())
                })
                .transpose()?;
            let mut history = entry.history.clone();
            let bwx::db::EntryData::Login {
                username: entry_username,
                password: entry_password,
                uris: entry_uris,
                totp: entry_totp,
            } = &entry.data
            else {
                unreachable!();
            };

            if let Some(prev_password) = entry_password.clone() {
                let new_history_entry = bwx::db::HistoryEntry {
                    last_used_date: format_rfc3339(
                        std::time::SystemTime::now(),
                    ),
                    password: prev_password,
                };
                history.insert(0, new_history_entry);
            }

            let data = bwx::db::EntryData::Login {
                username: entry_username.clone(),
                password,
                uris: entry_uris.clone(),
                totp: entry_totp.clone(),
            };
            (data, entry.fields, notes, history)
        }
        DecryptedData::SecureNote => {
            let data = bwx::db::EntryData::SecureNote {};

            let editor_content = decrypted.notes.map_or_else(
                || "\n".to_string(),
                |notes| format!("{notes}\n"),
            );
            let contents = bwx::edit::edit(&editor_content, HELP_NOTES)?;

            // prepend blank line to be parsed as pw by `parse_editor`
            let (_, notes) = parse_editor(&format!("\n{contents}\n"));

            let notes = notes
                .map(|notes| {
                    crate::actions::encrypt(&notes, entry.org_id.as_deref())
                })
                .transpose()?;

            (data, entry.fields, notes, entry.history)
        }
        _ => {
            return Err(crate::bin_error::err!(
                "modifications are only supported for login and note entries"
            ));
        }
    };

    if let (Some(access_token), ()) = bwx::actions::edit(
        access_token,
        refresh_token,
        &entry.id,
        entry.org_id.as_deref(),
        &entry.name,
        &data,
        &fields,
        notes.as_deref(),
        entry.folder_id.as_deref(),
        &history,
    )? {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;
    Ok(())
}

pub fn remove(
    name: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> bin_error::Result<()> {
    unlock()?;

    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        name
    );

    let (entry, _) = find_entry(&db, name, username, folder, ignore_case)
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if let (Some(access_token), ()) =
        bwx::actions::remove(access_token, refresh_token, &entry.id)?
    {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}
