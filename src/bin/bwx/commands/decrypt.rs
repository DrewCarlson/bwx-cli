use super::cipher::{
    DecryptedCipher, DecryptedData, DecryptedField, DecryptedHistoryEntry,
    DecryptedListCipher, DecryptedSearchCipher, DecryptedUri,
};
use super::field::{Field, ListField};
use crate::bin_error;

/// Stages cipherstrings into a single `DecryptBatch` IPC, then exposes
/// per-index typed reads with the same fatal-vs-warn-and-skip semantics
/// the per-field decrypt path used to have.
struct Batcher {
    items: Vec<bwx::protocol::DecryptItem>,
    results: Vec<bin_error::Result<String>>,
}

impl Batcher {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            results: Vec::new(),
        }
    }

    fn push(
        &mut self,
        cipherstring: &str,
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> usize {
        self.items.push(bwx::protocol::DecryptItem {
            cipherstring: cipherstring.to_string(),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        });
        self.items.len() - 1
    }

    fn push_opt(
        &mut self,
        cipherstring: Option<&str>,
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> Option<usize> {
        cipherstring.map(|c| self.push(c, entry_key, org_id))
    }

    fn run(&mut self) -> bin_error::Result<()> {
        if !self.items.is_empty() {
            let items = std::mem::take(&mut self.items);
            self.results = crate::actions::decrypt_batch(items)?;
        }
        Ok(())
    }

    /// Read a slot whose decrypt failure should propagate as an error.
    fn take_required(&self, idx: usize) -> bin_error::Result<String> {
        match &self.results[idx] {
            Ok(p) => Ok(p.clone()),
            Err(e) => Err(crate::bin_error::Error::msg(e.to_string())),
        }
    }

    /// Read a slot whose decrypt failure should warn and yield `None`.
    fn take_optional(
        &self,
        idx: Option<usize>,
        label: impl std::fmt::Display,
    ) -> Option<String> {
        idx.and_then(|i| match &self.results[i] {
            Ok(p) => Some(p.clone()),
            Err(e) => {
                log::warn!("failed to decrypt {label}: {e}");
                None
            }
        })
    }
}

/// Batched form of `decrypt_list_cipher`: stages every per-field
/// decrypt for the whole entry slice into a single `DecryptBatch` IPC,
/// then assembles the results back into per-entry list ciphers. Avoids
/// the N-IPC-per-entry blowup on `bwx list` for large vaults.
pub(super) fn decrypt_list_ciphers(
    entries: &[bwx::db::Entry],
    fields: &[ListField],
) -> bin_error::Result<Vec<DecryptedListCipher>> {
    struct Slots {
        id: String,
        entry_type: Option<String>,
        name_idx: Option<usize>,
        user_idx: Option<usize>,
        folder_idx: Option<usize>,
        // None means "list field not requested or not a Login"; an empty
        // Vec means "Login with no URIs".
        uri_indices: Option<Vec<usize>>,
    }

    let want_name = fields.contains(&ListField::Name);
    let want_user = fields.contains(&ListField::User);
    let want_folder = fields.contains(&ListField::Folder);
    let want_uris = fields.contains(&ListField::Uri);
    let want_type = fields.contains(&ListField::EntryType);

    let mut items: Vec<bwx::protocol::DecryptItem> = Vec::new();
    let mut slots: Vec<Slots> = Vec::with_capacity(entries.len());

    let push = |items: &mut Vec<bwx::protocol::DecryptItem>,
                cipherstring: &str,
                entry_key: Option<&str>,
                org_id: Option<&str>|
     -> usize {
        items.push(bwx::protocol::DecryptItem {
            cipherstring: cipherstring.to_string(),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        });
        items.len() - 1
    };

    for entry in entries {
        let entry_type = if want_type {
            Some(
                match &entry.data {
                    bwx::db::EntryData::Login { .. } => "Login",
                    bwx::db::EntryData::Identity { .. } => "Identity",
                    bwx::db::EntryData::SshKey { .. } => "SSH Key",
                    bwx::db::EntryData::SecureNote => "Note",
                    bwx::db::EntryData::Card { .. } => "Card",
                }
                .to_string(),
            )
        } else {
            None
        };

        let name_idx = want_name.then(|| {
            push(
                &mut items,
                &entry.name,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        });

        let user_idx = if want_user {
            match &entry.data {
                bwx::db::EntryData::Login {
                    username: Some(u), ..
                } => Some(push(
                    &mut items,
                    u,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )),
                _ => None,
            }
        } else {
            None
        };

        // Folder names always use the local key (folders are scoped to
        // the user's own vault, not the organisation).
        let folder_idx = if want_folder {
            entry
                .folder
                .as_ref()
                .map(|f| push(&mut items, f, None, None))
        } else {
            None
        };

        let uri_indices = if want_uris {
            match &entry.data {
                bwx::db::EntryData::Login { uris, .. } => Some(
                    uris.iter()
                        .map(|s| {
                            push(
                                &mut items,
                                &s.uri,
                                entry.key.as_deref(),
                                entry.org_id.as_deref(),
                            )
                        })
                        .collect(),
                ),
                _ => None,
            }
        } else {
            None
        };

        slots.push(Slots {
            id: entry.id.clone(),
            entry_type,
            name_idx,
            user_idx,
            folder_idx,
            uri_indices,
        });
    }

    let results = if items.is_empty() {
        Vec::new()
    } else {
        crate::actions::decrypt_batch(items)?
    };

    let take = |idx: Option<usize>, label: &str| -> Option<String> {
        idx.and_then(|i| match &results[i] {
            Ok(s) => Some(s.clone()),
            Err(e) => {
                log::warn!("failed to decrypt {label}: {e}");
                None
            }
        })
    };

    let mut out = Vec::with_capacity(slots.len());
    for s in slots {
        let name = if want_name {
            // Per-entry name decrypt failure is fatal, matching the
            // existing single-entry path (`decrypt_list_cipher`).
            match s.name_idx {
                Some(i) => match &results[i] {
                    Ok(s) => Some(s.clone()),
                    Err(e) => {
                        return Err(crate::bin_error::err!(
                            "failed to decrypt entry name: {e}"
                        ));
                    }
                },
                None => None,
            }
        } else {
            None
        };
        let user = take(s.user_idx, "username");
        let folder = if want_folder {
            match s.folder_idx {
                Some(i) => match &results[i] {
                    Ok(p) => Some(p.clone()),
                    Err(e) => {
                        return Err(crate::bin_error::err!(
                            "failed to decrypt folder name: {e}"
                        ));
                    }
                },
                None => None,
            }
        } else {
            None
        };
        let uris = s.uri_indices.map(|idxs| {
            idxs.into_iter()
                .filter_map(|i| match &results[i] {
                    Ok(p) => Some(p.clone()),
                    Err(e) => {
                        log::warn!("failed to decrypt uri: {e}");
                        None
                    }
                })
                .collect()
        });

        out.push(DecryptedListCipher {
            id: s.id,
            name,
            user,
            folder,
            uris,
            entry_type: s.entry_type,
        });
    }

    Ok(out)
}

/// Batched search-cipher decrypt: stages every per-field decrypt for the
/// whole entry slice into one `DecryptBatch` IPC, then assembles them
/// back into per-entry search ciphers. Avoids the N-IPC-per-entry
/// blow-up `find_entry`/`search` would otherwise inflict on large
/// vaults.
pub(super) fn decrypt_search_ciphers(
    entries: &[bwx::db::Entry],
) -> bin_error::Result<Vec<DecryptedSearchCipher>> {
    struct Slots<'a> {
        entry: &'a bwx::db::Entry,
        name_idx: usize,
        user_idx: Option<usize>,
        folder_idx: Option<usize>,
        notes_idx: Option<usize>,
        uri_indices: Vec<usize>,
        field_indices: Vec<usize>,
    }

    let mut items: Vec<bwx::protocol::DecryptItem> = Vec::new();
    let mut slots: Vec<Slots> = Vec::with_capacity(entries.len());

    let push = |items: &mut Vec<bwx::protocol::DecryptItem>,
                cipherstring: &str,
                entry_key: Option<&str>,
                org_id: Option<&str>|
     -> usize {
        items.push(bwx::protocol::DecryptItem {
            cipherstring: cipherstring.to_string(),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        });
        items.len() - 1
    };

    for entry in entries {
        let name_idx = push(
            &mut items,
            &entry.name,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        );

        let user_idx = match &entry.data {
            bwx::db::EntryData::Login {
                username: Some(u), ..
            } => Some(push(
                &mut items,
                u,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )),
            _ => None,
        };

        // Folder names always use the local key (folders are scoped to
        // the user's vault, never an organization).
        let folder_idx = entry
            .folder
            .as_ref()
            .map(|f| push(&mut items, f, None, None));

        let notes_idx = entry.notes.as_ref().map(|n| {
            push(&mut items, n, entry.key.as_deref(), entry.org_id.as_deref())
        });

        let uri_indices = match &entry.data {
            bwx::db::EntryData::Login { uris, .. } => uris
                .iter()
                .map(|s| {
                    push(
                        &mut items,
                        &s.uri,
                        entry.key.as_deref(),
                        entry.org_id.as_deref(),
                    )
                })
                .collect(),
            _ => Vec::new(),
        };

        let field_indices = entry
            .fields
            .iter()
            .filter_map(|field| {
                if field.ty == Some(bwx::api::FieldType::Hidden) {
                    None
                } else {
                    field.value.as_ref().map(|v| {
                        push(
                            &mut items,
                            v,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                }
            })
            .collect();

        slots.push(Slots {
            entry,
            name_idx,
            user_idx,
            folder_idx,
            notes_idx,
            uri_indices,
            field_indices,
        });
    }

    let results = if items.is_empty() {
        Vec::new()
    } else {
        crate::actions::decrypt_batch(items)?
    };

    let mut out = Vec::with_capacity(slots.len());
    for s in slots {
        // Name failure is fatal — matches the previous per-entry path.
        let name = match &results[s.name_idx] {
            Ok(p) => p.clone(),
            Err(e) => {
                return Err(crate::bin_error::err!(
                    "failed to decrypt entry name: {e}"
                ));
            }
        };

        let user = s.user_idx.and_then(|i| match &results[i] {
            Ok(p) => Some(p.clone()),
            Err(e) => {
                log::warn!("failed to decrypt {}: {e}", Field::Username);
                None
            }
        });

        // Folder failure was fatal in the prior path; preserved.
        let folder = match s.folder_idx {
            Some(i) => match &results[i] {
                Ok(p) => Some(p.clone()),
                Err(e) => {
                    return Err(crate::bin_error::err!(
                        "failed to decrypt folder name: {e}"
                    ));
                }
            },
            None => None,
        };

        let notes = s.notes_idx.and_then(|i| match &results[i] {
            Ok(p) => Some(p.clone()),
            Err(e) => {
                log::warn!("failed to decrypt notes: {e}");
                None
            }
        });

        let uri_match_types: Vec<Option<bwx::api::UriMatchType>> =
            if let bwx::db::EntryData::Login { uris, .. } = &s.entry.data {
                uris.iter().map(|u| u.match_type).collect()
            } else {
                Vec::new()
            };

        let uris = s
            .uri_indices
            .iter()
            .zip(uri_match_types)
            .filter_map(|(i, mt)| match &results[*i] {
                Ok(p) => Some((p.clone(), mt)),
                Err(e) => {
                    log::warn!("failed to decrypt {}: {e}", Field::Uris);
                    None
                }
            })
            .collect();

        let fields = s
            .field_indices
            .iter()
            .map(|i| match &results[*i] {
                Ok(p) => Ok(p.clone()),
                Err(e) => Err(crate::bin_error::err!(
                    "failed to decrypt entry field: {e}"
                )),
            })
            .collect::<bin_error::Result<_>>()?;

        let entry_type = (match &s.entry.data {
            bwx::db::EntryData::Login { .. } => "Login",
            bwx::db::EntryData::Identity { .. } => "Identity",
            bwx::db::EntryData::SshKey { .. } => "SSH Key",
            bwx::db::EntryData::SecureNote => "Note",
            bwx::db::EntryData::Card { .. } => "Card",
        })
        .to_string();

        out.push(DecryptedSearchCipher {
            id: s.entry.id.clone(),
            entry_type,
            folder,
            name,
            user,
            uris,
            fields,
            notes,
        });
    }

    Ok(out)
}

/// Build a `DecryptedCipher` for an entry that we already searched, reusing
/// the plaintext fields that `decrypt_search_ciphers` already produced
/// (name, folder, notes, login username/URIs). Stages the remaining
/// per-field decrypts into one `DecryptBatch` IPC.
pub(super) fn decrypt_cipher_using_search(
    entry: &bwx::db::Entry,
    search: &DecryptedSearchCipher,
) -> bin_error::Result<DecryptedCipher> {
    // Non-Login entries don't share enough plaintext with the search
    // cipher to skip work; defer to the full path.
    let bwx::db::EntryData::Login {
        password,
        totp,
        uris,
        ..
    } = &entry.data
    else {
        return decrypt_cipher(entry);
    };

    let key = entry.key.as_deref();
    let org = entry.org_id.as_deref();
    let mut b = Batcher::new();

    let field_slots: Vec<(
        Option<usize>,
        Option<usize>,
        Option<bwx::api::FieldType>,
    )> = entry
        .fields
        .iter()
        .map(|f| {
            (
                b.push_opt(f.name.as_deref(), key, org),
                b.push_opt(f.value.as_deref(), key, org),
                f.ty,
            )
        })
        .collect();

    let history_slots: Vec<(String, usize)> = entry
        .history
        .iter()
        .map(|h| (h.last_used_date.clone(), b.push(&h.password, key, org)))
        .collect();

    let password_idx = b.push_opt(password.as_deref(), key, org);
    let totp_idx = b.push_opt(totp.as_deref(), key, org);
    // URIs aren't reused from the search cipher: the search path drops
    // decrypt failures, but the full cipher signals failure by yielding
    // `None` for the whole list. Decrypt fresh to preserve that.
    let uri_slots: Vec<(usize, Option<bwx::api::UriMatchType>)> = uris
        .iter()
        .map(|s| (b.push(&s.uri, key, org), s.match_type))
        .collect();

    b.run()?;

    let fields = field_slots
        .into_iter()
        .map(|(n_idx, v_idx, ty)| {
            Ok(DecryptedField {
                name: n_idx.map(|i| b.take_required(i)).transpose()?,
                value: v_idx.map(|i| b.take_required(i)).transpose()?,
                ty,
            })
        })
        .collect::<bin_error::Result<_>>()?;

    let history = history_slots
        .into_iter()
        .map(|(date, idx)| {
            Ok(DecryptedHistoryEntry {
                last_used_date: date,
                password: b.take_required(idx)?,
            })
        })
        .collect::<bin_error::Result<_>>()?;

    let data = DecryptedData::Login {
        username: search.user.clone(),
        password: b.take_optional(password_idx, Field::Password),
        totp: b.take_optional(totp_idx, Field::Totp),
        uris: uri_slots
            .into_iter()
            .map(|(idx, match_type)| {
                b.take_optional(Some(idx), Field::Uris)
                    .map(|uri| DecryptedUri { uri, match_type })
            })
            .collect(),
    };

    Ok(DecryptedCipher {
        id: entry.id.clone(),
        folder: search.folder.clone(),
        name: search.name.clone(),
        data,
        fields,
        notes: search.notes.clone(),
        history,
    })
}

/// Captures `DecryptBatch` slot indices for the per-variant fields of an
/// entry's data payload. Mirrors `bwx::db::EntryData` so the assembly
/// step can rebuild `DecryptedData` from the batch results.
enum DataSlots {
    Login {
        username: Option<usize>,
        password: Option<usize>,
        totp: Option<usize>,
        uris: Vec<(usize, Option<bwx::api::UriMatchType>)>,
    },
    Card {
        cardholder_name: Option<usize>,
        number: Option<usize>,
        brand: Option<usize>,
        exp_month: Option<usize>,
        exp_year: Option<usize>,
        code: Option<usize>,
    },
    Identity {
        title: Option<usize>,
        first_name: Option<usize>,
        middle_name: Option<usize>,
        last_name: Option<usize>,
        address1: Option<usize>,
        address2: Option<usize>,
        address3: Option<usize>,
        city: Option<usize>,
        state: Option<usize>,
        postal_code: Option<usize>,
        country: Option<usize>,
        phone: Option<usize>,
        email: Option<usize>,
        ssn: Option<usize>,
        license_number: Option<usize>,
        passport_number: Option<usize>,
        username: Option<usize>,
    },
    SecureNote,
    SshKey {
        public_key: Option<usize>,
        fingerprint: Option<usize>,
        private_key: Option<usize>,
    },
}

fn stage_data(
    b: &mut Batcher,
    data: &bwx::db::EntryData,
    key: Option<&str>,
    org: Option<&str>,
) -> DataSlots {
    match data {
        bwx::db::EntryData::Login {
            username,
            password,
            totp,
            uris,
        } => DataSlots::Login {
            username: b.push_opt(username.as_deref(), key, org),
            password: b.push_opt(password.as_deref(), key, org),
            totp: b.push_opt(totp.as_deref(), key, org),
            uris: uris
                .iter()
                .map(|s| (b.push(&s.uri, key, org), s.match_type))
                .collect(),
        },
        bwx::db::EntryData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => DataSlots::Card {
            cardholder_name: b.push_opt(cardholder_name.as_deref(), key, org),
            number: b.push_opt(number.as_deref(), key, org),
            brand: b.push_opt(brand.as_deref(), key, org),
            exp_month: b.push_opt(exp_month.as_deref(), key, org),
            exp_year: b.push_opt(exp_year.as_deref(), key, org),
            code: b.push_opt(code.as_deref(), key, org),
        },
        bwx::db::EntryData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => DataSlots::Identity {
            title: b.push_opt(title.as_deref(), key, org),
            first_name: b.push_opt(first_name.as_deref(), key, org),
            middle_name: b.push_opt(middle_name.as_deref(), key, org),
            last_name: b.push_opt(last_name.as_deref(), key, org),
            address1: b.push_opt(address1.as_deref(), key, org),
            address2: b.push_opt(address2.as_deref(), key, org),
            address3: b.push_opt(address3.as_deref(), key, org),
            city: b.push_opt(city.as_deref(), key, org),
            state: b.push_opt(state.as_deref(), key, org),
            postal_code: b.push_opt(postal_code.as_deref(), key, org),
            country: b.push_opt(country.as_deref(), key, org),
            phone: b.push_opt(phone.as_deref(), key, org),
            email: b.push_opt(email.as_deref(), key, org),
            ssn: b.push_opt(ssn.as_deref(), key, org),
            license_number: b.push_opt(license_number.as_deref(), key, org),
            passport_number: b.push_opt(passport_number.as_deref(), key, org),
            username: b.push_opt(username.as_deref(), key, org),
        },
        bwx::db::EntryData::SecureNote => DataSlots::SecureNote,
        bwx::db::EntryData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => DataSlots::SshKey {
            public_key: b.push_opt(public_key.as_deref(), key, org),
            fingerprint: b.push_opt(fingerprint.as_deref(), key, org),
            private_key: b.push_opt(private_key.as_deref(), key, org),
        },
    }
}

fn assemble_data(b: &Batcher, slots: DataSlots) -> DecryptedData {
    match slots {
        DataSlots::Login {
            username,
            password,
            totp,
            uris,
        } => DecryptedData::Login {
            username: b.take_optional(username, Field::Username),
            password: b.take_optional(password, Field::Password),
            totp: b.take_optional(totp, Field::Totp),
            uris: uris
                .into_iter()
                .map(|(idx, match_type)| {
                    b.take_optional(Some(idx), Field::Uris)
                        .map(|uri| DecryptedUri { uri, match_type })
                })
                .collect(),
        },
        DataSlots::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => DecryptedData::Card {
            cardholder_name: b
                .take_optional(cardholder_name, Field::Cardholder),
            number: b.take_optional(number, Field::CardNumber),
            brand: b.take_optional(brand, Field::Brand),
            exp_month: b.take_optional(exp_month, Field::ExpMonth),
            exp_year: b.take_optional(exp_year, Field::ExpYear),
            code: b.take_optional(code, Field::Cvv),
        },
        DataSlots::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => DecryptedData::Identity {
            title: b.take_optional(title, Field::Title),
            first_name: b.take_optional(first_name, Field::FirstName),
            middle_name: b.take_optional(middle_name, Field::MiddleName),
            last_name: b.take_optional(last_name, Field::LastName),
            address1: b.take_optional(address1, Field::Address1),
            address2: b.take_optional(address2, Field::Address2),
            address3: b.take_optional(address3, Field::Address3),
            city: b.take_optional(city, Field::City),
            state: b.take_optional(state, Field::State),
            postal_code: b.take_optional(postal_code, Field::PostalCode),
            country: b.take_optional(country, Field::Country),
            phone: b.take_optional(phone, Field::Phone),
            email: b.take_optional(email, Field::Email),
            ssn: b.take_optional(ssn, Field::Ssn),
            license_number: b.take_optional(license_number, Field::License),
            passport_number: b
                .take_optional(passport_number, Field::Passport),
            username: b.take_optional(username, Field::Username),
        },
        DataSlots::SecureNote => DecryptedData::SecureNote {},
        DataSlots::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => DecryptedData::SshKey {
            public_key: b.take_optional(public_key, Field::PublicKey),
            fingerprint: b.take_optional(fingerprint, Field::Fingerprint),
            private_key: b.take_optional(private_key, Field::PrivateKey),
        },
    }
}

pub(super) fn decrypt_cipher(
    entry: &bwx::db::Entry,
) -> bin_error::Result<DecryptedCipher> {
    let key = entry.key.as_deref();
    let org = entry.org_id.as_deref();
    let mut b = Batcher::new();

    let name_idx = b.push(&entry.name, key, org);
    // Folder names always use the local key — folders are scoped to the
    // user's vault, never an organization.
    let folder_idx = b.push_opt(entry.folder.as_deref(), None, None);
    let notes_idx = b.push_opt(entry.notes.as_deref(), key, org);

    let field_slots: Vec<(
        Option<usize>,
        Option<usize>,
        Option<bwx::api::FieldType>,
    )> = entry
        .fields
        .iter()
        .map(|f| {
            (
                b.push_opt(f.name.as_deref(), key, org),
                b.push_opt(f.value.as_deref(), key, org),
                f.ty,
            )
        })
        .collect();

    let history_slots: Vec<(String, usize)> = entry
        .history
        .iter()
        .map(|h| (h.last_used_date.clone(), b.push(&h.password, key, org)))
        .collect();

    let data_slots = stage_data(&mut b, &entry.data, key, org);

    b.run()?;

    let name = b.take_required(name_idx)?;
    let folder = b.take_optional(folder_idx, "folder name");
    let notes = b.take_optional(notes_idx, Field::Notes);

    let fields = field_slots
        .into_iter()
        .map(|(n_idx, v_idx, ty)| {
            Ok(DecryptedField {
                name: n_idx.map(|i| b.take_required(i)).transpose()?,
                value: v_idx.map(|i| b.take_required(i)).transpose()?,
                ty,
            })
        })
        .collect::<bin_error::Result<_>>()?;

    let history = history_slots
        .into_iter()
        .map(|(date, idx)| {
            Ok(DecryptedHistoryEntry {
                last_used_date: date,
                password: b.take_required(idx)?,
            })
        })
        .collect::<bin_error::Result<_>>()?;

    let data = assemble_data(&b, data_slots);

    Ok(DecryptedCipher {
        id: entry.id.clone(),
        folder,
        name,
        data,
        fields,
        notes,
        history,
    })
}
