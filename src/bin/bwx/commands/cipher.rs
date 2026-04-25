use super::field::Field;
use super::find::Needle;
use super::totp::generate_totp;
use super::util::{display_field, val_display_or_store};
use crate::bin_error;

#[derive(Debug, serde::Serialize)]
pub(super) struct DecryptedListCipher {
    pub(super) id: String,
    pub(super) name: Option<String>,
    pub(super) user: Option<String>,
    pub(super) folder: Option<String>,
    pub(super) uris: Option<Vec<String>>,
    #[serde(rename = "type")]
    pub(super) entry_type: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(super) struct DecryptedSearchCipher {
    pub(super) id: String,
    #[serde(rename = "type")]
    pub(super) entry_type: String,
    pub(super) folder: Option<String>,
    pub(super) name: String,
    pub(super) user: Option<String>,
    pub(super) uris: Vec<(String, Option<bwx::api::UriMatchType>)>,
    pub(super) fields: Vec<String>,
    pub(super) notes: Option<String>,
}

impl DecryptedSearchCipher {
    pub(super) fn display_name(&self) -> String {
        self.user.as_ref().map_or_else(
            || self.name.clone(),
            |user| format!("{user}@{}", self.name),
        )
    }

    pub(super) fn matches(
        &self,
        needle: &Needle,
        username: Option<&str>,
        folder: Option<&str>,
        ignore_case: bool,
        strict_username: bool,
        strict_folder: bool,
        exact: bool,
    ) -> bool {
        let match_str = match (ignore_case, exact) {
            (true, true) => |field: &str, search_term: &str| {
                field.to_lowercase() == search_term.to_lowercase()
            },
            (true, false) => |field: &str, search_term: &str| {
                field.to_lowercase().contains(&search_term.to_lowercase())
            },
            (false, true) => {
                |field: &str, search_term: &str| field == search_term
            }
            (false, false) => {
                |field: &str, search_term: &str| field.contains(search_term)
            }
        };

        match (self.folder.as_deref(), folder) {
            (Some(folder), Some(given_folder)) => {
                if !match_str(folder, given_folder) {
                    return false;
                }
            }
            (Some(_), None) => {
                if strict_folder {
                    return false;
                }
            }
            (None, Some(_)) => {
                return false;
            }
            (None, None) => {}
        }

        match (&self.user, username) {
            (Some(username), Some(given_username)) => {
                if !match_str(username, given_username) {
                    return false;
                }
            }
            (Some(_), None) => {
                if strict_username {
                    return false;
                }
            }
            (None, Some(_)) => {
                return false;
            }
            (None, None) => {}
        }

        match needle {
            Needle::Uuid(uuid, s) => {
                if self.id.parse::<bwx::uuid::Uuid>() != Ok(*uuid)
                    && !match_str(&self.name, s)
                {
                    return false;
                }
            }
            Needle::Name(name) => {
                if !match_str(&self.name, name) {
                    return false;
                }
            }
            Needle::Uri(given_uri) => {
                if self.uris.iter().all(|(uri, match_type)| {
                    !super::find::matches_url(uri, *match_type, given_uri)
                }) {
                    return false;
                }
            }
        }

        true
    }

    pub(super) fn search_match(
        &self,
        term: &str,
        folder: Option<&str>,
    ) -> bool {
        if let Some(folder) = folder {
            if self.folder.as_deref() != Some(folder) {
                return false;
            }
        }

        let mut fields = vec![self.name.clone()];
        if let Some(notes) = &self.notes {
            fields.push(notes.clone());
        }
        if let Some(user) = &self.user {
            fields.push(user.clone());
        }
        fields.extend(self.uris.iter().map(|(uri, _)| uri).cloned());
        fields.extend(self.fields.iter().cloned());

        for field in fields {
            if field.to_lowercase().contains(&term.to_lowercase()) {
                return true;
            }
        }

        false
    }
}

impl From<DecryptedSearchCipher> for DecryptedListCipher {
    fn from(value: DecryptedSearchCipher) -> Self {
        Self {
            id: value.id,
            entry_type: Some(value.entry_type),
            name: Some(value.name),
            user: value.user,
            folder: value.folder,
            uris: Some(value.uris.into_iter().map(|(s, _)| s).collect()),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(super) struct DecryptedCipher {
    pub(super) id: String,
    pub(super) folder: Option<String>,
    pub(super) name: String,
    pub(super) data: DecryptedData,
    pub(super) fields: Vec<DecryptedField>,
    pub(super) notes: Option<String>,
    pub(super) history: Vec<DecryptedHistoryEntry>,
}

impl DecryptedCipher {
    pub(super) fn display_short(&self, desc: &str, clipboard: bool) -> bool {
        match &self.data {
            DecryptedData::Login { password, .. } => {
                password.as_ref().map_or_else(
                    || {
                        eprintln!("entry for '{desc}' had no password");
                        false
                    },
                    |password| val_display_or_store(clipboard, password),
                )
            }
            DecryptedData::Card { number, .. } => {
                number.as_ref().map_or_else(
                    || {
                        eprintln!("entry for '{desc}' had no card number");
                        false
                    },
                    |number| val_display_or_store(clipboard, number),
                )
            }
            DecryptedData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                ..
            } => {
                let names: Vec<_> =
                    [title, first_name, middle_name, last_name]
                        .iter()
                        .copied()
                        .flatten()
                        .cloned()
                        .collect();
                if names.is_empty() {
                    eprintln!("entry for '{desc}' had no name");
                    false
                } else {
                    val_display_or_store(clipboard, &names.join(" "))
                }
            }
            DecryptedData::SecureNote => self.notes.as_ref().map_or_else(
                || {
                    eprintln!("entry for '{desc}' had no notes");
                    false
                },
                |notes| val_display_or_store(clipboard, notes),
            ),
            DecryptedData::SshKey { public_key, .. } => {
                public_key.as_ref().map_or_else(
                    || {
                        eprintln!("entry for '{desc}' had no public key");
                        false
                    },
                    |public_key| val_display_or_store(clipboard, public_key),
                )
            }
        }
    }

    pub(super) fn display_field(
        &self,
        desc: &str,
        field: &str,
        clipboard: bool,
    ) {
        let field = field.to_lowercase();
        let field = field.as_str();
        match &self.data {
            DecryptedData::Login {
                username,
                totp,
                uris,
                ..
            } => match field.parse() {
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                Ok(Field::Username) => {
                    if let Some(username) = &username {
                        val_display_or_store(clipboard, username);
                    }
                }
                Ok(Field::Totp) => {
                    if let Some(totp) = totp {
                        match generate_totp(totp) {
                            Ok(code) => {
                                val_display_or_store(clipboard, &code);
                            }
                            Err(e) => {
                                eprintln!("{e}");
                            }
                        }
                    }
                }
                Ok(Field::Uris) => {
                    if let Some(uris) = uris {
                        let uri_strs: Vec<_> =
                            uris.iter().map(|uri| uri.uri.clone()).collect();
                        val_display_or_store(clipboard, &uri_strs.join("\n"));
                    }
                }
                Ok(Field::Password) => {
                    self.display_short(desc, clipboard);
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::Card {
                cardholder_name,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => match field.parse() {
                Ok(Field::CardNumber) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::Expiration) => {
                    if let (Some(month), Some(year)) = (exp_month, exp_year) {
                        val_display_or_store(
                            clipboard,
                            &format!("{month}/{year}"),
                        );
                    }
                }
                Ok(Field::ExpMonth) => {
                    if let Some(exp_month) = exp_month {
                        val_display_or_store(clipboard, exp_month);
                    }
                }
                Ok(Field::ExpYear) => {
                    if let Some(exp_year) = exp_year {
                        val_display_or_store(clipboard, exp_year);
                    }
                }
                Ok(Field::Cvv) => {
                    if let Some(code) = code {
                        val_display_or_store(clipboard, code);
                    }
                }
                Ok(Field::Name | Field::Cardholder) => {
                    if let Some(cardholder_name) = cardholder_name {
                        val_display_or_store(clipboard, cardholder_name);
                    }
                }
                Ok(Field::Brand) => {
                    if let Some(brand) = brand {
                        val_display_or_store(clipboard, brand);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::Identity {
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
                ..
            } => match field.parse() {
                Ok(Field::Name) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::Email) => {
                    if let Some(email) = email {
                        val_display_or_store(clipboard, email);
                    }
                }
                Ok(Field::Address) => {
                    let mut strs = vec![];
                    if let Some(address1) = address1 {
                        strs.push(address1.clone());
                    }
                    if let Some(address2) = address2 {
                        strs.push(address2.clone());
                    }
                    if let Some(address3) = address3 {
                        strs.push(address3.clone());
                    }
                    if !strs.is_empty() {
                        val_display_or_store(clipboard, &strs.join("\n"));
                    }
                }
                Ok(Field::City) => {
                    if let Some(city) = city {
                        val_display_or_store(clipboard, city);
                    }
                }
                Ok(Field::State) => {
                    if let Some(state) = state {
                        val_display_or_store(clipboard, state);
                    }
                }
                Ok(Field::PostalCode) => {
                    if let Some(postal_code) = postal_code {
                        val_display_or_store(clipboard, postal_code);
                    }
                }
                Ok(Field::Country) => {
                    if let Some(country) = country {
                        val_display_or_store(clipboard, country);
                    }
                }
                Ok(Field::Phone) => {
                    if let Some(phone) = phone {
                        val_display_or_store(clipboard, phone);
                    }
                }
                Ok(Field::Ssn) => {
                    if let Some(ssn) = ssn {
                        val_display_or_store(clipboard, ssn);
                    }
                }
                Ok(Field::License) => {
                    if let Some(license_number) = license_number {
                        val_display_or_store(clipboard, license_number);
                    }
                }
                Ok(Field::Passport) => {
                    if let Some(passport_number) = passport_number {
                        val_display_or_store(clipboard, passport_number);
                    }
                }
                Ok(Field::Username) => {
                    if let Some(username) = username {
                        val_display_or_store(clipboard, username);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::SecureNote => match field.parse() {
                Ok(Field::Notes) => {
                    self.display_short(desc, clipboard);
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
            DecryptedData::SshKey {
                fingerprint,
                private_key,
                ..
            } => match field.parse() {
                Ok(Field::Fingerprint) => {
                    if let Some(fingerprint) = fingerprint {
                        val_display_or_store(clipboard, fingerprint);
                    }
                }
                Ok(Field::PublicKey) => {
                    self.display_short(desc, clipboard);
                }
                Ok(Field::PrivateKey) => {
                    if let Some(private_key) = private_key {
                        val_display_or_store(clipboard, private_key);
                    }
                }
                Ok(Field::Notes) => {
                    if let Some(notes) = &self.notes {
                        val_display_or_store(clipboard, notes);
                    }
                }
                _ => {
                    for f in &self.fields {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().as_str().contains(field) {
                                val_display_or_store(
                                    clipboard,
                                    f.value.as_deref().unwrap_or(""),
                                );
                                break;
                            }
                        }
                    }
                }
            },
        }
    }

    pub(super) fn display_long(&self, desc: &str, clipboard: bool) {
        match &self.data {
            DecryptedData::Login {
                username,
                totp,
                uris,
                ..
            } => {
                let mut displayed = self.display_short(desc, clipboard);
                displayed |=
                    display_field("Username", username.as_deref(), clipboard);
                displayed |=
                    display_field("TOTP Secret", totp.as_deref(), clipboard);

                if let Some(uris) = uris {
                    for uri in uris {
                        displayed |=
                            display_field("URI", Some(&uri.uri), clipboard);
                        let match_type =
                            uri.match_type.map(|ty| format!("{ty}"));
                        displayed |= display_field(
                            "Match type",
                            match_type.as_deref(),
                            clipboard,
                        );
                    }
                }

                for field in &self.fields {
                    displayed |= display_field(
                        field.name.as_deref().unwrap_or("(null)"),
                        Some(field.value.as_deref().unwrap_or("")),
                        clipboard,
                    );
                }

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
            DecryptedData::Card {
                cardholder_name,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => {
                let mut displayed = false;

                displayed |= self.display_short(desc, clipboard);
                if let (Some(exp_month), Some(exp_year)) =
                    (exp_month, exp_year)
                {
                    println!("Expiration: {exp_month}/{exp_year}");
                    displayed = true;
                }
                displayed |= display_field("CVV", code.as_deref(), clipboard);
                displayed |= display_field(
                    "Name",
                    cardholder_name.as_deref(),
                    clipboard,
                );
                displayed |=
                    display_field("Brand", brand.as_deref(), clipboard);

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
            DecryptedData::Identity {
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
                ..
            } => {
                let mut displayed = self.display_short(desc, clipboard);

                displayed |=
                    display_field("Address", address1.as_deref(), clipboard);
                displayed |=
                    display_field("Address", address2.as_deref(), clipboard);
                displayed |=
                    display_field("Address", address3.as_deref(), clipboard);
                displayed |=
                    display_field("City", city.as_deref(), clipboard);
                displayed |=
                    display_field("State", state.as_deref(), clipboard);
                displayed |= display_field(
                    "Postcode",
                    postal_code.as_deref(),
                    clipboard,
                );
                displayed |=
                    display_field("Country", country.as_deref(), clipboard);
                displayed |=
                    display_field("Phone", phone.as_deref(), clipboard);
                displayed |=
                    display_field("Email", email.as_deref(), clipboard);
                displayed |= display_field("SSN", ssn.as_deref(), clipboard);
                displayed |= display_field(
                    "License",
                    license_number.as_deref(),
                    clipboard,
                );
                displayed |= display_field(
                    "Passport",
                    passport_number.as_deref(),
                    clipboard,
                );
                displayed |=
                    display_field("Username", username.as_deref(), clipboard);

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
            DecryptedData::SecureNote => {
                self.display_short(desc, clipboard);
            }
            DecryptedData::SshKey { fingerprint, .. } => {
                let mut displayed = self.display_short(desc, clipboard);
                displayed |= display_field(
                    "Fingerprint",
                    fingerprint.as_deref(),
                    clipboard,
                );

                for field in &self.fields {
                    displayed |= display_field(
                        field.name.as_deref().unwrap_or("(null)"),
                        Some(field.value.as_deref().unwrap_or("")),
                        clipboard,
                    );
                }

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{notes}");
                }
            }
        }
    }

    /// This implementation mirror the `fn display_fied` method on which field to list
    pub(super) fn display_fields_list(&self) {
        match &self.data {
            DecryptedData::Login {
                username,
                password,
                totp,
                uris,
                ..
            } => {
                if username.is_some() {
                    println!("{}", Field::Username);
                }
                if totp.is_some() {
                    println!("{}", Field::Totp);
                }
                if uris.is_some() {
                    println!("{}", Field::Uris);
                }
                if password.is_some() {
                    println!("{}", Field::Password);
                }
            }
            DecryptedData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => {
                if number.is_some() {
                    println!("{}", Field::CardNumber);
                }
                if exp_month.is_some() {
                    println!("{}", Field::ExpMonth);
                }
                if exp_year.is_some() {
                    println!("{}", Field::ExpYear);
                }
                if code.is_some() {
                    println!("{}", Field::Cvv);
                }
                if cardholder_name.is_some() {
                    println!("{}", Field::Cardholder);
                }
                if brand.is_some() {
                    println!("{}", Field::Brand);
                }
            }

            DecryptedData::Identity {
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
                title,
                first_name,
                middle_name,
                last_name,
                ..
            } => {
                if [title, first_name, middle_name, last_name]
                    .iter()
                    .any(|f| f.is_some())
                {
                    // the display_field combines all these fields together.
                    println!("name");
                }
                if email.is_some() {
                    println!("{}", Field::Email);
                }
                if [address1, address2, address3].iter().any(|f| f.is_some())
                {
                    // the display_field combines all these fields together.
                    println!("address");
                }
                if city.is_some() {
                    println!("{}", Field::City);
                }
                if state.is_some() {
                    println!("{}", Field::State);
                }
                if postal_code.is_some() {
                    println!("{}", Field::PostalCode);
                }
                if country.is_some() {
                    println!("{}", Field::Country);
                }
                if phone.is_some() {
                    println!("{}", Field::Phone);
                }
                if ssn.is_some() {
                    println!("{}", Field::Ssn);
                }
                if license_number.is_some() {
                    println!("{}", Field::License);
                }
                if passport_number.is_some() {
                    println!("{}", Field::Passport);
                }
                if username.is_some() {
                    println!("{}", Field::Username);
                }
            }

            DecryptedData::SecureNote => (), // handled at the end
            DecryptedData::SshKey {
                fingerprint,
                public_key,
                ..
            } => {
                if fingerprint.is_some() {
                    println!("{}", Field::Fingerprint);
                }
                if public_key.is_some() {
                    println!("{}", Field::PublicKey);
                }
            }
        }

        if self.notes.is_some() {
            println!("{}", Field::Notes);
        }
        for f in &self.fields {
            if let Some(name) = &f.name {
                println!("{name}");
            }
        }
    }

    pub(super) fn display_json(&self, desc: &str) -> bin_error::Result<()> {
        use crate::bin_error::ContextExt as _;
        serde_json::to_writer_pretty(std::io::stdout(), &self)
            .context(format!("failed to write entry '{desc}' to stdout"))?;
        println!();

        Ok(())
    }

    /// Resolve a field name to its plaintext value without printing.
    ///
    /// Mirrors `display_field` but returns `Option<String>` so callers
    /// (e.g. `bwx exec` env injection) can pass the value to a child
    /// process without staging it through stdout. Falls through to a
    /// substring match against custom (`fields[]`) entries when the name
    /// isn't a built-in field.
    pub(super) fn field_value(&self, field: &str) -> Option<String> {
        let lc = field.to_lowercase();
        let parsed: Result<Field, _> = lc.parse();
        if let Ok(f) = parsed {
            let from_data = match (&self.data, f) {
                (DecryptedData::Login { password, .. }, Field::Password) => {
                    password.clone()
                }
                (
                    DecryptedData::Login { username, .. }
                    | DecryptedData::Identity { username, .. },
                    Field::Username,
                ) => username.clone(),
                (
                    DecryptedData::Login {
                        totp: Some(totp), ..
                    },
                    Field::Totp,
                ) => generate_totp(totp).ok(),
                (
                    DecryptedData::Login {
                        uris: Some(uris), ..
                    },
                    Field::Uris,
                ) => Some(
                    uris.iter()
                        .map(|u| u.uri.clone())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (DecryptedData::Card { number, .. }, Field::CardNumber) => {
                    number.clone()
                }
                (
                    DecryptedData::Card {
                        exp_month: Some(m),
                        exp_year: Some(y),
                        ..
                    },
                    Field::Expiration,
                ) => Some(format!("{m}/{y}")),
                (DecryptedData::Card { exp_month, .. }, Field::ExpMonth) => {
                    exp_month.clone()
                }
                (DecryptedData::Card { exp_year, .. }, Field::ExpYear) => {
                    exp_year.clone()
                }
                (DecryptedData::Card { code, .. }, Field::Cvv) => {
                    code.clone()
                }
                (
                    DecryptedData::Card {
                        cardholder_name, ..
                    },
                    Field::Cardholder | Field::Name,
                ) => cardholder_name.clone(),
                (DecryptedData::Card { brand, .. }, Field::Brand) => {
                    brand.clone()
                }
                (DecryptedData::Identity { email, .. }, Field::Email) => {
                    email.clone()
                }
                (DecryptedData::Identity { city, .. }, Field::City) => {
                    city.clone()
                }
                (DecryptedData::Identity { state, .. }, Field::State) => {
                    state.clone()
                }
                (
                    DecryptedData::Identity { postal_code, .. },
                    Field::PostalCode,
                ) => postal_code.clone(),
                (DecryptedData::Identity { country, .. }, Field::Country) => {
                    country.clone()
                }
                (DecryptedData::Identity { phone, .. }, Field::Phone) => {
                    phone.clone()
                }
                (DecryptedData::Identity { ssn, .. }, Field::Ssn) => {
                    ssn.clone()
                }
                (
                    DecryptedData::Identity { license_number, .. },
                    Field::License,
                ) => license_number.clone(),
                (
                    DecryptedData::Identity {
                        passport_number, ..
                    },
                    Field::Passport,
                ) => passport_number.clone(),
                (
                    DecryptedData::SshKey { fingerprint, .. },
                    Field::Fingerprint,
                ) => fingerprint.clone(),
                (
                    DecryptedData::SshKey { public_key, .. },
                    Field::PublicKey,
                ) => public_key.clone(),
                (
                    DecryptedData::SshKey { private_key, .. },
                    Field::PrivateKey,
                ) => private_key.clone(),
                (_, Field::Notes) => self.notes.clone(),
                _ => None,
            };
            if from_data.is_some() {
                return from_data;
            }
        }

        for f in &self.fields {
            if let Some(name) = &f.name {
                if name.to_lowercase().contains(&lc) {
                    return f.value.clone();
                }
            }
        }
        None
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(super) enum DecryptedData {
    Login {
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        uris: Option<Vec<DecryptedUri>>,
    },
    Card {
        cardholder_name: Option<String>,
        number: Option<String>,
        brand: Option<String>,
        exp_month: Option<String>,
        exp_year: Option<String>,
        code: Option<String>,
    },
    Identity {
        title: Option<String>,
        first_name: Option<String>,
        middle_name: Option<String>,
        last_name: Option<String>,
        address1: Option<String>,
        address2: Option<String>,
        address3: Option<String>,
        city: Option<String>,
        state: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
        phone: Option<String>,
        email: Option<String>,
        ssn: Option<String>,
        license_number: Option<String>,
        passport_number: Option<String>,
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        public_key: Option<String>,
        fingerprint: Option<String>,
        private_key: Option<String>,
    },
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(super) struct DecryptedField {
    pub(super) name: Option<String>,
    pub(super) value: Option<String>,
    #[serde(serialize_with = "serialize_field_type", rename = "type")]
    pub(super) ty: Option<bwx::api::FieldType>,
}

#[allow(clippy::trivially_copy_pass_by_ref, clippy::ref_option)]
fn serialize_field_type<S>(
    ty: &Option<bwx::api::FieldType>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match ty {
        Some(ty) => {
            let s = match ty {
                bwx::api::FieldType::Text => "text",
                bwx::api::FieldType::Hidden => "hidden",
                bwx::api::FieldType::Boolean => "boolean",
                bwx::api::FieldType::Linked => "linked",
            };
            serializer.serialize_some(&Some(s))
        }
        None => serializer.serialize_none(),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(super) struct DecryptedHistoryEntry {
    pub(super) last_used_date: String,
    pub(super) password: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(super) struct DecryptedUri {
    pub(super) uri: String,
    pub(super) match_type: Option<bwx::api::UriMatchType>,
}
