use super::types::{
    CipherRepromptType, FieldType, KdfType, LinkedIdType,
    TwoFactorProviderType, UriMatchType,
};

#[derive(serde::Serialize, Debug)]
pub(super) struct PreloginReq {
    pub(super) email: String,
}

#[derive(serde::Deserialize, Debug)]
pub(super) struct PreloginRes {
    #[serde(rename = "Kdf", alias = "kdf")]
    pub(super) kdf: KdfType,
    #[serde(rename = "KdfIterations", alias = "kdfIterations")]
    pub(super) kdf_iterations: u32,
    #[serde(rename = "KdfMemory", alias = "kdfMemory")]
    pub(super) kdf_memory: Option<u32>,
    #[serde(rename = "KdfParallelism", alias = "kdfParallelism")]
    pub(super) kdf_parallelism: Option<u32>,
}

#[derive(serde::Serialize, Debug)]
pub(super) struct ConnectTokenReq {
    pub(super) grant_type: String,
    pub(super) scope: String,
    pub(super) client_id: String,
    #[serde(rename = "deviceType")]
    pub(super) device_type: u32,
    #[serde(rename = "deviceIdentifier")]
    pub(super) device_identifier: String,
    #[serde(rename = "deviceName")]
    pub(super) device_name: String,
    #[serde(rename = "devicePushToken")]
    pub(super) device_push_token: String,
    #[serde(rename = "twoFactorToken")]
    pub(super) two_factor_token: Option<String>,
    #[serde(rename = "twoFactorProvider")]
    pub(super) two_factor_provider: Option<u32>,
    #[serde(flatten)]
    pub(super) auth: ConnectTokenAuth,
}

#[derive(serde::Serialize, Debug)]
#[serde(untagged)]
pub(super) enum ConnectTokenAuth {
    Password(ConnectTokenPassword),
    AuthCode(ConnectTokenAuthCode),
    ClientCredentials(ConnectTokenClientCredentials),
}

#[derive(serde::Serialize, Debug)]
pub(super) struct ConnectTokenPassword {
    pub(super) username: String,
    pub(super) password: String,
}

#[derive(serde::Serialize, Debug)]
pub(super) struct ConnectTokenAuthCode {
    pub(super) code: String,
    pub(super) code_verifier: String,
    pub(super) redirect_uri: String,
}

#[derive(serde::Serialize, Debug)]
pub(super) struct ConnectTokenClientCredentials {
    pub(super) username: String,
    pub(super) client_secret: String,
}

#[derive(serde::Deserialize, Debug)]
pub(super) struct ConnectTokenRes {
    pub(super) access_token: String,
    pub(super) refresh_token: String,
    #[serde(rename = "Key", alias = "key")]
    pub(super) key: String,
}

#[derive(serde::Deserialize, Debug)]
pub(super) struct ConnectErrorRes {
    pub(super) error: String,
    pub(super) error_description: Option<String>,
    #[serde(rename = "ErrorModel", alias = "errorModel")]
    pub(super) error_model: Option<ConnectErrorResErrorModel>,
    #[serde(rename = "TwoFactorProviders", alias = "twoFactorProviders")]
    pub(super) two_factor_providers: Option<Vec<TwoFactorProviderType>>,
    #[serde(
        rename = "SsoEmail2faSessionToken",
        alias = "ssoEmail2faSessionToken"
    )]
    pub(super) sso_email_2fa_session_token: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
pub(super) struct ConnectErrorResErrorModel {
    #[serde(rename = "Message", alias = "message")]
    pub(super) message: String,
}

#[derive(serde::Serialize, Debug)]
pub(super) struct ConnectRefreshTokenReq {
    pub(super) grant_type: String,
    pub(super) client_id: String,
    pub(super) refresh_token: String,
}

#[derive(serde::Deserialize, Debug)]
pub(super) struct ConnectRefreshTokenRes {
    pub(super) access_token: String,
}

#[derive(serde::Serialize, Debug)]
pub(super) struct SendEmailLoginReq {
    pub(super) email: String,
    #[serde(rename = "DeviceIdentifier", alias = "deviceIdentifier")]
    pub(super) device_identifier: String,
    #[serde(
        rename = "SsoEmail2faSessionToken",
        alias = "ssoEmail2faSessionToken"
    )]
    pub(super) sso_email_2fa_session_token: String,
}

#[derive(serde::Deserialize, Debug)]
pub(super) struct SyncRes {
    #[serde(rename = "Ciphers", alias = "ciphers")]
    pub(super) ciphers: Vec<SyncResCipher>,
    #[serde(rename = "Profile", alias = "profile")]
    pub(super) profile: SyncResProfile,
    #[serde(rename = "Folders", alias = "folders")]
    pub(super) folders: Vec<SyncResFolder>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub(super) struct SyncResCipher {
    #[serde(rename = "Id", alias = "id")]
    pub(super) id: String,
    #[serde(rename = "FolderId", alias = "folderId")]
    pub(super) folder_id: Option<String>,
    #[serde(rename = "OrganizationId", alias = "organizationId")]
    pub(super) organization_id: Option<String>,
    #[serde(rename = "Name", alias = "name")]
    pub(super) name: String,
    #[serde(rename = "Login", alias = "login")]
    pub(super) login: Option<CipherLogin>,
    #[serde(rename = "Card", alias = "card")]
    pub(super) card: Option<CipherCard>,
    #[serde(rename = "Identity", alias = "identity")]
    pub(super) identity: Option<CipherIdentity>,
    #[serde(rename = "SecureNote", alias = "secureNote")]
    pub(super) secure_note: Option<CipherSecureNote>,
    #[serde(rename = "SshKey", alias = "sshKey")]
    pub(super) ssh_key: Option<CipherSshKey>,
    #[serde(rename = "Notes", alias = "notes")]
    pub(super) notes: Option<String>,
    #[serde(rename = "PasswordHistory", alias = "passwordHistory")]
    pub(super) password_history: Option<Vec<SyncResPasswordHistory>>,
    #[serde(rename = "Fields", alias = "fields")]
    pub(super) fields: Option<Vec<CipherField>>,
    #[serde(rename = "DeletedDate", alias = "deletedDate")]
    pub(super) deleted_date: Option<String>,
    #[serde(rename = "Key", alias = "key")]
    pub(super) key: Option<String>,
    #[serde(rename = "Reprompt", alias = "reprompt")]
    pub(super) reprompt: CipherRepromptType,
}

impl SyncResCipher {
    pub(super) fn to_entry(
        &self,
        folders: &[SyncResFolder],
    ) -> Option<crate::db::Entry> {
        if self.deleted_date.is_some() {
            return None;
        }
        let history =
            self.password_history
                .as_ref()
                .map_or_else(Vec::new, |history| {
                    history
                        .iter()
                        .filter_map(|entry| {
                            // Gets rid of entries with a non-existent
                            // password
                            entry.password.clone().map(|p| {
                                crate::db::HistoryEntry {
                                    last_used_date: entry
                                        .last_used_date
                                        .clone(),
                                    password: p,
                                }
                            })
                        })
                        .collect()
                });

        let (folder, folder_id) =
            self.folder_id.as_ref().map_or((None, None), |folder_id| {
                let mut folder_name = None;
                for folder in folders {
                    if &folder.id == folder_id {
                        folder_name = Some(folder.name.clone());
                    }
                }
                (folder_name, Some(folder_id))
            });
        let data = if let Some(login) = &self.login {
            crate::db::EntryData::Login {
                username: login.username.clone(),
                password: login.password.clone(),
                totp: login.totp.clone(),
                uris: login.uris.as_ref().map_or_else(
                    std::vec::Vec::new,
                    |uris| {
                        uris.iter()
                            .filter_map(|uri| {
                                uri.uri.clone().map(|s| crate::db::Uri {
                                    uri: s,
                                    match_type: uri.match_type,
                                })
                            })
                            .collect()
                    },
                ),
            }
        } else if let Some(card) = &self.card {
            crate::db::EntryData::Card {
                cardholder_name: card.cardholder_name.clone(),
                number: card.number.clone(),
                brand: card.brand.clone(),
                exp_month: card.exp_month.clone(),
                exp_year: card.exp_year.clone(),
                code: card.code.clone(),
            }
        } else if let Some(identity) = &self.identity {
            crate::db::EntryData::Identity {
                title: identity.title.clone(),
                first_name: identity.first_name.clone(),
                middle_name: identity.middle_name.clone(),
                last_name: identity.last_name.clone(),
                address1: identity.address1.clone(),
                address2: identity.address2.clone(),
                address3: identity.address3.clone(),
                city: identity.city.clone(),
                state: identity.state.clone(),
                postal_code: identity.postal_code.clone(),
                country: identity.country.clone(),
                phone: identity.phone.clone(),
                email: identity.email.clone(),
                ssn: identity.ssn.clone(),
                license_number: identity.license_number.clone(),
                passport_number: identity.passport_number.clone(),
                username: identity.username.clone(),
            }
        } else if let Some(_secure_note) = &self.secure_note {
            crate::db::EntryData::SecureNote
        } else if let Some(ssh_key) = &self.ssh_key {
            crate::db::EntryData::SshKey {
                private_key: ssh_key.private_key.clone(),
                public_key: ssh_key.public_key.clone(),
                fingerprint: ssh_key.fingerprint.clone(),
            }
        } else {
            return None;
        };
        let fields = self.fields.as_ref().map_or_else(Vec::new, |fields| {
            fields
                .iter()
                .map(|field| crate::db::Field {
                    ty: field.ty,
                    name: field.name.clone(),
                    value: field.value.clone(),
                    linked_id: field.linked_id,
                })
                .collect()
        });
        Some(crate::db::Entry {
            id: self.id.clone(),
            org_id: self.organization_id.clone(),
            folder,
            folder_id: folder_id.map(std::string::ToString::to_string),
            name: self.name.clone(),
            data,
            fields,
            notes: self.notes.clone(),
            history,
            key: self.key.clone(),
            master_password_reprompt: self.reprompt,
        })
    }
}

#[derive(serde::Deserialize, Debug)]
pub(super) struct SyncResProfile {
    #[serde(rename = "Key", alias = "key")]
    pub(super) key: String,
    #[serde(rename = "PrivateKey", alias = "privateKey")]
    pub(super) private_key: String,
    #[serde(rename = "Organizations", alias = "organizations")]
    pub(super) organizations: Vec<SyncResProfileOrganization>,
}

#[derive(serde::Deserialize, Debug)]
pub(super) struct SyncResProfileOrganization {
    #[serde(rename = "Id", alias = "id")]
    pub(super) id: String,
    #[serde(rename = "Key", alias = "key")]
    pub(super) key: String,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub(super) struct SyncResFolder {
    #[serde(rename = "Id", alias = "id")]
    pub(super) id: String,
    #[serde(rename = "Name", alias = "name")]
    pub(super) name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub(super) struct CipherLogin {
    #[serde(rename = "Username", alias = "username")]
    pub(super) username: Option<String>,
    #[serde(rename = "Password", alias = "password")]
    pub(super) password: Option<String>,
    #[serde(rename = "Totp", alias = "totp")]
    pub(super) totp: Option<String>,
    #[serde(rename = "Uris", alias = "uris")]
    pub(super) uris: Option<Vec<CipherLoginUri>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub(super) struct CipherLoginUri {
    #[serde(rename = "Uri", alias = "uri")]
    pub(super) uri: Option<String>,
    #[serde(rename = "Match", alias = "match")]
    pub(super) match_type: Option<UriMatchType>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub(super) struct CipherCard {
    #[serde(rename = "CardholderName", alias = "cardholderName")]
    pub(super) cardholder_name: Option<String>,
    #[serde(rename = "Number", alias = "number")]
    pub(super) number: Option<String>,
    #[serde(rename = "Brand", alias = "brand")]
    pub(super) brand: Option<String>,
    #[serde(rename = "ExpMonth", alias = "expMonth")]
    pub(super) exp_month: Option<String>,
    #[serde(rename = "ExpYear", alias = "expYear")]
    pub(super) exp_year: Option<String>,
    #[serde(rename = "Code", alias = "code")]
    pub(super) code: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub(super) struct CipherIdentity {
    #[serde(rename = "Title", alias = "title")]
    pub(super) title: Option<String>,
    #[serde(rename = "FirstName", alias = "firstName")]
    pub(super) first_name: Option<String>,
    #[serde(rename = "MiddleName", alias = "middleName")]
    pub(super) middle_name: Option<String>,
    #[serde(rename = "LastName", alias = "lastName")]
    pub(super) last_name: Option<String>,
    #[serde(rename = "Address1", alias = "address1")]
    pub(super) address1: Option<String>,
    #[serde(rename = "Address2", alias = "address2")]
    pub(super) address2: Option<String>,
    #[serde(rename = "Address3", alias = "address3")]
    pub(super) address3: Option<String>,
    #[serde(rename = "City", alias = "city")]
    pub(super) city: Option<String>,
    #[serde(rename = "State", alias = "state")]
    pub(super) state: Option<String>,
    #[serde(rename = "PostalCode", alias = "postalCode")]
    pub(super) postal_code: Option<String>,
    #[serde(rename = "Country", alias = "country")]
    pub(super) country: Option<String>,
    #[serde(rename = "Phone", alias = "phone")]
    pub(super) phone: Option<String>,
    #[serde(rename = "Email", alias = "email")]
    pub(super) email: Option<String>,
    #[serde(rename = "SSN", alias = "ssn")]
    pub(super) ssn: Option<String>,
    #[serde(rename = "LicenseNumber", alias = "licenseNumber")]
    pub(super) license_number: Option<String>,
    #[serde(rename = "PassportNumber", alias = "passportNumber")]
    pub(super) passport_number: Option<String>,
    #[serde(rename = "Username", alias = "username")]
    pub(super) username: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub(super) struct CipherSshKey {
    #[serde(rename = "PrivateKey", alias = "privateKey")]
    pub(super) private_key: Option<String>,
    #[serde(rename = "PublicKey", alias = "publicKey")]
    pub(super) public_key: Option<String>,
    #[serde(rename = "Fingerprint", alias = "keyFingerprint")]
    pub(super) fingerprint: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub(super) struct CipherField {
    #[serde(rename = "Type", alias = "type")]
    pub(super) ty: Option<FieldType>,
    #[serde(rename = "Name", alias = "name")]
    pub(super) name: Option<String>,
    #[serde(rename = "Value", alias = "value")]
    pub(super) value: Option<String>,
    #[serde(rename = "LinkedId", alias = "linkedId")]
    pub(super) linked_id: Option<LinkedIdType>,
}

// this is just a name and some notes, both of which are already on the cipher
// object
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub(super) struct CipherSecureNote {}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub(super) struct SyncResPasswordHistory {
    #[serde(rename = "LastUsedDate", alias = "lastUsedDate")]
    pub(super) last_used_date: String,
    #[serde(rename = "Password", alias = "password")]
    pub(super) password: Option<String>,
}

#[derive(serde::Serialize, Debug)]
pub(super) struct CiphersPostReq {
    #[serde(rename = "type")]
    pub(super) ty: u32,
    #[serde(rename = "folderId")]
    pub(super) folder_id: Option<String>,
    pub(super) name: String,
    pub(super) notes: Option<String>,
    pub(super) login: Option<CipherLogin>,
    pub(super) card: Option<CipherCard>,
    pub(super) identity: Option<CipherIdentity>,
    #[serde(rename = "secureNote")]
    pub(super) secure_note: Option<CipherSecureNote>,
}

#[derive(serde::Serialize, Debug)]
pub(super) struct CiphersPutReq {
    #[serde(rename = "type")]
    pub(super) ty: u32,
    #[serde(rename = "folderId")]
    pub(super) folder_id: Option<String>,
    #[serde(rename = "organizationId")]
    pub(super) organization_id: Option<String>,
    pub(super) name: String,
    pub(super) notes: Option<String>,
    pub(super) login: Option<CipherLogin>,
    pub(super) card: Option<CipherCard>,
    pub(super) identity: Option<CipherIdentity>,
    pub(super) fields: Vec<CipherField>,
    #[serde(rename = "secureNote")]
    pub(super) secure_note: Option<CipherSecureNote>,
    #[serde(rename = "passwordHistory")]
    pub(super) password_history: Vec<CiphersPutReqHistory>,
}

#[derive(serde::Serialize, Debug)]
pub(super) struct CiphersPutReqHistory {
    #[serde(rename = "LastUsedDate")]
    pub(super) last_used_date: String,
    #[serde(rename = "Password")]
    pub(super) password: String,
}

#[derive(serde::Deserialize, Debug)]
pub(super) struct FoldersRes {
    #[serde(rename = "Data", alias = "data")]
    pub(super) data: Vec<FoldersResData>,
}

#[derive(serde::Deserialize, Debug)]
pub(super) struct FoldersResData {
    #[serde(rename = "Id", alias = "id")]
    pub(super) id: String,
    #[serde(rename = "Name", alias = "name")]
    pub(super) name: String,
}

#[derive(serde::Serialize, Debug)]
pub(super) struct FoldersPostReq {
    pub(super) name: String,
}
