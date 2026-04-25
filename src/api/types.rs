use crate::prelude::*;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum UriMatchType {
    Domain = 0,
    Host = 1,
    StartsWith = 2,
    Exact = 3,
    RegularExpression = 4,
    Never = 5,
}

impl serde::Serialize for UriMatchType {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let v: u8 = match self {
            Self::Domain => 0,
            Self::Host => 1,
            Self::StartsWith => 2,
            Self::Exact => 3,
            Self::RegularExpression => 4,
            Self::Never => 5,
        };
        serializer.serialize_u8(v)
    }
}

impl<'de> serde::Deserialize<'de> for UriMatchType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u8::deserialize(deserializer)?;
        match v {
            0 => Ok(Self::Domain),
            1 => Ok(Self::Host),
            2 => Ok(Self::StartsWith),
            3 => Ok(Self::Exact),
            4 => Ok(Self::RegularExpression),
            5 => Ok(Self::Never),
            _ => Err(serde::de::Error::custom(format!(
                "invalid UriMatchType: {v}"
            ))),
        }
    }
}

impl std::fmt::Display for UriMatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[allow(clippy::enum_glob_use)]
        use UriMatchType::*;
        let s = match self {
            Domain => "domain",
            Host => "host",
            StartsWith => "starts_with",
            Exact => "exact",
            RegularExpression => "regular_expression",
            Never => "never",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TwoFactorProviderType {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    Yubikey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    WebAuthn = 7,
}

impl TwoFactorProviderType {
    pub fn message(&self) -> &str {
        match *self {
            Self::Authenticator => "Enter the 6 digit verification code from your authenticator app.",
            Self::Yubikey => "Insert your Yubikey and push the button.",
            Self::Email => "Enter the PIN you received via email.",
            _ => "Enter the code."
        }
    }

    pub fn header(&self) -> &str {
        match *self {
            Self::Authenticator => "Authenticator App",
            Self::Yubikey => "Yubikey",
            Self::Email => "Email Code",
            _ => "Two Factor Authentication",
        }
    }

    pub fn grab(&self) -> bool {
        !matches!(self, Self::Email)
    }
}

impl<'de> serde::Deserialize<'de> for TwoFactorProviderType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TwoFactorProviderTypeVisitor;
        impl serde::de::Visitor<'_> for TwoFactorProviderTypeVisitor {
            type Value = TwoFactorProviderType;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("two factor provider id")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(serde::de::Error::custom)
            }

            fn visit_u64<E>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                std::convert::TryFrom::try_from(value)
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(TwoFactorProviderTypeVisitor)
    }
}

impl std::convert::TryFrom<u64> for TwoFactorProviderType {
    type Error = Error;

    fn try_from(ty: u64) -> Result<Self> {
        match ty {
            0 => Ok(Self::Authenticator),
            1 => Ok(Self::Email),
            2 => Ok(Self::Duo),
            3 => Ok(Self::Yubikey),
            4 => Ok(Self::U2f),
            5 => Ok(Self::Remember),
            6 => Ok(Self::OrganizationDuo),
            7 => Ok(Self::WebAuthn),
            _ => Err(Error::InvalidTwoFactorProvider {
                ty: format!("{ty}"),
            }),
        }
    }
}

impl std::str::FromStr for TwoFactorProviderType {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self> {
        match ty {
            "0" => Ok(Self::Authenticator),
            "1" => Ok(Self::Email),
            "2" => Ok(Self::Duo),
            "3" => Ok(Self::Yubikey),
            "4" => Ok(Self::U2f),
            "5" => Ok(Self::Remember),
            "6" => Ok(Self::OrganizationDuo),
            "7" => Ok(Self::WebAuthn),
            _ => Err(Error::InvalidTwoFactorProvider { ty: ty.to_string() }),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KdfType {
    Pbkdf2 = 0,
    Argon2id = 1,
}

impl<'de> serde::Deserialize<'de> for KdfType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct KdfTypeVisitor;
        impl serde::de::Visitor<'_> for KdfTypeVisitor {
            type Value = KdfType;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("kdf id")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(serde::de::Error::custom)
            }

            fn visit_u64<E>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                std::convert::TryFrom::try_from(value)
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(KdfTypeVisitor)
    }
}

impl std::convert::TryFrom<u64> for KdfType {
    type Error = Error;

    fn try_from(ty: u64) -> Result<Self> {
        match ty {
            0 => Ok(Self::Pbkdf2),
            1 => Ok(Self::Argon2id),
            _ => Err(Error::InvalidKdfType {
                ty: format!("{ty}"),
            }),
        }
    }
}

impl std::str::FromStr for KdfType {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self> {
        match ty {
            "0" => Ok(Self::Pbkdf2),
            "1" => Ok(Self::Argon2id),
            _ => Err(Error::InvalidKdfType { ty: ty.to_string() }),
        }
    }
}

impl serde::Serialize for KdfType {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            Self::Pbkdf2 => "0",
            Self::Argon2id => "1",
        };
        serializer.serialize_str(s)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherRepromptType {
    None = 0,
    Password = 1,
}

impl serde::Serialize for CipherRepromptType {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let v: u8 = match self {
            Self::None => 0,
            Self::Password => 1,
        };
        serializer.serialize_u8(v)
    }
}

impl<'de> serde::Deserialize<'de> for CipherRepromptType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u8::deserialize(deserializer)?;
        match v {
            0 => Ok(Self::None),
            1 => Ok(Self::Password),
            _ => Err(serde::de::Error::custom(format!(
                "invalid CipherRepromptType: {v}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FieldType {
    Text = 0,
    Hidden = 1,
    Boolean = 2,
    Linked = 3,
}

impl serde::Serialize for FieldType {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let v: u16 = match self {
            Self::Text => 0,
            Self::Hidden => 1,
            Self::Boolean => 2,
            Self::Linked => 3,
        };
        serializer.serialize_u16(v)
    }
}

impl<'de> serde::Deserialize<'de> for FieldType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u16::deserialize(deserializer)?;
        match v {
            0 => Ok(Self::Text),
            1 => Ok(Self::Hidden),
            2 => Ok(Self::Boolean),
            3 => Ok(Self::Linked),
            _ => Err(serde::de::Error::custom(format!(
                "invalid FieldType: {v}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum LinkedIdType {
    LoginUsername = 100,
    LoginPassword = 101,
    CardCardholderName = 300,
    CardExpMonth = 301,
    CardExpYear = 302,
    CardCode = 303,
    CardBrand = 304,
    CardNumber = 305,
    IdentityTitle = 400,
    IdentityMiddleName = 401,
    IdentityAddress1 = 402,
    IdentityAddress2 = 403,
    IdentityAddress3 = 404,
    IdentityCity = 405,
    IdentityState = 406,
    IdentityPostalCode = 407,
    IdentityCountry = 408,
    IdentityCompany = 409,
    IdentityEmail = 410,
    IdentityPhone = 411,
    IdentitySsn = 412,
    IdentityUsername = 413,
    IdentityPassportNumber = 414,
    IdentityLicenseNumber = 415,
    IdentityFirstName = 416,
    IdentityLastName = 417,
    IdentityFullName = 418,
}

impl serde::Serialize for LinkedIdType {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let v: u16 = match self {
            Self::LoginUsername => 100,
            Self::LoginPassword => 101,
            Self::CardCardholderName => 300,
            Self::CardExpMonth => 301,
            Self::CardExpYear => 302,
            Self::CardCode => 303,
            Self::CardBrand => 304,
            Self::CardNumber => 305,
            Self::IdentityTitle => 400,
            Self::IdentityMiddleName => 401,
            Self::IdentityAddress1 => 402,
            Self::IdentityAddress2 => 403,
            Self::IdentityAddress3 => 404,
            Self::IdentityCity => 405,
            Self::IdentityState => 406,
            Self::IdentityPostalCode => 407,
            Self::IdentityCountry => 408,
            Self::IdentityCompany => 409,
            Self::IdentityEmail => 410,
            Self::IdentityPhone => 411,
            Self::IdentitySsn => 412,
            Self::IdentityUsername => 413,
            Self::IdentityPassportNumber => 414,
            Self::IdentityLicenseNumber => 415,
            Self::IdentityFirstName => 416,
            Self::IdentityLastName => 417,
            Self::IdentityFullName => 418,
        };
        serializer.serialize_u16(v)
    }
}

impl<'de> serde::Deserialize<'de> for LinkedIdType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u16::deserialize(deserializer)?;
        match v {
            100 => Ok(Self::LoginUsername),
            101 => Ok(Self::LoginPassword),
            300 => Ok(Self::CardCardholderName),
            301 => Ok(Self::CardExpMonth),
            302 => Ok(Self::CardExpYear),
            303 => Ok(Self::CardCode),
            304 => Ok(Self::CardBrand),
            305 => Ok(Self::CardNumber),
            400 => Ok(Self::IdentityTitle),
            401 => Ok(Self::IdentityMiddleName),
            402 => Ok(Self::IdentityAddress1),
            403 => Ok(Self::IdentityAddress2),
            404 => Ok(Self::IdentityAddress3),
            405 => Ok(Self::IdentityCity),
            406 => Ok(Self::IdentityState),
            407 => Ok(Self::IdentityPostalCode),
            408 => Ok(Self::IdentityCountry),
            409 => Ok(Self::IdentityCompany),
            410 => Ok(Self::IdentityEmail),
            411 => Ok(Self::IdentityPhone),
            412 => Ok(Self::IdentitySsn),
            413 => Ok(Self::IdentityUsername),
            414 => Ok(Self::IdentityPassportNumber),
            415 => Ok(Self::IdentityLicenseNumber),
            416 => Ok(Self::IdentityFirstName),
            417 => Ok(Self::IdentityLastName),
            418 => Ok(Self::IdentityFullName),
            _ => Err(serde::de::Error::custom(format!(
                "invalid LinkedIdType: {v}"
            ))),
        }
    }
}
