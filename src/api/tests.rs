use super::sso::{parse_query, sso_query_code};
use super::types::{
    CipherRepromptType, FieldType, KdfType, LinkedIdType,
    TwoFactorProviderType, UriMatchType,
};

fn roundtrip_u8<T>(variants: &[(T, u8)])
where
    T: serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + PartialEq
        + std::fmt::Debug
        + Copy,
{
    for (variant, n) in variants {
        let v = serde_json::to_value(variant).unwrap();
        assert_eq!(v, serde_json::json!(n));
        let back: T = serde_json::from_value(v).unwrap();
        assert_eq!(&back, variant);
    }
}

fn roundtrip_u16<T>(variants: &[(T, u16)])
where
    T: serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + PartialEq
        + std::fmt::Debug
        + Copy,
{
    for (variant, n) in variants {
        let v = serde_json::to_value(variant).unwrap();
        assert_eq!(v, serde_json::json!(n));
        let back: T = serde_json::from_value(v).unwrap();
        assert_eq!(&back, variant);
    }
}

#[test]
fn uri_match_type_roundtrip() {
    roundtrip_u8(&[
        (UriMatchType::Domain, 0),
        (UriMatchType::Host, 1),
        (UriMatchType::StartsWith, 2),
        (UriMatchType::Exact, 3),
        (UriMatchType::RegularExpression, 4),
        (UriMatchType::Never, 5),
    ]);
    let err = serde_json::from_value::<UriMatchType>(serde_json::json!(99));
    assert!(err.is_err());
}

#[test]
fn cipher_reprompt_type_roundtrip() {
    roundtrip_u8(&[
        (CipherRepromptType::None, 0),
        (CipherRepromptType::Password, 1),
    ]);
    let err =
        serde_json::from_value::<CipherRepromptType>(serde_json::json!(9));
    assert!(err.is_err());
}

#[test]
fn field_type_roundtrip() {
    roundtrip_u16(&[
        (FieldType::Text, 0),
        (FieldType::Hidden, 1),
        (FieldType::Boolean, 2),
        (FieldType::Linked, 3),
    ]);
    let err = serde_json::from_value::<FieldType>(serde_json::json!(999));
    assert!(err.is_err());
}

#[test]
fn two_factor_provider_type_from_u64() {
    let cases = [
        (0, TwoFactorProviderType::Authenticator),
        (1, TwoFactorProviderType::Email),
        (2, TwoFactorProviderType::Duo),
        (3, TwoFactorProviderType::Yubikey),
        (4, TwoFactorProviderType::U2f),
        (5, TwoFactorProviderType::Remember),
        (6, TwoFactorProviderType::OrganizationDuo),
        (7, TwoFactorProviderType::WebAuthn),
    ];
    for (n, expected) in cases {
        let got: TwoFactorProviderType =
            serde_json::from_value(serde_json::json!(n)).unwrap();
        assert_eq!(got, expected);
    }
    // Unknown numeric variants fail rather than silently decoding.
    let err = serde_json::from_value::<TwoFactorProviderType>(
        serde_json::json!(42),
    );
    assert!(err.is_err());
}

#[test]
fn two_factor_provider_type_from_str_map_key() {
    // Bitwarden sometimes serializes provider ids as stringified
    // digits (they appear as JSON object keys). The custom
    // `visit_str` delegates to FromStr, which accepts ASCII digits.
    let json = serde_json::json!("3");
    let got: TwoFactorProviderType = serde_json::from_value(json).unwrap();
    assert_eq!(got, TwoFactorProviderType::Yubikey);

    let err = serde_json::from_value::<TwoFactorProviderType>(
        serde_json::json!("not-a-number"),
    );
    assert!(err.is_err());
}

#[test]
fn kdf_type_deserialize() {
    let p: KdfType = serde_json::from_value(serde_json::json!(0)).unwrap();
    assert_eq!(p, KdfType::Pbkdf2);
    let a: KdfType = serde_json::from_value(serde_json::json!(1)).unwrap();
    assert_eq!(a, KdfType::Argon2id);
    // Unknown numeric variants fail rather than silently decoding.
    let err = serde_json::from_value::<KdfType>(serde_json::json!(9));
    assert!(err.is_err());
}

#[test]
fn kdf_type_serialize_as_string() {
    // Bitwarden's API expects the KDF type as the string "0"/"1"
    // in POST bodies, not a JSON number — the custom Serialize
    // impl encodes that intentionally.
    assert_eq!(
        serde_json::to_value(KdfType::Pbkdf2).unwrap(),
        serde_json::json!("0")
    );
    assert_eq!(
        serde_json::to_value(KdfType::Argon2id).unwrap(),
        serde_json::json!("1")
    );
}

#[test]
fn parse_query_basic() {
    let got = parse_query("code=abc&state=xyz");
    assert_eq!(got.get("code").map(String::as_str), Some("abc"));
    assert_eq!(got.get("state").map(String::as_str), Some("xyz"));
    assert_eq!(got.len(), 2);
}

#[test]
fn parse_query_empty() {
    assert!(parse_query("").is_empty());
}

#[test]
fn parse_query_percent_decodes_value_and_key() {
    // Bitwarden packs `_identifier=<org>` into the state value as an
    // appendage, percent-encoded.
    let got = parse_query("state=abc_identifier%3Dfoo&code=%20%2B");
    assert_eq!(
        got.get("state").map(String::as_str),
        Some("abc_identifier=foo")
    );
    assert_eq!(got.get("code").map(String::as_str), Some(" +"));
}

#[test]
fn parse_query_handles_missing_value() {
    // `foo` with no `=` should yield `foo` -> "".
    let got = parse_query("foo&bar=baz");
    assert_eq!(got.get("foo").map(String::as_str), Some(""));
    assert_eq!(got.get("bar").map(String::as_str), Some("baz"));
}

#[test]
fn parse_query_drops_empty_pairs() {
    // Bare `&` separators shouldn't contribute empty-key entries.
    let got = parse_query("&&a=1&&");
    assert_eq!(got.len(), 1);
    assert_eq!(got.get("a").map(String::as_str), Some("1"));
}

#[test]
fn sso_query_code_rejects_state_mismatch() {
    let mut params = std::collections::HashMap::new();
    params.insert("code".to_string(), "the-code".to_string());
    params.insert("state".to_string(), "other-state".to_string());
    let err = sso_query_code(&params, "expected-state")
        .expect_err("expected state mismatch to error");
    // The redacted message must NOT include either state token.
    let s = format!("{err}");
    assert!(!s.contains("other-state"), "leaked received state: {s}");
    assert!(!s.contains("expected-state"), "leaked sent state: {s}");
}

#[test]
fn sso_query_code_accepts_matching_state_with_identifier_suffix() {
    // Bitwarden appends `_identifier=<org>` to the state in the
    // callback; we match the prefix only.
    let mut params = std::collections::HashMap::new();
    params.insert("code".to_string(), "the-code".to_string());
    params.insert("state".to_string(), "s123_identifier=acme".to_string());
    let code = sso_query_code(&params, "s123").unwrap();
    assert_eq!(code, "the-code");
}

#[test]
fn linked_id_type_roundtrip() {
    roundtrip_u16(&[
        (LinkedIdType::LoginUsername, 100),
        (LinkedIdType::LoginPassword, 101),
        (LinkedIdType::CardCardholderName, 300),
        (LinkedIdType::CardExpMonth, 301),
        (LinkedIdType::CardExpYear, 302),
        (LinkedIdType::CardCode, 303),
        (LinkedIdType::CardBrand, 304),
        (LinkedIdType::CardNumber, 305),
        (LinkedIdType::IdentityTitle, 400),
        (LinkedIdType::IdentityMiddleName, 401),
        (LinkedIdType::IdentityAddress1, 402),
        (LinkedIdType::IdentityAddress2, 403),
        (LinkedIdType::IdentityAddress3, 404),
        (LinkedIdType::IdentityCity, 405),
        (LinkedIdType::IdentityState, 406),
        (LinkedIdType::IdentityPostalCode, 407),
        (LinkedIdType::IdentityCountry, 408),
        (LinkedIdType::IdentityCompany, 409),
        (LinkedIdType::IdentityEmail, 410),
        (LinkedIdType::IdentityPhone, 411),
        (LinkedIdType::IdentitySsn, 412),
        (LinkedIdType::IdentityUsername, 413),
        (LinkedIdType::IdentityPassportNumber, 414),
        (LinkedIdType::IdentityLicenseNumber, 415),
        (LinkedIdType::IdentityFirstName, 416),
        (LinkedIdType::IdentityLastName, 417),
        (LinkedIdType::IdentityFullName, 418),
    ]);
    let err = serde_json::from_value::<LinkedIdType>(serde_json::json!(9999));
    assert!(err.is_err());
}
