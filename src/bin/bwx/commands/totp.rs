use crate::bin_error;

// The default number of seconds the generated TOTP
// code lasts for before a new one must be generated
const TOTP_DEFAULT_STEP: u64 = 30;

pub(super) struct TotpParams {
    pub(super) secret: Vec<u8>,
    pub(super) algorithm: String,
    pub(super) digits: usize,
    pub(super) period: u64,
}

pub(super) fn decode_totp_secret(secret: &str) -> bin_error::Result<Vec<u8>> {
    bwx::totp::decode_base32(secret).ok_or_else(|| {
        crate::bin_error::err!("totp secret was not valid base32")
    })
}

pub(super) fn parse_totp_secret(
    secret: &str,
) -> bin_error::Result<TotpParams> {
    if let Ok(u) = url::Url::parse(secret) {
        match u.scheme() {
            "otpauth" => {
                if u.host_str() != Some("totp") {
                    return Err(crate::bin_error::err!(
                        "totp secret url must have totp host"
                    ));
                }

                let query: std::collections::HashMap<_, _> =
                    u.query_pairs().collect();

                let secret = decode_totp_secret(
                    query.get("secret").ok_or_else(|| {
                        crate::bin_error::err!(
                            "totp secret url must have secret"
                        )
                    })?,
                )?;
                let algorithm = query.get("algorithm").map_or_else(
                    || String::from("SHA1"),
                    std::string::ToString::to_string,
                );
                let digits = match query.get("digits") {
                    Some(dig) => dig
                        .parse::<usize>()
                        .map_err(|_| crate::bin_error::err!("digits parameter in totp url must be a valid integer."))?,
                    None => 6,
                };
                let period = match query.get("period") {
                    Some(dig) => {
                        dig.parse::<u64>().map_err(|_| crate::bin_error::err!("period parameter in totp url must be a valid integer."))?
                    }
                    None => TOTP_DEFAULT_STEP,
                };

                Ok(TotpParams {
                    secret,
                    algorithm,
                    digits,
                    period,
                })
            }
            "steam" => {
                let steam_secret = u.host_str().unwrap();

                Ok(TotpParams {
                    secret: decode_totp_secret(steam_secret)?,
                    algorithm: String::from("STEAM"),
                    digits: 5,
                    period: TOTP_DEFAULT_STEP,
                })
            }
            _ => Err(crate::bin_error::err!(
                "totp secret url must have 'otpauth' or 'steam' scheme"
            )),
        }
    } else {
        Ok(TotpParams {
            secret: decode_totp_secret(secret)?,
            algorithm: String::from("SHA1"),
            digits: 6,
            period: TOTP_DEFAULT_STEP,
        })
    }
}

pub(super) fn generate_totp(secret: &str) -> bin_error::Result<String> {
    let totp_params = parse_totp_secret(secret)?;
    let algorithm = match totp_params.algorithm.as_str() {
        "SHA1" => bwx::totp::Algorithm::Sha1,
        "SHA256" => bwx::totp::Algorithm::Sha256,
        "SHA512" => bwx::totp::Algorithm::Sha512,
        "STEAM" => bwx::totp::Algorithm::Steam,
        other => {
            return Err(crate::bin_error::err!(
                "{other} is not a valid totp algorithm"
            ));
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| crate::bin_error::err!("system time error: {e}"))?
        .as_secs();
    let digits = u32::try_from(totp_params.digits)
        .map_err(|_| crate::bin_error::err!("digits value out of range"))?;
    bwx::totp::generate(
        &totp_params.secret,
        now,
        totp_params.period,
        digits,
        &algorithm,
    )
    .map_err(crate::bin_error::Error::new)
}
