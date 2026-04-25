use super::wire::ConnectErrorRes;
use crate::prelude::*;

pub(super) async fn find_free_port(bottom: u16, top: u16) -> Result<u16> {
    for port in bottom..top {
        if tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Ok(port);
        }
    }

    Err(Error::FailedToFindFreePort {
        range: format!("({bottom}..{top})"),
    })
}

pub(super) async fn start_sso_callback_server(
    listener: tokio::net::TcpListener,
    state: &str,
) -> Result<String> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    const SUCCESS_BODY: &str =
        "<html><head><title>Success | bwx</title></head><body> \
         <h1>Successfully authenticated with bwx</h1> \
         <p>You may now close this tab and return to the terminal.</p> \
         </body></html>";
    const FAILURE_BODY: &str =
        "<html><head><title>Failed | bwx</title></head><body> \
         <h1>Something went wrong logging into the bwx</h1> \
         <p>You may now close this tab and return to the terminal.</p> \
         </body></html>";
    const MAX_REQUEST_BYTES: usize = 16 * 1024;

    loop {
        let (mut stream, _peer) = listener.accept().await.map_err(|e| {
            Error::FailedToProcessSSOCallback {
                msg: format!("accept: {e}"),
            }
        })?;

        let mut buf = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        let headers_complete = loop {
            let Ok(n) = stream.read(&mut chunk).await else {
                break false;
            };
            if n == 0 {
                break false;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break true;
            }
            if buf.len() >= MAX_REQUEST_BYTES {
                break false;
            }
        };
        if !headers_complete {
            continue;
        }

        let request_line = std::str::from_utf8(&buf)
            .ok()
            .and_then(|s| s.lines().next())
            .unwrap_or("");
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");

        if method != "GET" {
            let _ = write_response(
                &mut stream,
                "405 Method Not Allowed",
                FAILURE_BODY,
            )
            .await;
            continue;
        }

        let query = target.split_once('?').map_or("", |x| x.1);
        let params = parse_query(query);
        let result = sso_query_code(&params, state);

        let (status, body) = match &result {
            Ok(_) => ("200 OK", SUCCESS_BODY),
            Err(_) => ("400 Bad Request", FAILURE_BODY),
        };
        let _ = write_response(&mut stream, status, body).await;
        let _ = stream.shutdown().await;

        return result;
    }
}

pub(super) fn parse_query(
    query: &str,
) -> std::collections::HashMap<String, String> {
    query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            let key = urlencoding::decode(k).ok()?.into_owned();
            let val = urlencoding::decode(v).ok()?.into_owned();
            Some((key, val))
        })
        .collect()
}

async fn write_response(
    stream: &mut tokio::net::TcpStream,
    status: &str,
    body: &str,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt as _;
    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    );
    stream.write_all(response.as_bytes()).await
}

pub(super) fn sso_query_code(
    params: &std::collections::HashMap<String, String>,
    state: &str,
) -> Result<String> {
    let sso_code =
        params
            .get("code")
            .ok_or(Error::FailedToProcessSSOCallback {
                msg: "Could not obtain code from the URL".to_string(),
            })?;

    let received_state =
        params
            .get("state")
            .ok_or(Error::FailedToProcessSSOCallback {
                msg: "Could not obtain state from the URL".to_string(),
            })?;

    if received_state.split("_identifier=").next().unwrap() != state {
        // Intentionally does not include either state value — they are
        // live OAuth state tokens and this error can reach stderr / logs.
        return Err(Error::FailedToProcessSSOCallback {
            msg: "SSO callback state mismatch".to_string(),
        });
    }

    Ok(sso_code.clone())
}

pub(super) fn classify_login_error(
    error_res: &ConnectErrorRes,
    code: u16,
) -> Error {
    let error_desc = error_res.error_description.clone();
    let error_desc = error_desc.as_deref();
    match error_res.error.as_str() {
        "invalid_grant" => match error_desc {
            Some("invalid_username_or_password") => {
                if let Some(error_model) = error_res.error_model.as_ref() {
                    let message = error_model.message.as_str().to_string();
                    return Error::IncorrectPassword { message };
                }
            }
            Some("Two factor required.") => {
                if let Some(providers) =
                    error_res.two_factor_providers.as_ref()
                {
                    return Error::TwoFactorRequired {
                        providers: providers.clone(),
                        sso_email_2fa_session_token: error_res
                            .sso_email_2fa_session_token
                            .clone(),
                    };
                }
            }
            Some("Captcha required.") => {
                return Error::RegistrationRequired;
            }
            _ => {}
        },
        "invalid_client" => {
            return Error::IncorrectApiKey;
        }
        ""
            // bitwarden_rs returns an empty error and error_description for
            // this case, for some reason
            if error_desc.is_none() || error_desc == Some("") =>
        {
            if let Some(error_model) = error_res.error_model.as_ref() {
                let message = error_model.message.as_str().to_string();
                match message.as_str() {
                    "Username or password is incorrect. Try again"
                    | "TOTP code is not a number" => {
                        return Error::IncorrectPassword { message };
                    }
                    s => {
                        if s.starts_with(
                            "Invalid TOTP code! Server time: ",
                        ) {
                            return Error::IncorrectPassword { message };
                        }
                    }
                }
            }
        }
        _ => {}
    }

    log::warn!("unexpected error received during login: {error_res:?}");
    Error::RequestFailed { status: code }
}
