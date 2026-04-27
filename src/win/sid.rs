use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken,
};

/// Read the `TOKEN_USER` (user SID + attrs) buffer from an open token
/// handle. The returned `Vec<u8>` is laid out as a `TOKEN_USER` followed
/// by the SID bytes; callers reinterpret with
/// `&*buf.as_ptr().cast::<TOKEN_USER>()` to access the SID pointer.
pub fn token_user_sid_buf(token: HANDLE) -> std::io::Result<Vec<u8>> {
    let mut needed: u32 = 0;
    // SAFETY: documented size-query pattern with a null buffer.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buf = vec![0u8; needed as usize];
    // SAFETY: buf is sized per the prior query; token is valid.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(buf)
}

/// `TOKEN_USER` buffer for the current process, opening and closing the
/// process token internally.
pub fn current_user_sid_buf() -> std::io::Result<Vec<u8>> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess is a pseudo-handle; token is a stack out.
    let ok = unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let result = token_user_sid_buf(token);
    // SAFETY: token is closed exactly once.
    unsafe {
        CloseHandle(token);
    }
    result
}
