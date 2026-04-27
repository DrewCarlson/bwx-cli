use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt as _;

pub fn str_to_utf16_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn os_str_to_utf16_nul(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}
