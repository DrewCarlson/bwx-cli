use crate::prelude::*;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

#[cfg(unix)]
pub fn make_all() -> Result<()> {
    create_dir_all_with_permissions(&config_dir(), 0o700)?;
    create_dir_all_with_permissions(&cache_dir(), 0o700)?;
    create_dir_all_with_permissions(&runtime_dir(), 0o700)?;
    create_dir_all_with_permissions(&data_dir(), 0o700)?;

    Ok(())
}

#[cfg(windows)]
pub fn make_all() -> Result<()> {
    for path in [config_dir(), cache_dir(), runtime_dir(), data_dir()] {
        create_dir_all_with_user_acl(&path)?;
    }
    Ok(())
}

#[cfg(windows)]
fn create_dir_all_with_user_acl(path: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(path).map_err(|source| Error::CreateDirectory {
        source,
        file: path.to_path_buf(),
    })?;
    if let Err(e) = apply_user_only_dacl(path) {
        log::warn!(
            "failed to apply per-user DACL to {}: {e}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn apply_user_only_dacl(path: &std::path::Path) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::TRUE;
    use windows_sys::Win32::Security::Authorization::{
        SetEntriesInAclW, EXPLICIT_ACCESS_W, SET_ACCESS, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        InitializeSecurityDescriptor, IsValidSid, SetFileSecurityW,
        SetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION,
        NO_INHERITANCE, SECURITY_DESCRIPTOR, TOKEN_USER,
    };
    use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    let wide = crate::win::wide::os_str_to_utf16_nul(path.as_os_str());
    let buf = crate::win::sid::current_user_sid_buf()?;

    // SAFETY: buf holds a TOKEN_USER followed by the SID bytes.
    let token_user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
    let sid = token_user.User.Sid;
    // SAFETY: sid points into the same TOKEN_USER buffer.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(std::io::Error::other("invalid user SID"));
    }

    let mut ea: EXPLICIT_ACCESS_W = unsafe { std::mem::zeroed() };
    ea.grfAccessPermissions = FILE_ALL_ACCESS;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    let mut trustee: TRUSTEE_W = unsafe { std::mem::zeroed() };
    trustee.TrusteeForm =
        windows_sys::Win32::Security::Authorization::TRUSTEE_IS_SID;
    trustee.TrusteeType =
        windows_sys::Win32::Security::Authorization::TRUSTEE_IS_USER;
    trustee.ptstrName = sid.cast::<u16>();
    ea.Trustee = trustee;

    let mut new_acl: *mut ACL = std::ptr::null_mut();
    // SAFETY: ea describes a single ACE; new_acl receives a heap ACL
    // freed via LocalFree below.
    let status = unsafe {
        SetEntriesInAclW(1, &ea, std::ptr::null_mut(), &mut new_acl)
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(
            i32::try_from(status).unwrap_or(0),
        ));
    }
    let cleanup_acl = AclPtr(new_acl);

    let mut sd: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
    // SAFETY: sd is a stack-local SECURITY_DESCRIPTOR.
    let ok = unsafe {
        InitializeSecurityDescriptor(
            (&mut sd as *mut SECURITY_DESCRIPTOR).cast(),
            SECURITY_DESCRIPTOR_REVISION,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: sd was just initialized; new_acl is valid until LocalFree.
    let ok = unsafe {
        SetSecurityDescriptorDacl(
            (&mut sd as *mut SECURITY_DESCRIPTOR).cast(),
            TRUE,
            cleanup_acl.0,
            0,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: wide is NUL-terminated; sd is a fully built absolute SD.
    let ok = unsafe {
        SetFileSecurityW(
            wide.as_ptr(),
            DACL_SECURITY_INFORMATION,
            (&mut sd as *mut SECURITY_DESCRIPTOR).cast(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
struct AclPtr(*mut windows_sys::Win32::Security::ACL);

#[cfg(windows)]
impl Drop for AclPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: pointer originated from SetEntriesInAclW which
            // documents LocalFree as the matching deallocator.
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(self.0.cast());
            }
        }
    }
}

#[cfg(unix)]
fn create_dir_all_with_permissions(
    path: &std::path::Path,
    mode: u32,
) -> Result<()> {
    // create with the correct mode to avoid a race between mkdir and chmod
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
        .map_err(|source| Error::CreateDirectory {
            source,
            file: path.to_path_buf(),
        })?;
    // forcibly set the mode in case the directory already existed
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|source| Error::CreateDirectory {
            source,
            file: path.to_path_buf(),
        })?;
    Ok(())
}

pub fn config_file() -> std::path::PathBuf {
    config_dir().join("config.json")
}

pub fn db_file(server: &str, email: &str) -> std::path::PathBuf {
    let server = urlencoding::encode(server).into_owned();
    cache_dir().join(format!("{server}:{email}.json"))
}

pub fn pid_file() -> std::path::PathBuf {
    runtime_dir().join("pidfile")
}

pub fn agent_stdout_file() -> std::path::PathBuf {
    data_dir().join("agent.out")
}

pub fn agent_stderr_file() -> std::path::PathBuf {
    data_dir().join("agent.err")
}

pub fn device_id_file() -> std::path::PathBuf {
    data_dir().join("device_id")
}

pub fn socket_file() -> std::path::PathBuf {
    runtime_dir().join("socket")
}

pub fn ssh_agent_socket_file() -> std::path::PathBuf {
    runtime_dir().join("ssh-agent-socket")
}

/// Windows named-pipe path for the bwx-CLI ↔ bwx-agent control
/// channel. The DACL on the server pipe restricts access to the
/// current user, so no per-user prefix is required in the name;
/// the profile suffix preserves `BWX_PROFILE` isolation.
#[cfg(windows)]
pub fn pipe_name() -> String {
    format!(r"\\.\pipe\{}", profile())
}

/// Windows named-pipe path for the OpenSSH-for-Windows ssh-agent
/// channel. The base name `openssh-ssh-agent` is the well-known
/// path OpenSSH looks at via `SSH_AUTH_SOCK`. A profile suffix is
/// appended when `BWX_PROFILE` is set so parallel test instances
/// don't collide.
#[cfg(windows)]
pub fn ssh_agent_pipe_name() -> String {
    match std::env::var("BWX_PROFILE") {
        Ok(p) if !p.is_empty() => {
            format!(r"\\.\pipe\openssh-ssh-agent-{p}")
        }
        _ => r"\\.\pipe\openssh-ssh-agent".to_string(),
    }
}

#[cfg(unix)]
fn home_dir() -> std::path::PathBuf {
    std::env::var_os("HOME").map_or_else(
        || std::path::PathBuf::from("/"),
        std::path::PathBuf::from,
    )
}

#[cfg(windows)]
fn local_app_data() -> std::path::PathBuf {
    if let Some(d) = std::env::var_os("LOCALAPPDATA") {
        return std::path::PathBuf::from(d);
    }
    if let Some(home) = std::env::var_os("USERPROFILE") {
        return std::path::PathBuf::from(home).join("AppData").join("Local");
    }
    std::path::PathBuf::from(".")
}

#[cfg(target_os = "macos")]
fn config_dir() -> std::path::PathBuf {
    home_dir()
        .join("Library/Application Support")
        .join(profile())
}

#[cfg(target_os = "macos")]
fn cache_dir() -> std::path::PathBuf {
    home_dir().join("Library/Caches").join(profile())
}

#[cfg(target_os = "macos")]
fn data_dir() -> std::path::PathBuf {
    config_dir()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn xdg_or(env: &str, fallback_rel: &str) -> std::path::PathBuf {
    std::env::var_os(env)
        .filter(|v| std::path::Path::new(v).is_absolute())
        .map_or_else(
            || home_dir().join(fallback_rel),
            std::path::PathBuf::from,
        )
}

#[cfg(all(unix, not(target_os = "macos")))]
fn config_dir() -> std::path::PathBuf {
    xdg_or("XDG_CONFIG_HOME", ".config").join(profile())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn cache_dir() -> std::path::PathBuf {
    xdg_or("XDG_CACHE_HOME", ".cache").join(profile())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn data_dir() -> std::path::PathBuf {
    xdg_or("XDG_DATA_HOME", ".local/share").join(profile())
}

#[cfg(windows)]
fn config_dir() -> std::path::PathBuf {
    local_app_data().join("bwx-cli").join(profile())
}

#[cfg(windows)]
fn cache_dir() -> std::path::PathBuf {
    local_app_data().join("bwx-cli").join(profile())
}

#[cfg(windows)]
fn data_dir() -> std::path::PathBuf {
    local_app_data().join("bwx-cli").join(profile())
}

fn runtime_dir() -> std::path::PathBuf {
    // Honor XDG_RUNTIME_DIR on all platforms when explicitly set. macOS has
    // no native equivalent, but respecting the override lets tests and
    // advanced users isolate per-instance sockets. Falls through to a
    // $TMPDIR-based path when unset.
    if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR") {
        if std::path::Path::new(&d).is_absolute() {
            return std::path::PathBuf::from(d).join(profile());
        }
    }
    #[cfg(unix)]
    {
        format!(
            "{}/{}-{}",
            std::env::temp_dir().to_string_lossy(),
            profile(),
            rustix::process::getuid().as_raw()
        )
        .into()
    }
    #[cfg(windows)]
    {
        local_app_data().join("bwx-cli").join("run").join(profile())
    }
}

pub fn profile() -> String {
    match std::env::var("BWX_PROFILE") {
        Ok(profile) if !profile.is_empty() => format!("bwx-{profile}"),
        _ => "bwx".to_string(),
    }
}
