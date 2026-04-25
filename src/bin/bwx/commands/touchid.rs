#[cfg(target_os = "macos")]
use super::auth::unlock;
use crate::bin_error;

#[cfg(not(target_os = "macos"))]
pub fn touchid_enroll() -> bin_error::Result<()> {
    Err(bin_error::Error::msg("touchid is only supported on macOS"))
}

#[cfg(target_os = "macos")]
pub fn touchid_enroll() -> bin_error::Result<()> {
    unlock()?;
    crate::actions::touchid_enroll()?;
    println!(
        "Touch ID enrollment active. Set `touchid_gate` to \
         'signing' or 'all' to require a Touch ID prompt on \
         sensitive operations."
    );
    Ok(())
}

pub fn touchid_disable() -> bin_error::Result<()> {
    crate::actions::touchid_disable()?;
    println!("Touch ID enrollment removed.");
    // `touchid_gate` and enrollment are orthogonal; disabling enrollment
    // doesn't stop per-operation prompts.
    let gate = bwx::config::Config::load()
        .map(|c| c.touchid_gate)
        .unwrap_or_default();
    if !matches!(gate, bwx::touchid::Gate::Off) {
        println!(
            "\nNote: `touchid_gate` is still '{gate}'; bwx will keep \
             prompting for Touch ID on sensitive operations. Run \
             `bwx config unset touchid_gate` to stop those prompts."
        );
    }
    Ok(())
}

pub fn touchid_status() -> bin_error::Result<()> {
    let (enrolled, gate, label) = crate::actions::touchid_status()?;
    println!("enrolled: {}", if enrolled { "yes" } else { "no" });
    println!("gate: {gate}");
    if let Some(label) = label {
        println!("keychain_label: {label}");
    }
    Ok(())
}
