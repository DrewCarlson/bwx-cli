use super::auth::unlock;
use crate::bin_error;

pub fn biometric_enroll() -> bin_error::Result<()> {
    unlock()?;
    crate::actions::biometric_enroll()?;
    println!(
        "Biometric enrollment active. Set `biometric_gate` to \
         'signing' or 'all' to require a Touch ID prompt on \
         sensitive operations."
    );
    Ok(())
}

pub fn biometric_disable() -> bin_error::Result<()> {
    crate::actions::biometric_disable()?;
    println!("Biometric enrollment removed.");
    // `biometric_gate` and enrollment are orthogonal; disabling enrollment
    // doesn't stop per-operation prompts.
    let gate = bwx::config::Config::load_cached()
        .map(|c| c.biometric_gate)
        .unwrap_or_default();
    if !matches!(gate, bwx::biometric::Gate::Off) {
        println!(
            "\nNote: `biometric_gate` is still '{gate}'; bwx will keep \
             prompting for Touch ID on sensitive operations. Run \
             `bwx config unset biometric_gate` to stop those prompts."
        );
    }
    Ok(())
}

pub fn biometric_status() -> bin_error::Result<()> {
    let (enrolled, gate, label) = crate::actions::biometric_status()?;
    println!("enrolled: {}", if enrolled { "yes" } else { "no" });
    println!("gate: {gate}");
    if let Some(label) = label {
        println!("keychain_label: {label}");
    }
    Ok(())
}
