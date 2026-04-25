use super::util::{check_agent_version, ensure_agent, remove_db};
use crate::bin_error;

pub fn register() -> bin_error::Result<()> {
    ensure_agent()?;
    crate::actions::register()?;

    Ok(())
}

pub fn login() -> bin_error::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;

    Ok(())
}

pub fn unlock() -> bin_error::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;
    crate::actions::unlock()?;

    Ok(())
}

pub fn unlocked() -> bin_error::Result<()> {
    // not ensure_agent, because we don't want `bwx unlocked` to start the
    // agent if it's not running
    let _ = check_agent_version();
    crate::actions::unlocked()?;

    Ok(())
}

pub fn sync() -> bin_error::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;
    crate::actions::sync()?;

    Ok(())
}

pub fn lock() -> bin_error::Result<()> {
    ensure_agent()?;
    crate::actions::lock()?;

    Ok(())
}

pub fn purge() -> bin_error::Result<()> {
    stop_agent()?;

    remove_db()?;

    Ok(())
}

pub fn stop_agent() -> bin_error::Result<()> {
    crate::actions::quit()?;

    Ok(())
}
