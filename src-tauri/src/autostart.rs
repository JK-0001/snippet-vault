//! Start-with-Windows via the per-user Run key, written by us so the command
//! is always a properly quoted path. (The generic autostart plugin wrote an
//! unquoted path with a trailing space, which Windows failed to launch.)

use std::process::Command;

const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE_NAME: &str = "Snippet Vault";

fn reg(args: &[&str]) -> Result<std::process::Output, String> {
    let mut cmd = Command::new("reg.exe");
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.output().map_err(|e| e.to_string())
}

/// The command we want in the Run key: quoted exe path plus a marker flag.
pub fn desired_command() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    Ok(format!("\"{}\" --autostart", exe.display()))
}

/// Current Run-key command, if any.
pub fn current_command() -> Option<String> {
    let out = reg(&["query", RUN_KEY, "/v", VALUE_NAME]).ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if line.contains(VALUE_NAME) && line.contains("REG_SZ") {
            if let Some((_, value)) = line.split_once("REG_SZ") {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

pub fn is_enabled() -> bool {
    current_command().is_some()
}

pub fn enable() -> Result<(), String> {
    let cmd = desired_command()?;
    let out = reg(&["add", RUN_KEY, "/v", VALUE_NAME, "/t", "REG_SZ", "/d", &cmd, "/f"])?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

pub fn disable() -> Result<(), String> {
    let out = reg(&["delete", RUN_KEY, "/v", VALUE_NAME, "/f"])?;
    if out.status.success() || !is_enabled() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// If an entry exists but does not match the exact command we want (old
/// unquoted form, trailing space, moved exe), rewrite it.
pub fn repair_if_needed() {
    let Some(current) = current_command() else {
        return;
    };
    match desired_command() {
        Ok(desired) if current != desired => match enable() {
            Ok(()) => log::info!("repaired startup entry: {current:?} -> {desired:?}"),
            Err(e) => log::error!("could not repair startup entry: {e}"),
        },
        _ => {}
    }
}
