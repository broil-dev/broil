// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::fmt;
use std::path::{Component, Path};

use zeroize::Zeroizing;

use crate::FailureClass;
use crate::path_safety::{CapabilityError, sudo_nonce};
use crate::secret::OwnedSecret;

pub const MAX_SUDO_FRAME_BYTES: usize = 4096;

const SUDO_FRAME_PREFIX: &[u8] = b"BROIL-SUDO:";
const SUDO_FRAME_PATH_SUFFIX: &str = ".broil-sudo-frame";
const SUDO_FRAME_WRAPPER: &str = concat!(
    "broil_sudo_frame=$1; shift || exit 1; ",
    "broil_launcher=$1; ",
    "case \"$broil_sudo_frame\" in /*) ;; *) exit 1;; esac; ",
    "case \"$broil_launcher\" in /*) ;; *) exit 1;; esac; ",
    "broil_frame_dir=${broil_sudo_frame%/*}; ",
    "broil_launcher_dir=${broil_launcher%/*}; ",
    "if [ -z \"$broil_frame_dir\" ] || [ -z \"$broil_launcher_dir\" ]; then exit 1; fi; ",
    "broil_no_symlink() { broil_check_path=$1; while [ \"$broil_check_path\" != / ]; do ",
    "[ ! -L \"$broil_check_path\" ] || return 1; ",
    "broil_check_parent=${broil_check_path%/*}; ",
    "[ \"$broil_check_parent\" != \"$broil_check_path\" ] || return 1; ",
    "[ -n \"$broil_check_parent\" ] || broil_check_parent=/; ",
    "broil_check_path=$broil_check_parent; done; }; ",
    "if [ \"$broil_frame_dir\" != \"$broil_launcher_dir\" ] || ",
    "[ \"$broil_sudo_frame\" != \"$broil_launcher.broil-sudo-frame\" ]; then exit 1; fi; ",
    "if [ -L \"$broil_sudo_frame\" ] || [ ! -f \"$broil_sudo_frame\" ]; then exit 1; fi; ",
    "if [ -L \"$broil_launcher\" ] || [ ! -f \"$broil_launcher\" ]; then exit 1; fi; ",
    "broil_no_symlink \"$broil_sudo_frame\" || exit 1; ",
    "broil_no_symlink \"$broil_launcher\" || exit 1; ",
    "broil_sudo_uid=${SUDO_UID:-}; ",
    "case \"$broil_sudo_uid\" in ''|*[!0123456789]*) exit 1;; esac; ",
    "broil_launcher_uid=$(stat -c '%u' \"$broil_launcher\") || exit 1; ",
    "exec 3< \"$broil_sudo_frame\" || exit 1; ",
    "if [ -L \"$broil_sudo_frame\" ]; then exit 1; fi; ",
    "[ \"$broil_sudo_frame\" -ef /proc/self/fd/3 ] || exit 1; ",
    "if [ ! -f /proc/self/fd/3 ]; then exit 1; fi; ",
    "broil_frame_uid=$(stat -Lc '%u' /proc/self/fd/3) || exit 1; ",
    "broil_frame_mode=$(stat -Lc '%a' /proc/self/fd/3) || exit 1; ",
    "broil_frame_size=$(stat -Lc '%s' /proc/self/fd/3) || exit 1; ",
    "broil_frame_links=$(stat -Lc '%h' /proc/self/fd/3) || exit 1; ",
    "if [ \"$broil_frame_uid\" != \"$broil_sudo_uid\" ] || ",
    "[ \"$broil_launcher_uid\" != \"$broil_sudo_uid\" ] || ",
    "[ \"$broil_frame_mode\" != 600 ] || [ \"$broil_frame_size\" != 44 ] || ",
    "[ \"$broil_frame_links\" != 1 ]; then exit 1; fi; ",
    "broil_frame=$(cat <&3) || exit 1; ",
    "case \"$broil_frame\" in BROIL-SUDO:*) broil_frame_nonce=${broil_frame#BROIL-SUDO:};; *) exit 1;; esac; ",
    "if [ \"${#broil_frame_nonce}\" -ne 32 ]; then exit 1; fi; ",
    "case \"$broil_frame_nonce\" in *[!0123456789abcdefABCDEF]*) exit 1;; esac; ",
    "broil_no_symlink \"$broil_sudo_frame\" || exit 1; ",
    "if [ -L \"$broil_sudo_frame\" ]; then exit 1; fi; ",
    "[ \"$broil_sudo_frame\" -ef /proc/self/fd/3 ] || exit 1; ",
    "rm -f -- \"$broil_sudo_frame\" || exit 1; ",
    "broil_frame_links_after=$(stat -Lc '%h' /proc/self/fd/3) || exit 1; ",
    "if [ \"$broil_frame_links_after\" != 0 ]; then exit 1; fi; ",
    "exec 3<&-; ",
    "printf '%s\\n' \"$broil_frame\" >&2 || exit 1; ",
    "unset broil_sudo_frame broil_launcher broil_frame_dir broil_launcher_dir ",
    "broil_check_path broil_check_parent broil_sudo_uid broil_frame_uid ",
    "broil_frame_mode broil_frame_size broil_frame_links broil_frame_links_after ",
    "broil_launcher_uid broil_frame broil_frame_nonce; ",
    "exec \"$@\""
);

#[derive(Debug)]
pub struct SudoFailure {
    diagnostic: String,
}

impl SudoFailure {
    fn new(diagnostic: impl Into<String>) -> Self {
        Self {
            diagnostic: diagnostic.into(),
        }
    }

    pub fn class(&self) -> FailureClass {
        FailureClass::Sudo
    }
}

impl fmt::Display for SudoFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.diagnostic)
    }
}

impl std::error::Error for SudoFailure {}

pub struct PreparedPasswordSudo {
    pub argv: Vec<String>,
    pub password_stdin: Zeroizing<Vec<u8>>,
    pub control_frame_path: String,
    pub control_frame_contents: Zeroizing<Vec<u8>>,
    pub nonce: String,
    pub withhold_user_stdin_until_frame: bool,
}

pub struct PreparedPasswordlessSudo {
    pub argv: Vec<String>,
    pub control_frame_path: String,
    pub control_frame_contents: Zeroizing<Vec<u8>>,
    pub nonce: String,
    pub withhold_user_stdin_until_frame: bool,
}

impl fmt::Debug for PreparedPasswordSudo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedPasswordSudo")
            .field("argv", &"[REDACTED]")
            .field("password_stdin", &"[REDACTED]")
            .field("control_frame_path", &"[REDACTED]")
            .field("control_frame_contents", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field(
                "withhold_user_stdin_until_frame",
                &self.withhold_user_stdin_until_frame,
            )
            .finish()
    }
}

impl fmt::Debug for PreparedPasswordlessSudo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedPasswordlessSudo")
            .field("argv", &"[REDACTED]")
            .field("control_frame_path", &"[REDACTED]")
            .field("control_frame_contents", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field(
                "withhold_user_stdin_until_frame",
                &self.withhold_user_stdin_until_frame,
            )
            .finish()
    }
}

pub fn sudo_preflight_argv() -> Vec<String> {
    strings(["sudo", "-n", "true"])
}

pub fn prepare_passwordless_sudo(
    launcher_argv: &[String],
) -> Result<PreparedPasswordlessSudo, SudoFailure> {
    let nonce = sudo_nonce().map_err(sudo_capability_failure)?;
    let control_frame_path = sudo_control_frame_path(launcher_argv)?;
    Ok(PreparedPasswordlessSudo {
        argv: passwordless_sudo_argv(launcher_argv, &nonce)?,
        control_frame_contents: sudo_control_frame_contents(&nonce)?,
        control_frame_path,
        nonce,
        withhold_user_stdin_until_frame: true,
    })
}

pub fn passwordless_sudo_argv(
    launcher_argv: &[String],
    nonce: &str,
) -> Result<Vec<String>, SudoFailure> {
    passwordless_wrapper_argv(launcher_argv, nonce)
}

pub fn prepare_password_sudo(
    launcher_argv: &[String],
    password: &OwnedSecret,
) -> Result<PreparedPasswordSudo, SudoFailure> {
    let nonce = sudo_nonce().map_err(sudo_capability_failure)?;
    let control_frame_path = sudo_control_frame_path(launcher_argv)?;
    Ok(PreparedPasswordSudo {
        argv: password_sudo_argv(launcher_argv, &nonce)?,
        password_stdin: sudo_password_input(password)?,
        control_frame_contents: sudo_control_frame_contents(&nonce)?,
        control_frame_path,
        nonce,
        withhold_user_stdin_until_frame: true,
    })
}

pub fn password_sudo_argv(
    launcher_argv: &[String],
    nonce: &str,
) -> Result<Vec<String>, SudoFailure> {
    sudo_password_wrapper_argv(launcher_argv, nonce)
}

fn passwordless_wrapper_argv(
    launcher_argv: &[String],
    nonce: &str,
) -> Result<Vec<String>, SudoFailure> {
    require_launcher(launcher_argv)?;
    require_nonce(nonce)?;
    let control_frame_path = sudo_control_frame_path(launcher_argv)?;
    let mut argv = strings(["sudo", "-n", "--", "sh", "-c", SUDO_FRAME_WRAPPER]);
    argv.push("broil-sudo-wrapper".to_string());
    argv.push(control_frame_path);
    argv.extend_from_slice(launcher_argv);
    Ok(argv)
}

fn sudo_password_wrapper_argv(
    launcher_argv: &[String],
    nonce: &str,
) -> Result<Vec<String>, SudoFailure> {
    require_launcher(launcher_argv)?;
    require_nonce(nonce)?;
    let control_frame_path = sudo_control_frame_path(launcher_argv)?;
    let mut argv = strings(["sudo", "-S", "-p", "", "--", "sh", "-c", SUDO_FRAME_WRAPPER]);
    argv.push("broil-sudo-wrapper".to_string());
    argv.push(control_frame_path);
    argv.extend_from_slice(launcher_argv);
    Ok(argv)
}

pub fn sudo_password_input(password: &OwnedSecret) -> Result<Zeroizing<Vec<u8>>, SudoFailure> {
    if password
        .as_str()
        .as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'\r' | b'\n'))
    {
        return Err(SudoFailure::new(
            "sudo password contains an unsupported line break",
        ));
    }
    let mut input = Zeroizing::new(Vec::with_capacity(password.len() + 1));
    input.extend_from_slice(password.as_str().as_bytes());
    input.push(b'\n');
    Ok(input)
}

fn sudo_control_frame_contents(nonce: &str) -> Result<Zeroizing<Vec<u8>>, SudoFailure> {
    require_nonce(nonce)?;
    let mut frame = Zeroizing::new(Vec::with_capacity(
        SUDO_FRAME_PREFIX.len() + nonce.len() + 1,
    ));
    frame.extend_from_slice(SUDO_FRAME_PREFIX);
    frame.extend_from_slice(nonce.as_bytes());
    frame.push(b'\n');
    Ok(frame)
}

fn sudo_control_frame_path(launcher_argv: &[String]) -> Result<String, SudoFailure> {
    let launcher = require_launcher(launcher_argv)?;
    require_absolute_launcher_path(launcher)?;
    Ok(format!("{launcher}{SUDO_FRAME_PATH_SUFFIX}"))
}

#[derive(Debug, Eq, PartialEq)]
pub enum SudoControlFrameParse<'a> {
    Pending,
    Complete(ParsedSudoControlFrame<'a>),
}

#[derive(Debug, Eq, PartialEq)]
pub struct ParsedSudoControlFrame<'a> {
    pub preceding: &'a [u8],
    pub payload: &'a [u8],
}

pub fn parse_sudo_control_frame<'a>(
    prelude: &'a [u8],
    expected_nonce: &str,
) -> Result<SudoControlFrameParse<'a>, SudoFailure> {
    require_nonce(expected_nonce)?;
    let mut expected = Vec::with_capacity(SUDO_FRAME_PREFIX.len() + expected_nonce.len() + 2);
    expected.extend_from_slice(SUDO_FRAME_PREFIX);
    expected.extend_from_slice(expected_nonce.as_bytes());
    expected.push(b'\n');
    let lf_expected = expected.clone();
    expected.pop();
    expected.extend_from_slice(b"\r\n");
    let crlf_expected = expected;

    let mut line_start = 0;
    while line_start < prelude.len() {
        let newline = match prelude[line_start..].iter().position(|byte| *byte == b'\n') {
            Some(index) => line_start + index,
            None if prelude.len() > MAX_SUDO_FRAME_BYTES => {
                return Err(SudoFailure::new("sudo control frame exceeded maximum size"));
            }
            None => return Ok(SudoControlFrameParse::Pending),
        };
        let frame_end = newline + 1;
        if frame_end > MAX_SUDO_FRAME_BYTES {
            return Err(SudoFailure::new("sudo control frame exceeded maximum size"));
        }

        let line = &prelude[line_start..frame_end];
        if line == lf_expected.as_slice() || line == crlf_expected.as_slice() {
            return Ok(SudoControlFrameParse::Complete(ParsedSudoControlFrame {
                preceding: &prelude[..line_start],
                payload: &prelude[frame_end..],
            }));
        }
        if line.starts_with(SUDO_FRAME_PREFIX) {
            return Err(SudoFailure::new(
                "sudo control frame was missing or malformed",
            ));
        }
        line_start = frame_end;
    }

    if prelude.len() > MAX_SUDO_FRAME_BYTES {
        Err(SudoFailure::new("sudo control frame exceeded maximum size"))
    } else {
        Ok(SudoControlFrameParse::Pending)
    }
}

fn require_launcher(launcher_argv: &[String]) -> Result<&str, SudoFailure> {
    match launcher_argv.first() {
        Some(launcher) if !launcher.is_empty() => Ok(launcher),
        _ => Err(SudoFailure::new("sudo launcher argv is empty")),
    }
}

fn require_absolute_launcher_path(launcher: &str) -> Result<(), SudoFailure> {
    let path = Path::new(launcher);
    if !path.is_absolute() || launcher.ends_with('/') {
        return Err(SudoFailure::new("sudo launcher path is unsafe"));
    }
    match path.parent() {
        Some(parent) if parent != Path::new("/") => {}
        _ => return Err(SudoFailure::new("sudo launcher path is unsafe")),
    }

    if path.file_name().is_none() {
        return Err(SudoFailure::new("sudo launcher path is unsafe"));
    }
    for component in path.components() {
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            return Err(SudoFailure::new("sudo launcher path is unsafe"));
        }
    }
    Ok(())
}

fn require_nonce(nonce: &str) -> Result<(), SudoFailure> {
    if !nonce.is_empty() && nonce.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(SudoFailure::new("sudo nonce is invalid"))
    }
}

fn sudo_capability_failure(_error: CapabilityError) -> SudoFailure {
    SudoFailure::new("sudo nonce generation failed")
}

fn strings<const N: usize>(values: [&str; N]) -> Vec<String> {
    values.into_iter().map(str::to_string).collect()
}

