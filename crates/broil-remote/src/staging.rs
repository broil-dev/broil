// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::FailureClass;

const RECEIVER_MAGIC: &str = "BROIL-EXEC-STAGING-1";
const RECEIVER_END: &str = "END";
const SCRIPT_BODY_SUFFIX: &str = ".broil-script-body";
const SUDO_FRAME_SUFFIX: &str = ".broil-sudo-frame";

const RECEIVER_SCRIPT: &str = r#"set -efu
broil_digits() { case "$1" in ''|*[!0123456789]*) return 1;; *) return 0;; esac; }
broil_private_dir() {
path=$1
if [ -e "$path" ]; then
[ ! -L "$path" ] || exit 1
[ -d "$path" ] || exit 1
else
mkdir "$path" || exit 1
fi
[ ! -L "$path" ] || exit 1
[ "$(stat -c '%u' "$path")" = "$uid" ] || exit 1
chmod 00700 "$path" || exit 1
[ "$(stat -c '%a' "$path")" = 700 ] || exit 1
}
broil_private_file() {
path=$1
[ ! -L "$path" ] || exit 1
[ -f "$path" ] || exit 1
[ "$(stat -c '%u' "$path")" = "$uid" ] || exit 1
chmod 00600 "$path" || exit 1
[ "$(stat -c '%a' "$path")" = 600 ] || exit 1
}
broil_reclaim() {
base=$1
find "$base" -mindepth 1 -maxdepth 1 -type d -name 'exec.*' -mmin +1440 -exec sh -c '
uid=$(id -u)
for dir do
[ ! -L "$dir" ] || continue
[ -d "$dir" ] || continue
[ "$(stat -c "%u" "$dir")" = "$uid" ] || continue
[ "$(stat -c "%a" "$dir")" = 700 ] || continue
case "${dir##*/}" in exec.*) rm -rf -- "$dir";; esac
done
' sh {} + 2>/dev/null || true
}
IFS= read -r magic || exit 1
[ "$magic" = BROIL-EXEC-STAGING-1 ] || exit 1
IFS= read -r launcher_len || exit 1
IFS= read -r body_present || exit 1
IFS= read -r body_len || exit 1
IFS= read -r sidecar_len || exit 1
IFS= read -r marker || exit 1
[ "$marker" = END ] || exit 1
broil_digits "$launcher_len" || exit 1
case "$body_present" in 0|1) ;; *) exit 1;; esac
broil_digits "$body_len" || exit 1
broil_digits "$sidecar_len" || exit 1
uid=$(id -u)
umask 077
broil_private_dir "${HOME:?}/.broil"
broil_private_dir "${HOME:?}/.broil/tmp"
base="${HOME:?}/.broil/tmp/exec"
broil_private_dir "$base"
broil_reclaim "$base"
dir=$(mktemp -d "$base/exec.XXXXXXXXXX")
broil_private_dir "$dir"
launcher="$dir/launcher"
set -C
: >"$launcher"
set +C
broil_private_file "$launcher"
dd bs=1 count="$launcher_len" of="$launcher" 2>/dev/null || exit 1
[ "$(wc -c <"$launcher")" = "$launcher_len" ] || exit 1
broil_private_file "$launcher"
if [ "$body_present" = 1 ]; then
body="$launcher.broil-script-body"
set -C
: >"$body"
set +C
broil_private_file "$body"
dd bs=1 count="$body_len" of="$body" 2>/dev/null || exit 1
[ "$(wc -c <"$body")" = "$body_len" ] || exit 1
broil_private_file "$body"
fi
if [ "$sidecar_len" != 0 ]; then
sidecar="$launcher.broil-sudo-frame"
set -C
: >"$sidecar"
set +C
broil_private_file "$sidecar"
dd bs=1 count="$sidecar_len" of="$sidecar" 2>/dev/null || exit 1
[ "$(wc -c <"$sidecar")" = "$sidecar_len" ] || exit 1
broil_private_file "$sidecar"
fi
printf '%s\n' "$launcher"
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedLauncher {
    pub launcher: String,
    pub body: Option<String>,
    pub sidecar: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingFailure {
    pub class: FailureClass,
    pub diagnostic: String,
    pub possible_staging_residue: bool,
}

impl StagingFailure {
    pub fn new(class: FailureClass, diagnostic: impl Into<String>) -> Self {
        Self {
            class,
            diagnostic: diagnostic.into(),
            possible_staging_residue: false,
        }
    }

    pub fn residue(mut self) -> Self {
        self.possible_staging_residue = true;
        self
    }
}

pub fn launcher_for_argv(argv: &[Vec<u8>]) -> Vec<u8> {
    let mut script = Vec::from(&b"#!/bin/sh\nset --"[..]);
    for arg in argv {
        script.push(b' ');
        push_shell_quoted_bytes(&mut script, arg);
    }
    script.extend_from_slice(b"\ncase \"$1\" in\n-*) \"$@\";;\n*) exec \"$@\";;\nesac\n");
    script
}

pub fn launcher_for_shell(body: &[u8]) -> Vec<u8> {
    let mut script = Vec::from(&b"#!/bin/sh\n"[..]);
    script.extend_from_slice(body);
    if !body.ends_with(b"\n") {
        script.push(b'\n');
    }
    script
}

pub fn launcher_for_script(
    body_has_shebang: bool,
    interpreter: Option<&[Vec<u8>]>,
    cwd: Option<&[u8]>,
    cwd_nonce: &str,
    env: &BTreeMap<String, Vec<u8>>,
    args: &[Vec<u8>],
) -> Vec<u8> {
    let mut script = Vec::from(&b"#!/bin/sh\nset -efu\nbroil_body=$0.broil-script-body\n"[..]);
    for (name, value) in env {
        script.extend_from_slice(name.as_bytes());
        script.push(b'=');
        push_shell_quoted_bytes(&mut script, value);
        script.push(b'\n');
        script.extend_from_slice(b"export ");
        script.extend_from_slice(name.as_bytes());
        script.push(b'\n');
    }
    if let Some(cwd) = cwd {
        script.extend_from_slice(b"cd ");
        push_shell_quoted_bytes(&mut script, cwd);
        script.extend_from_slice(b" 2>/dev/null || { printf '%s\\n' ");
        push_shell_quoted_bytes(&mut script, format!("BROIL-RUN-CWD:{cwd_nonce}").as_bytes());
        script.extend_from_slice(b" >&2; exit 125; }\n");
    }
    script.extend_from_slice(b"set --");
    if body_has_shebang {
        script.extend_from_slice(b" \"$broil_body\"");
    } else {
        for arg in interpreter.expect("non-shebang script launchers require an interpreter") {
            script.push(b' ');
            push_shell_quoted_bytes(&mut script, arg);
        }
        script.extend_from_slice(b" \"$broil_body\"");
    }
    for arg in args {
        script.push(b' ');
        push_shell_quoted_bytes(&mut script, arg);
    }
    script.extend_from_slice(b"\ncase \"$1\" in\n-*) \"$@\";;\n*) exec \"$@\";;\nesac\n");
    script
}

pub fn body_has_shebang(body: &[u8]) -> bool {
    body.starts_with(b"#!")
}

pub fn staging_input(
    launcher: &[u8],
    body: Option<&[u8]>,
    sidecar: Option<&[u8]>,
) -> Zeroizing<Vec<u8>> {
    let body_present = u8::from(body.is_some());
    let body_len = body.map_or(0, <[u8]>::len);
    let sidecar_len = sidecar.map_or(0, <[u8]>::len);
    let mut input = Zeroizing::new(
        format!(
            "{RECEIVER_MAGIC}\n{}\n{body_present}\n{body_len}\n{sidecar_len}\n{RECEIVER_END}\n",
            launcher.len()
        )
        .into_bytes(),
    );
    input.extend_from_slice(launcher);
    if let Some(body) = body {
        input.extend_from_slice(body);
    }
    if let Some(sidecar) = sidecar {
        input.extend_from_slice(sidecar);
    }
    input
}

pub fn receiver_command() -> String {
    format!("sh -c {}", shell_quote_str(RECEIVER_SCRIPT))
}

pub fn parse_receiver_stdout(
    stdout: &[u8],
    body_expected: bool,
    sidecar_expected: bool,
) -> Result<StagedLauncher, StagingFailure> {
    let launcher = String::from_utf8_lossy(stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    validate_launcher_path(&launcher)?;
    let body = body_expected.then(|| format!("{launcher}{SCRIPT_BODY_SUFFIX}"));
    if let Some(body) = &body {
        validate_artifact_path(body, SCRIPT_BODY_SUFFIX)?;
    }
    let sidecar = sidecar_expected.then(|| format!("{launcher}{SUDO_FRAME_SUFFIX}"));
    if let Some(sidecar) = &sidecar {
        validate_artifact_path(sidecar, SUDO_FRAME_SUFFIX)?;
    }
    Ok(StagedLauncher {
        launcher,
        body,
        sidecar,
    })
}

pub fn classify_receiver_status(
    status: Option<i32>,
    stdout: &[u8],
    body_expected: bool,
    sidecar_expected: bool,
) -> Result<StagedLauncher, StagingFailure> {
    match status {
        Some(0) => parse_receiver_stdout(stdout, body_expected, sidecar_expected),
        Some(_) => Err(StagingFailure::new(
            FailureClass::TransferPathSafety,
            "remote exec launcher staging receiver failed",
        )
        .residue()),
        None => Err(StagingFailure::new(
            FailureClass::Protocol,
            "remote exec launcher staging ended without a numeric status",
        )
        .residue()),
    }
}

pub fn make_launcher_executable_command(launcher: &str) -> Result<String, StagingFailure> {
    validate_launcher_path(launcher)?;
    let launcher = shell_quote_str(launcher);
    Ok(format!(
        "uid=$(id -u); path={launcher}; [ ! -L \"$path\" ] && [ -f \"$path\" ] && [ \"$(stat -c '%u' \"$path\")\" = \"$uid\" ] && chmod 00700 -- \"$path\" && [ \"$(stat -c '%a' \"$path\")\" = 700 ]"
    ))
}

pub fn make_script_body_executable_command(body: &str) -> Result<String, StagingFailure> {
    validate_artifact_path(body, SCRIPT_BODY_SUFFIX)?;
    let body = shell_quote_str(body);
    Ok(format!(
        "uid=$(id -u); path={body}; [ ! -L \"$path\" ] && [ -f \"$path\" ] && [ \"$(stat -c '%u' \"$path\")\" = \"$uid\" ] && chmod 00700 -- \"$path\" && [ \"$(stat -c '%a' \"$path\")\" = 700 ]"
    ))
}

pub fn cleanup_command(launcher: &str) -> Result<String, StagingFailure> {
    let parent = staging_parent(launcher)?;
    Ok(format!(
        "rm -f -- {} {} {}; rmdir -- {}",
        shell_quote_str(launcher),
        shell_quote_str(&format!("{launcher}{SCRIPT_BODY_SUFFIX}")),
        shell_quote_str(&format!("{launcher}{SUDO_FRAME_SUFFIX}")),
        shell_quote_str(parent)
    ))
}

pub fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| shell_quote_str(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn staging_parent(launcher: &str) -> Result<&str, StagingFailure> {
    validate_launcher_path(launcher)?;
    launcher
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .ok_or_else(|| {
            StagingFailure::new(
                FailureClass::TransferPathSafety,
                "remote exec staging path is unsafe",
            )
        })
}

fn validate_launcher_path(launcher: &str) -> Result<(), StagingFailure> {
    let components = launcher.split('/').collect::<Vec<_>>();
    let tail_start = components.len().saturating_sub(5);
    let valid = launcher.starts_with('/')
        && !launcher.contains('\0')
        && components.len() >= 7
        && components
            .iter()
            .skip(1)
            .all(|component| !component.is_empty())
        && components.iter().all(|component| *component != "..")
        && matches!(
            &components[tail_start..],
            [".broil", "tmp", "exec", action, "launcher"]
                if action.starts_with("exec.") && action.len() > "exec.".len()
        );
    if valid {
        Ok(())
    } else {
        Err(StagingFailure::new(
            FailureClass::TransferPathSafety,
            "remote exec staging path is unsafe",
        ))
    }
}

fn validate_artifact_path(path: &str, suffix: &str) -> Result<(), StagingFailure> {
    let Some(launcher) = path.strip_suffix(suffix) else {
        return Err(StagingFailure::new(
            FailureClass::TransferPathSafety,
            "remote exec staging path is unsafe",
        ));
    };
    validate_launcher_path(launcher)
}

fn shell_quote_str(value: &str) -> String {
    String::from_utf8(shell_quote_bytes(value.as_bytes())).expect("quoted UTF-8 input stays UTF-8")
}

fn push_shell_quoted_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&shell_quote_bytes(value));
}

fn shell_quote_bytes(value: &[u8]) -> Vec<u8> {
    if value.is_empty() {
        return b"''".to_vec();
    }
    if value
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return value.to_vec();
    }
    let mut quoted = Vec::with_capacity(value.len() + 2);
    quoted.push(b'\'');
    for byte in value {
        if *byte == b'\'' {
            quoted.extend_from_slice(b"'\\''");
        } else {
            quoted.push(*byte);
        }
    }
    quoted.push(b'\'');
    quoted
}

