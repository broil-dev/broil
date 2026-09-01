// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use broil_core::error::ExecutionError;
use broil_core::model::BroilConfig;

use tempfile::{NamedTempFile, TempDir};

use crate::execenv;

pub fn execute_one_shot(
    broil_root: &Path,
    config: &BroilConfig,
    name: &OsStr,
    cwd: &Path,
    command_tokens: &[OsString],
    base_env: &[(OsString, OsString)],
) -> Result<i32, ExecutionError> {
    let resolved = execenv::resolve(config, Some(name))?;
    let env = execenv::child_env(base_env, &resolved, broil_root);
    let mut child = Command::new("bash")
        .arg("-c")
        .arg(one_shot_command(command_tokens.len()))
        .args(command_tokens)
        .current_dir(cwd)
        .env_clear()
        .envs(&env)
        .spawn()
        .map_err(|error| spawn_error("run", error))?;
    let status = child
        .wait()
        .map_err(|error| spawn_error("wait for", error))?;
    execenv::status_code(status)
}

pub fn execute_interactive(
    broil_root: &Path,
    config: &BroilConfig,
    name: &OsStr,
    cwd: &Path,
    tmp_parent: &Path,
    base_env: &[(OsString, OsString)],
) -> Result<i32, ExecutionError> {
    let resolved = execenv::resolve(config, Some(name))?;
    let env = execenv::child_env(base_env, &resolved, broil_root);
    let env_name = resolved.env_name.as_deref().unwrap_or_default();
    let contents = rcfile_contents(&resolved.env_vars, broil_root, env_name);
    let rcfile = create_rcfile(tmp_parent, &contents)?;
    let mut child = Command::new("bash")
        .arg("--rcfile")
        .arg(rcfile.path())
        .current_dir(cwd)
        .env_clear()
        .envs(&env)
        .spawn()
        .map_err(|error| spawn_error("run", error))?;
    let status = child
        .wait()
        .map_err(|error| spawn_error("wait for", error))?;
    let code = execenv::status_code(status);
    drop(rcfile);
    code
}

pub fn one_shot_command(token_count: usize) -> String {
    let references: Vec<String> = (0..token_count).map(|i| format!("\"${{{i}}}\"")).collect();
    references.join(" ")
}

pub fn prompt_names(project: &OsStr, env_name: &str) -> Vec<u8> {
    let mut names = Vec::new();
    names.push(b'[');
    names.extend_from_slice(project.as_bytes());
    names.push(b' ');
    names.extend_from_slice(env_name.as_bytes());
    names.push(b']');
    names
}

pub fn shell_quote_single(bytes: &[u8]) -> Vec<u8> {
    let mut quoted = Vec::with_capacity(bytes.len() + 2);
    quoted.push(b'\'');
    for byte in bytes {
        if *byte == b'\'' {
            quoted.extend_from_slice(b"'\\''");
        } else {
            quoted.push(*byte);
        }
    }
    quoted.push(b'\'');
    quoted
}

const OPEN: &str = r"\[\033[1m\]\[\033[30m\]\[\033[103m\]";
const CLOSE: &str = r"\[\033[0m\]";

const GUARDS: &str = "if [ -f /etc/bashrc ]; then\n  source /etc/bashrc\nfi\nif [ -f ~/.bashrc ]; then\n  source ~/.bashrc\nfi\n";

const CAPTURE_RESET_RESTORE: &str = "BROIL_LAST_STATUS=$?; [[ -n ${BROIL_PS1_BASE+x} ]] && PS1=\"$BROIL_PS1_BASE\"; (exit \"$BROIL_LAST_STATUS\")";

fn prepend_and_restore() -> String {
    format!(
        "if [[ -n ${{BROIL_PS1_BASE+x}} ]]; then if shopt -q promptvars; then PS1='{OPEN}${{BROIL_PROMPT_NAMES}}{CLOSE} '\"$PS1\"; else PS1=\"{OPEN}${{BROIL_PROMPT_NAMES//\\\\/\\\\\\\\}}{CLOSE} $PS1\"; fi; fi; (exit \"$BROIL_LAST_STATUS\")"
    )
}

fn sq_escape(text: &str) -> String {
    text.replace('\'', "'\\''")
}

fn dq_escape(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if matches!(ch, '$' | '"' | '\\' | '`') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

pub fn rcfile_contents(
    configured: &BTreeMap<String, String>,
    broil_root: &Path,
    env_name: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(GUARDS.as_bytes());
    for (name, value) in configured {
        push_export(&mut out, name.as_bytes(), value.as_bytes());
    }
    push_export(&mut out, b"BROIL_ROOT", broil_root.as_os_str().as_bytes());
    push_export(&mut out, b"BROIL_ENV", env_name.as_bytes());

    let project = broil_root.file_name().unwrap_or(OsStr::new("/"));
    let names = prompt_names(project, env_name);

    out.extend_from_slice(
        b"export -n BROIL_PROMPT_NAMES BROIL_PS1_BASE BROIL_LAST_STATUS 2>/dev/null\n",
    );
    out.extend_from_slice(b"BROIL_PROMPT_NAMES=");
    out.extend_from_slice(&shell_quote_single(&names));
    out.push(b'\n');
    out.extend_from_slice(
        format!("PS1=\"${{PS1//\"{OPEN}\\${{BROIL_PROMPT_NAMES}}{CLOSE} \"/}}\"\n").as_bytes(),
    );
    out.extend_from_slice(format!("PS1=\"${{PS1#\"{OPEN}\"*\"{CLOSE} \"}}\"\n").as_bytes());
    out.extend_from_slice(b"BROIL_PS1_BASE=\"$PS1\"\n");
    out.extend_from_slice(
        format!(
            "PROMPT_COMMAND=\"${{PROMPT_COMMAND//\"{}\n\"/}}\"\n",
            dq_escape(CAPTURE_RESET_RESTORE)
        )
        .as_bytes(),
    );
    out.extend_from_slice(
        format!(
            "PROMPT_COMMAND=\"${{PROMPT_COMMAND//\"\n:\n{}\"/}}\"\n",
            dq_escape(&prepend_and_restore())
        )
        .as_bytes(),
    );
    out.extend_from_slice(
        b"if (( BASH_VERSINFO[0] > 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] >= 1) )) && [[ \"$(declare -p PROMPT_COMMAND 2>/dev/null)\" == declare\\ -a* ]]; then\n",
    );
    out.extend_from_slice(
        format!(
            "  PROMPT_COMMAND=('{CAPTURE_RESET_RESTORE}' \"${{PROMPT_COMMAND[@]}}\" '{}')\n",
            sq_escape(&prepend_and_restore())
        )
        .as_bytes(),
    );
    out.extend_from_slice(b"else\n");
    out.extend_from_slice(
        format!(
            "  PROMPT_COMMAND='{CAPTURE_RESET_RESTORE}\n'\"${{PROMPT_COMMAND:-:}}\"'\n:\n{}'\n",
            sq_escape(&prepend_and_restore())
        )
        .as_bytes(),
    );
    out.extend_from_slice(b"fi\n");
    out
}

fn push_export(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.extend_from_slice(b"export ");
    out.extend_from_slice(name);
    out.push(b'=');
    out.extend_from_slice(&shell_quote_single(value));
    out.push(b'\n');
}

#[derive(Debug)]
pub struct Rcfile {
    _dir: TempDir,
    _file: NamedTempFile,
    path: PathBuf,
}

impl Rcfile {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn create_rcfile(tmp_parent: &Path, contents: &[u8]) -> Result<Rcfile, ExecutionError> {
    let dir = tempfile::Builder::new()
        .prefix("broil-env-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(tmp_parent)
        .map_err(|error| rcfile_error("create rcfile directory", error))?;
    let mut file = tempfile::Builder::new()
        .prefix("bashrc-")
        .tempfile_in(dir.path())
        .map_err(|error| rcfile_error("create rcfile", error))?;
    file.as_file_mut()
        .write_all(contents)
        .and_then(|()| file.as_file_mut().flush())
        .map_err(|error| rcfile_error("write rcfile", error))?;
    let path = file.path().to_path_buf();
    Ok(Rcfile {
        _dir: dir,
        _file: file,
        path,
    })
}

fn rcfile_error(action: &str, error: io::Error) -> ExecutionError {
    ExecutionError::Rcfile {
        message: format!("cannot {action}: {error}"),
    }
}

fn spawn_error(action: &str, error: io::Error) -> ExecutionError {
    ExecutionError::Spawn {
        message: format!("cannot {action} bash: {error}"),
    }
}
