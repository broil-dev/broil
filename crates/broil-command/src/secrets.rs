// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use broil_core::{model::BroilConfig, secret::environment::CredentialInputs};
use broil_secrets::read::{self, Selection};
pub use broil_secrets::{
    output::{ExportFormat, public_name},
    read::Options,
};
use std::{
    ffi::{OsStr, OsString},
    io::Write,
    path::Path,
    process::Command,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verb {
    Login,
    Get,
    List,
    Set,
    Edit,
    Export,
    Check,
    Sync,
    Init,
    Rekey,
    UserAdd,
    UserRemove,
    UserRotate,
    UserList,
    UserRename,
    VaultStatus,
    VaultUnseal,
    VaultReconcile,
    VaultExec,
    RotateNew,
    RotateResume,
    RotateStatus,
    RotateRollback,
    RotateCleanup,
    RotateClearPrevious,
}
impl Verb {
    pub const ALL: [Self; 25] = [
        Self::Login,
        Self::Get,
        Self::List,
        Self::Set,
        Self::Edit,
        Self::Export,
        Self::Check,
        Self::Sync,
        Self::Init,
        Self::Rekey,
        Self::UserAdd,
        Self::UserRemove,
        Self::UserRotate,
        Self::UserList,
        Self::UserRename,
        Self::VaultStatus,
        Self::VaultUnseal,
        Self::VaultReconcile,
        Self::VaultExec,
        Self::RotateNew,
        Self::RotateResume,
        Self::RotateStatus,
        Self::RotateRollback,
        Self::RotateCleanup,
        Self::RotateClearPrevious,
    ];
    pub fn named(path: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|verb| verb.name() == path)
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Get => "get",
            Self::List => "list",
            Self::Set => "set",
            Self::Edit => "edit",
            Self::Export => "export",
            Self::Check => "check",
            Self::Sync => "sync",
            Self::Init => "init",
            Self::Rekey => "rekey",
            Self::UserAdd => "user add",
            Self::UserRemove => "user remove",
            Self::UserRotate => "user rotate",
            Self::UserList => "user list",
            Self::UserRename => "user rename",
            Self::VaultStatus => "vault status",
            Self::VaultUnseal => "vault unseal",
            Self::VaultReconcile => "vault reconcile",
            Self::VaultExec => "vault exec",
            Self::RotateNew => "rotate new",
            Self::RotateResume => "rotate resume",
            Self::RotateStatus => "rotate status",
            Self::RotateRollback => "rotate rollback",
            Self::RotateCleanup => "rotate cleanup",
            Self::RotateClearPrevious => "rotate clear-previous",
        }
    }
    pub fn writes_store(self) -> bool {
        matches!(
            self,
            Self::Set
                | Self::Edit
                | Self::Init
                | Self::Rekey
                | Self::UserAdd
                | Self::UserRemove
                | Self::UserRotate
                | Self::UserRename
                | Self::RotateNew
                | Self::RotateResume
                | Self::RotateRollback
                | Self::RotateCleanup
                | Self::RotateClearPrevious
        )
    }
}

pub struct Invocation<'a> {
    pub config: &'a BroilConfig,
    pub root: &'a Path,
    pub cwd: &'a Path,
    pub environment: Option<&'a OsStr>,
    pub env_snapshot: &'a [(OsString, OsString)],
    pub explicit_file: bool,
}
pub fn run(
    verb: Verb,
    options: &Options,
    context: Invocation<'_>,
    inputs: CredentialInputs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let selected = match Selection::new(context.config, context.root, context.environment) {
        Ok(selected) => selected,
        Err(error) => return failure(verb, stderr, &error.to_string(), 1),
    };
    if matches!(
        verb,
        Verb::Login | Verb::Sync | Verb::VaultStatus | Verb::VaultUnseal | Verb::VaultExec
    ) {
        return crate::vault::run(verb, options, context, &selected, inputs, stdout, stderr);
    }
    if matches!(
        verb,
        Verb::RotateNew
            | Verb::RotateResume
            | Verb::RotateStatus
            | Verb::RotateRollback
            | Verb::RotateCleanup
            | Verb::RotateClearPrevious
    ) {
        return crate::rotation::run(verb, options, context, &selected, inputs, stdout, stderr);
    }
    let writing = match verb {
        Verb::Set => Some(broil_secrets::write::Kind::Set),
        Verb::Edit => Some(broil_secrets::write::Kind::Edit),
        Verb::Init => Some(broil_secrets::write::Kind::Init),
        Verb::Rekey => Some(broil_secrets::write::Kind::Rekey),
        _ => None,
    };
    if let Some(kind) = writing {
        let editor = if verb == Verb::Edit {
            match editor_command(context.env_snapshot) {
                Ok(editor) => Some(editor),
                Err(error) => return failure(verb, stderr, &error.to_string(), 1),
            }
        } else {
            None
        };
        let mut interaction = LocalInteraction {
            cwd: context.cwd,
            env: context.env_snapshot,
            editor,
        };
        let report = broil_secrets::write::run(
            kind,
            &selected,
            options,
            context.cwd,
            inputs,
            &mut interaction,
        );
        return write_report(verb, options.quiet, &report, stderr);
    }
    if matches!(verb, Verb::UserRotate | Verb::VaultReconcile) {
        let mut interaction = LocalInteraction {
            cwd: context.cwd,
            env: context.env_snapshot,
            editor: None,
        };
        let report = if verb == Verb::VaultReconcile {
            broil_secrets::users::reconcile(
                &selected,
                options,
                context.cwd,
                inputs,
                &mut interaction,
                stderr,
            )
        } else {
            broil_secrets::users::rotate(&selected, options, context.cwd, inputs, &mut interaction)
        };
        let status = write_report(verb, options.quiet, &report, stderr);
        if status == 0
            && verb == Verb::VaultReconcile
            && stdout
                .write_all(b"ok\n")
                .and_then(|()| stdout.flush())
                .is_err()
        {
            return failure(verb, stderr, "output I/O", 1);
        }
        return status;
    }
    if matches!(verb, Verb::UserAdd | Verb::UserRemove | Verb::UserRename) {
        let kind = match verb {
            Verb::UserAdd => broil_secrets::users::Kind::Add,
            Verb::UserRemove => broil_secrets::users::Kind::Remove,
            _ => broil_secrets::users::Kind::Rename,
        };
        let mut interaction = LocalInteraction {
            cwd: context.cwd,
            env: context.env_snapshot,
            editor: None,
        };
        let report = broil_secrets::users::run(
            kind,
            &selected,
            options,
            context.cwd,
            inputs,
            &mut interaction,
        );
        return write_report(verb, options.quiet, &report, stderr);
    }
    if verb == Verb::UserList {
        return match broil_secrets::users::list(&selected, options, context.cwd, inputs) {
            Ok(result)
                if stdout
                    .write_all(result.as_bytes())
                    .and_then(|()| stdout.flush())
                    .is_ok() =>
            {
                0
            }
            Ok(_) => failure(verb, stderr, "output I/O", 1),
            Err(error) => failure(verb, stderr, &error.to_string(), 1),
        };
    }
    let kind = match verb {
        Verb::Get => read::ReadKind::Get,
        Verb::List => read::ReadKind::List,
        Verb::Export => read::ReadKind::Export,
        Verb::Check => read::ReadKind::Check,
        _ => return failure(verb, stderr, "operation unavailable", 1),
    };
    let result = match read::run(kind, &selected, options, context.cwd, inputs) {
        Ok(result) => result,
        Err(error) => return failure(verb, stderr, &error.to_string(), 1),
    };
    if stdout
        .write_all(result.as_bytes())
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return failure(verb, stderr, "output I/O", 1);
    }
    0
}

fn editor_command(env: &[(OsString, OsString)]) -> read::Result<Vec<String>> {
    let command = ["VISUAL", "EDITOR"]
        .into_iter()
        .find_map(|name| {
            env.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value)
                .filter(|value| !value.is_empty())
        })
        .ok_or(read::Error::class("editor unavailable"))?;
    let command = command
        .to_str()
        .filter(|s| !s.contains('\0'))
        .ok_or(read::Error::class("invalid editor command"))?;
    let tokens = broil_core::tokens::tokenize_alias_command(command)
        .map_err(|_| read::Error::class("invalid editor command"))?;
    if tokens.first().is_none_or(|s| s.is_empty()) {
        return Err(read::Error::class("invalid editor command"));
    }
    Ok(tokens)
}

struct LocalInteraction<'a> {
    cwd: &'a Path,
    env: &'a [(OsString, OsString)],
    editor: Option<Vec<String>>,
}
impl broil_secrets::write::Interaction for LocalInteraction<'_> {
    fn prompt(
        &mut self,
        label: &str,
        hidden: bool,
        limit: usize,
    ) -> read::Result<broil_core::secret::OwnedSecret> {
        broil_core::secret::prompt_private_bounded(label, hidden, limit)
            .map_err(|_| read::Error::class("terminal input cancelled or unavailable"))
    }
    fn editor(&mut self, path: &Path) -> read::Result<()> {
        let args = self
            .editor
            .as_ref()
            .ok_or(read::Error::class("editor unavailable"))?;
        let mut child = Command::new(&args[0])
            .args(&args[1..])
            .arg(path)
            .current_dir(self.cwd)
            .env_clear()
            .envs(
                self.env
                    .iter()
                    .filter(|(name, _)| !broil_core::secret::environment::is_credential_input(name))
                    .map(|(name, value)| (name, value)),
            )
            .spawn()
            .map_err(|_| read::Error::class("editor spawn"))?;
        let status = child
            .wait()
            .map_err(|_| read::Error::class("editor wait"))?;
        if !status.success() {
            return Err(read::Error::class("editor exit"));
        }
        Ok(())
    }
    fn runtime_dir(&self) -> Option<&Path> {
        self.env
            .iter()
            .find(|(key, _)| key == "XDG_RUNTIME_DIR")
            .map(|(_, value)| Path::new(value))
            .filter(|p| !p.as_os_str().is_empty())
    }
}

pub fn write_report(
    verb: Verb,
    quiet: bool,
    report: &broil_secrets::write::Report,
    stderr: &mut dyn Write,
) -> i32 {
    let mut io_failed = false;
    for detail in &report.details {
        io_failed |= writeln!(stderr, "broil: {detail}").is_err();
    }
    for path in &report.changed {
        io_failed |= writeln!(stderr, "{}", public_name(path)).is_err();
    }
    for path in &report.uncertain {
        io_failed |= writeln!(stderr, "{} (may have changed)", public_name(path)).is_err();
    }
    if (!report.changed.is_empty() || !report.uncertain.is_empty()) && !quiet {
        io_failed |= writeln!(
            stderr,
            "Commit and distribute the changed secret-store files."
        )
        .is_err();
    }
    if let Some(path) = &report.failed_path {
        io_failed |= writeln!(stderr, "broil: failed path: {}", public_name(path)).is_err();
    }
    if report.cleanup_failed {
        io_failed |= writeln!(stderr, "broil: temporary storage cleanup failed").is_err();
    }
    if report.error.is_some() && (!report.changed.is_empty() || !report.uncertain.is_empty()) {
        io_failed |= writeln!(stderr, "broil: Inspect the reported paths and durability disposition; correct the failure before retrying {}.", verb.name()).is_err();
    }
    if verb == Verb::Init && report.error.is_none() {
        io_failed |= writeln!(stderr, "Add a set with broil secrets set <key> --set <set>; distribute the encrypted store to its users.").is_err();
    }
    io_failed |= stderr.flush().is_err();
    if let Some(error) = &report.error {
        return failure(verb, stderr, &error.to_string(), 1);
    }
    if io_failed {
        return failure(verb, stderr, "output I/O", 1);
    }
    0
}
pub fn failure(verb: Verb, stderr: &mut dyn Write, class: &str, status: i32) -> i32 {
    let _ = writeln!(stderr, "broil: secrets {}: {class}", verb.name());
    if verb == Verb::Login {
        let _ = writeln!(stderr, "failure class: runtime");
    }
    status
}

pub fn help(path: &str) -> &'static [u8] {
    match path {
        "" => b"Usage: broil secrets <command> [args...]\n\nManage encrypted secrets and optional vault access.\n\nCommands:\n  check    Validate sets and declared exports\n  edit     Edit one encrypted set\n  export   Print declared secret exports\n  get      Read one user key\n  init     Initialize an encrypted store\n  list     List user keys\n  login    Print a vault login token\n  rekey    Update encrypted recipients\n  rotate   Rotate a secret with recovery\n  set      Set a secret through hidden input\n  sync     Push local sets to the vault\n  user     Manage users and teams\n  vault    Manage optional vault access\n",
        "user" => b"Usage: broil secrets user <command> [args...]\n\nManage secret-store users and teams.\n\nCommands:\n  add      Add a user or team membership\n  list     List users and memberships\n  remove   Remove a user and access\n  rename   Rename a user\n  rotate   Rotate a user identity and credentials\n",
        "vault" => b"Usage: broil secrets vault <command> [args...]\n\nManage optional vault access.\n\nCommands:\n  exec        Run a client with a scoped token\n  reconcile   Reconcile policies and AppRoles\n  status      Inspect vault status\n  unseal      Unseal the configured vault\n",
        "rotate" => b"Usage: broil secrets rotate <command> [args...]\n\nRotate a secret with verified recovery.\n\nCommands:\n  cleanup          Remove local rotation data with a warning\n  clear-previous   Remove a retained previous slot\n  new              Start a verified rotation\n  resume           Resume an interrupted rotation\n  rollback         Roll back within supported state bounds\n  status           Inspect unverified rotation metadata\n",
        "login" => b"Usage: broil secrets login [--non-interactive]\n\nPrint a vault login token.\n",
        "get" => b"Usage: broil secrets get <key> [--set <set>] [--plain|--json] [--local] [--non-interactive]\n\nRead one secret user key.\n",
        "list" => b"Usage: broil secrets list [--set <set>] [--slots] [--local] [--non-interactive]\n\nList user keys without values.\n",
        "set" => b"Usage: broil secrets set <key> [--set <set>] [--non-interactive] [--quiet]\n\nSet a secret through hidden input; without --set, visit project sets with prod last.\n",
        "edit" => b"Usage: broil secrets edit [--set <set>] [--non-interactive] [--quiet]\n\nEdit one set in a private tmpfs directory.\n",
        "export" => b"Usage: broil secrets export [--set <set>] [--format sh|env|json] [--local] [--non-interactive]\n\nPrint all declared exports after validating their values.\n",
        "check" => b"Usage: broil secrets check [--set <set>|--all] [--local] [--non-interactive]\n\nValidate selected sets and declared exports.\n",
        "sync" => b"Usage: broil secrets sync [--set <set>|--all] [--non-interactive]\n\nPush local user data to the vault, excluding rotation data.\n",
        "init" => b"Usage: broil secrets init [--identity <name>] [--non-interactive] [--quiet]\n\nInitialize an encrypted store and first identity.\n",
        "rekey" => b"Usage: broil secrets rekey [--set <set>|--all] [--non-interactive] [--quiet]\n\nUpdate encrypted recipients from creation rules.\n",
        "user add" => b"Usage: broil secrets user add <name> --team <team> [--machine] [--non-interactive] [--quiet]\n\nAdd a user or team membership.\n",
        "user remove" => b"Usage: broil secrets user remove <name> [--yes] [--non-interactive] [--quiet]\n\nRemove a user and revoke managed access.\n",
        "user rotate" => b"Usage: broil secrets user rotate <name> [--machine] [--non-interactive] [--quiet]\n\nRotate identity and credentials after verifying replacement access.\n",
        "user list" => b"Usage: broil secrets user list [--non-interactive]\n\nList users and memberships.\n",
        "user rename" => b"Usage: broil secrets user rename <old> <new> [--non-interactive] [--quiet]\n\nRename a user after verifying replacement access.\n",
        "vault status" => b"Usage: broil secrets vault status [--non-interactive]\n\nInspect non-secret vault status.\n",
        "vault unseal" => b"Usage: broil secrets vault unseal [--non-interactive]\n\nUnseal the configured vault.\n",
        "vault reconcile" => b"Usage: broil secrets vault reconcile [--yes] [--non-interactive]\n\nShow drift and reconcile policies without rotating credential IDs.\n",
        "vault exec" => b"Usage: broil secrets vault exec [--non-interactive] -- <argv...>\n\nRun a client with a child-only vault token.\n",
        "rotate new" => b"Usage: broil secrets rotate new <key> --generator <generator> [--type <type>] [--set <set>] [--keep-previous] [--non-interactive] [--quiet]\n\nStart a verified rotation.\n",
        "rotate resume" => b"Usage: broil secrets rotate resume <key> [--set <set>] [--force] [--non-interactive] [--quiet]\n\nResume an interrupted rotation from its authenticated marker.\n",
        "rotate status" => b"Usage: broil secrets rotate status [<key>] [--set <set>|--all] [--non-interactive]\n\nInspect rotation metadata without decryption or MAC verification.\n",
        "rotate rollback" => b"Usage: broil secrets rotate rollback <key> [--set <set>] [--force] [--non-interactive] [--quiet]\n\nRoll back within the handler-supported state bounds.\n",
        "rotate cleanup" => b"Usage: broil secrets rotate cleanup <key> [--set <set>] --force [--non-interactive] [--quiet]\n\nRemove rotation slots and marker without revoking external credentials.\n",
        "rotate clear-previous" => b"Usage: broil secrets rotate clear-previous <key> [--set <set>] [--non-interactive] [--quiet]\n\nRemove a retained previous slot when no rotation is active.\n",
        _ => unreachable!("recognized secrets help path"),
    }
}
