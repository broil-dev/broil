// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Topic {
    General,
    Secrets(&'static str),
    Image(&'static str),
    K3s(&'static str),
    Run,
    Env,
    Get,
    Remote,
    RemoteList,
    RemoteTrust,
    RemoteCheck,
    RemoteStats,
    RemoteSsh,
    RemoteExec,
    RemoteRun,
    RemoteCopyTo,
    RemoteCopyFrom,
    RemoteProvision,
    Help,
    Version,
}

impl Topic {
    pub fn named(name: &str) -> Option<Self> {
        match name {
            "run" => Some(Self::Run),
            "env" => Some(Self::Env),
            "get" => Some(Self::Get),
            "remote" => Some(Self::Remote),
            "secrets" => Some(Self::Secrets("")),
            "image" => Some(Self::Image("")),
            "k3s" => Some(Self::K3s("")),
            "help" => Some(Self::Help),
            "version" => Some(Self::Version),
            _ => None,
        }
    }

    pub fn remote_named(name: &str) -> Option<Self> {
        match name {
            "list" => Some(Self::RemoteList),
            "trust" => Some(Self::RemoteTrust),
            "check" => Some(Self::RemoteCheck),
            "stats" => Some(Self::RemoteStats),
            "ssh" => Some(Self::RemoteSsh),
            "exec" => Some(Self::RemoteExec),
            "run" => Some(Self::RemoteRun),
            "copy-to" => Some(Self::RemoteCopyTo),
            "copy-from" => Some(Self::RemoteCopyFrom),
            "provision" => Some(Self::RemoteProvision),
            _ => None,
        }
    }
}

pub fn render(topic: Topic) -> &'static [u8] {
    match topic {
        Topic::Secrets(path) => crate::secrets::help(path),
        Topic::Image(path) => crate::images::commands::help(path),
        Topic::K3s(path) => crate::k3s::commands::help(path),
        Topic::General => b"Usage: broil [--file <path>] [command] [args...]\n\nCommands:\n  env <name> [command...]   Enter an environment or run a command\n  get <selector>            Inspect resolved project state\n  help [command]            Show help for Broil or a built-in command\n  image <command>           Build, publish and inspect project images\n  k3s <command>             Manage K3s infrastructure and its registry\n  remote <command>          Manage remote machines\n  run <script> [args...]    Run a configured script\n  secrets <command>         Manage encrypted secrets and optional vault access\n  version                   Show the Broil version\n\nOptions:\n  --file <path>             Use a specific Broil config file\n  --help                    Show help\n  --version                 Show the Broil version\n",
        Topic::Run => {
            b"Usage: broil run <script> [args...]\n\nRun a configured script.\n"
        }
        Topic::Env => b"Usage: broil env <name> [command...]\n\nEnter an environment or run one command inside it.\n",
        Topic::Get => b"Usage:\n  broil get [--plain|--json] root\n  broil get [--plain|--json] name\n  broil get [--plain|--json] cfg <dot.path>\n\nInspect resolved Broil project state.\n",
        Topic::Remote => b"Usage: broil remote <command> [args...]\n\nManage remote machines.\n\nCommands:\n  check       Check operational and security readiness\n  copy-from   Copy files or directories from machines\n  copy-to     Copy files or directories to machines\n  exec        Execute a remote command\n  list        Inspect the effective inventory\n  provision   Provision machines\n  run         Run a configured remote script\n  ssh         Open an interactive SSH session\n  stats       Report machine resource state\n  trust       Enroll or replace host-key trust\n",
        Topic::RemoteList => b"Usage: broil remote list [selectors] [--plan] [--format table|json]\n\nInspect the active environment's effective remote inventory.\n",
        Topic::RemoteTrust => b"Usage: broil remote trust (<selectors>|--jump <name>) [--known-hosts <path>] [--fingerprint <sha256>] [--replace] [--report <path>]\n\nEnroll or replace host-key trust for declared machines and jump hosts.\n",
        Topic::RemoteCheck => b"Usage: broil remote check <selectors> [--sudo] [--format table|json] [--jobs <number|all>] [--fail-fast] [--known-hosts <path>] [--report <path>]\n\nCheck remote operational and security readiness.\n",
        Topic::RemoteStats => b"Usage: broil remote stats <selectors> [--format table|json] [--jobs <number|all>] [--fail-fast] [--known-hosts <path>] [--report <path>]\n\nReport remote machine resource state.\n",
        Topic::RemoteSsh => b"Usage: broil remote ssh <selector> [--bootstrap] [--pty|--no-pty] [--known-hosts <path>]\n\nOpen an interactive SSH session to one declared machine.\n",
        Topic::RemoteExec => b"Usage: broil remote exec <selectors> [--pty|--no-pty] [--privilege <profile>] [--jobs <number|all>] [--fail-fast] [--known-hosts <path>] [--report <path>] [--shell] -- <command...>\n\nExecute a command on selected machines.\n",
        Topic::RemoteRun => b"Usage: broil remote run <selectors> [--pty|--no-pty] [--jobs <number|all>] [--fail-fast] [--known-hosts <path>] [--report <path>] -- <script> [args...]\n\nRun a configured remote script on selected machines.\n",
        Topic::RemoteCopyTo => b"Usage: broil remote copy-to <selectors> [--recursive] [--overwrite] [--mode <octal>] [--owner <owner>] [--privilege <profile>] [--jobs <number|all>] [--fail-fast] [--known-hosts <path>] [--report <path>] -- <source> <destination>\n\nCopy a file or directory to selected machines.\n",
        Topic::RemoteCopyFrom => b"Usage: broil remote copy-from <selectors> [--recursive] [--overwrite] [--mode <octal>] [--jobs <number|all>] [--fail-fast] [--known-hosts <path>] [--report <path>] -- <source> <destination>\n\nCopy a file or directory from selected machines.\n",
        Topic::RemoteProvision => b"Usage: broil remote provision <selectors> [--jobs <number|all>] [--fail-fast] [--known-hosts <path>] [--report <path>]\n\nProvision selected machines through their resolved profiles.\n",
        Topic::Help => {
            b"Usage: broil help [command]\n\nShow help for Broil or a built-in command.\n"
        }
        Topic::Version => b"Usage: broil version\n\nShow the Broil version.\n",
    }
}
