// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::path::PathBuf;

use crate::tokens::TokenizeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    Usage,
    Runtime,
}

impl ErrorClass {
    pub fn exit_code(self) -> i32 {
        match self {
            ErrorClass::Usage => 2,
            ErrorClass::Runtime => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    NoConfigFound { start_dir: PathBuf },
    BothDefaultsPresent { dir: PathBuf },
    DefaultNotReadableRegularFile { path: PathBuf },
    ExplicitFileMissing { path: PathBuf },
    ExplicitFileUnreadable { path: PathBuf },
    ExplicitFileNotRegular { path: PathBuf },
    YamlParse { path: PathBuf, message: String },
    NonMappingRoot { path: PathBuf },
    FragmentEmptyPathSegment { filename: String },
    FragmentFilenameNotUtf8 { filename_lossy: String },
    FragmentTargetAlreadyDefined { key_path: String, filename: String },
    FragmentParentNotMapping { key_path: String, filename: String },
    FragmentDirNotDirectory { path: PathBuf },
    FragmentDirUnreadable { path: PathBuf, message: String },
    FragmentFileUnusable { path: PathBuf, message: String },
    ExtendsNonString { key_path: String },
    ExtendsMissingTarget { key_path: String, target: String },
    ExtendsNonMappingTarget { key_path: String, target: String },
    ExtendsCycle { chain: Vec<String> },
    Schema(SchemaError),
}

impl ConfigError {
    pub fn class(&self) -> ErrorClass {
        ErrorClass::Runtime
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::NoConfigFound { start_dir } => {
                write!(
                    f,
                    "no broil.yaml or broil.yml found from {} up to the filesystem root",
                    start_dir.display()
                )
            }
            ConfigError::BothDefaultsPresent { dir } => {
                write!(
                    f,
                    "both broil.yaml and broil.yml exist in {}",
                    dir.display()
                )
            }
            ConfigError::DefaultNotReadableRegularFile { path } => {
                write!(
                    f,
                    "config file {} exists but is not a readable regular file",
                    path.display()
                )
            }
            ConfigError::ExplicitFileMissing { path } => {
                write!(f, "config file {} does not exist", path.display())
            }
            ConfigError::ExplicitFileUnreadable { path } => {
                write!(f, "config file {} is not readable", path.display())
            }
            ConfigError::ExplicitFileNotRegular { path } => {
                write!(f, "config file {} is not a regular file", path.display())
            }
            ConfigError::YamlParse { path, message } => {
                write!(f, "cannot parse {}: {message}", path.display())
            }
            ConfigError::NonMappingRoot { path } => {
                write!(f, "config root in {} must be a mapping", path.display())
            }
            ConfigError::FragmentEmptyPathSegment { filename } => {
                write!(
                    f,
                    "fragment filename {filename} has an empty target path segment"
                )
            }
            ConfigError::FragmentFilenameNotUtf8 { filename_lossy } => {
                write!(f, "fragment filename {filename_lossy} is not valid UTF-8")
            }
            ConfigError::FragmentTargetAlreadyDefined { key_path, filename } => {
                write!(
                    f,
                    "fragment {filename} targets already-defined config path {key_path}"
                )
            }
            ConfigError::FragmentParentNotMapping { key_path, filename } => {
                write!(
                    f,
                    "fragment {filename} needs parent path {key_path} which exists as a non-mapping value"
                )
            }
            ConfigError::FragmentDirNotDirectory { path } => {
                write!(
                    f,
                    "fragment directory {} exists but is not a usable directory",
                    path.display()
                )
            }
            ConfigError::FragmentDirUnreadable { path, message } => {
                write!(
                    f,
                    "cannot read fragment directory {}: {message}",
                    path.display()
                )
            }
            ConfigError::FragmentFileUnusable { path, message } => {
                write!(
                    f,
                    "cannot use fragment candidate {}: {message}",
                    path.display()
                )
            }
            ConfigError::ExtendsNonString { key_path } => {
                write!(f, "$extends at {key_path} must be a string")
            }
            ConfigError::ExtendsMissingTarget { key_path, target } => {
                write!(f, "$extends at {key_path} references missing path {target}")
            }
            ConfigError::ExtendsNonMappingTarget { key_path, target } => {
                write!(
                    f,
                    "$extends at {key_path} references non-mapping path {target}"
                )
            }
            ConfigError::ExtendsCycle { chain } => {
                write!(f, "$extends cycle: {}", chain.join(" -> "))
            }
            ConfigError::Schema(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    UnknownKey { key_path: String },
    NonStringKey { key_path: String, key_repr: String },
    NonStringValue { key_path: String },
    InvalidEnvVarName { key_path: String, name: String },
    ReservedEnvVarName { key_path: String, name: String },
    EmptyScriptName { key_path: String },
    EmptyEnvironmentName,
    EnvironmentNameWithDot { name: String },
    NonMappingSection { key_path: String },
    EmptyAliasGroup { key_path: String },
    InvalidAliasPathSegment { key_path: String, segment: String },
    AliasTokenization {
        key_path: String,
        error: TokenizeError,
    },
    EmptyAliasTokenList { key_path: String },
    PromptOwnedEnvVarName { key_path: String, name: String },
    MissingRequiredRemoteField { key_path: String },
    InvalidRemoteValue { key_path: String, expected: String },
    UnknownRemoteReference { key_path: String, target: String },
    DuplicateRemoteRoute { first: String, second: String },
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaError::UnknownKey { key_path } => {
                write!(f, "unknown config key {key_path}")
            }
            SchemaError::NonStringKey { key_path, key_repr } => {
                write!(f, "non-string config key {key_repr} under {key_path}")
            }
            SchemaError::NonStringValue { key_path } => {
                write!(f, "value at {key_path} must be a string")
            }
            SchemaError::InvalidEnvVarName { key_path, name } => {
                write!(f, "invalid env var name {name} under {key_path}")
            }
            SchemaError::ReservedEnvVarName { key_path, name } => {
                write!(
                    f,
                    "reserved env var name {name} may not be configured under {key_path}"
                )
            }
            SchemaError::EmptyScriptName { key_path } => {
                write!(f, "empty script name under {key_path}")
            }
            SchemaError::EmptyEnvironmentName => {
                f.write_str("empty environment name under environments")
            }
            SchemaError::EnvironmentNameWithDot { name } => {
                write!(f, "environment name {name} must not contain '.'")
            }
            SchemaError::NonMappingSection { key_path } => {
                write!(f, "section {key_path} must be a mapping or null")
            }
            SchemaError::EmptyAliasGroup { key_path } => {
                write!(f, "alias group {key_path} must not be empty")
            }
            SchemaError::InvalidAliasPathSegment { key_path, segment } => {
                write!(f, "invalid alias path segment {segment} under {key_path}")
            }
            SchemaError::AliasTokenization { key_path, error } => {
                write!(f, "alias command at {key_path} failed to tokenize: {error}")
            }
            SchemaError::EmptyAliasTokenList { key_path } => {
                write!(f, "alias command at {key_path} has no tokens")
            }
            SchemaError::PromptOwnedEnvVarName { key_path, name } => {
                write!(
                    f,
                    "env var name {name} is owned by the interactive-shell prompt mechanism and may not be configured under {key_path}"
                )
            }
            SchemaError::MissingRequiredRemoteField { key_path } => {
                write!(f, "missing required remote config field {key_path}")
            }
            SchemaError::InvalidRemoteValue { key_path, expected } => {
                write!(f, "remote config value at {key_path} must be {expected}")
            }
            SchemaError::UnknownRemoteReference { key_path, target } => {
                write!(
                    f,
                    "remote config reference {target} at {key_path} is not defined"
                )
            }
            SchemaError::DuplicateRemoteRoute { first, second } => {
                write!(
                    f,
                    "remote machines {first} and {second} resolve to the same route"
                )
            }
        }
    }
}

impl std::error::Error for SchemaError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    AbsentCommand,
    UnknownCommand { token: String },
    IncompleteAliasGroup { chain: String },
    UnknownAliasChain { chain: String, token: String },
    IncompleteExecutableGroup { chain: String },
    UnknownExecutableChain { chain: String, token: String },
    ExpandedAliasTargetUnknown { target: String },
    MissingRunScript,
    MissingEnvName,
    UnknownHelpTopic { topic: String },
    UnexpectedOperand { token: String },
    GetMissingSelector,
    GetUnknownSelector { token: String },
    GetUnknownOption { token: String },
    GetRepeatedOutputOption { option: String },
    GetCombinedOutputOptions,
    GetMissingCfgPath,
    GetEmptyDotPathSegment { dot_path: String },
    GetExtraOperands { token: String },
    RemoteMissingCommand,
    RemoteUnknownCommand { token: String },
    RemoteUnknownOption { verb: String, token: String },
    RemoteMissingOptionValue { option: String },
    RemoteInvalidOptionValue { option: String, value: String },
    RemoteRepeatedOption { option: String },
    RemoteUnexpectedOperand { verb: String, token: String },
    RemoteSelectorConflict,
    RemoteJumpSelectorConflict,
    RemoteUnknownJump { name: String },
    RemoteFingerprintCardinality,
    RemoteInvalidFingerprint { value: String },
    RemoteMissingSelector,
    RemoteMissingOperandBoundary { verb: String },
    RemoteMissingExecCommand,
    RemoteMissingRunScript,
    RemoteTransferOperandCardinality { verb: String },
    RemoteShellBodyCardinality,
    RemotePtyConflict,
    RemotePtyCardinality,
    RemoteBootstrapNoPty,
    RemoteSingleTargetRequired { verb: String },
    RemoteUnknownMachine { selector: String },
    RemoteAmbiguousMachine { selector: String },
    RemoteEmptySelection,
}

impl UsageError {
    pub fn class(&self) -> ErrorClass {
        ErrorClass::Usage
    }
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsageError::AbsentCommand => f.write_str("missing command"),
            UsageError::UnknownCommand { token } => {
                write!(f, "unknown command {token}")
            }
            UsageError::IncompleteAliasGroup { chain } => {
                write!(f, "incomplete alias group {chain}")
            }
            UsageError::UnknownAliasChain { chain, token } => {
                write!(f, "alias group {chain} has no child alias {token}")
            }
            UsageError::IncompleteExecutableGroup { chain } => {
                write!(f, "incomplete executable command group {chain}")
            }
            UsageError::UnknownExecutableChain { chain, token } => {
                write!(f, "executable command group {chain} has no child {token}")
            }
            UsageError::ExpandedAliasTargetUnknown { target } => {
                write!(f, "unknown expanded alias target {target}")
            }
            UsageError::MissingRunScript => f.write_str("missing <script> after run"),
            UsageError::MissingEnvName => f.write_str("missing <name> after env"),
            UsageError::UnknownHelpTopic { topic } => {
                write!(f, "unknown help topic {topic}")
            }
            UsageError::UnexpectedOperand { token } => {
                write!(f, "unexpected operand {token}")
            }
            UsageError::GetMissingSelector => f.write_str("missing get selector"),
            UsageError::GetUnknownSelector { token } => {
                write!(f, "unknown get selector {token}")
            }
            UsageError::GetUnknownOption { token } => {
                write!(f, "unknown get option {token}")
            }
            UsageError::GetRepeatedOutputOption { option } => {
                write!(f, "repeated get option {option}")
            }
            UsageError::GetCombinedOutputOptions => {
                f.write_str("--plain and --json cannot be combined")
            }
            UsageError::GetMissingCfgPath => f.write_str("missing dot path after get cfg"),
            UsageError::GetEmptyDotPathSegment { dot_path } => {
                write!(f, "empty segment in dot path {dot_path}")
            }
            UsageError::GetExtraOperands { token } => {
                write!(f, "unexpected operand {token}")
            }
            UsageError::RemoteMissingCommand => f.write_str("missing remote command"),
            UsageError::RemoteUnknownCommand { token } => {
                write!(f, "unknown remote command {token}")
            }
            UsageError::RemoteUnknownOption { verb, token } => {
                write!(f, "unknown remote {verb} option {token}")
            }
            UsageError::RemoteMissingOptionValue { option } => {
                write!(f, "missing value after {option}")
            }
            UsageError::RemoteInvalidOptionValue { option, value } => {
                write!(f, "invalid value {value} for {option}")
            }
            UsageError::RemoteRepeatedOption { option } => {
                write!(f, "repeated remote option {option}")
            }
            UsageError::RemoteUnexpectedOperand { verb, token } => {
                write!(f, "unexpected operand {token} after remote {verb}")
            }
            UsageError::RemoteSelectorConflict => {
                f.write_str("--all cannot be combined with --machine or --tag")
            }
            UsageError::RemoteJumpSelectorConflict => {
                f.write_str("--jump cannot be combined with --machine, --tag, or --all")
            }
            UsageError::RemoteUnknownJump { name } => {
                write!(f, "unknown remote jump host {name}")
            }
            UsageError::RemoteFingerprintCardinality => {
                f.write_str("--fingerprint requires --jump or exactly one selected machine")
            }
            UsageError::RemoteInvalidFingerprint { value } => {
                write!(f, "invalid SHA-256 host-key fingerprint {value}")
            }
            UsageError::RemoteMissingSelector => {
                f.write_str("remote operation requires --machine, --tag, or --all")
            }
            UsageError::RemoteMissingOperandBoundary { verb } => {
                write!(f, "remote {verb} requires -- before operands")
            }
            UsageError::RemoteMissingExecCommand => {
                f.write_str("remote exec requires at least one command argument after --")
            }
            UsageError::RemoteMissingRunScript => {
                f.write_str("remote run requires a script name after --")
            }
            UsageError::RemoteTransferOperandCardinality { verb } => {
                write!(f, "remote {verb} requires exactly two operands after --")
            }
            UsageError::RemoteShellBodyCardinality => {
                f.write_str("remote exec --shell requires exactly one shell body after --")
            }
            UsageError::RemotePtyConflict => f.write_str("--pty cannot be combined with --no-pty"),
            UsageError::RemotePtyCardinality => {
                f.write_str("--pty requires exactly one selected machine")
            }
            UsageError::RemoteBootstrapNoPty => {
                f.write_str("remote ssh --bootstrap cannot be combined with --no-pty")
            }
            UsageError::RemoteSingleTargetRequired { verb } => {
                write!(f, "remote {verb} requires exactly one selected machine")
            }
            UsageError::RemoteUnknownMachine { selector } => {
                write!(f, "unknown remote machine or address {selector}")
            }
            UsageError::RemoteAmbiguousMachine { selector } => {
                write!(f, "ambiguous remote machine or address {selector}")
            }
            UsageError::RemoteEmptySelection => f.write_str("remote selector matched no machines"),
        }
    }
}

impl std::error::Error for UsageError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetError {
    MissingPath { dot_path: String },
    NonMappingTraversal { prefix: String },
    NonUtf8Path,
}

impl GetError {
    pub fn class(&self) -> ErrorClass {
        ErrorClass::Runtime
    }
}

impl fmt::Display for GetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GetError::MissingPath { dot_path } => {
                write!(f, "config path {dot_path} is not defined")
            }
            GetError::NonMappingTraversal { prefix } => {
                write!(f, "config path {prefix} is not a mapping")
            }
            GetError::NonUtf8Path => f.write_str("project root path is not valid UTF-8"),
        }
    }
}

impl std::error::Error for GetError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteError {
    MissingEnvironment,
    NonUtf8Environment,
    UnknownEnvironment { name: String },
    UnavailablePhase { verb: String },
}

impl RemoteError {
    pub fn class(&self) -> ErrorClass {
        ErrorClass::Runtime
    }
}

impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEnvironment => {
                f.write_str("remote operations require a non-empty BROIL_ENV")
            }
            Self::NonUtf8Environment => f.write_str("BROIL_ENV is not valid UTF-8"),
            Self::UnknownEnvironment { name } => {
                write!(f, "unknown remote environment {name}")
            }
            Self::UnavailablePhase { verb } => {
                write!(
                    f,
                    "remote {verb} is not available in implementation phase 1"
                )
            }
        }
    }
}

impl std::error::Error for RemoteError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionError {
    UnknownEnvironment { name: String },
    UnknownScript { name: String },
    Spawn { message: String },
    Rcfile { message: String },
    ExecutableDirNotDirectory { path: PathBuf },
    ExecutableDirUnreadable { path: PathBuf, message: String },
    ExecutableGroupUnenumerable { path: PathBuf, message: String },
}

impl ExecutionError {
    pub fn class(&self) -> ErrorClass {
        ErrorClass::Runtime
    }
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionError::UnknownEnvironment { name } => {
                write!(f, "unknown execution environment {name}")
            }
            ExecutionError::UnknownScript { name } => {
                write!(f, "unknown script {name}")
            }
            ExecutionError::Spawn { message } => f.write_str(message),
            ExecutionError::Rcfile { message } => f.write_str(message),
            ExecutionError::ExecutableDirNotDirectory { path } => {
                write!(
                    f,
                    "executable command directory {} exists but is not a usable directory",
                    path.display()
                )
            }
            ExecutionError::ExecutableDirUnreadable { path, message } => {
                write!(
                    f,
                    "cannot read executable command directory {}: {message}",
                    path.display()
                )
            }
            ExecutionError::ExecutableGroupUnenumerable { path, message } => {
                write!(
                    f,
                    "cannot read executable command group {}: {message}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for ExecutionError {}
