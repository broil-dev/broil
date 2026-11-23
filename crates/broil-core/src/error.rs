// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! Broil error taxonomy shared across workspace crates.
//!
//! Two error classes exist: CLI usage errors exit `2` and Broil-detected
//! runtime errors exit `1`. Every config-pipeline failure
//! is a runtime error; the usage class is constructible without config
//! loading, so every command can map both classes uniformly.

use std::fmt;
use std::path::PathBuf;

use crate::tokens::TokenizeError;

/// Exit-status class for a Broil-detected error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// CLI usage error; exits `2`.
    Usage,
    /// Broil-detected runtime error; exits `1`.
    Runtime,
}

impl ErrorClass {
    /// The process exit code for this class.
    pub fn exit_code(self) -> i32 {
        match self {
            ErrorClass::Usage => 2,
            ErrorClass::Runtime => 1,
        }
    }
}

/// A failure in config discovery, selection, parsing, fragment loading,
/// `$extends` resolution, or schema validation. All variants are runtime
/// errors (exit `1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Discovery reached the filesystem root without a default config file.
    NoConfigFound { start_dir: PathBuf },
    /// Both `broil.yaml` and `broil.yml` exist in the discovered root.
    BothDefaultsPresent { dir: PathBuf },
    /// A default-named path exists but is not a readable regular file.
    DefaultNotReadableRegularFile { path: PathBuf },
    /// `--file` names a path that does not exist.
    ExplicitFileMissing { path: PathBuf },
    /// `--file` names a path that is not readable.
    ExplicitFileUnreadable { path: PathBuf },
    /// `--file` names a path that is not a regular file.
    ExplicitFileNotRegular { path: PathBuf },
    /// YAML parsing failed, including multi-document streams and
    /// unknown-tag rejections.
    YamlParse { path: PathBuf, message: String },
    /// A non-empty base config file's root value is not a mapping.
    NonMappingRoot { path: PathBuf },
    /// A fragment filename has an empty target key-path segment.
    FragmentEmptyPathSegment { filename: String },
    /// A fragment filename stem is not valid UTF-8.
    FragmentFilenameNotUtf8 { filename_lossy: String },
    /// A fragment targets a key path that is already defined.
    FragmentTargetAlreadyDefined { key_path: String, filename: String },
    /// A parent path needed by a fragment exists as a non-mapping value.
    FragmentParentNotMapping { key_path: String, filename: String },
    /// `broil/` or `broil/cfg/` exists but is not a usable directory.
    FragmentDirNotDirectory { path: PathBuf },
    /// The fragment directory cannot be inspected, opened, or iterated.
    FragmentDirUnreadable { path: PathBuf, message: String },
    /// A fragment candidate is neither a directory nor a readable regular
    /// file: open/read failure, dangling candidate symlink, non-regular
    /// non-directory target, or any other stat/IO failure on a candidate.
    FragmentFileUnusable { path: PathBuf, message: String },
    /// `$extends` value is not a string.
    ExtendsNonString { key_path: String },
    /// `$extends` references a missing dot path.
    ExtendsMissingTarget { key_path: String, target: String },
    /// `$extends` references a non-mapping value.
    ExtendsNonMappingTarget { key_path: String, target: String },
    /// `$extends` resolution found a circular inheritance chain.
    ExtendsCycle { chain: Vec<String> },
    /// Schema validation failed on the resolved config.
    Schema(SchemaError),
}

impl ConfigError {
    /// Every config error is a runtime error (exit `1`).
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

/// A schema-validation failure on the resolved config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    /// An unknown key at a validated level.
    UnknownKey {
        key_path: String,
    },
    /// A non-string YAML mapping key; never coerced.
    NonStringKey {
        key_path: String,
        key_repr: String,
    },
    /// A value that must be a string is not a string.
    NonStringValue {
        key_path: String,
    },
    /// An env-var name does not match `[A-Za-z_][A-Za-z0-9_]*`.
    InvalidEnvVarName {
        key_path: String,
        name: String,
    },
    /// A configured env-var name is reserved (`BROIL_ROOT`, `BROIL_ENV`).
    ReservedEnvVarName {
        key_path: String,
        name: String,
    },
    /// A script map key is empty.
    EmptyScriptName {
        key_path: String,
    },
    /// An environment map key is empty.
    EmptyEnvironmentName,
    /// An environment name contains `.`.
    EnvironmentNameWithDot {
        name: String,
    },
    /// A present, non-null section value is not a mapping.
    NonMappingSection {
        key_path: String,
    },
    /// A nested alias group mapping is empty.
    EmptyAliasGroup {
        key_path: String,
    },
    /// An alias path segment is empty, contains `.`, or begins with `-`.
    InvalidAliasPathSegment {
        key_path: String,
        segment: String,
    },
    /// An alias command failed tokenization.
    AliasTokenization {
        key_path: String,
        error: TokenizeError,
    },
    /// An alias command produced zero tokens.
    EmptyAliasTokenList {
        key_path: String,
    },
    /// A configured env-var name is owned by the interactive-shell prompt
    /// mechanism (`BROIL_PROMPT_NAMES`, `BROIL_PS1_BASE`,
    /// `BROIL_LAST_STATUS`); these are not among the reserved names.
    PromptOwnedEnvVarName {
        key_path: String,
        name: String,
    },
    /// A required remote configuration field is absent.
    MissingRequiredRemoteField {
        key_path: String,
    },
    /// A remote configuration value has the wrong type, shape, or range.
    InvalidRemoteValue {
        key_path: String,
        expected: String,
    },
    InvalidSecretsValue {
        key_path: String,
        expected: String,
    },
    /// Image syntax or selected-view reference failure; never contains invalid input values.
    InvalidImageValue {
        key_path: String,
        expected: String,
    },
    /// K3s declaration or selected-reference failure, without rejected scalar values.
    InvalidK3sValue {
        key_path: String,
        expected: String,
    },
    /// Application catalog failure, without rejected scalar values.
    InvalidApplicationValue {
        key_path: String,
        expected: String,
    },
    AmbiguousImageDefinition {
        first: String,
        second: String,
    },
    /// A remote configuration reference cannot be resolved in its scope.
    UnknownRemoteReference {
        key_path: String,
        target: String,
    },
    /// Two environment-owned machines resolve to the same route tuple.
    DuplicateRemoteRoute {
        first: String,
        second: String,
    },
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
            SchemaError::InvalidSecretsValue { key_path, expected } => {
                write!(f, "secrets config value at {key_path} must be {expected}")
            }
            SchemaError::InvalidImageValue { key_path, expected } => {
                write!(f, "image config value at {key_path} must be {expected}")
            }
            SchemaError::InvalidK3sValue { key_path, expected } => {
                write!(f, "k3s config value at {key_path} must be {expected}")
            }
            SchemaError::InvalidApplicationValue { key_path, expected } => {
                write!(
                    f,
                    "application config value at {key_path} must be {expected}"
                )
            }
            SchemaError::AmbiguousImageDefinition { first, second } => {
                write!(
                    f,
                    "ambiguous image catalog definitions at {first} and {second}"
                )
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

/// A CLI usage error (exit `2`).
///
/// Token-carrying fields hold lossily-rendered argv tokens: they are
/// diagnostic text, never re-parsed. `chain` fields carry consumed alias
/// or executable command chains as space-joined strings; consumed
/// segments are valid UTF-8, though segment boundaries are not
/// recoverable when segments contain spaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    K3s {
        reason: String,
    },
    ImagePartial {
        path: String,
        unknown: bool,
    },
    ImageMissingOperand {
        path: String,
        operand: String,
    },
    ImageUnknownOption {
        path: String,
        token: String,
    },
    ImageRepeatedOption {
        option: String,
    },
    ImageMissingValue {
        option: String,
    },
    ImageInvalidValue {
        option: String,
        value: String,
    },
    ImageConflictingOptions {
        first: String,
        second: String,
    },
    ImageUnexpectedOperand {
        path: String,
        token: String,
    },
    /// No command-or-alias token remains after global options.
    AbsentCommand,
    /// The command-or-alias token matched nothing after all resolution
    /// stages.
    UnknownCommand {
        token: String,
    },
    /// A matched alias group ran out of CLI tokens before reaching a
    /// leaf.
    IncompleteAliasGroup {
        chain: String,
    },
    /// A matched alias group has no child alias named by the next CLI
    /// token.
    UnknownAliasChain {
        chain: String,
        token: String,
    },
    /// A matched executable command group ran out of CLI tokens before
    /// reaching an executable command.
    IncompleteExecutableGroup {
        chain: String,
    },
    /// A matched executable command group has no eligible child named by
    /// the next CLI token.
    UnknownExecutableChain {
        chain: String,
        token: String,
    },
    /// An expanded alias target matched neither a built-in command nor
    /// an eligible executable command.
    ExpandedAliasTargetUnknown {
        target: String,
    },
    /// Built-in `run` selected with no `<script>` operand.
    MissingRunScript,
    /// Built-in `env` selected with no `<name>` operand.
    MissingEnvName,
    /// `help <topic>` names no built-in command.
    UnknownHelpTopic {
        topic: String,
    },
    /// A config-independent leaf or command-local help leaf owns a
    /// trailing token that its grammar does not accept. This stays
    /// semantically distinct from `GetExtraOperands` so the shared
    /// diagnostic text does not couple independent command grammars.
    UnexpectedOperand {
        token: String,
    },
    /// `get` with no selector token.
    GetMissingSelector,
    /// `get` selector is not `root`, `name`, or `cfg`.
    GetUnknownSelector {
        token: String,
    },
    /// An unknown `--…` option between `get` and the selector.
    GetUnknownOption {
        token: String,
    },
    /// `--plain` or `--json` repeated.
    GetRepeatedOutputOption {
        option: String,
    },
    /// `--plain` and `--json` combined.
    GetCombinedOutputOptions,
    /// `get cfg` with no dot-path operand.
    GetMissingCfgPath,
    /// A dot path with an empty segment.
    GetEmptyDotPathSegment {
        dot_path: String,
    },
    /// A trailing operand after a complete selector form.
    GetExtraOperands {
        token: String,
    },
    /// Bare `remote` retained no operational verb.
    SecretsPartial {
        path: String,
        unknown: bool,
    },
    RemoteMissingCommand,
    /// The second `remote` token is not a recognized operational verb.
    RemoteUnknownCommand {
        token: String,
    },
    /// An operational remote leaf received an unknown option.
    RemoteUnknownOption {
        verb: String,
        token: String,
    },
    /// A remote option requiring a value has none.
    RemoteMissingOptionValue {
        option: String,
    },
    /// A remote option value is invalid.
    RemoteInvalidOptionValue {
        option: String,
        value: String,
    },
    /// A single-use remote option was repeated.
    RemoteRepeatedOption {
        option: String,
    },
    /// A selected remote leaf received an unexpected operand.
    RemoteUnexpectedOperand {
        verb: String,
        token: String,
    },
    /// `--all` was combined with another selector form.
    RemoteSelectorConflict,
    /// `--jump` was combined with a machine selector form.
    RemoteJumpSelectorConflict,
    /// An explicit jump selector has no match.
    RemoteUnknownJump {
        name: String,
    },
    /// `--fingerprint` was used with more than one selected target.
    RemoteFingerprintCardinality,
    /// `--fingerprint` was not an OpenSSH SHA-256 fingerprint.
    RemoteInvalidFingerprint {
        value: String,
    },
    /// An operational remote command omitted every selector form.
    RemoteMissingSelector,
    /// A remote execution or transfer command omitted the mandatory `--`.
    RemoteMissingOperandBoundary {
        verb: String,
    },
    /// `remote exec` argv mode received no command argv after `--`.
    RemoteMissingExecCommand,
    /// `remote run` received no script name after `--`.
    RemoteMissingRunScript,
    /// `remote copy-to` or `remote copy-from` received other than two operands after `--`.
    RemoteTransferOperandCardinality {
        verb: String,
    },
    /// `remote exec --shell` received other than one shell body after `--`.
    RemoteShellBodyCardinality,
    /// `remote exec` received both PTY override flags.
    RemotePtyConflict,
    /// `remote exec --pty` selected other than one machine.
    RemotePtyCardinality,
    /// `remote ssh --bootstrap` cannot run without a PTY.
    RemoteBootstrapNoPty,
    /// A single-target remote command selected other than one machine.
    RemoteSingleTargetRequired {
        verb: String,
    },
    /// A machine name/address selector has no match.
    RemoteUnknownMachine {
        selector: String,
    },
    /// A machine name/address selector identifies more than one machine.
    RemoteAmbiguousMachine {
        selector: String,
    },
    /// Selector evaluation produced no machines.
    RemoteEmptySelection,
}

impl UsageError {
    /// Every usage error is a usage-class error (exit `2`).
    pub fn class(&self) -> ErrorClass {
        ErrorClass::Usage
    }
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsageError::K3s { reason } => f.write_str(reason),
            UsageError::ImagePartial { path, unknown } => write!(
                f,
                "{} image command {path}",
                if *unknown { "unknown" } else { "incomplete" }
            ),
            UsageError::ImageMissingOperand { path, operand } => {
                write!(f, "missing {operand} after image {path}")
            }
            UsageError::ImageUnknownOption { path, token } => {
                write!(f, "unknown image {path} option {token}")
            }
            UsageError::ImageRepeatedOption { option } => {
                write!(f, "repeated image option {option}")
            }
            UsageError::ImageMissingValue { option } => {
                write!(f, "missing value for image option {option}")
            }
            UsageError::ImageInvalidValue { option, value } => {
                write!(f, "invalid image {option} value {value}")
            }
            UsageError::ImageConflictingOptions { first, second } => {
                write!(f, "image options {first} and {second} cannot be combined")
            }
            UsageError::ImageUnexpectedOperand { path, token } => {
                write!(f, "unexpected image {path} operand {token}")
            }
            UsageError::AbsentCommand => f.write_str("missing command"),
            UsageError::UnknownCommand { token } => {
                write!(f, "unknown command {token}")
            }
            UsageError::IncompleteAliasGroup { chain } => {
                write!(f, "incomplete alias group {chain}")
            }
            // The chain and the unknown child appear in distinctly named
            // roles: alias path segments may themselves contain spaces,
            // so a plain join would lose the boundary between them.
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
            UsageError::SecretsPartial { path, unknown } => write!(
                f,
                "{} secrets command {path}",
                if *unknown { "unknown" } else { "incomplete" }
            ),
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

/// A `get` runtime failure after dispatch. All
/// variants are runtime errors (exit `1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetError {
    /// The dot path names no defined config path. Also stands in for every
    /// traversal outcome of a well-formed non-UTF-8 dot-path operand,
    /// whose byte-faithful traversal is deliberately never attempted.
    MissingPath { dot_path: String },
    /// Traversal reached a non-mapping value before the final segment.
    NonMappingTraversal { prefix: String },
    /// `get root` or `get name` selected a non-UTF-8 path string.
    NonUtf8Path,
}

impl GetError {
    /// Every `get` runtime error is a runtime-class error (exit `1`).
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

/// A remote inventory failure.
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
                write!(f, "remote {verb} is not available")
            }
        }
    }
}

impl std::error::Error for RemoteError {}

/// A child-execution failure for child-launching commands: execution-environment
/// resolution, script lookup, spawn/wait/status-decode failures, and
/// executable command directory and group failures. Built-in `run` constructs
/// these; `env` and executable commands
/// reuse `UnknownEnvironment` and `Spawn`, and the executable command
/// directory variants mirror the fragment-directory twins in
/// `ConfigError`. All variants are runtime errors (exit `1`).
///
/// Name-carrying fields hold lossily-rendered diagnostics, never
/// re-parsed. `Spawn` renders its carried message as the whole
/// diagnostic — no fixed prefix — so each construction site writes
/// accurate text: a wait failure is never described as a spawn failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionError {
    /// The active execution environment is not defined in `environments`.
    UnknownEnvironment { name: String },
    /// `<script>` is not present in the resolved script map.
    UnknownScript { name: String },
    /// Child process spawn failure, also carrying wait
    /// failures and the neither-code-nor-signal status-decode arm.
    Spawn { message: String },
    /// Interactive-shell rcfile directory or rcfile creation or write
    /// failure. Renders its carried message
    /// wholesale, like `Spawn`.
    Rcfile { message: String },
    /// Already-redacted export-resolution failure; never carries a secret value.
    Injection { message: String },
    /// `broil/bin` exists but does not resolve to a directory, including
    /// an unresolvable symlink.
    ExecutableDirNotDirectory { path: PathBuf },
    /// `broil/bin` cannot be inspected, read, or searched.
    ExecutableDirUnreadable { path: PathBuf, message: String },
    /// A matched executable command group's entries cannot be enumerated
    /// when the resolution walk requires them.
    ExecutableGroupUnenumerable { path: PathBuf, message: String },
}

impl ExecutionError {
    /// Every execution error is a runtime-class error (exit `1`).
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
            ExecutionError::Injection { message } => write!(f, "secret injection: {message}"),
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
