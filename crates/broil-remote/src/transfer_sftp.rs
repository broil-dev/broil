// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File as LocalFile};
use std::future::Future;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use broil_config::LoadedProject;
use broil_core::remote::{PrivilegeProfile, SecretProvider};
use russh::ChannelMsg;
use russh::client;
use russh::keys::Algorithm;
use russh_sftp::protocol::{FileAttributes, OpenFlags, Packet, StatusCode};
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

use crate::auth::{self, AuthContext};
use crate::known_hosts::{AliasState, KnownHostsStore, StoreError};
use crate::path_safety::{self, CapabilityError, SafePathEntryType};
use crate::scheduler::CancellationToken;
use crate::transfer::{
    KnownHostsSource, ResolvedKnownHosts, TargetTransferOptions, TransferBackend,
    TransferDirection, TransferJob, TransferJump, TransferTargetResult,
};
use crate::transfer_path::{
    NormalizedLocalPath, RemoteTransferPath, TransferPathError, join_remote_base,
    parse_remote_base_result, preflight_transfer_paths, remote_component_prefixes,
};
use crate::transport::StrictHandler;
use crate::{FailureClass, HostKey};

const UPLOAD_WRITE_CHUNK: usize = 32 * 1024;
const DOWNLOAD_READ_CHUNK: u32 = 32 * 1024;
const TEMP_INITIAL_MODE: u32 = 0o600;
const POSIX_RENAME_EXTENSION: &str = "posix-rename@openssh.com";

#[derive(Clone)]
pub struct SftpSetupBackend {
    auth_context: AuthContext,
    privilege_context: TransferPrivilegeContext,
}

impl SftpSetupBackend {
    pub fn new(auth_context: AuthContext) -> Self {
        Self {
            auth_context,
            privilege_context: TransferPrivilegeContext::default(),
        }
    }

    pub fn with_privilege_context(
        auth_context: AuthContext,
        privilege_context: TransferPrivilegeContext,
    ) -> Self {
        Self {
            auth_context,
            privilege_context,
        }
    }
}

#[derive(Clone)]
pub struct TransferPrivilegeContext {
    secret_context: crate::secret::SecretContext,
    privilege_profiles: BTreeMap<String, PrivilegeProfile>,
}

impl TransferPrivilegeContext {
    pub fn from_project(
        project: &LoadedProject,
        environment: &str,
        env_snapshot: &[(OsString, OsString)],
    ) -> Self {
        let env_remote = &project.config.environments[environment].remote.definitions;
        let mut secret_providers = project.config.remote.definitions.secret_providers.clone();
        secret_providers.extend(env_remote.secret_providers.clone());
        let mut privilege_profiles = project.config.remote.definitions.privilege_profiles.clone();
        privilege_profiles.extend(env_remote.privilege_profiles.clone());
        Self::new(
            project.broil_root.clone(),
            env_snapshot.to_vec(),
            secret_providers,
            privilege_profiles,
        )
    }

    pub fn new(
        root: PathBuf,
        env_snapshot: Vec<(OsString, OsString)>,
        secret_providers: BTreeMap<String, SecretProvider>,
        privilege_profiles: BTreeMap<String, PrivilegeProfile>,
    ) -> Self {
        Self {
            secret_context: crate::secret::SecretContext::new(root, env_snapshot, secret_providers),
            privilege_profiles,
        }
    }

    fn profile(&self, name: &str) -> Result<&PrivilegeProfile, TransferRequestError> {
        self.privilege_profiles.get(name).ok_or_else(|| {
            TransferRequestError::new(
                FailureClass::Configuration,
                format!("unknown privilege profile {name}"),
                TransferRequestErrorSource::Local,
            )
        })
    }

    async fn sudo_password_input(
        &self,
        profile: &PrivilegeProfile,
        cancel: &CancellationToken,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, TransferRequestError> {
        let Some(secret) = &profile.password else {
            return Ok(None);
        };
        let password = self
            .secret_context
            .resolve_owned_cancellable(&secret.secret, cancel)
            .await
            .map_err(|error| {
                TransferRequestError::new(
                    error.class(),
                    format!("sudo password secret {} unavailable", secret.secret),
                    TransferRequestErrorSource::Local,
                )
            })?;
        let input = crate::sudo::sudo_password_input(&password).map_err(|error| {
            TransferRequestError::new(
                error.class(),
                error.to_string(),
                TransferRequestErrorSource::Local,
            )
        })?;
        Ok(Some(input))
    }
}

impl Default for TransferPrivilegeContext {
    fn default() -> Self {
        Self::new(PathBuf::new(), Vec::new(), BTreeMap::new(), BTreeMap::new())
    }
}

impl TransferBackend for SftpSetupBackend {
    fn transfer_target(
        &self,
        job: TransferJob,
        options: TargetTransferOptions,
    ) -> Pin<Box<dyn Future<Output = TransferTargetResult> + Send>> {
        let auth_context = self.auth_context.clone();
        let privilege_context = self.privilege_context.clone();
        Box::pin(async move {
            let metadata = match TransferMetadata::from_job(&job) {
                Ok(metadata) => metadata,
                Err(result) => return result,
            };
            if let Some(result) = unsupported_phase_options(&job, &metadata) {
                return result;
            }
            if job.direction == TransferDirection::Upload {
                if let Some(profile_name) = job.privilege.as_deref() {
                    if let Err(error) = privilege_context.profile(profile_name) {
                        return TransferTargetResult::failure(
                            job.machine,
                            job.direction,
                            error.class,
                            error.diagnostic,
                        );
                    }
                }
            }
            let paths = match preflight_transfer_paths(&job) {
                Ok(paths) => paths,
                Err(error) => {
                    return TransferTargetResult::failure(
                        job.machine,
                        job.direction,
                        FailureClass::TransferPathSafety,
                        error.diagnostic(),
                    );
                }
            };
            let upload_source = if job.direction == TransferDirection::Upload && !job.recursive {
                match UploadSource::open(&paths.local) {
                    Ok(source) => Some(source),
                    Err(error) => {
                        return TransferTargetResult::failure(
                            job.machine,
                            job.direction,
                            FailureClass::TransferPathSafety,
                            error.diagnostic(),
                        );
                    }
                }
            } else {
                None
            };
            let download_destination = if job.direction == TransferDirection::Download
                && !job.recursive
                && !job.multi_machine_download
            {
                match DownloadDestination::analyze(&paths.local, job.overwrite) {
                    Ok(destination) => Some(destination),
                    Err(error) => {
                        return TransferTargetResult::failure(
                            job.machine,
                            job.direction,
                            FailureClass::TransferPathSafety,
                            error.diagnostic(),
                        );
                    }
                }
            } else {
                None
            };
            match setup_transfer_session(&job, &auth_context, &options.cancel).await {
                Ok(mut handle) => {
                    let extensions = handle.extensions.clone();
                    let request_context =
                        TransferRequestContext::new(&handle.raw_sftp, &job, options.cancel.clone());
                    let result = match request_context.resolve_remote_operand(&paths.remote).await {
                        Ok(remote) => match (job.direction, upload_source, download_destination) {
                            (TransferDirection::Upload, None, None)
                                if job.recursive && job.privilege.is_some() =>
                            {
                                request_context
                                    .upload_privileged(
                                        PrivilegedUploadRequest {
                                            job: &job,
                                            source: None,
                                            local: &paths.local,
                                            remote: &remote,
                                            metadata: &metadata,
                                            privilege_context: &privilege_context,
                                        },
                                        &mut handle.target_session,
                                    )
                                    .await
                                    .map(|()| TransferTargetResult::success(&job))
                                    .unwrap_or_else(|error| error.into_result(&job))
                            }
                            (TransferDirection::Upload, None, None) if job.recursive => {
                                request_context
                                    .upload_recursive(
                                        &job,
                                        &paths.local,
                                        &remote,
                                        &extensions,
                                        &metadata,
                                    )
                                    .await
                                    .map(|()| TransferTargetResult::success(&job))
                                    .unwrap_or_else(|error| error.into_result(&job))
                            }
                            (TransferDirection::Upload, Some(source), None)
                                if job.privilege.is_some() =>
                            {
                                request_context
                                    .upload_privileged(
                                        PrivilegedUploadRequest {
                                            job: &job,
                                            source: Some(source),
                                            local: &paths.local,
                                            remote: &remote,
                                            metadata: &metadata,
                                            privilege_context: &privilege_context,
                                        },
                                        &mut handle.target_session,
                                    )
                                    .await
                                    .map(|()| TransferTargetResult::success(&job))
                                    .unwrap_or_else(|error| error.into_result(&job))
                            }
                            (TransferDirection::Upload, Some(source), None) => request_context
                                .upload_single_file(
                                    &job,
                                    source,
                                    &remote,
                                    &extensions,
                                    metadata.explicit_mode,
                                )
                                .await
                                .map(|()| TransferTargetResult::success(&job))
                                .unwrap_or_else(|error| error.into_result(&job)),
                            (TransferDirection::Download, None, None)
                                if job.recursive || job.multi_machine_download =>
                            {
                                request_context
                                    .download_to_local_target(
                                        &job,
                                        &paths.local,
                                        &remote,
                                        &metadata,
                                    )
                                    .await
                                    .map(|()| TransferTargetResult::success(&job))
                                    .unwrap_or_else(|error| error.into_result(&job))
                            }
                            (TransferDirection::Download, None, Some(destination)) => {
                                request_context
                                    .download_single_file(
                                        &job,
                                        &remote,
                                        destination,
                                        metadata.explicit_mode,
                                    )
                                    .await
                                    .map(|()| TransferTargetResult::success(&job))
                                    .unwrap_or_else(|error| error.into_result(&job))
                            }
                            _ => TransferTargetResult::success(&job),
                        },
                        Err(error) => error.into_result(&job),
                    };
                    handle.close().await;
                    result
                }
                Err(error) => error.into_result(&job),
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransferMetadata {
    explicit_mode: Option<u32>,
    upload_owner: Option<UploadOwner>,
}

impl TransferMetadata {
    fn from_job(job: &TransferJob) -> Result<Self, TransferTargetResult> {
        let explicit_mode = job
            .mode
            .as_deref()
            .map(parse_transfer_mode)
            .transpose()
            .map_err(|()| {
                TransferTargetResult::failure(
                    job.machine.clone(),
                    job.direction,
                    FailureClass::Configuration,
                    "transfer mode must be an octal string matching 0[0-7]{3}",
                )
            })?;
        let upload_owner = job
            .owner
            .as_deref()
            .map(parse_upload_owner)
            .transpose()
            .map_err(|()| {
                TransferTargetResult::failure(
                    job.machine.clone(),
                    job.direction,
                    FailureClass::Configuration,
                    "transfer owner must be user or user:group with symbolic names",
                )
            })?;
        Ok(Self {
            explicit_mode,
            upload_owner,
        })
    }

    fn root_mode(&self, default_mode: u32, is_root: bool) -> u32 {
        if is_root {
            self.explicit_mode.unwrap_or(default_mode)
        } else {
            default_mode
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UploadOwner {
    user: String,
    group: Option<String>,
}

impl UploadOwner {
    fn spec(&self) -> String {
        match &self.group {
            Some(group) => format!("{}:{group}", self.user),
            None => self.user.clone(),
        }
    }
}

fn parse_transfer_mode(value: &str) -> Result<u32, ()> {
    let bytes = value.as_bytes();
    if bytes.len() != 4
        || bytes[0] != b'0'
        || !bytes[1..].iter().all(|byte| matches!(byte, b'0'..=b'7'))
    {
        return Err(());
    }
    Ok(bytes[1..]
        .iter()
        .fold(0u32, |mode, byte| (mode << 3) | u32::from(byte - b'0')))
}

fn parse_upload_owner(value: &str) -> Result<UploadOwner, ()> {
    let mut parts = value.split(':');
    let user = parts.next().unwrap_or_default();
    let group = parts.next();
    if parts.next().is_some()
        || !owner_component(user)
        || group.is_some_and(|group| !owner_component(group))
    {
        return Err(());
    }
    Ok(UploadOwner {
        user: user.to_string(),
        group: group.map(str::to_string),
    })
}

fn owner_component(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn unsupported_phase_options(
    job: &TransferJob,
    metadata: &TransferMetadata,
) -> Option<TransferTargetResult> {
    let diagnostic = match job.direction {
        TransferDirection::Upload if metadata.upload_owner.is_some() && job.privilege.is_none() => {
            let owner = metadata.upload_owner.as_ref().expect("owner checked");
            debug_assert!(!owner.user.is_empty());
            let diagnostic = if owner.group.is_some() {
                "explicit upload owner/group requires privileged upload support"
            } else {
                "explicit upload owner requires privileged upload support"
            };
            return Some(TransferTargetResult::failure(
                job.machine.clone(),
                job.direction,
                FailureClass::CapabilityUnsupported,
                diagnostic,
            ));
        }
        TransferDirection::Download if job.privilege.is_some() => {
            Some("privileged download is not available")
        }
        _ => None,
    }?;
    Some(TransferTargetResult::failure(
        job.machine.clone(),
        job.direction,
        FailureClass::Configuration,
        diagnostic,
    ))
}

#[derive(Debug)]
struct UploadSource {
    file: LocalFile,
    size: u64,
    mode: u32,
}

impl UploadSource {
    fn open(path: &NormalizedLocalPath) -> Result<Self, TransferPathError> {
        if !matches!(
            path.final_component,
            Some(crate::path_safety::SafePathFinal::Existing(
                SafePathEntryType::RegularFile
            ))
        ) {
            return Err(TransferPathError::new(
                "local transfer source is not a regular file",
            ));
        }
        let file = path_safety::defensive_open_regular_no_symlink(&path.path)
            .map_err(local_source_error)?;
        Self::from_open_file(file)
    }

    fn open_child(directory: &LocalFile, name: &OsStr) -> Result<Self, TransferPathError> {
        let descriptor = open_local_child_descriptor(directory, name)?;
        let metadata = descriptor
            .metadata()
            .map_err(|_| TransferPathError::new("local transfer path is not permitted"))?;
        if metadata.file_type().is_symlink() {
            return Err(TransferPathError::new("local transfer path is unsafe"));
        }
        if !metadata.is_file() {
            return Err(TransferPathError::new(
                "local transfer source is not a regular file",
            ));
        }
        let file = path_safety::reopen_for_read(&descriptor).map_err(local_source_error)?;
        Self::from_open_file(file)
    }

    fn from_open_file(file: LocalFile) -> Result<Self, TransferPathError> {
        let metadata = file
            .metadata()
            .map_err(|_| TransferPathError::new("local transfer path is not permitted"))?;
        if !metadata.is_file() {
            return Err(TransferPathError::new(
                "local transfer source is not a regular file",
            ));
        }
        Ok(Self {
            file,
            size: metadata.len(),
            mode: default_regular_file_mode(Some(metadata.mode())),
        })
    }
}

#[derive(Debug)]
struct DownloadDestination {
    path: PathBuf,
    parent: LocalFile,
    name: OsString,
    state: DownloadDestinationState,
}

impl DownloadDestination {
    fn analyze(path: &NormalizedLocalPath, overwrite: bool) -> Result<Self, TransferPathError> {
        let state = match path.final_component {
            Some(crate::path_safety::SafePathFinal::Absent) => DownloadDestinationState::Absent,
            Some(crate::path_safety::SafePathFinal::Existing(SafePathEntryType::RegularFile))
                if overwrite =>
            {
                DownloadDestinationState::ExistingRegular
            }
            Some(crate::path_safety::SafePathFinal::Existing(SafePathEntryType::RegularFile)) => {
                return Err(TransferPathError::new(
                    "local destination exists; pass --overwrite to replace it",
                ));
            }
            _ => {
                return Err(TransferPathError::new(
                    "local destination is not a regular file",
                ));
            }
        };
        let (parent, name) =
            path_safety::defensive_open_parent(&path.path).map_err(local_source_error)?;
        Ok(Self {
            path: path.path.clone(),
            parent,
            name,
            state,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownloadDestinationState {
    Absent,
    ExistingRegular,
}

struct DownloadSource {
    handle: String,
    size: u64,
    mode: u32,
}

#[derive(Debug, Clone)]
struct LocalUploadFile {
    directory: Arc<LocalFile>,
    name: OsString,
}

impl LocalUploadFile {
    fn open(&self) -> Result<UploadSource, TransferPathError> {
        UploadSource::open_child(self.directory.as_ref(), &self.name)
    }
}

struct LocalTempFile {
    file: LocalFile,
    name: OsString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnalyzedDownloadSource {
    size: u64,
    mode: u32,
}

#[derive(Debug)]
struct LocalUploadEntry {
    remote_components: Vec<String>,
    kind: LocalUploadEntryKind,
}

#[derive(Debug, Clone)]
enum LocalUploadEntryKind {
    File(LocalUploadFile),
    Directory { mode: u32 },
}

#[derive(Debug)]
struct StagedUpload {
    action_dir: String,
    payload_path: String,
    cleanup_entries: Vec<StagedCleanupEntry>,
    install_entries: Vec<StagedInstallEntry>,
}

impl StagedUpload {
    fn new(action_dir: String) -> Self {
        let payload_path = join_remote_child_unchecked(&action_dir, "payload");
        Self {
            action_dir,
            payload_path,
            cleanup_entries: Vec::new(),
            install_entries: Vec::new(),
        }
    }

    fn stage_path(&self, components: &[String]) -> String {
        join_remote_components(&self.payload_path, components)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StagedInstallEntry {
    remote_components: Vec<String>,
    kind: StagedInstallKind,
    mode: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StagedInstallKind {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StagedCleanupEntry {
    path: String,
    kind: StagedInstallKind,
}

struct PrivilegedUploadRequest<'a> {
    job: &'a TransferJob,
    source: Option<UploadSource>,
    local: &'a NormalizedLocalPath,
    remote: &'a ResolvedRemotePath,
    metadata: &'a TransferMetadata,
    privilege_context: &'a TransferPrivilegeContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteTreeEntry {
    path: String,
    local_components: Vec<OsString>,
    kind: RemoteTreeEntryKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteTreeEntryKind {
    File,
    Directory { mode: u32 },
}

fn default_regular_file_mode(source_mode: Option<u32>) -> u32 {
    source_mode.map_or(0o600, |mode| mode & 0o777)
}

fn default_directory_mode(source_mode: Option<u32>) -> u32 {
    source_mode.map_or(0o700, |mode| mode & 0o777)
}

fn collect_local_upload_entries(
    root: &NormalizedLocalPath,
) -> Result<Vec<LocalUploadEntry>, TransferPathError> {
    let root_kind = match root.final_component {
        Some(crate::path_safety::SafePathFinal::Existing(kind)) => kind,
        _ => {
            return Err(TransferPathError::new(
                "local transfer source is not a file or directory",
            ));
        }
    };
    match root_kind {
        SafePathEntryType::RegularFile => {
            let (directory, name) =
                path_safety::defensive_open_parent(&root.path).map_err(local_source_error)?;
            Ok(vec![LocalUploadEntry {
                remote_components: Vec::new(),
                kind: LocalUploadEntryKind::File(LocalUploadFile {
                    directory: Arc::new(directory),
                    name,
                }),
            }])
        }
        SafePathEntryType::Directory => collect_local_upload_directory(&root.path),
        SafePathEntryType::Other => Err(TransferPathError::new(
            "local transfer source is not a file or directory",
        )),
    }
}

fn collect_local_upload_directory(root: &Path) -> Result<Vec<LocalUploadEntry>, TransferPathError> {
    let root = Arc::new(
        path_safety::defensive_open_directory_no_symlink(root).map_err(local_source_error)?,
    );
    let mode = local_directory_mode(root.as_ref())?;
    let mut entries = vec![LocalUploadEntry {
        remote_components: Vec::new(),
        kind: LocalUploadEntryKind::Directory { mode },
    }];
    let mut stack = vec![(root, Vec::<String>::new())];
    while let Some((directory, relative)) = stack.pop() {
        for name in local_directory_child_names(directory.as_ref())? {
            let remote_name = local_name_to_remote_component(&name)?;
            let descriptor = Arc::new(open_local_child_descriptor(directory.as_ref(), &name)?);
            let metadata = descriptor
                .metadata()
                .map_err(|_| TransferPathError::new("local transfer path is not permitted"))?;
            if metadata.file_type().is_symlink() {
                return Err(TransferPathError::new("local transfer path is unsafe"));
            }
            let mut child_relative = relative.clone();
            child_relative.push(remote_name);
            if metadata.is_dir() {
                entries.push(LocalUploadEntry {
                    remote_components: child_relative.clone(),
                    kind: LocalUploadEntryKind::Directory {
                        mode: default_directory_mode(Some(metadata.mode())),
                    },
                });
                stack.push((descriptor, child_relative));
            } else if metadata.is_file() {
                entries.push(LocalUploadEntry {
                    remote_components: child_relative,
                    kind: LocalUploadEntryKind::File(LocalUploadFile {
                        directory: directory.clone(),
                        name,
                    }),
                });
            } else {
                return Err(TransferPathError::new(
                    "local transfer source contains an unsupported entry",
                ));
            }
        }
    }
    Ok(entries)
}

fn local_directory_mode(directory: &LocalFile) -> Result<u32, TransferPathError> {
    let metadata = directory
        .metadata()
        .map_err(|_| TransferPathError::new("local transfer path is not permitted"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(TransferPathError::new(
            "local transfer source is not a directory",
        ));
    }
    Ok(default_directory_mode(Some(metadata.mode())))
}

fn local_directory_child_names(directory: &LocalFile) -> Result<Vec<OsString>, TransferPathError> {
    let mut children = fs::read_dir(PathBuf::from(format!(
        "/proc/self/fd/{}",
        directory.as_raw_fd()
    )))
    .map_err(|_| TransferPathError::new("local transfer directory cannot be read"))?
    .map(|entry| {
        entry
            .map(|entry| entry.file_name())
            .map_err(|_| TransferPathError::new("local transfer directory cannot be read"))
    })
    .collect::<Result<Vec<_>, _>>()?;
    children.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(children)
}

fn open_local_child_descriptor(
    directory: &LocalFile,
    name: &OsStr,
) -> Result<LocalFile, TransferPathError> {
    rustix::fs::openat(
        directory,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(LocalFile::from)
    .map_err(|error| match error {
        rustix::io::Errno::LOOP => TransferPathError::new("local transfer path is unsafe"),
        _ => TransferPathError::new("local transfer path is not permitted"),
    })
}

fn local_name_to_remote_component(name: &OsStr) -> Result<String, TransferPathError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(TransferPathError::new(
            "local transfer source contains an unsafe entry",
        ));
    }
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| TransferPathError::new("local transfer source entry is not valid UTF-8"))
}

fn local_download_target_path(
    job: &TransferJob,
    local: &NormalizedLocalPath,
    remote_path: &str,
) -> Result<PathBuf, TransferRequestError> {
    if !job.multi_machine_download {
        return Ok(local.path.clone());
    }
    ensure_local_directory(&local.path, 0o700)?;
    let machine = safe_local_component(&job.machine).ok_or_else(|| TransferRequestError {
        class: FailureClass::Configuration,
        diagnostic: "machine name is not safe for a download container".to_string(),
        source: TransferRequestErrorSource::Local,
    })?;
    let machine_dir = local.path.join(machine);
    ensure_machine_container(&machine_dir)?;
    Ok(machine_dir.join(remote_basename(remote_path)?))
}

fn normalized_download_target(path: &Path) -> Result<NormalizedLocalPath, TransferRequestError> {
    Ok(NormalizedLocalPath {
        path: path.to_path_buf(),
        final_component: Some(
            path_safety::defensive_classify_or_absent_final(path).map_err(local_target_error)?,
        ),
    })
}

fn ensure_local_directory(path: &Path, mode: u32) -> Result<(), TransferRequestError> {
    ensure_local_directory_with_mode(path, mode, false)
}

fn ensure_local_directory_with_mode(
    path: &Path,
    mode: u32,
    apply_existing_mode: bool,
) -> Result<(), TransferRequestError> {
    match path_safety::defensive_classify_or_absent_final(path).map_err(local_target_error)? {
        crate::path_safety::SafePathFinal::Existing(SafePathEntryType::Directory) => {
            if apply_existing_mode {
                apply_local_directory_mode(path, mode)?;
            }
            Ok(())
        }
        crate::path_safety::SafePathFinal::Existing(_) => Err(TransferRequestError::path_safety(
            TransferPathError::new("local destination is not a directory"),
        )),
        crate::path_safety::SafePathFinal::Absent => create_local_directory(path, mode),
    }
}

fn apply_local_directory_mode(path: &Path, mode: u32) -> Result<(), TransferRequestError> {
    let (parent, name) = path_safety::defensive_open_parent(path).map_err(local_target_error)?;
    let descriptor = rustix::fs::openat(
        &parent,
        &name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        local_download_failure(
            "local directory could not be proved safe",
            Some(error.to_string()),
        )
    })?;
    let descriptor = LocalFile::from(descriptor);
    rustix::fs::fchmod(&descriptor, Mode::from(mode)).map_err(|error| {
        local_download_failure(
            "local directory mode could not be applied",
            Some(error.to_string()),
        )
    })?;
    validate_local_directory_mode(&descriptor, mode)
}

fn ensure_machine_container(path: &Path) -> Result<(), TransferRequestError> {
    ensure_local_directory(path, 0o700)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        local_download_failure(
            "local machine container could not be proved safe",
            Some(error.to_string()),
        )
    })?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != path_safety::effective_uid()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(TransferRequestError::path_safety(TransferPathError::new(
            "local machine container is not owner-only",
        )));
    }
    Ok(())
}

fn create_local_directory(path: &Path, mode: u32) -> Result<(), TransferRequestError> {
    let (parent, name) = path_safety::defensive_open_parent(path).map_err(local_target_error)?;
    rustix::fs::mkdirat(&parent, &name, Mode::from(mode)).map_err(|error| {
        local_download_failure(
            "local directory could not be created",
            Some(error.to_string()),
        )
    })?;
    let descriptor = rustix::fs::openat(
        &parent,
        &name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        local_download_failure(
            "local directory could not be proved safe",
            Some(error.to_string()),
        )
    })?;
    let descriptor = LocalFile::from(descriptor);
    rustix::fs::fchmod(&descriptor, Mode::from(mode)).map_err(|error| {
        local_download_failure(
            "local directory mode could not be applied",
            Some(error.to_string()),
        )
    })?;
    validate_local_directory_mode(&descriptor, mode)?;
    match path_safety::defensive_classify(path).map_err(local_target_error)? {
        SafePathEntryType::Directory => Ok(()),
        _ => Err(TransferRequestError::path_safety(TransferPathError::new(
            "local directory could not be proved safe",
        ))),
    }
}

fn validate_local_directory_mode(
    descriptor: &LocalFile,
    mode: u32,
) -> Result<(), TransferRequestError> {
    let metadata = descriptor.metadata().map_err(|error| {
        local_download_failure(
            "local directory could not be proved safe",
            Some(error.to_string()),
        )
    })?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o777 != mode & 0o777
    {
        return Err(TransferRequestError::path_safety(TransferPathError::new(
            "local directory mode could not be proved safe",
        )));
    }
    Ok(())
}

fn local_target_error(error: CapabilityError) -> TransferRequestError {
    match error {
        CapabilityError::UnsafePath => TransferRequestError::path_safety(TransferPathError::new(
            "local transfer path is unsafe",
        )),
        _ => local_download_failure("local transfer path is not permitted", None),
    }
}

fn safe_local_component(value: &str) -> Option<OsString> {
    (!value.is_empty()
        && value != "."
        && value != ".."
        && !value.as_bytes().contains(&b'/')
        && !value.as_bytes().contains(&0))
    .then(|| OsString::from(value))
}

fn remote_basename(path: &str) -> Result<OsString, TransferRequestError> {
    if path == "/" {
        return Ok(OsString::from("root"));
    }
    let name = path.rsplit('/').next().unwrap_or_default();
    remote_name_to_local_component(name)
}

fn remote_name_to_local_component(name: &str) -> Result<OsString, TransferRequestError> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(TransferRequestError::path_safety(TransferPathError::new(
            "remote source contains an unsafe entry",
        )));
    }
    Ok(OsString::from(name))
}

fn join_local_components(root: &Path, components: &[OsString]) -> PathBuf {
    components
        .iter()
        .fold(root.to_path_buf(), |path, component| path.join(component))
}

fn remote_tree_entry_kind(
    attrs: &FileAttributes,
    label: &'static str,
) -> Result<RemoteTreeEntryKind, TransferRequestError> {
    if attrs.file_type().is_file() {
        Ok(RemoteTreeEntryKind::File)
    } else if attrs.file_type().is_dir() {
        Ok(RemoteTreeEntryKind::Directory {
            mode: default_directory_mode(attrs.permissions),
        })
    } else {
        Err(TransferRequestError::path_safety(TransferPathError::new(
            match label {
                "remote source" => "remote source is not a file or directory",
                _ => "remote source descendant is not a file or directory",
            },
        )))
    }
}

fn join_remote_components(root: &str, components: &[String]) -> String {
    components.iter().fold(root.to_string(), |path, component| {
        join_remote_child_unchecked(&path, component)
    })
}

fn join_remote_child(parent: &str, name: &str) -> Result<String, TransferRequestError> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(TransferRequestError::path_safety(TransferPathError::new(
            "remote source contains an unsafe entry",
        )));
    }
    Ok(join_remote_child_unchecked(parent, name))
}

fn join_remote_child_unchecked(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn local_source_error(error: CapabilityError) -> TransferPathError {
    match error {
        CapabilityError::UnsafePath => TransferPathError::new("local transfer path is unsafe"),
        _ => TransferPathError::new("local transfer path is not permitted"),
    }
}

pub struct TransferSetupHandle {
    target_session: client::Handle<StrictHandler>,
    jump_session: Option<client::Handle<StrictHandler>>,
    raw_sftp: russh_sftp::client::RawSftpSession,
    extensions: BTreeMap<String, String>,
}

impl TransferSetupHandle {
    pub fn extensions(&self) -> &BTreeMap<String, String> {
        &self.extensions
    }

    pub fn raw_sftp(&self) -> &russh_sftp::client::RawSftpSession {
        &self.raw_sftp
    }

    pub async fn close(mut self) {
        let _ = self.raw_sftp.close_session();
        let _ = self
            .target_session
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await;
        if let Some(jump) = self.jump_session.take() {
            let _ = jump
                .disconnect(russh::Disconnect::ByApplication, "", "English")
                .await;
        }
    }
}

struct ProvisionSftpHandle {
    raw_sftp: russh_sftp::client::RawSftpSession,
    extensions: BTreeMap<String, String>,
}

impl ProvisionSftpHandle {
    async fn open(
        session: &client::Handle<StrictHandler>,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<Self, TransferSetupError> {
        let (raw_sftp, extensions) = open_raw_sftp_session(session, timeout, cancel).await?;
        Ok(Self {
            raw_sftp,
            extensions,
        })
    }

    fn close(self) {
        let _ = self.raw_sftp.close_session();
    }
}

pub(crate) async fn provision_sftp_gate_probe(
    session: &client::Handle<StrictHandler>,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<(), TransferSetupError> {
    let handle = ProvisionSftpHandle::open(session, timeout, cancel).await?;
    handle.close();
    Ok(())
}

pub(crate) async fn provision_transfer_target(
    session: &mut client::Handle<StrictHandler>,
    root_authenticated: bool,
    job: &TransferJob,
    privilege_context: &TransferPrivilegeContext,
    cancel: &CancellationToken,
) -> TransferTargetResult {
    let metadata = match TransferMetadata::from_job(job) {
        Ok(metadata) => metadata,
        Err(result) => return result,
    };
    if let Some(result) = provision_unsupported_options(job, &metadata) {
        return result;
    }
    if job.direction == TransferDirection::Upload {
        if let Some(profile_name) = job.privilege.as_deref() {
            if let Err(error) = privilege_context.profile(profile_name) {
                return TransferTargetResult::failure(
                    job.machine.clone(),
                    job.direction,
                    error.class,
                    error.diagnostic,
                );
            }
        } else if metadata.upload_owner.is_some() && !root_authenticated {
            return TransferTargetResult::failure(
                job.machine.clone(),
                job.direction,
                FailureClass::Configuration,
                "provisioning upload owner without a privilege profile requires a \
                 root-authenticated session",
            );
        }
    }
    let paths = match preflight_transfer_paths(job) {
        Ok(paths) => paths,
        Err(error) => {
            return TransferTargetResult::failure(
                job.machine.clone(),
                job.direction,
                FailureClass::TransferPathSafety,
                error.diagnostic(),
            );
        }
    };
    let upload_source = if job.direction == TransferDirection::Upload && !job.recursive {
        match UploadSource::open(&paths.local) {
            Ok(source) => Some(source),
            Err(error) => {
                return TransferTargetResult::failure(
                    job.machine.clone(),
                    job.direction,
                    FailureClass::TransferPathSafety,
                    error.diagnostic(),
                );
            }
        }
    } else {
        None
    };
    let download_destination = if job.direction == TransferDirection::Download
        && !job.recursive
        && !job.multi_machine_download
    {
        match DownloadDestination::analyze(&paths.local, job.overwrite) {
            Ok(destination) => Some(destination),
            Err(error) => {
                return TransferTargetResult::failure(
                    job.machine.clone(),
                    job.direction,
                    FailureClass::TransferPathSafety,
                    error.diagnostic(),
                );
            }
        }
    } else {
        None
    };
    let probe_timeout = Duration::from_secs(job.capability_probe_timeout.seconds);
    let handle = match ProvisionSftpHandle::open(session, probe_timeout, cancel).await {
        Ok(handle) => handle,
        Err(error) => return error.into_result(job),
    };
    let extensions = handle.extensions.clone();
    if provision_privileged_overwrite_missing_posix_rename(job, &metadata, &extensions) {
        handle.close();
        return TransferRequestError::new(
            FailureClass::CapabilityUnsupported,
            "remote target does not advertise posix-rename@openssh.com=1",
            TransferRequestErrorSource::Local,
        )
        .into_result(job);
    }
    let request_context = TransferRequestContext::new(&handle.raw_sftp, job, cancel.clone());
    let privileged = job.privilege.is_some() || metadata.upload_owner.is_some();
    let result = match request_context.resolve_remote_operand(&paths.remote).await {
        Ok(remote) => match (job.direction, upload_source, download_destination) {
            (TransferDirection::Upload, source, None) if privileged => request_context
                .upload_privileged(
                    PrivilegedUploadRequest {
                        job,
                        source,
                        local: &paths.local,
                        remote: &remote,
                        metadata: &metadata,
                        privilege_context,
                    },
                    session,
                )
                .await
                .map(|()| TransferTargetResult::success(job))
                .unwrap_or_else(|error| error.into_result(job)),
            (TransferDirection::Upload, None, None) if job.recursive => request_context
                .upload_recursive(job, &paths.local, &remote, &extensions, &metadata)
                .await
                .map(|()| TransferTargetResult::success(job))
                .unwrap_or_else(|error| error.into_result(job)),
            (TransferDirection::Upload, Some(source), None) => request_context
                .upload_single_file(job, source, &remote, &extensions, metadata.explicit_mode)
                .await
                .map(|()| TransferTargetResult::success(job))
                .unwrap_or_else(|error| error.into_result(job)),
            (TransferDirection::Download, None, None) if job.recursive => request_context
                .download_to_local_target(job, &paths.local, &remote, &metadata)
                .await
                .map(|()| TransferTargetResult::success(job))
                .unwrap_or_else(|error| error.into_result(job)),
            (TransferDirection::Download, None, Some(destination)) => request_context
                .download_single_file(job, &remote, destination, metadata.explicit_mode)
                .await
                .map(|()| TransferTargetResult::success(job))
                .unwrap_or_else(|error| error.into_result(job)),
            _ => TransferTargetResult::success(job),
        },
        Err(error) => error.into_result(job),
    };
    handle.close();
    result
}

fn provision_unsupported_options(
    job: &TransferJob,
    _metadata: &TransferMetadata,
) -> Option<TransferTargetResult> {
    if job.direction == TransferDirection::Download && job.privilege.is_some() {
        return Some(TransferTargetResult::failure(
            job.machine.clone(),
            job.direction,
            FailureClass::Configuration,
            "privileged download is not available",
        ));
    }
    None
}

fn provision_privileged_overwrite_missing_posix_rename(
    job: &TransferJob,
    metadata: &TransferMetadata,
    extensions: &BTreeMap<String, String>,
) -> bool {
    job.direction == TransferDirection::Upload
        && (job.privilege.is_some() || metadata.upload_owner.is_some())
        && job.overwrite
        && extensions.get(POSIX_RENAME_EXTENSION).map(String::as_str) != Some("1")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedRemotePath {
    pub(crate) path: String,
}

struct TransferRequestContext<'a> {
    raw_sftp: &'a russh_sftp::client::RawSftpSession,
    cancel: CancellationToken,
}

impl<'a> TransferRequestContext<'a> {
    fn new(
        raw_sftp: &'a russh_sftp::client::RawSftpSession,
        job: &TransferJob,
        cancel: CancellationToken,
    ) -> Self {
        raw_sftp.set_timeout(job.transfer_timeout.seconds);
        Self { raw_sftp, cancel }
    }

    async fn resolve_remote_operand(
        &self,
        operand: &RemoteTransferPath,
    ) -> Result<ResolvedRemotePath, TransferRequestError> {
        if !operand.is_relative() {
            return Ok(ResolvedRemotePath {
                path: operand.path().to_string(),
            });
        }
        let base = self.discover_remote_base().await?;
        Ok(ResolvedRemotePath {
            path: join_remote_base(&base, operand),
        })
    }

    async fn discover_remote_base(&self) -> Result<String, TransferRequestError> {
        let name = self
            .request("remote realpath", |raw_sftp| raw_sftp.realpath("."))
            .await?;
        let base = realpath_name(name).map_err(TransferRequestError::path_safety)?;
        let base = parse_remote_base_result(&base).map_err(TransferRequestError::path_safety)?;
        self.validate_remote_base_components(&base).await?;
        Ok(base)
    }

    async fn validate_remote_base_components(
        &self,
        base: &str,
    ) -> Result<(), TransferRequestError> {
        for prefix in remote_component_prefixes(base).map_err(TransferRequestError::path_safety)? {
            let attrs = self
                .request("remote lstat", |raw_sftp| raw_sftp.lstat(prefix))
                .await
                .map_err(|error| {
                    path_safety_proof_failure(
                        error,
                        "remote login-directory base could not be proved safe",
                    )
                })?;
            if !attrs.attrs.file_type().is_dir() {
                return Err(TransferRequestError::path_safety(TransferPathError::new(
                    "remote login-directory base contains an unsafe component",
                )));
            }
        }
        Ok(())
    }

    async fn upload_single_file(
        &self,
        job: &TransferJob,
        source: UploadSource,
        remote: &ResolvedRemotePath,
        extensions: &BTreeMap<String, String>,
        explicit_mode: Option<u32>,
    ) -> Result<(), UploadError> {
        let source = UploadSource {
            mode: explicit_mode.unwrap_or(source.mode),
            ..source
        };
        let destination = self
            .analyze_upload_destination(&remote.path, job.overwrite)
            .await?;
        if destination.state == UploadDestinationState::ExistingRegular {
            match extensions.get(POSIX_RENAME_EXTENSION).map(String::as_str) {
                Some("1") => {}
                _ => {
                    return Err(TransferRequestError {
                        class: FailureClass::CapabilityUnsupported,
                        diagnostic: "remote target does not advertise posix-rename@openssh.com=1"
                            .to_string(),
                        source: TransferRequestErrorSource::Local,
                    }
                    .into());
                }
            }
        }
        let temp_path = same_directory_temp_path(&destination.parent)?;
        let handle = match self.open_upload_temp(&temp_path).await {
            Ok(handle) => handle,
            Err(error) if error.possibly_created_temp() => {
                let residue = self.cleanup_temp_after_failure(None, &temp_path).await;
                return Err(UploadError::new(error.for_upload_dispatch(), residue));
            }
            Err(error) => return Err(error.into()),
        };
        self.write_upload_temp(&handle, &temp_path, source, &destination)
            .await?;
        Ok(())
    }

    async fn upload_recursive(
        &self,
        job: &TransferJob,
        local: &NormalizedLocalPath,
        remote: &ResolvedRemotePath,
        extensions: &BTreeMap<String, String>,
        metadata: &TransferMetadata,
    ) -> Result<(), UploadError> {
        for entry in
            collect_local_upload_entries(local).map_err(TransferRequestError::path_safety)?
        {
            let is_root = entry.remote_components.is_empty();
            let remote_path = join_remote_components(&remote.path, &entry.remote_components);
            match entry.kind {
                LocalUploadEntryKind::Directory { mode } => {
                    self.ensure_remote_directory(
                        &remote_path,
                        metadata.root_mode(mode, is_root),
                        is_root && metadata.explicit_mode.is_some(),
                    )
                    .await
                    .map_err(UploadError::from)?;
                }
                LocalUploadEntryKind::File(file) => {
                    let source = file.open().map_err(TransferRequestError::path_safety)?;
                    self.upload_single_file(
                        job,
                        source,
                        &ResolvedRemotePath { path: remote_path },
                        extensions,
                        if is_root {
                            metadata.explicit_mode
                        } else {
                            None
                        },
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    async fn upload_privileged(
        &self,
        request: PrivilegedUploadRequest<'_>,
        session: &mut client::Handle<StrictHandler>,
    ) -> Result<(), UploadError> {
        let PrivilegedUploadRequest {
            job,
            source,
            local,
            remote,
            metadata,
            privilege_context,
        } = request;
        let timeout = Duration::from_secs(job.capability_probe_timeout.seconds);
        let dispatch = match job.privilege.as_deref() {
            Some(profile_name) => PrivilegedUploadDispatch::Sudo(
                prepare_transfer_sudo(
                    session,
                    privilege_context,
                    profile_name,
                    timeout,
                    &self.cancel,
                )
                .await
                .map_err(UploadError::from)?,
            ),
            None => PrivilegedUploadDispatch::RootDirect,
        };
        let staged = self
            .stage_privileged_upload_payload(job, source, local, metadata)
            .await?;
        let launcher = match privileged_upload_launcher(
            &staged,
            remote,
            metadata,
            job.overwrite,
            dispatch.uid_source(),
        ) {
            Ok(launcher) => launcher,
            Err(error) => {
                let residue = self.cleanup_staged_upload(&staged).await;
                return Err(UploadError::new(error, residue));
            }
        };
        let staged_launcher = match stage_privileged_launcher(
            session,
            &launcher,
            dispatch.sidecar(),
            timeout,
            &self.cancel,
        )
        .await
        {
            Ok(staged_launcher) => staged_launcher,
            Err(error) => {
                let residue =
                    error.possible_staging_residue || self.cleanup_staged_upload(&staged).await;
                return Err(UploadError::new(error.error, residue));
            }
        };
        if let Err(error) =
            make_privileged_launcher_executable(session, &staged_launcher.launcher, timeout).await
        {
            let error =
                cleanup_exec_staging_or_residue(session, &staged_launcher.launcher, timeout, error)
                    .await;
            let residue =
                error.possible_staging_residue || self.cleanup_staged_upload(&staged).await;
            return Err(UploadError::new(error.error, residue));
        }
        let command_line = match dispatch
            .command(privilege_context, &staged_launcher.launcher, &self.cancel)
            .await
        {
            Ok(command_line) => command_line,
            Err(error) => {
                let error = cleanup_exec_staging_or_residue(
                    session,
                    &staged_launcher.launcher,
                    timeout,
                    RemoteStagingError::new(error, true),
                )
                .await;
                let residue =
                    error.possible_staging_residue || self.cleanup_staged_upload(&staged).await;
                return Err(UploadError::new(error.error, residue));
            }
        };
        let command = match run_remote_command(
            session,
            &command_line.command,
            command_line.password_stdin,
            Duration::from_secs(job.transfer_timeout.seconds),
            false,
            dispatch.control_frame_nonce().is_some(),
            &self.cancel,
        )
        .await
        {
            Ok(command) => command,
            Err(error) => {
                let error = cleanup_exec_staging_or_residue(
                    session,
                    &staged_launcher.launcher,
                    timeout,
                    RemoteStagingError::new(error.for_upload_dispatch(), true),
                )
                .await;
                return Err(UploadError::new(error.error, true));
            }
        };
        let exec_residue = cleanup_exec_staging(session, &staged_launcher.launcher, timeout)
            .await
            .is_err();
        self.classify_privileged_install_result(
            command,
            dispatch.control_frame_nonce(),
            staged,
            exec_residue,
        )
        .await
    }

    async fn stage_privileged_upload_payload(
        &self,
        job: &TransferJob,
        source: Option<UploadSource>,
        local: &NormalizedLocalPath,
        metadata: &TransferMetadata,
    ) -> Result<StagedUpload, UploadError> {
        let login_base = self
            .discover_remote_base()
            .await
            .map_err(UploadError::from)?;
        let staging_base = self
            .ensure_transfer_staging_base(&login_base)
            .await
            .map_err(UploadError::from)?;
        let action_dir = self
            .create_transfer_action_dir(&staging_base)
            .await
            .map_err(UploadError::from)?;
        let mut staged = StagedUpload::new(action_dir);
        let result = if job.recursive {
            let entries =
                collect_local_upload_entries(local).map_err(TransferRequestError::path_safety)?;
            for entry in entries {
                self.stage_local_upload_entry(entry, metadata, &mut staged)
                    .await?;
            }
            Ok(())
        } else {
            let source = source.expect("non-recursive privileged upload has an opened source");
            let final_mode = metadata.explicit_mode.unwrap_or(source.mode);
            self.stage_privileged_upload_file(
                staged.payload_path.clone(),
                source,
                final_mode,
                Vec::new(),
                &mut staged,
            )
            .await
        };
        if let Err(error) = result {
            let residue = self.cleanup_staged_upload(&staged).await;
            return Err(UploadError::new(error, residue));
        }
        Ok(staged)
    }

    async fn stage_local_upload_entry(
        &self,
        entry: LocalUploadEntry,
        metadata: &TransferMetadata,
        staged: &mut StagedUpload,
    ) -> Result<(), TransferRequestError> {
        let is_root = entry.remote_components.is_empty();
        let stage_path = staged.stage_path(&entry.remote_components);
        match entry.kind {
            LocalUploadEntryKind::Directory { mode } => {
                let final_mode = metadata.root_mode(mode, is_root);
                self.create_transfer_staging_directory(&stage_path).await?;
                staged.cleanup_entries.push(StagedCleanupEntry {
                    path: stage_path,
                    kind: StagedInstallKind::Directory,
                });
                staged.install_entries.push(StagedInstallEntry {
                    remote_components: entry.remote_components,
                    kind: StagedInstallKind::Directory,
                    mode: final_mode,
                });
                Ok(())
            }
            LocalUploadEntryKind::File(file) => {
                let source = file.open().map_err(TransferRequestError::path_safety)?;
                let final_mode = metadata.root_mode(source.mode, is_root);
                self.stage_privileged_upload_file(
                    stage_path,
                    source,
                    final_mode,
                    entry.remote_components,
                    staged,
                )
                .await
            }
        }
    }

    async fn stage_privileged_upload_file(
        &self,
        stage_path: String,
        source: UploadSource,
        final_mode: u32,
        remote_components: Vec<String>,
        staged: &mut StagedUpload,
    ) -> Result<(), TransferRequestError> {
        staged.cleanup_entries.push(StagedCleanupEntry {
            path: stage_path.clone(),
            kind: StagedInstallKind::File,
        });
        let staging_source = UploadSource {
            mode: TEMP_INITIAL_MODE,
            ..source
        };
        let handle = self.open_upload_temp(&stage_path).await?;
        self.write_staging_file(&handle, &stage_path, staging_source)
            .await?;
        staged.install_entries.push(StagedInstallEntry {
            remote_components,
            kind: StagedInstallKind::File,
            mode: final_mode,
        });
        Ok(())
    }

    async fn download_to_local_target(
        &self,
        job: &TransferJob,
        local: &NormalizedLocalPath,
        remote: &ResolvedRemotePath,
        metadata: &TransferMetadata,
    ) -> Result<(), DownloadError> {
        let target =
            local_download_target_path(job, local, &remote.path).map_err(DownloadError::from)?;
        if job.recursive {
            self.download_recursive_root(job, &remote.path, &target, metadata)
                .await
        } else {
            let destination = DownloadDestination::analyze(
                &normalized_download_target(&target).map_err(DownloadError::from)?,
                job.overwrite,
            )
            .map_err(TransferRequestError::path_safety)?;
            self.download_single_file(job, remote, destination, metadata.explicit_mode)
                .await
        }
    }

    async fn download_recursive_root(
        &self,
        job: &TransferJob,
        remote_path: &str,
        local_root: &Path,
        metadata: &TransferMetadata,
    ) -> Result<(), DownloadError> {
        let entries = self
            .collect_remote_tree(remote_path)
            .await
            .map_err(DownloadError::from)?;
        for entry in entries {
            let is_root = entry.local_components.is_empty();
            let local_path = join_local_components(local_root, &entry.local_components);
            match entry.kind {
                RemoteTreeEntryKind::Directory { mode } => {
                    ensure_local_directory_with_mode(
                        &local_path,
                        metadata.root_mode(mode, is_root),
                        is_root && metadata.explicit_mode.is_some(),
                    )
                    .map_err(DownloadError::from)?;
                }
                RemoteTreeEntryKind::File => {
                    let destination = DownloadDestination::analyze(
                        &normalized_download_target(&local_path).map_err(DownloadError::from)?,
                        job.overwrite,
                    )
                    .map_err(TransferRequestError::path_safety)?;
                    self.download_single_file(
                        job,
                        &ResolvedRemotePath { path: entry.path },
                        destination,
                        if is_root {
                            metadata.explicit_mode
                        } else {
                            None
                        },
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    async fn download_single_file(
        &self,
        _job: &TransferJob,
        remote: &ResolvedRemotePath,
        destination: DownloadDestination,
        explicit_mode: Option<u32>,
    ) -> Result<(), DownloadError> {
        let source = self.open_download_source(&remote.path).await?;
        let mut temp = match self.open_local_download_temp(&destination) {
            Ok(temp) => temp,
            Err(error) => {
                self.close_download_source(&source.handle).await;
                return Err(error);
            }
        };
        if let Err(error) = self
            .copy_download_source(&source, &mut temp, &destination)
            .await
        {
            self.close_download_source(&source.handle).await;
            return Err(error);
        }
        if let Err(error) = self
            .request("remote source close", |raw_sftp| {
                raw_sftp.close(source.handle.clone())
            })
            .await
        {
            return Err(DownloadError::new(error.for_download_dispatch(), false)
                .with_cleanup(&destination, &temp.name));
        }
        let mode = explicit_mode.unwrap_or(source.mode);
        if let Err(error) = apply_local_download_mode(&temp.file, mode) {
            return Err(DownloadError::new(error, false).with_cleanup(&destination, &temp.name));
        }
        if let Err(error) = sync_local_download_temp(&temp.file) {
            return Err(DownloadError::new(error, false).with_cleanup(&destination, &temp.name));
        }
        if let Err(error) = validate_local_download_temp(&temp.file, source.size) {
            return Err(DownloadError::new(error, false).with_cleanup(&destination, &temp.name));
        }
        match destination.state {
            DownloadDestinationState::Absent => finalize_new_local_destination(&destination, &temp),
            DownloadDestinationState::ExistingRegular => {
                finalize_existing_local_destination(&destination, &temp)
            }
        }
    }

    async fn open_download_source(
        &self,
        path: &str,
    ) -> Result<DownloadSource, TransferRequestError> {
        let source = self.analyze_download_source(path).await?;
        let handle = self
            .request("remote source open", |raw_sftp| {
                raw_sftp.open(path.to_string(), OpenFlags::READ, FileAttributes::empty())
            })
            .await?
            .handle;
        let handle_attrs = match self
            .request("remote source fstat", |raw_sftp| {
                raw_sftp.fstat(handle.clone())
            })
            .await
        {
            Ok(attrs) => attrs,
            Err(error) => {
                self.close_download_source(&handle).await;
                return Err(post_open_download_source_proof_failure(
                    error,
                    "remote source post-open proof failed",
                ));
            }
        };
        let path_attrs = match self
            .request("remote source post-open lstat", |raw_sftp| {
                raw_sftp.lstat(path.to_string())
            })
            .await
        {
            Ok(attrs) => attrs,
            Err(error) => {
                self.close_download_source(&handle).await;
                return Err(post_open_download_source_proof_failure(
                    error,
                    "remote source post-open proof failed",
                ));
            }
        };
        if let Err(error) =
            validate_download_source_revalidation(&source, &handle_attrs.attrs, &path_attrs.attrs)
        {
            self.close_download_source(&handle).await;
            return Err(error);
        }
        Ok(DownloadSource {
            handle,
            size: source.size,
            mode: source.mode,
        })
    }

    async fn analyze_download_source(
        &self,
        path: &str,
    ) -> Result<AnalyzedDownloadSource, TransferRequestError> {
        let (parent, _final_component) = split_remote_destination(path)?;
        self.validate_remote_directory_components(
            &parent,
            "remote source parent could not be proved safe",
            "remote source parent contains an unsafe component",
        )
        .await?;
        let attrs = self
            .request("remote source lstat", |raw_sftp| {
                raw_sftp.lstat(path.to_string())
            })
            .await
            .map_err(|error| {
                path_safety_proof_failure(error, "remote source could not be proved safe")
            })?;
        analyzed_download_source(&attrs.attrs)
    }

    async fn copy_download_source(
        &self,
        source: &DownloadSource,
        temp: &mut LocalTempFile,
        destination: &DownloadDestination,
    ) -> Result<(), DownloadError> {
        let mut offset = 0u64;
        while offset < source.size {
            if let Err(error) = self.check_cancelled_after_dispatch() {
                return Err(error.with_cleanup(destination, &temp.name));
            }
            let request_len =
                std::cmp::min(DOWNLOAD_READ_CHUNK as u64, source.size - offset) as u32;
            let data = match self
                .request("remote source read", |raw_sftp| {
                    raw_sftp.read(source.handle.clone(), offset, request_len)
                })
                .await
            {
                Ok(data) => data,
                Err(error)
                    if error.source == TransferRequestErrorSource::SftpStatus(StatusCode::Eof) =>
                {
                    let error = TransferRequestError::path_safety(TransferPathError::new(
                        "remote source ended before expected size",
                    ));
                    return Err(
                        DownloadError::new(error, false).with_cleanup(destination, &temp.name)
                    );
                }
                Err(error) => {
                    return Err(DownloadError::new(error.for_download_dispatch(), false)
                        .with_cleanup(destination, &temp.name));
                }
            };
            if data.data.is_empty() {
                let error = TransferRequestError::path_safety(TransferPathError::new(
                    "remote source ended before expected size",
                ));
                return Err(DownloadError::new(error, false).with_cleanup(destination, &temp.name));
            }
            if let Err(error) = temp.file.write_all(&data.data) {
                let error = local_download_failure(
                    "local download temp could not be written",
                    Some(error.to_string()),
                );
                return Err(DownloadError::new(error, false).with_cleanup(destination, &temp.name));
            }
            offset += data.data.len() as u64;
        }
        Ok(())
    }

    fn open_local_download_temp(
        &self,
        destination: &DownloadDestination,
    ) -> Result<LocalTempFile, DownloadError> {
        self.check_cancelled_after_dispatch()?;
        let temp_name = local_download_temp_name().map_err(DownloadError::from)?;
        self.open_named_local_download_temp(destination, temp_name)
    }

    fn open_named_local_download_temp(
        &self,
        destination: &DownloadDestination,
        temp_name: OsString,
    ) -> Result<LocalTempFile, DownloadError> {
        let descriptor = match rustix::fs::openat(
            &destination.parent,
            &temp_name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from(TEMP_INITIAL_MODE),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                let primary = local_download_failure(
                    "local download temp could not be created",
                    Some(error.to_string()),
                );
                return Err(DownloadError::new(primary, false));
            }
        };
        let file = LocalFile::from(descriptor);
        if !file
            .metadata()
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
        {
            let error = TransferRequestError::path_safety(TransferPathError::new(
                "local download temp could not be proved safe",
            ));
            return Err(DownloadError::new(error, false).with_cleanup(destination, &temp_name));
        }
        Ok(LocalTempFile {
            file,
            name: temp_name,
        })
    }

    async fn close_download_source(&self, handle: &str) {
        let _ = self
            .request("remote source cleanup close", |raw_sftp| {
                raw_sftp.close(handle.to_string())
            })
            .await;
    }

    fn check_cancelled_after_dispatch(&self) -> Result<(), DownloadError> {
        if self.cancel.is_cancelled() {
            Err(DownloadError::new(
                TransferRequestError {
                    class: FailureClass::Cancellation,
                    diagnostic: "cancelled".to_string(),
                    source: TransferRequestErrorSource::CancellationAfterDispatch,
                },
                false,
            ))
        } else {
            Ok(())
        }
    }

    async fn analyze_upload_destination(
        &self,
        path: &str,
        overwrite: bool,
    ) -> Result<UploadDestination, TransferRequestError> {
        let (parent, _final_component) = split_remote_destination(path)?;
        self.validate_upload_parent_components(&parent).await?;
        let attrs = match self
            .request("remote destination lstat", |raw_sftp| {
                raw_sftp.lstat(path.to_string())
            })
            .await
        {
            Ok(attrs) => attrs,
            Err(error) if error.is_no_such_file() => {
                return Ok(UploadDestination {
                    path: path.to_string(),
                    parent,
                    state: UploadDestinationState::Absent,
                });
            }
            Err(error) => return Err(error),
        };
        if !attrs.attrs.file_type().is_file() {
            return Err(TransferRequestError::path_safety(TransferPathError::new(
                "remote destination is not a regular file",
            )));
        }
        if !overwrite {
            return Err(TransferRequestError::path_safety(TransferPathError::new(
                "remote destination exists; pass --overwrite to replace it",
            )));
        }
        Ok(UploadDestination {
            path: path.to_string(),
            parent,
            state: UploadDestinationState::ExistingRegular,
        })
    }

    async fn validate_upload_parent_components(
        &self,
        parent: &str,
    ) -> Result<(), TransferRequestError> {
        self.validate_remote_directory_components(
            parent,
            "remote destination parent could not be proved safe",
            "remote destination parent contains an unsafe component",
        )
        .await
    }

    async fn ensure_remote_directory(
        &self,
        path: &str,
        mode: u32,
        apply_existing_mode: bool,
    ) -> Result<(), TransferRequestError> {
        if path == "/" {
            return Ok(());
        }
        let (parent, _final_component) = split_remote_destination(path)?;
        self.validate_remote_directory_components(
            &parent,
            "remote destination parent could not be proved safe",
            "remote destination parent contains an unsafe component",
        )
        .await?;
        match self
            .request("remote directory lstat", |raw_sftp| {
                raw_sftp.lstat(path.to_string())
            })
            .await
        {
            Ok(attrs) if attrs.attrs.file_type().is_dir() => {
                if apply_existing_mode {
                    self.apply_remote_directory_mode(path, mode).await?;
                }
                return Ok(());
            }
            Ok(_) => {
                return Err(TransferRequestError::path_safety(TransferPathError::new(
                    "remote destination is not a directory",
                )));
            }
            Err(error) if error.is_no_such_file() => {}
            Err(error) => return Err(error),
        }
        if let Err(error) = self
            .request("remote directory mkdir", |raw_sftp| {
                raw_sftp.mkdir(path.to_string(), mode_attrs(mode))
            })
            .await
        {
            return Err(error.for_upload_dispatch());
        }
        self.request("remote directory setstat", |raw_sftp| {
            raw_sftp.setstat(path.to_string(), mode_attrs(mode))
        })
        .await
        .map_err(|error| error.for_upload_dispatch())?;
        let attrs = self
            .request("remote directory post-mkdir lstat", |raw_sftp| {
                raw_sftp.lstat(path.to_string())
            })
            .await
            .map_err(|error| error.for_upload_dispatch())?;
        if !attrs.attrs.file_type().is_dir() {
            return Err(TransferRequestError::path_safety(TransferPathError::new(
                "remote destination directory could not be proved safe",
            )));
        }
        if attrs.attrs.permissions.map(|mode| mode & 0o777) != Some(mode & 0o777) {
            return Err(TransferRequestError::path_safety(TransferPathError::new(
                "remote destination directory mode could not be proved safe",
            )));
        }
        Ok(())
    }

    async fn apply_remote_directory_mode(
        &self,
        path: &str,
        mode: u32,
    ) -> Result<(), TransferRequestError> {
        self.request("remote directory setstat", |raw_sftp| {
            raw_sftp.setstat(path.to_string(), mode_attrs(mode))
        })
        .await
        .map_err(|error| error.for_upload_dispatch())?;
        let attrs = self
            .request("remote directory post-setstat lstat", |raw_sftp| {
                raw_sftp.lstat(path.to_string())
            })
            .await
            .map_err(|error| error.for_upload_dispatch())?;
        if !attrs.attrs.file_type().is_dir()
            || attrs.attrs.permissions.map(|mode| mode & 0o777) != Some(mode & 0o777)
        {
            return Err(TransferRequestError::path_safety(TransferPathError::new(
                "remote destination directory mode could not be proved safe",
            )));
        }
        Ok(())
    }

    async fn ensure_transfer_staging_base(
        &self,
        login_base: &str,
    ) -> Result<String, TransferRequestError> {
        let broil = join_remote_child_unchecked(login_base, ".broil");
        self.ensure_transfer_staging_directory(&broil).await?;
        let tmp = join_remote_child_unchecked(&broil, "tmp");
        self.ensure_transfer_staging_directory(&tmp).await?;
        let transfer = join_remote_child_unchecked(&tmp, "transfer");
        self.ensure_transfer_staging_directory(&transfer).await?;
        Ok(transfer)
    }

    async fn ensure_transfer_staging_directory(
        &self,
        path: &str,
    ) -> Result<(), TransferRequestError> {
        if path == "/" {
            return Err(TransferRequestError::path_safety(TransferPathError::new(
                "remote transfer staging path is unsafe",
            )));
        }
        let (parent, _final_component) = split_remote_destination(path)?;
        self.validate_remote_directory_components(
            &parent,
            "remote transfer staging parent could not be proved safe",
            "remote transfer staging parent contains an unsafe component",
        )
        .await?;
        match self
            .request("remote transfer staging directory lstat", |raw_sftp| {
                raw_sftp.lstat(path.to_string())
            })
            .await
        {
            Ok(attrs) if attrs.attrs.file_type().is_dir() => {}
            Ok(_) => {
                return Err(TransferRequestError::path_safety(TransferPathError::new(
                    "remote transfer staging path is not a directory",
                )));
            }
            Err(error) if error.is_no_such_file() => {
                self.request("remote transfer staging directory mkdir", |raw_sftp| {
                    raw_sftp.mkdir(path.to_string(), mode_attrs(0o700))
                })
                .await
                .map_err(|error| error.for_upload_dispatch())?;
            }
            Err(error) => return Err(error),
        }
        self.request("remote transfer staging directory setstat", |raw_sftp| {
            raw_sftp.setstat(path.to_string(), mode_attrs(0o700))
        })
        .await
        .map_err(|error| error.for_upload_dispatch())?;
        self.validate_transfer_staging_directory(path).await
    }

    async fn create_transfer_action_dir(
        &self,
        staging_base: &str,
    ) -> Result<String, TransferRequestError> {
        let action_dir = transfer_action_dir(staging_base)?;
        self.request("remote transfer action directory mkdir", |raw_sftp| {
            raw_sftp.mkdir(action_dir.clone(), mode_attrs(0o700))
        })
        .await
        .map_err(|error| error.for_upload_dispatch())?;
        self.request("remote transfer action directory setstat", |raw_sftp| {
            raw_sftp.setstat(action_dir.clone(), mode_attrs(0o700))
        })
        .await
        .map_err(|error| error.for_upload_dispatch())?;
        self.validate_transfer_staging_directory(&action_dir)
            .await?;
        Ok(action_dir)
    }

    async fn create_transfer_staging_directory(
        &self,
        path: &str,
    ) -> Result<(), TransferRequestError> {
        self.request("remote transfer payload directory mkdir", |raw_sftp| {
            raw_sftp.mkdir(path.to_string(), mode_attrs(0o700))
        })
        .await
        .map_err(|error| error.for_upload_dispatch())?;
        self.request("remote transfer payload directory setstat", |raw_sftp| {
            raw_sftp.setstat(path.to_string(), mode_attrs(0o700))
        })
        .await
        .map_err(|error| error.for_upload_dispatch())?;
        self.validate_transfer_staging_directory(path).await
    }

    async fn validate_transfer_staging_directory(
        &self,
        path: &str,
    ) -> Result<(), TransferRequestError> {
        let attrs = self
            .request("remote transfer staging directory proof", |raw_sftp| {
                raw_sftp.lstat(path.to_string())
            })
            .await
            .map_err(|error| error.for_upload_dispatch())?;
        if !attrs.attrs.file_type().is_dir()
            || attrs.attrs.permissions.map(|mode| mode & 0o777) != Some(0o700)
        {
            return Err(TransferRequestError::path_safety(TransferPathError::new(
                "remote transfer staging directory could not be proved owner-only",
            )));
        }
        Ok(())
    }

    async fn collect_remote_tree(
        &self,
        root: &str,
    ) -> Result<Vec<RemoteTreeEntry>, TransferRequestError> {
        let attrs = self
            .remote_tree_lstat(root, "remote source could not be proved safe")
            .await?;
        let root_kind = remote_tree_entry_kind(&attrs.attrs, "remote source")?;
        let mut entries = vec![RemoteTreeEntry {
            path: root.to_string(),
            local_components: Vec::new(),
            kind: root_kind,
        }];
        if !matches!(root_kind, RemoteTreeEntryKind::Directory { .. }) {
            return Ok(entries);
        }

        let mut stack = vec![(root.to_string(), Vec::<OsString>::new())];
        while let Some((directory, relative)) = stack.pop() {
            let mut children = self.read_remote_directory(&directory).await?;
            children.sort();
            for child in children {
                let child_path = join_remote_child(&directory, &child)?;
                let attrs = self
                    .remote_tree_lstat(
                        &child_path,
                        "remote source descendant could not be proved safe",
                    )
                    .await?;
                let kind = remote_tree_entry_kind(&attrs.attrs, "remote source descendant")?;
                let mut child_relative = relative.clone();
                child_relative.push(remote_name_to_local_component(&child)?);
                entries.push(RemoteTreeEntry {
                    path: child_path.clone(),
                    local_components: child_relative.clone(),
                    kind,
                });
                if matches!(kind, RemoteTreeEntryKind::Directory { .. }) {
                    stack.push((child_path, child_relative));
                }
            }
        }
        Ok(entries)
    }

    async fn remote_tree_lstat(
        &self,
        path: &str,
        diagnostic: &'static str,
    ) -> Result<russh_sftp::protocol::Attrs, TransferRequestError> {
        self.request("remote tree lstat", |raw_sftp| {
            raw_sftp.lstat(path.to_string())
        })
        .await
        .map_err(|error| path_safety_proof_failure(error, diagnostic))
    }

    async fn read_remote_directory(&self, path: &str) -> Result<Vec<String>, TransferRequestError> {
        let handle = self
            .request("remote directory open", |raw_sftp| {
                raw_sftp.opendir(path.to_string())
            })
            .await
            .map_err(|error| error.for_download_dispatch())?
            .handle;
        let mut names = Vec::new();
        loop {
            match self
                .request("remote directory read", |raw_sftp| {
                    raw_sftp.readdir(handle.clone())
                })
                .await
            {
                Ok(name) => {
                    names.extend(name.files.into_iter().map(|file| file.filename));
                }
                Err(error)
                    if error.source == TransferRequestErrorSource::SftpStatus(StatusCode::Eof) =>
                {
                    break;
                }
                Err(error) => {
                    self.close_download_source(&handle).await;
                    return Err(error.for_download_dispatch());
                }
            }
        }
        self.close_download_source(&handle).await;
        Ok(names)
    }

    async fn validate_remote_directory_components(
        &self,
        path: &str,
        missing_diagnostic: &'static str,
        unsafe_diagnostic: &'static str,
    ) -> Result<(), TransferRequestError> {
        for prefix in remote_component_prefixes(path).map_err(TransferRequestError::path_safety)? {
            let attrs = self
                .request("remote path component lstat", |raw_sftp| {
                    raw_sftp.lstat(prefix)
                })
                .await
                .map_err(|error| path_safety_proof_failure(error, missing_diagnostic))?;
            if !attrs.attrs.file_type().is_dir() {
                return Err(TransferRequestError::path_safety(TransferPathError::new(
                    unsafe_diagnostic,
                )));
            }
        }
        Ok(())
    }

    async fn open_upload_temp(&self, temp_path: &str) -> Result<String, TransferRequestError> {
        let handle = self
            .request("remote temp open", |raw_sftp| {
                raw_sftp.open(
                    temp_path.to_string(),
                    OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
                    mode_attrs(TEMP_INITIAL_MODE),
                )
            })
            .await?;
        Ok(handle.handle)
    }

    async fn write_staging_file(
        &self,
        handle: &str,
        stage_path: &str,
        mut source: UploadSource,
    ) -> Result<(), TransferRequestError> {
        let mut offset = 0u64;
        let mut buffer = vec![0u8; UPLOAD_WRITE_CHUNK];
        loop {
            let read = source.file.read(&mut buffer).map_err(|error| {
                TransferRequestError::path_safety(TransferPathError::new(
                    "local transfer source could not be read",
                ))
                .with_diagnostic(format!("local transfer source could not be read: {error}"))
            })?;
            if read == 0 {
                break;
            }
            if let Err(error) = self
                .request("remote transfer staging write", |raw_sftp| {
                    raw_sftp.write(handle.to_string(), offset, buffer[..read].to_vec())
                })
                .await
            {
                self.close_staging_handle_after_failure(handle).await;
                return Err(error.for_upload_dispatch());
            }
            offset += read as u64;
        }
        let handle_attrs = match self
            .request("remote transfer staging fstat", |raw_sftp| {
                raw_sftp.fstat(handle.to_string())
            })
            .await
        {
            Ok(attrs) => attrs,
            Err(error) => {
                self.close_staging_handle_after_failure(handle).await;
                return Err(error.for_upload_dispatch());
            }
        };
        if let Err(error) = validate_handle_attrs(&handle_attrs.attrs, offset, source.size) {
            self.close_staging_handle_after_failure(handle).await;
            return Err(error);
        }
        if let Err(error) = self
            .request("remote transfer staging fsetstat", |raw_sftp| {
                raw_sftp.fsetstat(handle.to_string(), mode_attrs(source.mode))
            })
            .await
        {
            self.close_staging_handle_after_failure(handle).await;
            return Err(error.for_upload_dispatch());
        }
        self.request("remote transfer staging close", |raw_sftp| {
            raw_sftp.close(handle.to_string())
        })
        .await
        .map_err(|error| error.for_upload_dispatch())?;
        let stage_attrs = self
            .request("remote transfer staging lstat", |raw_sftp| {
                raw_sftp.lstat(stage_path.to_string())
            })
            .await
            .map_err(|error| error.for_upload_dispatch())?;
        validate_temp_revalidation(&handle_attrs.attrs, &stage_attrs.attrs, source.size)?;
        if stage_attrs.attrs.permissions.map(|mode| mode & 0o777) != Some(TEMP_INITIAL_MODE) {
            return Err(TransferRequestError::path_safety(TransferPathError::new(
                "remote transfer staging file could not be proved owner-only",
            )));
        }
        Ok(())
    }

    async fn close_staging_handle_after_failure(&self, handle: &str) {
        let _ = self
            .request("remote transfer staging cleanup close", |raw_sftp| {
                raw_sftp.close(handle.to_string())
            })
            .await;
    }

    async fn write_upload_temp(
        &self,
        handle: &str,
        temp_path: &str,
        mut source: UploadSource,
        destination: &UploadDestination,
    ) -> Result<(), UploadError> {
        let mut offset = 0u64;
        let mut buffer = vec![0u8; UPLOAD_WRITE_CHUNK];
        loop {
            let read = match source.file.read(&mut buffer) {
                Ok(read) => read,
                Err(error) => {
                    let error = TransferRequestError::path_safety(TransferPathError::new(
                        "local transfer source could not be read",
                    ))
                    .with_diagnostic(format!("local transfer source could not be read: {error}"));
                    return Err(UploadError::new(error, false)
                        .with_cleanup(self, Some(handle), temp_path)
                        .await);
                }
            };
            if read == 0 {
                break;
            }
            let write_result = self
                .request("remote temp write", |raw_sftp| {
                    raw_sftp.write(handle.to_string(), offset, buffer[..read].to_vec())
                })
                .await;
            if let Err(error) = write_result {
                return Err(UploadError::new(error.for_upload_dispatch(), false)
                    .with_cleanup(self, Some(handle), temp_path)
                    .await);
            }
            offset += read as u64;
        }
        let handle_attrs = match self
            .request("remote temp fstat", |raw_sftp| {
                raw_sftp.fstat(handle.to_string())
            })
            .await
        {
            Ok(attrs) => attrs,
            Err(error) => {
                return Err(UploadError::new(error.for_upload_dispatch(), false)
                    .with_cleanup(self, Some(handle), temp_path)
                    .await);
            }
        };
        if let Err(error) = validate_handle_attrs(&handle_attrs.attrs, offset, source.size) {
            return Err(UploadError::new(error, false)
                .with_cleanup(self, Some(handle), temp_path)
                .await);
        }
        if let Err(error) = self
            .request("remote temp fsetstat", |raw_sftp| {
                raw_sftp.fsetstat(handle.to_string(), mode_attrs(source.mode))
            })
            .await
        {
            return Err(UploadError::new(error.for_upload_dispatch(), false)
                .with_cleanup(self, Some(handle), temp_path)
                .await);
        }
        if let Err(error) = self
            .request("remote temp close", |raw_sftp| {
                raw_sftp.close(handle.to_string())
            })
            .await
        {
            return Err(UploadError::new(error.for_upload_dispatch(), false)
                .with_cleanup(self, None, temp_path)
                .await);
        }
        let temp_attrs = match self
            .request("remote temp lstat", |raw_sftp| {
                raw_sftp.lstat(temp_path.to_string())
            })
            .await
        {
            Ok(attrs) => attrs,
            Err(error) => {
                return Err(UploadError::new(error.for_upload_dispatch(), false)
                    .with_cleanup(self, None, temp_path)
                    .await);
            }
        };
        if let Err(error) =
            validate_temp_revalidation(&handle_attrs.attrs, &temp_attrs.attrs, source.size)
        {
            return Err(UploadError::new(error, false)
                .with_cleanup(self, None, temp_path)
                .await);
        }
        match destination.state {
            UploadDestinationState::Absent => {
                self.finalize_new_destination(temp_path, destination).await
            }
            UploadDestinationState::ExistingRegular => {
                self.finalize_existing_destination(temp_path, destination)
                    .await
            }
        }
    }

    async fn finalize_new_destination(
        &self,
        temp_path: &str,
        destination: &UploadDestination,
    ) -> Result<(), UploadError> {
        match self
            .request("remote destination pre-rename lstat", |raw_sftp| {
                raw_sftp.lstat(destination.path.clone())
            })
            .await
        {
            Ok(_) => {
                let error = TransferRequestError::path_safety(TransferPathError::new(
                    "remote destination appeared before finalization",
                ));
                return Err(UploadError::new(error, false)
                    .with_cleanup(self, None, temp_path)
                    .await);
            }
            Err(error) if error.is_no_such_file() => {}
            Err(error) => {
                return Err(UploadError::new(error.for_upload_dispatch(), false)
                    .with_cleanup(self, None, temp_path)
                    .await);
            }
        }
        match self
            .request("remote rename", |raw_sftp| {
                raw_sftp.rename(temp_path.to_string(), destination.path.clone())
            })
            .await
        {
            Ok(_) => Ok(()),
            Err(error) => {
                let primary = match self
                    .request("remote destination post-rename lstat", |raw_sftp| {
                        raw_sftp.lstat(destination.path.clone())
                    })
                    .await
                {
                    Ok(_)
                        if matches!(
                            error.source,
                            TransferRequestErrorSource::Timeout
                                | TransferRequestErrorSource::TransportLoss
                        ) =>
                    {
                        error.for_upload_dispatch()
                    }
                    Ok(_) => TransferRequestError::path_safety(TransferPathError::new(
                        "remote destination appeared during finalization",
                    )),
                    Err(post_error) if post_error.is_no_such_file() => error.for_upload_dispatch(),
                    Err(_) => error.for_upload_dispatch(),
                };
                Err(UploadError::new(primary, false)
                    .with_cleanup(self, None, temp_path)
                    .await)
            }
        }
    }

    async fn finalize_existing_destination(
        &self,
        temp_path: &str,
        destination: &UploadDestination,
    ) -> Result<(), UploadError> {
        let attrs = match self
            .request("remote destination pre-posix-rename lstat", |raw_sftp| {
                raw_sftp.lstat(destination.path.clone())
            })
            .await
        {
            Ok(attrs) => attrs,
            Err(error) => {
                return Err(UploadError::new(error.for_upload_dispatch(), false)
                    .with_cleanup(self, None, temp_path)
                    .await);
            }
        };
        if !attrs.attrs.file_type().is_file() {
            return Err(UploadError::new(
                TransferRequestError::path_safety(TransferPathError::new(
                    "remote destination is no longer a regular file",
                )),
                false,
            )
            .with_cleanup(self, None, temp_path)
            .await);
        }
        let payload = posix_rename_payload(temp_path, &destination.path);
        let packet = match self
            .request("remote posix rename", |raw_sftp| {
                raw_sftp.extended(POSIX_RENAME_EXTENSION, payload)
            })
            .await
        {
            Ok(packet) => packet,
            Err(error) => {
                return Err(UploadError::new(error.for_upload_dispatch(), false)
                    .with_cleanup(self, None, temp_path)
                    .await);
            }
        };
        match packet {
            Packet::Status(status) if status.status_code == StatusCode::Ok => Ok(()),
            Packet::Status(status) => Err(UploadError::new(
                sftp_request_failure(
                    "remote posix rename",
                    russh_sftp::client::error::Error::Status(status),
                ),
                false,
            )
            .with_cleanup(self, None, temp_path)
            .await),
            _ => Err(UploadError::new(
                TransferRequestError {
                    class: FailureClass::Sftp,
                    diagnostic: "remote posix rename failed: unexpected reply packet".to_string(),
                    source: TransferRequestErrorSource::Sftp,
                },
                false,
            )
            .with_cleanup(self, None, temp_path)
            .await),
        }
    }

    async fn cleanup_temp_after_failure(&self, handle: Option<&str>, temp_path: &str) -> bool {
        if let Some(handle) = handle {
            let _ = self
                .request("remote temp cleanup close", |raw_sftp| {
                    raw_sftp.close(handle.to_string())
                })
                .await;
        }
        match self
            .request("remote temp cleanup remove", |raw_sftp| {
                raw_sftp.remove(temp_path.to_string())
            })
            .await
        {
            Ok(_) => false,
            Err(error) if error.is_no_such_file() => false,
            Err(_) => true,
        }
    }

    async fn cleanup_staged_upload(&self, staged: &StagedUpload) -> bool {
        let mut residue = false;
        for entry in staged.cleanup_entries.iter().rev() {
            let result = match entry.kind {
                StagedInstallKind::File => {
                    self.request("remote transfer staging cleanup remove", |raw_sftp| {
                        raw_sftp.remove(entry.path.clone())
                    })
                    .await
                }
                StagedInstallKind::Directory => {
                    self.request("remote transfer staging cleanup rmdir", |raw_sftp| {
                        raw_sftp.rmdir(entry.path.clone())
                    })
                    .await
                }
            };
            residue |= cleanup_sftp_result_has_residue(result);
        }
        let action_result = self
            .request("remote transfer action cleanup rmdir", |raw_sftp| {
                raw_sftp.rmdir(staged.action_dir.clone())
            })
            .await;
        residue | cleanup_sftp_result_has_residue(action_result)
    }

    async fn transfer_staging_residue(&self, staged: &StagedUpload) -> bool {
        !matches!(
            self
            .request("remote transfer action cleanup proof", |raw_sftp| {
                raw_sftp.lstat(staged.action_dir.clone())
            })
            .await,
            Err(error) if error.is_no_such_file()
        )
    }

    async fn classify_privileged_install_result(
        &self,
        command: RemoteCommand,
        nonce: Option<&str>,
        staged: StagedUpload,
        exec_residue: bool,
    ) -> Result<(), UploadError> {
        let Some(nonce) = nonce else {
            return self
                .classify_privileged_install_status(command.status, staged, exec_residue)
                .await;
        };
        match crate::sudo::parse_sudo_control_frame(&command.stderr, nonce) {
            Ok(crate::sudo::SudoControlFrameParse::Complete(_)) => {
                self.classify_privileged_install_status(command.status, staged, exec_residue)
                    .await
            }
            Ok(crate::sudo::SudoControlFrameParse::Pending) => {
                let residue = exec_residue || self.cleanup_staged_upload(&staged).await;
                Err(UploadError::new(
                    TransferRequestError::new(
                        FailureClass::Sudo,
                        "sudo control frame was not observed",
                        TransferRequestErrorSource::RemoteCommand,
                    ),
                    residue,
                ))
            }
            Err(error) => {
                let residue = exec_residue || self.cleanup_staged_upload(&staged).await;
                Err(UploadError::new(
                    TransferRequestError::new(
                        error.class(),
                        error.to_string(),
                        TransferRequestErrorSource::RemoteCommand,
                    ),
                    residue,
                ))
            }
        }
    }

    async fn classify_privileged_install_status(
        &self,
        status: Option<i32>,
        staged: StagedUpload,
        exec_residue: bool,
    ) -> Result<(), UploadError> {
        match status {
            Some(0) => {
                let transfer_residue = self.transfer_staging_residue(&staged).await;
                if exec_residue || transfer_residue {
                    Err(UploadError::new(
                        TransferRequestError::new(
                            FailureClass::TransferPathSafety,
                            "privileged upload staging cleanup did not complete",
                            TransferRequestErrorSource::RemoteCommand,
                        ),
                        true,
                    ))
                } else {
                    Ok(())
                }
            }
            Some(_status) => {
                let residue = exec_residue || self.cleanup_staged_upload(&staged).await;
                Err(UploadError::new(
                    TransferRequestError::new(
                        FailureClass::TransferPathSafety,
                        "privileged upload installer failed",
                        TransferRequestErrorSource::RemoteCommand,
                    ),
                    residue,
                ))
            }
            None => {
                let residue = exec_residue || self.cleanup_staged_upload(&staged).await;
                Err(UploadError::new(
                    TransferRequestError::new(
                        FailureClass::IndeterminateAfterDispatch,
                        "privileged upload installer ended without a numeric status",
                        TransferRequestErrorSource::RemoteCommand,
                    ),
                    residue,
                ))
            }
        }
    }

    async fn request<T, Fut>(
        &self,
        operation: &'static str,
        request: impl FnOnce(&'a russh_sftp::client::RawSftpSession) -> Fut,
    ) -> Result<T, TransferRequestError>
    where
        Fut: Future<Output = Result<T, russh_sftp::client::error::Error>>,
    {
        cancellable_sftp_request(&self.cancel, operation, request(self.raw_sftp)).await
    }
}

fn cleanup_sftp_result_has_residue<T>(result: Result<T, TransferRequestError>) -> bool {
    match result {
        Ok(_) => false,
        Err(error) if error.is_no_such_file() => false,
        Err(_) => true,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TransferRequestError {
    class: FailureClass,
    diagnostic: String,
    source: TransferRequestErrorSource,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum TransferRequestErrorSource {
    CancellationBeforeDispatch,
    CancellationAfterDispatch,
    Timeout,
    RemoteCommand,
    Sftp,
    SftpStatus(russh_sftp::protocol::StatusCode),
    PathSafety,
    TransportLoss,
    Local,
}

impl TransferRequestError {
    fn new(
        class: FailureClass,
        diagnostic: impl Into<String>,
        source: TransferRequestErrorSource,
    ) -> Self {
        Self {
            class,
            diagnostic: diagnostic.into(),
            source,
        }
    }

    fn path_safety(error: TransferPathError) -> Self {
        Self {
            class: FailureClass::TransferPathSafety,
            diagnostic: error.diagnostic().to_string(),
            source: TransferRequestErrorSource::PathSafety,
        }
    }

    fn into_result(self, job: &TransferJob) -> TransferTargetResult {
        TransferTargetResult::failure_with_dispatch(
            job.machine.clone(),
            job.direction,
            self.class,
            self.diagnostic,
            true,
        )
    }

    fn with_diagnostic(mut self, diagnostic: String) -> Self {
        self.diagnostic = diagnostic;
        self
    }

    fn is_no_such_file(&self) -> bool {
        matches!(
            self.source,
            TransferRequestErrorSource::SftpStatus(StatusCode::NoSuchFile)
        )
    }

    fn possibly_created_temp(&self) -> bool {
        !matches!(
            self.source,
            TransferRequestErrorSource::SftpStatus(_)
                | TransferRequestErrorSource::CancellationBeforeDispatch
        )
    }

    fn for_upload_dispatch(mut self) -> Self {
        if matches!(self.source, TransferRequestErrorSource::TransportLoss) {
            self.class = FailureClass::IndeterminateAfterDispatch;
        }
        self
    }

    fn for_download_dispatch(mut self) -> Self {
        if matches!(self.source, TransferRequestErrorSource::TransportLoss) {
            self.class = FailureClass::IndeterminateAfterDispatch;
        }
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
struct UploadError {
    error: TransferRequestError,
    possible_staging_residue: bool,
}

impl UploadError {
    fn new(error: TransferRequestError, possible_staging_residue: bool) -> Self {
        Self {
            error,
            possible_staging_residue,
        }
    }

    async fn with_cleanup(
        mut self,
        context: &TransferRequestContext<'_>,
        handle: Option<&str>,
        temp_path: &str,
    ) -> Self {
        self.possible_staging_residue = context.cleanup_temp_after_failure(handle, temp_path).await;
        self
    }

    fn into_result(self, job: &TransferJob) -> TransferTargetResult {
        let mut result = self.error.into_result(job);
        result.possible_staging_residue = self.possible_staging_residue;
        result
    }
}

impl From<TransferRequestError> for UploadError {
    fn from(error: TransferRequestError) -> Self {
        Self::new(error, false)
    }
}

#[derive(Debug, Clone, PartialEq)]
struct DownloadError {
    error: TransferRequestError,
    possible_staging_residue: bool,
}

impl DownloadError {
    fn new(error: TransferRequestError, possible_staging_residue: bool) -> Self {
        Self {
            error,
            possible_staging_residue,
        }
    }

    fn with_cleanup(mut self, destination: &DownloadDestination, temp_name: &OsString) -> Self {
        self.possible_staging_residue = cleanup_local_download_temp(destination, temp_name);
        self
    }

    fn into_result(self, job: &TransferJob) -> TransferTargetResult {
        let mut result = self.error.into_result(job);
        result.possible_staging_residue = self.possible_staging_residue;
        result
    }
}

impl From<TransferRequestError> for DownloadError {
    fn from(error: TransferRequestError) -> Self {
        Self::new(error, false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadDestinationState {
    Absent,
    ExistingRegular,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UploadDestination {
    path: String,
    parent: String,
    state: UploadDestinationState,
}

fn split_remote_destination(path: &str) -> Result<(String, String), TransferRequestError> {
    if !path.starts_with('/') {
        return Err(TransferRequestError::path_safety(TransferPathError::new(
            "remote destination is not absolute after resolution",
        )));
    }
    let split = path.rfind('/').ok_or_else(|| {
        TransferRequestError::path_safety(TransferPathError::new(
            "remote destination has no final component",
        ))
    })?;
    let final_component = &path[split + 1..];
    if final_component.is_empty() {
        return Err(TransferRequestError::path_safety(TransferPathError::new(
            "remote destination has no final component",
        )));
    }
    let parent = if split == 0 { "/" } else { &path[..split] };
    Ok((parent.to_string(), final_component.to_string()))
}

fn same_directory_temp_path(parent: &str) -> Result<String, TransferRequestError> {
    let nonce = transfer_temp_nonce("remote upload temp name could not be generated")?;
    let filename = format!(".broil-upload-{nonce}.tmp");
    if parent == "/" {
        Ok(format!("/{filename}"))
    } else {
        Ok(format!("{parent}/{filename}"))
    }
}

fn transfer_action_dir(staging_base: &str) -> Result<String, TransferRequestError> {
    let nonce = transfer_temp_nonce("remote transfer staging name could not be generated")?;
    Ok(join_remote_child_unchecked(
        staging_base,
        &format!("upload.{nonce}"),
    ))
}

fn transfer_temp_nonce(diagnostic: &'static str) -> Result<String, TransferRequestError> {
    let mut raw = [0u8; 16];
    path_safety::random_bytes(&mut raw).map_err(|_| {
        TransferRequestError::new(
            FailureClass::CapabilityUnsupported,
            diagnostic,
            TransferRequestErrorSource::Local,
        )
    })?;
    Ok(raw.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallerUidSource {
    SudoUid,
    RootDirect,
}

fn privileged_upload_launcher(
    staged: &StagedUpload,
    remote: &ResolvedRemotePath,
    metadata: &TransferMetadata,
    overwrite: bool,
    uid_source: InstallerUidSource,
) -> Result<Vec<u8>, TransferRequestError> {
    let tmp_nonce = transfer_temp_nonce("privileged upload temp name could not be generated")?;
    let owner = metadata
        .upload_owner
        .as_ref()
        .map(UploadOwner::spec)
        .unwrap_or_else(|| "root:root".to_string());
    let top_metadata = metadata.explicit_mode.is_some() || metadata.upload_owner.is_some();
    let mut script = String::new();
    script.push_str("set -efu\n");
    script.push_str(&format!(
        "transfer_action={}\n",
        shell_quote(&staged.action_dir)
    ));
    script.push_str(&format!("owner={}\n", shell_quote(&owner)));
    script.push_str(&format!("overwrite={}\n", u8::from(overwrite)));
    script.push_str(&format!("tmp_nonce={}\n", shell_quote(&tmp_nonce)));
    script.push_str(PRIVILEGED_UPLOAD_INSTALLER_FUNCTIONS);
    script.push_str(match uid_source {
        InstallerUidSource::SudoUid => {
            "sudo_uid=${SUDO_UID:-}\ncase \"$sudo_uid\" in ''|*[!0123456789]*) fail;; esac\n"
        }
        InstallerUidSource::RootDirect => {
            "sudo_uid=$(id -u) || fail\ncase \"$sudo_uid\" in 0) ;; *) fail;; esac\n"
        }
    });
    script.push_str(PRIVILEGED_UPLOAD_INSTALLER_MAIN);
    for entry in &staged.install_entries {
        let source_path = staged.stage_path(&entry.remote_components);
        let destination_path = join_remote_components(&remote.path, &entry.remote_components);
        let chmod_mode = format!("0{:03o}", entry.mode & 0o777);
        let expected_mode = format!("{:o}", entry.mode & 0o777);
        match entry.kind {
            StagedInstallKind::File => {
                script.push_str(&format!(
                    "install_file {} {} {} {}\n",
                    shell_quote(&source_path),
                    shell_quote(&destination_path),
                    chmod_mode,
                    expected_mode
                ));
            }
            StagedInstallKind::Directory => {
                let apply_existing = u8::from(entry.remote_components.is_empty() && top_metadata);
                script.push_str(&format!(
                    "ensure_dir {} {} {} {} {}\n",
                    shell_quote(&source_path),
                    shell_quote(&destination_path),
                    chmod_mode,
                    expected_mode,
                    apply_existing
                ));
            }
        }
    }
    script.push_str(
        "rm -rf -- \"$transfer_action\" || fail\n\
         [ ! -e \"$transfer_action\" ] || fail\n\
         trap - EXIT HUP INT TERM\n\
         exit 0\n",
    );
    Ok(crate::staging::launcher_for_shell(script.as_bytes()))
}

fn shell_quote(value: &str) -> String {
    crate::staging::shell_join(&[value.to_string()])
}

const PRIVILEGED_UPLOAD_INSTALLER_FUNCTIONS: &str = r#"fail() { exit 125; }
safe_abs() { case "$1" in /*) ;; *) fail;; esac; case "$1" in *'//'*) fail;; esac; case "$1" in */../*|*/..|*/./*|*/.) fail;; esac; }
no_symlink_chain() { p=$1; safe_abs "$p"; while [ "$p" != / ]; do [ ! -L "$p" ] || fail; parent=${p%/*}; [ "$parent" != "$p" ] || fail; [ -n "$parent" ] || parent=/; p=$parent; done; }
require_staged_common() { p=$1; mode=$2; safe_abs "$p"; case "$p" in "$transfer_action"|"$transfer_action"/*) ;; *) fail;; esac; no_symlink_chain "$p"; [ "$(stat -c '%u' "$p")" = "$sudo_uid" ] || fail; [ "$(stat -c '%a' "$p")" = "$mode" ] || fail; }
require_src_file() { [ ! -L "$1" ] || fail; [ -f "$1" ] || fail; require_staged_common "$1" 600; [ "$(stat -c '%h' "$1")" = 1 ] || fail; }
require_src_dir() { [ ! -L "$1" ] || fail; [ -d "$1" ] || fail; require_staged_common "$1" 700; }
require_action() { case "$transfer_action" in */.broil/tmp/transfer/upload.*) ;; *) fail;; esac; require_src_dir "$transfer_action"; }
validate_parent() { parent=$1; [ -n "$parent" ] || parent=/; safe_abs "$parent"; [ ! -L "$parent" ] || fail; [ -d "$parent" ] || fail; no_symlink_chain "$parent"; }
apply_owner_mode() { path=$1; chmod_mode=$2; expected_mode=$3; [ ! -L "$path" ] || fail; chown -- "$owner" "$path" || fail; chmod -- "$chmod_mode" "$path" || fail; [ "$(stat -c '%a' "$path")" = "$expected_mode" ] || fail; }
close_tmp_fd() { if [ "${tmp_fd_open:-0}" = 1 ]; then exec 9>&- || true; tmp_fd_open=0; fi; }
validate_tmp_fd() { expected_mode=$1; [ "${tmp_fd_open:-0}" = 1 ] || fail; [ "$tmp_path" -ef /proc/self/fd/9 ] || fail; [ ! -L "$tmp_path" ] || fail; [ -f /proc/self/fd/9 ] || fail; [ "$(stat -Lc '%a' /proc/self/fd/9)" = "$expected_mode" ] || fail; }
make_tmp() { parent=$1; close_tmp_fd; counter=$((counter + 1)); tmp_path="$parent/.broil-upload-root-$tmp_nonce.$counter.tmp"; [ ! -e "$tmp_path" ] || fail; [ ! -L "$tmp_path" ] || fail; old_umask=$(umask) || fail; umask 077 || fail; set -C; if ! exec 9>"$tmp_path"; then set +C; umask "$old_umask"; fail; fi; set +C; umask "$old_umask" || fail; tmp_fd_open=1; validate_tmp_fd 600; }
copy_to_tmp() { src=$1; validate_tmp_fd 600; cat "$src" >&9 || fail; src_size=$(stat -c '%s' "$src") || fail; tmp_size=$(stat -Lc '%s' /proc/self/fd/9) || fail; [ "$src_size" = "$tmp_size" ] || fail; }
apply_tmp_owner_mode() { chmod_mode=$1; expected_mode=$2; chown -- "$owner" /proc/self/fd/9 || fail; chmod -- "$chmod_mode" /proc/self/fd/9 || fail; [ "$(stat -Lc '%a' /proc/self/fd/9)" = "$expected_mode" ] || fail; validate_tmp_fd "$expected_mode"; }
validate_final_file() { path=$1; expected_mode=$2; [ ! -L "$path" ] || fail; [ -f "$path" ] || fail; [ "$(stat -c '%a' "$path")" = "$expected_mode" ] || fail; }
install_file() { src=$1; dst=$2; chmod_mode=$3; expected_mode=$4; require_src_file "$src"; safe_abs "$dst"; parent=${dst%/*}; validate_parent "$parent"; if [ -e "$dst" ]; then [ "$overwrite" = 1 ] || fail; [ ! -L "$dst" ] || fail; [ -f "$dst" ] || fail; no_symlink_chain "$dst"; existing=1; else existing=0; fi; make_tmp "$parent"; copy_to_tmp "$src"; apply_tmp_owner_mode "$chmod_mode" "$expected_mode"; if [ "$existing" = 1 ]; then validate_tmp_fd "$expected_mode"; mv -f -- "$tmp_path" "$dst" || fail; [ "$dst" -ef /proc/self/fd/9 ] || fail; close_tmp_fd; tmp_path=; else validate_tmp_fd "$expected_mode"; ln -P -- "$tmp_path" "$dst" || fail; [ "$dst" -ef /proc/self/fd/9 ] || fail; [ "$tmp_path" -ef /proc/self/fd/9 ] || fail; rm -f -- "$tmp_path" || fail; close_tmp_fd; tmp_path=; fi; validate_final_file "$dst" "$expected_mode"; }
ensure_dir() { src=$1; dst=$2; chmod_mode=$3; expected_mode=$4; apply_existing=$5; require_src_dir "$src"; safe_abs "$dst"; if [ -e "$dst" ]; then [ ! -L "$dst" ] || fail; [ -d "$dst" ] || fail; no_symlink_chain "$dst"; if [ "$apply_existing" = 1 ]; then apply_owner_mode "$dst" "$chmod_mode" "$expected_mode"; fi; else parent=${dst%/*}; validate_parent "$parent"; mkdir -- "$dst" || fail; [ ! -L "$dst" ] || fail; [ -d "$dst" ] || fail; apply_owner_mode "$dst" "$chmod_mode" "$expected_mode"; fi; }
"#;

const PRIVILEGED_UPLOAD_INSTALLER_MAIN: &str = r#"require_action
tmp_path=
tmp_fd_open=0
counter=0
cleanup_all() {
if [ -n "${tmp_path:-}" ]; then if [ "${tmp_fd_open:-0}" = 1 ]; then [ "$tmp_path" -ef /proc/self/fd/9 ] && rm -f -- "$tmp_path" || true; else rm -f -- "$tmp_path" || true; fi; fi
close_tmp_fd
rm -rf -- "$transfer_action" || true
}
trap cleanup_all EXIT HUP INT TERM
"#;

fn mode_attrs(mode: u32) -> FileAttributes {
    let mut attrs = FileAttributes::empty();
    attrs.permissions = Some(mode);
    attrs
}

fn analyzed_download_source(
    attrs: &FileAttributes,
) -> Result<AnalyzedDownloadSource, TransferRequestError> {
    if !attrs.file_type().is_file() {
        return Err(TransferRequestError::path_safety(TransferPathError::new(
            "remote source is not a regular file",
        )));
    }
    let size = attrs.size.ok_or_else(|| {
        TransferRequestError::path_safety(TransferPathError::new(
            "remote source size could not be proved",
        ))
    })?;
    Ok(AnalyzedDownloadSource {
        size,
        mode: default_regular_file_mode(attrs.permissions),
    })
}

fn validate_download_source_revalidation(
    pre_open: &AnalyzedDownloadSource,
    handle_attrs: &FileAttributes,
    path_attrs: &FileAttributes,
) -> Result<(), TransferRequestError> {
    let handle = analyzed_download_source(handle_attrs).map_err(|_| {
        TransferRequestError::path_safety(TransferPathError::new(
            "remote source post-open proof failed",
        ))
    })?;
    let path = analyzed_download_source(path_attrs).map_err(|_| {
        TransferRequestError::path_safety(TransferPathError::new(
            "remote source post-open proof failed",
        ))
    })?;
    if handle != *pre_open || path != *pre_open {
        return Err(TransferRequestError::path_safety(TransferPathError::new(
            "remote source changed during download",
        )));
    }
    Ok(())
}

fn local_download_temp_name() -> Result<OsString, TransferRequestError> {
    let mut raw = [0u8; 16];
    path_safety::random_bytes(&mut raw).map_err(|_| TransferRequestError {
        class: FailureClass::CapabilityUnsupported,
        diagnostic: "local download temp name could not be generated".to_string(),
        source: TransferRequestErrorSource::Local,
    })?;
    let nonce = raw
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(OsString::from(format!(".broil-download-{nonce}.tmp")))
}

fn cleanup_local_download_temp(destination: &DownloadDestination, temp_name: &OsString) -> bool {
    match rustix::fs::unlinkat(&destination.parent, temp_name, AtFlags::empty()) {
        Ok(()) => false,
        Err(rustix::io::Errno::NOENT) => false,
        Err(_) => true,
    }
}

fn apply_local_download_mode(file: &LocalFile, mode: u32) -> Result<(), TransferRequestError> {
    rustix::fs::fchmod(file, Mode::from(mode)).map_err(|error| {
        local_download_failure(
            "local download temp mode could not be applied",
            Some(error.to_string()),
        )
    })
}

fn sync_local_download_temp(file: &LocalFile) -> Result<(), TransferRequestError> {
    file.sync_all().map_err(|error| {
        local_download_failure(
            "local download temp could not be flushed",
            Some(error.to_string()),
        )
    })
}

fn validate_local_download_temp(
    file: &LocalFile,
    expected_size: u64,
) -> Result<(), TransferRequestError> {
    let metadata = file.metadata().map_err(|error| {
        local_download_failure(
            "local download temp could not be proved safe",
            Some(error.to_string()),
        )
    })?;
    if !metadata.is_file() || metadata.len() != expected_size {
        return Err(TransferRequestError::path_safety(TransferPathError::new(
            "local download temp could not be proved safe",
        )));
    }
    Ok(())
}

fn finalize_new_local_destination(
    destination: &DownloadDestination,
    temp: &LocalTempFile,
) -> Result<(), DownloadError> {
    match rustix::fs::renameat_with(
        &destination.parent,
        &temp.name,
        &destination.parent,
        &destination.name,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::EXIST) => Err(DownloadError::new(
            TransferRequestError::path_safety(TransferPathError::new(
                "local destination appeared during finalization",
            )),
            false,
        )
        .with_cleanup(destination, &temp.name)),
        Err(rustix::io::Errno::INVAL | rustix::io::Errno::NOSYS | rustix::io::Errno::OPNOTSUPP) => {
            finalize_new_local_destination_by_link(destination, temp)
        }
        Err(error) => Err(DownloadError::new(
            local_download_failure(
                "local destination could not be finalized",
                Some(error.to_string()),
            ),
            false,
        )
        .with_cleanup(destination, &temp.name)),
    }
}

fn finalize_new_local_destination_by_link(
    destination: &DownloadDestination,
    temp: &LocalTempFile,
) -> Result<(), DownloadError> {
    match rustix::fs::linkat(
        &destination.parent,
        &temp.name,
        &destination.parent,
        &destination.name,
        AtFlags::empty(),
    ) {
        Ok(()) => match rustix::fs::unlinkat(&destination.parent, &temp.name, AtFlags::empty()) {
            Ok(()) => Ok(()),
            Err(error) => Err(DownloadError::new(
                local_download_failure(
                    "local download temp could not be cleaned after finalization",
                    Some(error.to_string()),
                ),
                true,
            )),
        },
        Err(rustix::io::Errno::EXIST) => Err(DownloadError::new(
            TransferRequestError::path_safety(TransferPathError::new(
                "local destination appeared during finalization",
            )),
            false,
        )
        .with_cleanup(destination, &temp.name)),
        Err(error) => Err(DownloadError::new(
            local_download_failure(
                "local destination could not be finalized",
                Some(error.to_string()),
            ),
            false,
        )
        .with_cleanup(destination, &temp.name)),
    }
}

fn finalize_existing_local_destination(
    destination: &DownloadDestination,
    temp: &LocalTempFile,
) -> Result<(), DownloadError> {
    match path_safety::defensive_classify(&destination.path) {
        Ok(SafePathEntryType::RegularFile) => {}
        _ => {
            return Err(DownloadError::new(
                TransferRequestError::path_safety(TransferPathError::new(
                    "local destination is no longer a regular file",
                )),
                false,
            )
            .with_cleanup(destination, &temp.name));
        }
    }
    match rustix::fs::renameat(
        &destination.parent,
        &temp.name,
        &destination.parent,
        &destination.name,
    ) {
        Ok(()) => Ok(()),
        Err(error) => Err(DownloadError::new(
            local_download_failure(
                "local destination could not be finalized",
                Some(error.to_string()),
            ),
            false,
        )
        .with_cleanup(destination, &temp.name)),
    }
}

fn local_download_failure(diagnostic: &'static str, error: Option<String>) -> TransferRequestError {
    TransferRequestError {
        class: FailureClass::IndeterminateAfterDispatch,
        diagnostic: match error {
            Some(error) => format!("{diagnostic}: {error}"),
            None => diagnostic.to_string(),
        },
        source: TransferRequestErrorSource::Local,
    }
}

fn validate_handle_attrs(
    attrs: &FileAttributes,
    uploaded_size: u64,
    source_size: u64,
) -> Result<(), TransferRequestError> {
    if uploaded_size != source_size {
        return Err(TransferRequestError::path_safety(TransferPathError::new(
            "local transfer source changed during upload",
        )));
    }
    if !attrs.file_type().is_file() {
        return Err(TransferRequestError::path_safety(TransferPathError::new(
            "remote temp handle could not be proved safe",
        )));
    }
    if attrs.size != Some(uploaded_size) {
        return Err(TransferRequestError::path_safety(TransferPathError::new(
            "remote temp handle size could not be proved",
        )));
    }
    Ok(())
}

fn validate_temp_revalidation(
    handle_attrs: &FileAttributes,
    temp_attrs: &FileAttributes,
    uploaded_size: u64,
) -> Result<(), TransferRequestError> {
    if !temp_attrs.file_type().is_file() {
        return Err(TransferRequestError::path_safety(TransferPathError::new(
            "remote temp path revalidation failed",
        )));
    }
    if temp_attrs.size != Some(uploaded_size) {
        return Err(TransferRequestError::path_safety(TransferPathError::new(
            "remote temp path revalidation failed",
        )));
    }
    if handle_attrs.permissions.is_some() && handle_attrs.file_type() != temp_attrs.file_type() {
        return Err(TransferRequestError::path_safety(TransferPathError::new(
            "remote temp path revalidation failed",
        )));
    }
    if handle_attrs.uid.is_some() && temp_attrs.uid.is_some() && handle_attrs.uid != temp_attrs.uid
    {
        return Err(TransferRequestError::path_safety(TransferPathError::new(
            "remote temp path revalidation failed",
        )));
    }
    if handle_attrs.gid.is_some() && temp_attrs.gid.is_some() && handle_attrs.gid != temp_attrs.gid
    {
        return Err(TransferRequestError::path_safety(TransferPathError::new(
            "remote temp path revalidation failed",
        )));
    }
    Ok(())
}

fn posix_rename_payload(oldpath: &str, newpath: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + oldpath.len() + newpath.len());
    append_sftp_string(&mut payload, oldpath);
    append_sftp_string(&mut payload, newpath);
    payload
}

fn append_sftp_string(payload: &mut Vec<u8>, value: &str) {
    payload.extend_from_slice(&(value.len() as u32).to_be_bytes());
    payload.extend_from_slice(value.as_bytes());
}

fn path_safety_proof_failure(
    error: TransferRequestError,
    diagnostic: &'static str,
) -> TransferRequestError {
    if matches!(
        error.source,
        TransferRequestErrorSource::SftpStatus(russh_sftp::protocol::StatusCode::NoSuchFile)
    ) {
        TransferRequestError::path_safety(TransferPathError::new(diagnostic))
    } else {
        error
    }
}

fn post_open_download_source_proof_failure(
    error: TransferRequestError,
    diagnostic: &'static str,
) -> TransferRequestError {
    if matches!(error.source, TransferRequestErrorSource::SftpStatus(_)) {
        TransferRequestError::path_safety(TransferPathError::new(diagnostic))
    } else {
        error
    }
}

async fn cancellable_sftp_request<T>(
    cancel: &CancellationToken,
    operation: &'static str,
    future: impl Future<Output = Result<T, russh_sftp::client::error::Error>>,
) -> Result<T, TransferRequestError> {
    if cancel.is_cancelled() {
        return Err(TransferRequestError {
            class: FailureClass::Cancellation,
            diagnostic: "cancelled".to_string(),
            source: TransferRequestErrorSource::CancellationBeforeDispatch,
        });
    }
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(TransferRequestError {
            class: FailureClass::Cancellation,
            diagnostic: "cancelled".to_string(),
            source: TransferRequestErrorSource::CancellationAfterDispatch,
        }),
        result = future => result.map_err(|error| sftp_request_failure(operation, error)),
    }
}

fn sftp_request_failure(
    operation: &'static str,
    error: russh_sftp::client::error::Error,
) -> TransferRequestError {
    match error {
        russh_sftp::client::error::Error::Timeout => TransferRequestError {
            class: FailureClass::IndeterminateAfterDispatch,
            diagnostic: format!("{operation} timed out after SFTP dispatch"),
            source: TransferRequestErrorSource::Timeout,
        },
        russh_sftp::client::error::Error::Status(status) => {
            let status_code = status.status_code;
            TransferRequestError {
                class: FailureClass::Sftp,
                diagnostic: format!("{operation} failed: SFTP status {status_code}"),
                source: TransferRequestErrorSource::SftpStatus(status_code),
            }
        }
        error @ (russh_sftp::client::error::Error::IO(_)
        | russh_sftp::client::error::Error::UnexpectedBehavior(_)) => TransferRequestError {
            class: FailureClass::Sftp,
            diagnostic: format!("{operation} failed: {error}"),
            source: TransferRequestErrorSource::TransportLoss,
        },
        error @ (russh_sftp::client::error::Error::Limited(_)
        | russh_sftp::client::error::Error::UnexpectedPacket) => TransferRequestError {
            class: FailureClass::Sftp,
            diagnostic: format!("{operation} failed: {error}"),
            source: TransferRequestErrorSource::Sftp,
        },
        #[allow(unreachable_patterns)]
        error => TransferRequestError {
            class: FailureClass::Sftp,
            diagnostic: format!("{operation} failed: {error}"),
            source: TransferRequestErrorSource::Sftp,
        },
    }
}

fn realpath_name(name: russh_sftp::protocol::Name) -> Result<String, TransferPathError> {
    let mut files = name.files.into_iter();
    let file = files
        .next()
        .ok_or_else(|| TransferPathError::new("remote realpath returned no path"))?;
    if files.next().is_some() {
        return Err(TransferPathError::new(
            "remote realpath returned multiple paths",
        ));
    }
    Ok(file.filename)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransferSetupError {
    class: FailureClass,
    diagnostic: String,
    dispatched: bool,
}

impl TransferSetupError {
    fn new(class: FailureClass, diagnostic: impl Into<String>, dispatched: bool) -> Self {
        Self {
            class,
            diagnostic: diagnostic.into(),
            dispatched,
        }
    }

    fn into_result(self, job: &TransferJob) -> TransferTargetResult {
        TransferTargetResult::failure_with_dispatch(
            job.machine.clone(),
            job.direction,
            self.class,
            self.diagnostic,
            self.dispatched,
        )
    }

    pub(crate) fn class(&self) -> FailureClass {
        self.class
    }

    pub(crate) fn diagnostic(&self) -> &str {
        &self.diagnostic
    }

    pub(crate) fn dispatched(&self) -> bool {
        self.dispatched
    }
}

#[derive(Debug)]
struct RemoteCommand {
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

struct RemoteCommandInput {
    bytes: Zeroizing<Vec<u8>>,
    position: usize,
}

impl RemoteCommandInput {
    fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self { bytes, position: 0 }
    }
}

impl AsyncRead for RemoteCommandInput {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let available = self.bytes.len().saturating_sub(self.position);
        if available == 0 || buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let copied = available.min(buffer.remaining());
        let start = self.position;
        let end = start + copied;
        buffer.put_slice(&self.bytes[start..end]);
        self.position = end;
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug)]
struct RemoteStagingError {
    error: TransferRequestError,
    possible_staging_residue: bool,
}

impl RemoteStagingError {
    fn new(error: TransferRequestError, possible_staging_residue: bool) -> Self {
        Self {
            error,
            possible_staging_residue,
        }
    }
}

struct PendingTransferSudo {
    mode: PendingTransferSudoMode,
    control_frame_contents: Zeroizing<Vec<u8>>,
    nonce: String,
}

enum PendingTransferSudoMode {
    Passwordless,
    Password(PrivilegeProfile),
}

struct TransferDispatchCommand {
    command: String,
    password_stdin: Option<Zeroizing<Vec<u8>>>,
}

impl PendingTransferSudo {
    fn passwordless() -> Result<Self, TransferRequestError> {
        let nonce = crate::path_safety::sudo_nonce().map_err(|_| {
            TransferRequestError::new(
                FailureClass::Sudo,
                "sudo nonce generation failed",
                TransferRequestErrorSource::Local,
            )
        })?;
        let control_frame_contents = sudo_control_frame_contents(&nonce)?;
        Ok(Self {
            mode: PendingTransferSudoMode::Passwordless,
            control_frame_contents,
            nonce,
        })
    }

    fn password(profile: PrivilegeProfile) -> Result<Self, TransferRequestError> {
        let nonce = crate::path_safety::sudo_nonce().map_err(|_| {
            TransferRequestError::new(
                FailureClass::Sudo,
                "sudo nonce generation failed",
                TransferRequestErrorSource::Local,
            )
        })?;
        let control_frame_contents = sudo_control_frame_contents(&nonce)?;
        Ok(Self {
            mode: PendingTransferSudoMode::Password(profile),
            control_frame_contents,
            nonce,
        })
    }

    async fn dispatch(
        &self,
        privilege_context: &TransferPrivilegeContext,
        launcher: &str,
        cancel: &CancellationToken,
    ) -> Result<TransferDispatchCommand, TransferRequestError> {
        let launcher_argv = vec![launcher.to_string()];
        match &self.mode {
            PendingTransferSudoMode::Passwordless => {
                let argv = crate::sudo::passwordless_sudo_argv(&launcher_argv, &self.nonce)
                    .map_err(|error| {
                        TransferRequestError::new(
                            error.class(),
                            error.to_string(),
                            TransferRequestErrorSource::Local,
                        )
                    })?;
                Ok(TransferDispatchCommand {
                    command: crate::staging::shell_join(&argv),
                    password_stdin: None,
                })
            }
            PendingTransferSudoMode::Password(profile) => {
                let argv = crate::sudo::password_sudo_argv(&launcher_argv, &self.nonce).map_err(
                    |error| {
                        TransferRequestError::new(
                            error.class(),
                            error.to_string(),
                            TransferRequestErrorSource::Local,
                        )
                    },
                )?;
                Ok(TransferDispatchCommand {
                    command: crate::staging::shell_join(&argv),
                    password_stdin: privilege_context
                        .sudo_password_input(profile, cancel)
                        .await?,
                })
            }
        }
    }
}

enum PrivilegedUploadDispatch {
    Sudo(PendingTransferSudo),
    RootDirect,
}

impl PrivilegedUploadDispatch {
    fn uid_source(&self) -> InstallerUidSource {
        match self {
            Self::Sudo(_) => InstallerUidSource::SudoUid,
            Self::RootDirect => InstallerUidSource::RootDirect,
        }
    }

    fn sidecar(&self) -> Option<&[u8]> {
        match self {
            Self::Sudo(sudo) => Some(&sudo.control_frame_contents),
            Self::RootDirect => None,
        }
    }

    fn control_frame_nonce(&self) -> Option<&str> {
        match self {
            Self::Sudo(sudo) => Some(&sudo.nonce),
            Self::RootDirect => None,
        }
    }

    async fn command(
        &self,
        privilege_context: &TransferPrivilegeContext,
        launcher: &str,
        cancel: &CancellationToken,
    ) -> Result<TransferDispatchCommand, TransferRequestError> {
        match self {
            Self::Sudo(sudo) => sudo.dispatch(privilege_context, launcher, cancel).await,
            Self::RootDirect => Ok(TransferDispatchCommand {
                command: crate::staging::shell_join(&[launcher.to_string()]),
                password_stdin: None,
            }),
        }
    }
}

async fn prepare_transfer_sudo(
    session: &mut client::Handle<StrictHandler>,
    privilege_context: &TransferPrivilegeContext,
    profile_name: &str,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<PendingTransferSudo, TransferRequestError> {
    let profile = privilege_context.profile(profile_name)?.clone();
    let preflight = crate::staging::shell_join(&crate::sudo::sudo_preflight_argv());
    let result =
        run_remote_command(session, &preflight, None, timeout, false, false, cancel).await?;
    match classify_transfer_sudo_preflight(result, profile.password.is_some())? {
        TransferSudoMode::Passwordless => PendingTransferSudo::passwordless(),
        TransferSudoMode::Password => PendingTransferSudo::password(profile),
    }
}

enum TransferSudoMode {
    Passwordless,
    Password,
}

fn classify_transfer_sudo_preflight(
    result: RemoteCommand,
    has_password: bool,
) -> Result<TransferSudoMode, TransferRequestError> {
    match result.status {
        Some(0) => Ok(TransferSudoMode::Passwordless),
        Some(126 | 127) => Err(TransferRequestError::new(
            FailureClass::Sudo,
            "sudo preflight command was not executable or was not found",
            TransferRequestErrorSource::RemoteCommand,
        )),
        Some(_) if has_password => Ok(TransferSudoMode::Password),
        Some(_) => Err(TransferRequestError::new(
            FailureClass::Sudo,
            "passwordless sudo preflight did not succeed",
            TransferRequestErrorSource::RemoteCommand,
        )),
        None => Err(TransferRequestError::new(
            FailureClass::Protocol,
            "sudo preflight ended without a numeric status",
            TransferRequestErrorSource::RemoteCommand,
        )),
    }
}

fn sudo_control_frame_contents(nonce: &str) -> Result<Zeroizing<Vec<u8>>, TransferRequestError> {
    if nonce.is_empty() || !nonce.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(TransferRequestError::new(
            FailureClass::Sudo,
            "sudo nonce is invalid",
            TransferRequestErrorSource::Local,
        ));
    }
    let mut frame = Zeroizing::new(Vec::with_capacity("BROIL-SUDO:".len() + nonce.len() + 1));
    frame.extend_from_slice(b"BROIL-SUDO:");
    frame.extend_from_slice(nonce.as_bytes());
    frame.push(b'\n');
    Ok(frame)
}

async fn stage_privileged_launcher(
    session: &mut client::Handle<StrictHandler>,
    launcher: &[u8],
    sidecar: Option<&[u8]>,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<crate::staging::StagedLauncher, RemoteStagingError> {
    let input = crate::staging::staging_input(launcher, None, sidecar);
    let result = run_remote_command(
        session,
        &crate::staging::receiver_command(),
        Some(input),
        timeout,
        true,
        false,
        cancel,
    )
    .await
    .map_err(|error| RemoteStagingError::new(error, true))?;
    crate::staging::classify_receiver_status(
        result.status,
        &result.stdout,
        false,
        sidecar.is_some(),
    )
    .map_err(|error| {
        RemoteStagingError::new(
            TransferRequestError::new(
                error.class,
                error.diagnostic,
                TransferRequestErrorSource::RemoteCommand,
            ),
            error.possible_staging_residue,
        )
    })
}

async fn make_privileged_launcher_executable(
    session: &mut client::Handle<StrictHandler>,
    launcher: &str,
    timeout: Duration,
) -> Result<(), RemoteStagingError> {
    let command = crate::staging::make_launcher_executable_command(launcher).map_err(|error| {
        RemoteStagingError::new(
            TransferRequestError::new(
                error.class,
                error.diagnostic,
                TransferRequestErrorSource::Local,
            ),
            error.possible_staging_residue,
        )
    })?;
    let result = run_remote_command(
        session,
        &command,
        None,
        timeout,
        false,
        false,
        &CancellationToken::default(),
    )
    .await
    .map_err(|error| RemoteStagingError::new(error, true))?;
    if result.status == Some(0) {
        Ok(())
    } else {
        Err(RemoteStagingError::new(
            TransferRequestError::new(
                FailureClass::TransferPathSafety,
                "remote exec launcher chmod did not complete",
                TransferRequestErrorSource::RemoteCommand,
            ),
            true,
        ))
    }
}

async fn cleanup_exec_staging(
    session: &mut client::Handle<StrictHandler>,
    launcher: &str,
    timeout: Duration,
) -> Result<(), RemoteStagingError> {
    let command = crate::staging::cleanup_command(launcher).map_err(|error| {
        RemoteStagingError::new(
            TransferRequestError::new(
                error.class,
                error.diagnostic,
                TransferRequestErrorSource::Local,
            ),
            error.possible_staging_residue,
        )
    })?;
    let result = run_remote_command(
        session,
        &command,
        None,
        timeout,
        false,
        false,
        &CancellationToken::default(),
    )
    .await
    .map_err(|error| RemoteStagingError::new(error, true))?;
    if result.status == Some(0) {
        Ok(())
    } else {
        Err(RemoteStagingError::new(
            TransferRequestError::new(
                FailureClass::TransferPathSafety,
                "remote exec staging cleanup did not complete",
                TransferRequestErrorSource::RemoteCommand,
            ),
            true,
        ))
    }
}

async fn cleanup_exec_staging_or_residue(
    session: &mut client::Handle<StrictHandler>,
    launcher: &str,
    timeout: Duration,
    mut failure: RemoteStagingError,
) -> RemoteStagingError {
    failure.possible_staging_residue = cleanup_exec_staging(session, launcher, timeout)
        .await
        .is_err();
    failure
}

async fn run_remote_command(
    session: &mut client::Handle<StrictHandler>,
    command: &str,
    stdin: Option<Zeroizing<Vec<u8>>>,
    timeout: Duration,
    capture_stdout: bool,
    capture_stderr: bool,
    cancel: &CancellationToken,
) -> Result<RemoteCommand, TransferRequestError> {
    if cancel.is_cancelled() {
        return Err(TransferRequestError::new(
            FailureClass::Cancellation,
            "cancelled",
            TransferRequestErrorSource::CancellationBeforeDispatch,
        ));
    }
    let command = command.as_bytes().to_vec();
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(TransferRequestError::new(
            FailureClass::Cancellation,
            "cancelled",
            TransferRequestErrorSource::CancellationAfterDispatch,
        )),
        result = tokio::time::timeout(timeout, async move {
            let mut channel = session.channel_open_session().await.map_err(|error| {
                TransferRequestError::new(
                    FailureClass::Protocol,
                    format!("cannot open SSH session channel: {error}"),
                    TransferRequestErrorSource::RemoteCommand,
                )
            })?;
            channel.exec(true, command).await.map_err(|error| {
                TransferRequestError::new(
                    FailureClass::IndeterminateAfterDispatch,
                    format!("cannot dispatch SSH exec request: {error}"),
                    TransferRequestErrorSource::RemoteCommand,
                )
            })?;
            if let Some(stdin) = stdin {
                channel.data(RemoteCommandInput::new(stdin)).await.map_err(|error| {
                    TransferRequestError::new(
                        FailureClass::IndeterminateAfterDispatch,
                        format!("cannot write SSH channel input: {error}"),
                        TransferRequestErrorSource::RemoteCommand,
                    )
                })?;
            }
            channel.eof().await.map_err(|error| {
                TransferRequestError::new(
                    FailureClass::IndeterminateAfterDispatch,
                    format!("cannot send SSH channel EOF: {error}"),
                    TransferRequestErrorSource::RemoteCommand,
                )
            })?;
            let mut status = None;
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            while let Some(message) = channel.wait().await {
                match message {
                    ChannelMsg::Data { data } if capture_stdout => append_bounded(&mut stdout, &data),
                    ChannelMsg::ExtendedData { data, ext } if capture_stderr && ext == 1 => {
                        append_bounded(&mut stderr, &data)
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        status = Some(i32::try_from(exit_status).unwrap_or(i32::MAX));
                    }
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            Ok(RemoteCommand { status, stdout, stderr })
        }) => result.map_err(|_| {
            TransferRequestError::new(
                FailureClass::IndeterminateAfterDispatch,
                "remote command timed out after dispatch",
                TransferRequestErrorSource::Timeout,
            )
        })?,
    }
}

fn append_bounded(output: &mut Vec<u8>, data: &[u8]) {
    let available = 8192usize.saturating_sub(output.len());
    output.extend_from_slice(&data[..data.len().min(available)]);
}

async fn setup_transfer_session(
    job: &TransferJob,
    auth_context: &AuthContext,
    cancel: &CancellationToken,
) -> Result<TransferSetupHandle, TransferSetupError> {
    let store = known_hosts_store(&job.known_hosts)?;
    let route_keys = preflight_known_hosts(&store, job)?;
    let (mut target_session, jump_session) =
        connect_transfer_target(job, route_keys, auth_context, cancel).await?;
    authenticate_transfer_target(job, auth_context, &mut target_session, cancel).await?;
    open_sftp_session(job, target_session, jump_session, cancel).await
}

fn known_hosts_store(
    known_hosts: &ResolvedKnownHosts,
) -> Result<KnownHostsStore, TransferSetupError> {
    match known_hosts.source {
        KnownHostsSource::DefaultHome => KnownHostsStore::open_default(&known_hosts.path),
        KnownHostsSource::Override => KnownHostsStore::open_override(&known_hosts.path),
    }
    .map_err(store_failure)
}

#[derive(Debug)]
struct PinnedRouteKeys {
    target: HostKey,
    jump: Option<HostKey>,
}

fn preflight_known_hosts(
    store: &KnownHostsStore,
    job: &TransferJob,
) -> Result<PinnedRouteKeys, TransferSetupError> {
    let target = pinned_key(store, &job.target_alias, FailureClass::UnknownHostKey)?;
    let jump = job
        .jump
        .as_ref()
        .map(|jump| pinned_key(store, &jump.alias, FailureClass::UnknownHostKey))
        .transpose()?;
    Ok(PinnedRouteKeys { target, jump })
}

fn pinned_key(
    store: &KnownHostsStore,
    alias: &str,
    unknown_class: FailureClass,
) -> Result<HostKey, TransferSetupError> {
    match store
        .snapshot()
        .and_then(|snapshot| snapshot.inspect(alias, false))
    {
        Ok(AliasState::Pinned(key)) => Ok(key),
        Ok(AliasState::Unknown) => Err(TransferSetupError::new(
            unknown_class,
            "host key is not pinned in the Broil known-hosts store",
            false,
        )),
        Ok(AliasState::Replaceable { .. }) => Err(TransferSetupError::new(
            FailureClass::Configuration,
            "known-hosts state requires replacement before read-only verification",
            false,
        )),
        Err(error) => Err(store_failure(error)),
    }
}

async fn connect_transfer_target(
    job: &TransferJob,
    route_keys: PinnedRouteKeys,
    auth_context: &AuthContext,
    cancel: &CancellationToken,
) -> Result<
    (
        client::Handle<StrictHandler>,
        Option<client::Handle<StrictHandler>>,
    ),
    TransferSetupError,
> {
    let connect_timeout = Duration::from_secs(job.connect_timeout.seconds);
    let deadline = tokio::time::Instant::now() + connect_timeout;
    if let Some(jump) = &job.jump {
        let jump_key = route_keys.jump.clone().ok_or_else(|| {
            TransferSetupError::new(
                FailureClass::Configuration,
                "transfer jump route is missing a pinned key",
                false,
            )
        })?;
        let stream = cancellable(cancel, false, async {
            crate::transport::connect_tcp(&jump.address, jump.port, deadline)
                .await
                .map_err(|error| jump_endpoint_failure(jump, error))
        })
        .await?;
        let mut jump_session =
            cancellable(cancel, false, connect_strict(stream, jump_key, deadline))
                .await
                .map_err(|error| strict_jump_failure(&jump.name, error))?;
        cancellable(cancel, false, async {
            timeout_at(
                deadline,
                auth::authenticate_profile_cancellable(
                    &mut jump_session,
                    auth_context,
                    &jump.auth_profile,
                    cancel,
                ),
                FailureClass::JumpFailure,
                "jump authentication timed out",
            )
            .await?
            .map_err(|error| {
                let error = error.into_jump_failure(&jump.name);
                TransferSetupError::new(error.class(), error.to_string(), false)
            })
        })
        .await?;
        let channel = cancellable(cancel, false, async {
            tokio::time::timeout_at(
                deadline,
                jump_session.channel_open_direct_tcpip(
                    job.address.clone(),
                    u32::from(job.port),
                    "127.0.0.1",
                    0,
                ),
            )
            .await
            .map_err(|_| {
                TransferSetupError::new(
                    FailureClass::JumpFailure,
                    format!(
                        "jump host {} timed out opening target channel to {}:{}",
                        jump.name, job.address, job.port
                    ),
                    false,
                )
            })?
            .map_err(|error| {
                TransferSetupError::new(
                    FailureClass::JumpFailure,
                    format!(
                        "jump host {} could not open target channel to {}:{}: {error}",
                        jump.name, job.address, job.port
                    ),
                    false,
                )
            })
        })
        .await?;
        let target_session = cancellable(
            cancel,
            false,
            connect_strict(channel.into_stream(), route_keys.target, deadline),
        )
        .await
        .map_err(|error| strict_target_failure(&job.machine, error))?;
        Ok((target_session, Some(jump_session)))
    } else {
        let stream = cancellable(cancel, false, async {
            crate::transport::connect_tcp(&job.address, job.port, deadline)
                .await
                .map_err(transport_failure)
        })
        .await?;
        let target_session = cancellable(
            cancel,
            false,
            connect_strict(stream, route_keys.target, deadline),
        )
        .await
        .map_err(|error| strict_target_failure(&job.machine, error))?;
        Ok((target_session, None))
    }
}

async fn authenticate_transfer_target(
    job: &TransferJob,
    auth_context: &AuthContext,
    session: &mut client::Handle<StrictHandler>,
    cancel: &CancellationToken,
) -> Result<(), TransferSetupError> {
    let timeout = Duration::from_secs(job.capability_probe_timeout.seconds);
    cancellable(cancel, false, async {
        tokio::time::timeout(
            timeout,
            auth::authenticate_profile_cancellable(
                session,
                auth_context,
                &job.canonical_profile,
                cancel,
            ),
        )
        .await
        .map_err(|_| {
            TransferSetupError::new(
                FailureClass::Protocol,
                "transfer target canonical authentication timed out",
                false,
            )
        })?
        .map_err(|error| TransferSetupError::new(error.class(), error.to_string(), false))
    })
    .await
}

async fn open_sftp_session(
    job: &TransferJob,
    target_session: client::Handle<StrictHandler>,
    jump_session: Option<client::Handle<StrictHandler>>,
    cancel: &CancellationToken,
) -> Result<TransferSetupHandle, TransferSetupError> {
    let timeout = Duration::from_secs(job.capability_probe_timeout.seconds);
    let (raw_sftp, extensions) = open_raw_sftp_session(&target_session, timeout, cancel).await?;
    Ok(TransferSetupHandle {
        target_session,
        jump_session,
        raw_sftp,
        extensions,
    })
}

async fn open_raw_sftp_session(
    session: &client::Handle<StrictHandler>,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<(russh_sftp::client::RawSftpSession, BTreeMap<String, String>), TransferSetupError> {
    ensure_not_cancelled_before_sftp_dispatch(cancel)?;
    cancellable(cancel, true, async {
        tokio::time::timeout(timeout, async {
            let mut channel = session.channel_open_session().await.map_err(|error| {
                TransferSetupError::new(
                    FailureClass::Protocol,
                    format!("cannot open transfer SSH session channel for SFTP: {error}"),
                    true,
                )
            })?;
            channel
                .request_subsystem(true, "sftp")
                .await
                .map_err(|error| {
                    TransferSetupError::new(
                        FailureClass::Sftp,
                        format!("SFTP subsystem request failed: {error}"),
                        true,
                    )
                })?;
            loop {
                match classify_sftp_subsystem_reply(channel.wait().await)? {
                    Some(true) => break,
                    Some(false) => {
                        return Err(TransferSetupError::new(
                            FailureClass::Sftp,
                            "SFTP subsystem request was refused",
                            true,
                        ));
                    }
                    None => {}
                }
            }
            initialize_raw_sftp_session(channel.into_stream(), timeout).await
        })
        .await
        .map_err(|_| sftp_timeout_failure())?
    })
    .await
}

fn classify_sftp_subsystem_reply(
    message: Option<ChannelMsg>,
) -> Result<Option<bool>, TransferSetupError> {
    match message {
        Some(ChannelMsg::Success) => Ok(Some(true)),
        Some(ChannelMsg::Failure) => Ok(Some(false)),
        Some(ChannelMsg::WindowAdjusted { .. }) => Ok(None),
        Some(ChannelMsg::Close) | None => Err(TransferSetupError::new(
            FailureClass::Sftp,
            "SFTP subsystem request closed before success",
            true,
        )),
        Some(message) => Err(TransferSetupError::new(
            FailureClass::Sftp,
            format!(
                "unexpected SFTP subsystem reply before success: {}",
                sftp_channel_message_name(&message)
            ),
            true,
        )),
    }
}

fn sftp_channel_message_name(message: &ChannelMsg) -> &'static str {
    match message {
        ChannelMsg::Open { .. } => "open",
        ChannelMsg::Data { .. } => "data",
        ChannelMsg::ExtendedData { .. } => "extended_data",
        ChannelMsg::Eof => "eof",
        ChannelMsg::Close => "close",
        ChannelMsg::RequestPty { .. } => "request_pty",
        ChannelMsg::RequestShell { .. } => "request_shell",
        ChannelMsg::Exec { .. } => "exec",
        ChannelMsg::Signal { .. } => "signal",
        ChannelMsg::RequestSubsystem { .. } => "request_subsystem",
        ChannelMsg::RequestX11 { .. } => "request_x11",
        ChannelMsg::SetEnv { .. } => "set_env",
        ChannelMsg::WindowChange { .. } => "window_change",
        ChannelMsg::AgentForward { .. } => "agent_forward",
        ChannelMsg::XonXoff { .. } => "xon_xoff",
        ChannelMsg::ExitStatus { .. } => "exit_status",
        ChannelMsg::ExitSignal { .. } => "exit_signal",
        ChannelMsg::WindowAdjusted { .. } => "window_adjusted",
        ChannelMsg::Success => "success",
        ChannelMsg::Failure => "failure",
        ChannelMsg::OpenFailure(_) => "open_failure",
        _ => "unknown",
    }
}

pub(crate) async fn initialize_raw_sftp_session<S>(
    stream: S,
    timeout: Duration,
) -> Result<(russh_sftp::client::RawSftpSession, BTreeMap<String, String>), TransferSetupError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let raw_sftp =
        russh_sftp::client::RawSftpSession::new_with_config(stream, sftp_client_config(timeout));
    raw_sftp.set_timeout(timeout.as_secs());
    let version = raw_sftp.init().await.map_err(sftp_init_failure)?;
    Ok((raw_sftp, version.extensions.into_iter().collect()))
}

fn sftp_client_config(timeout: Duration) -> russh_sftp::client::Config {
    russh_sftp::client::Config {
        request_timeout_secs: timeout.as_secs(),
        ..Default::default()
    }
}

async fn connect_strict<R>(
    stream: R,
    expected: HostKey,
    deadline: tokio::time::Instant,
) -> Result<client::Handle<StrictHandler>, TransferSetupError>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = transfer_client_config(&expected)?;
    tokio::time::timeout_at(
        deadline,
        client::connect_stream(
            Arc::new(config),
            stream,
            StrictHandler::new(expected.clone()),
        ),
    )
    .await
    .map_err(|_| {
        TransferSetupError::new(FailureClass::Protocol, "SSH key exchange timed out", false)
    })?
    .map_err(strict_connect_failure)
}

fn transfer_client_config(expected: &HostKey) -> Result<client::Config, TransferSetupError> {
    let algorithm = Algorithm::from_str(&expected.algorithm).map_err(|_| {
        TransferSetupError::new(
            FailureClass::Configuration,
            format!(
                "unsupported configured host-key algorithm {}",
                expected.algorithm
            ),
            false,
        )
    })?;
    Ok(crate::transport::strict_client_config_from_algorithms(
        vec![algorithm],
        None,
    ))
}

fn strict_connect_failure(error: russh::Error) -> TransferSetupError {
    match error {
        russh::Error::UnknownKey | russh::Error::KeyChanged { .. } => TransferSetupError::new(
            FailureClass::UnknownHostKey,
            "strict host-key verification failed",
            false,
        ),
        russh::Error::NoCommonAlgo {
            kind: russh::AlgorithmKind::Key,
            ..
        } => TransferSetupError::new(
            FailureClass::ChangedHostKey,
            "host no longer offers the pinned host-key algorithm",
            false,
        ),
        error => TransferSetupError::new(
            FailureClass::Protocol,
            format!("SSH protocol failure before host-key verification: {error}"),
            false,
        ),
    }
}

fn strict_target_failure(machine: &str, error: TransferSetupError) -> TransferSetupError {
    match error.class {
        FailureClass::UnknownHostKey => TransferSetupError::new(
            FailureClass::ChangedHostKey,
            "target host key does not match the pinned key",
            false,
        ),
        FailureClass::Protocol => TransferSetupError::new(
            FailureClass::Protocol,
            format!("target {machine}: {}", error.diagnostic),
            false,
        ),
        _ => error,
    }
}

fn strict_jump_failure(jump_name: &str, error: TransferSetupError) -> TransferSetupError {
    match error.class {
        FailureClass::UnknownHostKey => TransferSetupError::new(
            FailureClass::ChangedHostKey,
            format!("jump host {jump_name} key does not match the pinned key"),
            false,
        ),
        FailureClass::Protocol => TransferSetupError::new(
            FailureClass::Protocol,
            format!("jump host {jump_name}: {}", error.diagnostic),
            false,
        ),
        _ => error,
    }
}

fn transport_failure(error: crate::transport::FetchFailure) -> TransferSetupError {
    TransferSetupError::new(error.class, error.diagnostic, false)
}

fn jump_endpoint_failure(
    jump: &TransferJump,
    error: crate::transport::FetchFailure,
) -> TransferSetupError {
    TransferSetupError::new(
        error.class,
        format!(
            "jump host {} endpoint failed before target connection: {}",
            jump.name, error.diagnostic
        ),
        false,
    )
}

fn store_failure(error: StoreError) -> TransferSetupError {
    TransferSetupError::new(error.class(), error.to_string(), false)
}

fn sftp_init_failure(error: russh_sftp::client::error::Error) -> TransferSetupError {
    if matches!(error, russh_sftp::client::error::Error::Timeout) {
        sftp_timeout_failure()
    } else {
        TransferSetupError::new(
            FailureClass::Sftp,
            format!("SFTP initialization failed: {error}"),
            true,
        )
    }
}

fn sftp_timeout_failure() -> TransferSetupError {
    TransferSetupError::new(
        FailureClass::IndeterminateAfterDispatch,
        "SFTP setup timed out after dispatch",
        true,
    )
}

async fn timeout_at<T>(
    deadline: tokio::time::Instant,
    future: impl Future<Output = T>,
    class: FailureClass,
    diagnostic: &'static str,
) -> Result<T, TransferSetupError> {
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| TransferSetupError::new(class, diagnostic, false))
}

async fn cancellable<T>(
    cancel: &CancellationToken,
    dispatched: bool,
    future: impl Future<Output = Result<T, TransferSetupError>>,
) -> Result<T, TransferSetupError> {
    if cancel.is_cancelled() {
        return Err(cancellation_failure(dispatched));
    }
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(cancellation_failure(dispatched)),
        result = future => result,
    }
}

fn ensure_not_cancelled_before_sftp_dispatch(
    cancel: &CancellationToken,
) -> Result<(), TransferSetupError> {
    if cancel.is_cancelled() {
        return Err(cancellation_failure(false));
    }
    Ok(())
}

fn cancellation_failure(dispatched: bool) -> TransferSetupError {
    TransferSetupError::new(FailureClass::Cancellation, "cancelled", dispatched)
}

