// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    filesystem::{self, DirectoryPlan, checkpoint},
    *,
};
use crate::{age, output};
use broil_core::secret::OwnedSecret;

pub struct Initialization {
    root: PathBuf,
    project: String,
    name: String,
    directory: DirectoryPlan,
}
impl Initialization {
    pub fn prepare(root: &Path, project: &str, name: &str) -> Result<Self> {
        validate_project(project)?;
        validate_component(name)?;
        let directory = DirectoryPlan::inspect(root)?;
        let value = Self {
            root: root.into(),
            project: project.into(),
            name: name.into(),
            directory,
        };
        value.empty()?;
        Ok(value)
    }
    fn empty(&self) -> Result<()> {
        self.directory.fresh()?;
        if let Some(directory) = self.directory.existing() {
            if !filesystem::names(directory)?.is_empty() {
                let store = Store::open(&self.root)?;
                if let Ok(sets) = store.sets() {
                    for id in sets {
                        if store
                            .status(&id)
                            .is_err_and(|e| e.kind == ErrorKind::OwnedSchema)
                        {
                            return Err(ErrorKind::OwnedSchema.into());
                        }
                    }
                }
                return Err(ErrorKind::Exists.into());
            }
        }
        Ok(())
    }
    pub fn create(self, passphrase: OwnedSecret) -> std::result::Result<Vec<String>, BatchFailure> {
        let mut completed = Vec::new();
        let mut failing = ".".to_owned();
        let result = (|| -> Result<()> {
            self.empty()?;
            if passphrase.is_empty() || passphrase.as_str().contains('\0') {
                return Err(ErrorKind::Identity.into());
            }
            let identity = age::Identity::generate().map_err(|_| ErrorKind::Identity)?;
            let recipient = identity.recipient().to_string();
            let key = identity.encode().map_err(|_| ErrorKind::Identity)?;
            drop(identity);
            let encrypted = age::encrypt_with_passphrase(key.as_str().as_bytes(), &passphrase)
                .map_err(|_| ErrorKind::Identity)?;
            drop(key);
            drop(passphrase);
            let pattern = format!("(?s)^{}/.*\\.yaml$", regex::escape(&self.project));
            let quoted =
                output::get(&Value::string(&pattern)?, true).map_err(|_| ErrorKind::SizeLimit)?;
            let rules = format!(
                "creation_rules:\n  - path_regex: {}    age: '{}'\n",
                quoted.as_str(),
                recipient
            );
            let rules_plain = Plaintext::copy_from(&rules)?;
            sops::recipients_for(&rules_plain, &format!("{}/dev.yaml", self.project))?;
            self.empty()?;
            checkpoint("init-before-create")?;
            let directory = self
                .directory
                .create(|path| completed.push(relative_directory(&self.root, path)))
                .inspect_err(|error| {
                    if error.disposition == Disposition::MayHaveChanged {
                        if let Some(path) = completed.pop() {
                            failing = path;
                        }
                    }
                })?;
            let store = Store::open(&self.root)?;
            if !filesystem::same_inode(&directory, &store.directory)? {
                return Err(ErrorKind::Stale.into());
            }
            let _session = store.write()?;
            if !filesystem::names(&store.directory)?.is_empty() {
                return Err(ErrorKind::Exists.into());
            }
            for name in ["keys", self.project.as_str()] {
                failing = format!("{name}/");
                let plan = DirectoryPlan::inspect(&self.root.join(name))?;
                if plan.exists() {
                    return Err(ErrorKind::Exists.into());
                }
                plan.create(|path| completed.push(relative_directory(&self.root, path)))
                    .inspect_err(|error| {
                        if error.disposition == Disposition::MayHaveChanged {
                            if let Some(path) = completed.pop() {
                                failing = path;
                            }
                        }
                    })?;
                store.root_current()?;
            }
            let public = format!("{recipient}\n");
            for (path, bytes) in [
                (format!("keys/{}.key.age", self.name), encrypted.as_slice()),
                (format!("keys/{}.pub", self.name), public.as_bytes()),
                (".sops.yaml".to_owned(), rules.as_bytes()),
            ] {
                failing = path.clone();
                let target = store.target(path.clone(), true, false)?;
                if filesystem::open_entry(&target.parent, &target.name)?.is_some() {
                    return Err(ErrorKind::Exists.into());
                }
                filesystem::replace_bytes(&store, &target, bytes, None)?;
                completed.push(path);
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(completed),
            Err(error) => Err(BatchFailure {
                completed,
                failing,
                error,
            }),
        }
    }
}

pub(super) fn relative_directory(root: &Path, path: &Path) -> String {
    if let Ok(relative) = path.strip_prefix(root) {
        if relative.as_os_str().is_empty() {
            "./".into()
        } else {
            format!("{}/", relative.to_string_lossy())
        }
    } else {
        let count = root
            .strip_prefix(path)
            .map(|p| p.components().count())
            .unwrap_or(0);
        "../".repeat(count)
    }
}
