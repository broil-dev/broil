# Remote Example Templates

These files are templates for project-owned Broil remote scripts. They are not
Broil core policy and should not be used unchanged on production machines.

The templates are intentionally generic:

* no distribution package manager is named;
* no service manager command is hard-coded;
* no secret values are embedded;
* no host-key checking bypass is shown;
* every machine-specific path or command is supplied by project configuration.

Typical use:

1. Copy the relevant template into your project scripts directory.
2. Replace the project hook variables with fixed commands for your operating
   system and SSH server policy.
3. Reference the resulting script from `remote.scripts`.
4. Use it from a provisioning profile `ssh_transition` action or
   `security.verify` action.
5. Inspect `broil remote list --plan` before provisioning.

Template files:

* `openssh-transition-template.sh` shows the `prepare`, `apply`, `validate`,
  `reload`, and `rollback` shape for an SSH/SFTP transition.
* `verify-public-key-only-template.sh` checks effective OpenSSH daemon policy
  output for public-key-only access.
* `verify-sftp-template.sh` checks effective OpenSSH daemon policy output for
  an SFTP subsystem.
* `verify-project-security-template.sh` provides a place for project-specific
  assertions, such as required users, groups, firewall state, or audit controls.

The transition template expects project-provided commands because package names,
config paths, reload commands, and backup layout are operating-system policy.
The verifier templates prefer `sshd -T` output but allow a project to supply a
trusted equivalent command.
