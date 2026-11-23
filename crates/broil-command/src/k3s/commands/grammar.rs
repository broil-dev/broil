// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verb(&'static str);

impl Verb {
    pub fn name(self) -> &'static str {
        self.0
    }
    pub fn named(name: &str) -> Option<Self> {
        LEAVES.iter().find(|v| v.0 == name).map(|v| Self(v.0))
    }
    pub fn grammar(self) -> &'static str {
        LEAVES.iter().find(|v| v.0 == self.0).expect("fixed leaf").1
    }
}

pub fn group(name: &str) -> Option<&'static str> {
    GROUPS.iter().find(|v| v.0 == name).map(|v| v.0)
}

pub const LEAVES: &[(&str, &str, &str)] = &[
    (
        "list",
        "",
        "List declared targets in the active environment.",
    ),
    (
        "show",
        "<target>",
        "Inspect one target declaration without external access.",
    ),
    (
        "plan",
        "<target> --action <action> [--member <name>] [--consumer <consumer>] [--backup <id>] [--version <version>] [--scope runtime|registry|all] [--owner <name>] [--purpose <purpose>] [--artifact <id>] [--repository <repository>] [--application <name>] [--release <id>] [--keep-days <n>] [--keep-last <n>] [--observe]",
        "Preview one action; live observation requires --observe.",
    ),
    (
        "create",
        "<target>",
        "Create and verify the declared cluster and infrastructure.",
    ),
    (
        "reconcile",
        "<target>",
        "Observe and converge owned infrastructure without implicit removal.",
    ),
    (
        "status",
        "<target>",
        "Observe cluster, node and declared-service readiness separately.",
    ),
    (
        "diagnose",
        "<target> --component api|datastore|network|dns|storage|ingress|certificates|registry [--limit <n>]",
        "Collect bounded typed diagnostics for one component.",
    ),
    (
        "nodes",
        "<target> [--limit <n>]",
        "Observe member identities and readiness.",
    ),
    (
        "workloads",
        "<target> [--limit <n>]",
        "Inspect bounded workload metadata without release actions.",
    ),
    (
        "services",
        "<target> [--limit <n>]",
        "Inspect bounded service metadata and infrastructure ownership.",
    ),
    (
        "node join",
        "<target> <member>",
        "Join one declared member through the ordered membership gates.",
    ),
    (
        "node join-agents",
        "<target>",
        "Join remaining declared agents in bounded ordered waves.",
    ),
    (
        "node drain",
        "<target> <member> [--approve <digest>]",
        "Drain one owned member while respecting disruption policy.",
    ),
    (
        "node uncordon",
        "<target> <member>",
        "Return a drained member to scheduling.",
    ),
    (
        "node remove",
        "<target> <member> --approve <digest>",
        "Remove one owned member while preserving retained data.",
    ),
    (
        "node replace",
        "<target> <member> --approve <digest>",
        "Join the declared machine of one removed member.",
    ),
    (
        "credentials inspect",
        "<target> --consumer <consumer>",
        "Inspect credential references and observed access state without values.",
    ),
    (
        "credentials reconcile",
        "<target> --consumer <consumer>",
        "Reconcile one protected infrastructure consumer and verify access.",
    ),
    (
        "access check",
        "<target>",
        "Verify isolated administrative access to the selected cluster.",
    ),
    (
        "access export",
        "<target> --output <path>",
        "Write explicitly requested private administrator access to a new file.",
    ),
    (
        "backup create",
        "<target>",
        "Capture and verify an encrypted off-node cluster recovery bundle.",
    ),
    (
        "backup list",
        "<target>",
        "Inspect recorded cluster backup identities and verification times.",
    ),
    (
        "backup restore",
        "<target> --backup <id> --approve <digest>",
        "Restore the selected cluster bundle into the approved owned destination.",
    ),
    (
        "upgrade",
        "<target> --version <version>",
        "Apply one supported K3s transition with backup and readiness gates.",
    ),
    (
        "remove",
        "<target> --approve <digest>",
        "Remove owned cluster services while retaining persistent data.",
    ),
    (
        "purge",
        "<target> --scope runtime|registry|all --approve <digest>",
        "Delete only the approved unheld owned persistent data.",
    ),
    (
        "operation list",
        "<target>",
        "List this target's recorded infrastructure operations.",
    ),
    (
        "operation show",
        "<target> <operation-id>",
        "Inspect one recorded request and its ordered observations.",
    ),
    (
        "operation resume",
        "<target> <operation-id>",
        "Observe unresolved work without replaying its effects.",
    ),
    (
        "operation retry",
        "<target> <operation-id> --step <id> --approve <digest>",
        "Start an explicitly approved retry of one observed recoverable step.",
    ),
    (
        "operation prune",
        "<target> [--keep-days <n>] [--keep-last <n>] --approve <digest>",
        "Remove the approved settled operation and release records outside the retention policy, with their attempt records on every member.",
    ),
    (
        "registry inspect",
        "<target>",
        "Observe the registry writer, replicas, readers, storage and endpoint.",
    ),
    (
        "registry reconcile",
        "<target>",
        "Create or converge the declared owned registry service.",
    ),
    (
        "registry backup",
        "<target>",
        "Capture a fenced protected registry backup with its hold ledger.",
    ),
    (
        "registry restore",
        "<target> --backup <id> --approve <digest>",
        "Restore approved registry content, ownership and access dependencies.",
    ),
    (
        "registry upgrade",
        "<target> --version <version>",
        "Apply one proved registry transition while preserving content and holds.",
    ),
    (
        "registry remove",
        "<target> --approve <digest>",
        "Remove the owned registry service while retaining its storage and holds.",
    ),
    (
        "registry retention list",
        "<target>",
        "Inspect recorded immutable-content holds without granting deletion.",
    ),
    (
        "registry retention hold",
        "<target> --owner <name> --purpose <purpose> --artifact <id> --repository <repository>",
        "Protect a verified artifact closure for one explicit owner and purpose.",
    ),
    (
        "registry retention release",
        "<target> --owner <name> --purpose <purpose> --artifact <id> --repository <repository> --approve <digest>",
        "Release only the approved holder's protection without deleting content.",
    ),
    (
        "registry maintenance plan",
        "<target>",
        "Observe and propose bounded registry cleanup without deleting content.",
    ),
    (
        "registry maintenance run",
        "<target> --approve <digest>",
        "Revalidate and execute approved cleanup under the actual writer fence.",
    ),
    (
        "release prepare",
        "<target> <application> [--artifacts <image>=<artifact-id>[,...]]",
        "Record an immutable release from declared manifests and image records.",
    ),
    (
        "release deliver",
        "<target> <release>",
        "Pull and pin a release's images on its required nodes.",
    ),
    (
        "release apply",
        "<target> <release> [--approve <digest>]",
        "Apply a delivered release and verify its health.",
    ),
    (
        "release deploy",
        "<target> <application> [--artifacts <image>=<artifact-id>[,...]]",
        "Prepare, deliver and apply one release of an application.",
    ),
    (
        "release status",
        "<target> <application>",
        "Observe the active and rollback releases on the cluster.",
    ),
    (
        "release list",
        "<target> <application> [--limit <n>]",
        "List an application's recorded releases.",
    ),
    (
        "release show",
        "<target> <release>",
        "Inspect one recorded release and its evidence.",
    ),
    (
        "release rollback",
        "<target> <application>",
        "Re-apply the recorded rollback release and verify its health.",
    ),
    (
        "release retain",
        "<target> <application> --approve <digest>",
        "Unpin images of releases that are neither active nor rollback.",
    ),
    (
        "delivery report",
        "<target> <release>",
        "Report recorded per-node delivery measurements.",
    ),
    (
        "delivery check",
        "<target>",
        "Observe replica sync, local readers and token services on every member.",
    ),
];

const GROUPS: &[(&str, &str)] = &[
    (
        "",
        "Manage declared K3s infrastructure, its registry and releases.",
    ),
    ("node", "Join, drain, remove and replace owned members."),
    (
        "credentials",
        "Inspect and reconcile protected infrastructure consumers.",
    ),
    (
        "access",
        "Verify or explicitly export isolated administrator access.",
    ),
    (
        "backup",
        "Create, inspect and restore protected cluster backups.",
    ),
    (
        "operation",
        "Inspect, recover and clean up recorded infrastructure operations.",
    ),
    (
        "registry",
        "Manage the declared persistent registry service.",
    ),
    (
        "registry retention",
        "Manage immutable-content protection by explicit owner.",
    ),
    (
        "registry maintenance",
        "Plan and execute fenced registry cleanup.",
    ),
    (
        "release",
        "Prepare, deliver, apply and roll back recorded application releases.",
    ),
    ("delivery", "Inspect delivery evidence and replica health."),
];

pub fn help(path: &str) -> &'static [u8] {
    match path {
        "list" => b"Usage: broil k3s list [--non-interactive] [--format table|json]\n\nList declared targets in the active environment.\n",
        "show" => b"Usage: broil k3s show <target> [--non-interactive] [--format table|json]\n\nInspect one target declaration without external access.\n",
        "plan" => b"Usage: broil k3s plan <target> --action <action> [--member <name>] [--consumer <consumer>] [--backup <id>] [--version <version>] [--scope runtime|registry|all] [--owner <name>] [--purpose <purpose>] [--artifact <id>] [--repository <repository>] [--application <name>] [--release <id>] [--keep-days <n>] [--keep-last <n>] [--observe] [--non-interactive] [--format table|json]\n\nPreview one action; live observation requires --observe.\n",
        "create" => b"Usage: broil k3s create <target> [--non-interactive] [--format table|json]\n\nCreate and verify the declared cluster and infrastructure.\n",
        "reconcile" => b"Usage: broil k3s reconcile <target> [--non-interactive] [--format table|json]\n\nObserve and converge owned infrastructure without implicit removal.\n",
        "status" => b"Usage: broil k3s status <target> [--non-interactive] [--format table|json]\n\nObserve cluster, node and declared-service readiness separately.\n",
        "diagnose" => b"Usage: broil k3s diagnose <target> --component api|datastore|network|dns|storage|ingress|certificates|registry [--limit <n>] [--non-interactive] [--format table|json]\n\nCollect bounded typed diagnostics for one component.\n",
        "nodes" => b"Usage: broil k3s nodes <target> [--limit <n>] [--non-interactive] [--format table|json]\n\nObserve member identities and readiness.\n",
        "workloads" => b"Usage: broil k3s workloads <target> [--limit <n>] [--non-interactive] [--format table|json]\n\nInspect bounded workload metadata without release actions.\n",
        "services" => b"Usage: broil k3s services <target> [--limit <n>] [--non-interactive] [--format table|json]\n\nInspect bounded service metadata and infrastructure ownership.\n",
        "node join" => b"Usage: broil k3s node join <target> <member> [--non-interactive] [--format table|json]\n\nJoin one declared member through the ordered membership gates.\n",
        "node join-agents" => b"Usage: broil k3s node join-agents <target> [--non-interactive] [--format table|json]\n\nJoin remaining declared agents in bounded ordered waves.\n",
        "node drain" => b"Usage: broil k3s node drain <target> <member> [--approve <digest>] [--non-interactive] [--format table|json]\n\nDrain one owned member while respecting disruption policy.\n",
        "node uncordon" => b"Usage: broil k3s node uncordon <target> <member> [--non-interactive] [--format table|json]\n\nReturn a drained member to scheduling.\n",
        "node remove" => b"Usage: broil k3s node remove <target> <member> --approve <digest> [--non-interactive] [--format table|json]\n\nRemove one owned member while preserving retained data.\n",
        "node replace" => b"Usage: broil k3s node replace <target> <member> --approve <digest> [--non-interactive] [--format table|json]\n\nJoin the declared machine of one removed member.\n",
        "credentials inspect" => b"Usage: broil k3s credentials inspect <target> --consumer <consumer> [--non-interactive] [--format table|json]\n\nInspect credential references and observed access state without values.\n",
        "credentials reconcile" => b"Usage: broil k3s credentials reconcile <target> --consumer <consumer> [--non-interactive] [--format table|json]\n\nReconcile one protected infrastructure consumer and verify access.\n",
        "access check" => b"Usage: broil k3s access check <target> [--non-interactive] [--format table|json]\n\nVerify isolated administrative access to the selected cluster.\n",
        "access export" => b"Usage: broil k3s access export <target> --output <path> [--non-interactive] [--format table|json]\n\nWrite explicitly requested private administrator access to a new file.\n",
        "backup create" => b"Usage: broil k3s backup create <target> [--non-interactive] [--format table|json]\n\nCapture and verify an encrypted off-node cluster recovery bundle.\n",
        "backup list" => b"Usage: broil k3s backup list <target> [--non-interactive] [--format table|json]\n\nInspect recorded cluster backup identities and verification times.\n",
        "backup restore" => b"Usage: broil k3s backup restore <target> --backup <id> --approve <digest> [--non-interactive] [--format table|json]\n\nRestore the selected cluster bundle into the approved owned destination.\n",
        "upgrade" => b"Usage: broil k3s upgrade <target> --version <version> [--non-interactive] [--format table|json]\n\nApply one supported K3s transition with backup and readiness gates.\n",
        "remove" => b"Usage: broil k3s remove <target> --approve <digest> [--non-interactive] [--format table|json]\n\nRemove owned cluster services while retaining persistent data.\n",
        "purge" => b"Usage: broil k3s purge <target> --scope runtime|registry|all --approve <digest> [--non-interactive] [--format table|json]\n\nDelete only the approved unheld owned persistent data.\n",
        "operation list" => b"Usage: broil k3s operation list <target> [--non-interactive] [--format table|json]\n\nList this target's recorded infrastructure operations.\n",
        "operation show" => b"Usage: broil k3s operation show <target> <operation-id> [--non-interactive] [--format table|json]\n\nInspect one recorded request and its ordered observations.\n",
        "operation resume" => b"Usage: broil k3s operation resume <target> <operation-id> [--non-interactive] [--format table|json]\n\nObserve unresolved work without replaying its effects.\n",
        "operation retry" => b"Usage: broil k3s operation retry <target> <operation-id> --step <id> --approve <digest> [--non-interactive] [--format table|json]\n\nStart an explicitly approved retry of one observed recoverable step.\n",
        "operation prune" => b"Usage: broil k3s operation prune <target> [--keep-days <n>] [--keep-last <n>] --approve <digest> [--non-interactive] [--format table|json]\n\nRemove the approved settled operation and release records outside the retention policy, with their attempt records on every member.\n",
        "registry inspect" => b"Usage: broil k3s registry inspect <target> [--non-interactive] [--format table|json]\n\nObserve the registry writer, replicas, readers, storage and endpoint.\n",
        "registry reconcile" => b"Usage: broil k3s registry reconcile <target> [--non-interactive] [--format table|json]\n\nCreate or converge the declared owned registry service.\n",
        "registry backup" => b"Usage: broil k3s registry backup <target> [--non-interactive] [--format table|json]\n\nCapture a fenced protected registry backup with its hold ledger.\n",
        "registry restore" => b"Usage: broil k3s registry restore <target> --backup <id> --approve <digest> [--non-interactive] [--format table|json]\n\nRestore approved registry content, ownership and access dependencies.\n",
        "registry upgrade" => b"Usage: broil k3s registry upgrade <target> --version <version> [--non-interactive] [--format table|json]\n\nApply one proved registry transition while preserving content and holds.\n",
        "registry remove" => b"Usage: broil k3s registry remove <target> --approve <digest> [--non-interactive] [--format table|json]\n\nRemove the owned registry service while retaining its storage and holds.\n",
        "registry retention list" => b"Usage: broil k3s registry retention list <target> [--non-interactive] [--format table|json]\n\nInspect recorded immutable-content holds without granting deletion.\n",
        "registry retention hold" => b"Usage: broil k3s registry retention hold <target> --owner <name> --purpose <purpose> --artifact <id> --repository <repository> [--non-interactive] [--format table|json]\n\nProtect a verified artifact closure for one explicit owner and purpose.\n",
        "registry retention release" => b"Usage: broil k3s registry retention release <target> --owner <name> --purpose <purpose> --artifact <id> --repository <repository> --approve <digest> [--non-interactive] [--format table|json]\n\nRelease only the approved holder's protection without deleting content.\n",
        "registry maintenance plan" => b"Usage: broil k3s registry maintenance plan <target> [--non-interactive] [--format table|json]\n\nObserve and propose bounded registry cleanup without deleting content.\n",
        "registry maintenance run" => b"Usage: broil k3s registry maintenance run <target> --approve <digest> [--non-interactive] [--format table|json]\n\nRevalidate and execute approved cleanup under the actual writer fence.\n",
        "release prepare" => b"Usage: broil k3s release prepare <target> <application> [--artifacts <image>=<artifact-id>[,...]] [--non-interactive] [--format table|json]\n\nRecord an immutable release from declared manifests and image records.\n",
        "release deliver" => b"Usage: broil k3s release deliver <target> <release> [--non-interactive] [--format table|json]\n\nPull and pin a release's images on its required nodes.\n",
        "release apply" => b"Usage: broil k3s release apply <target> <release> [--approve <digest>] [--non-interactive] [--format table|json]\n\nApply a delivered release and verify its health.\n",
        "release deploy" => b"Usage: broil k3s release deploy <target> <application> [--artifacts <image>=<artifact-id>[,...]] [--non-interactive] [--format table|json]\n\nPrepare, deliver and apply one release of an application.\n",
        "release status" => b"Usage: broil k3s release status <target> <application> [--non-interactive] [--format table|json]\n\nObserve the active and rollback releases on the cluster.\n",
        "release list" => b"Usage: broil k3s release list <target> <application> [--limit <n>] [--non-interactive] [--format table|json]\n\nList an application's recorded releases.\n",
        "release show" => b"Usage: broil k3s release show <target> <release> [--non-interactive] [--format table|json]\n\nInspect one recorded release and its evidence.\n",
        "release rollback" => b"Usage: broil k3s release rollback <target> <application> [--non-interactive] [--format table|json]\n\nRe-apply the recorded rollback release and verify its health.\n",
        "release retain" => b"Usage: broil k3s release retain <target> <application> --approve <digest> [--non-interactive] [--format table|json]\n\nUnpin images of releases that are neither active nor rollback.\n",
        "delivery report" => b"Usage: broil k3s delivery report <target> <release> [--non-interactive] [--format table|json]\n\nReport recorded per-node delivery measurements.\n",
        "delivery check" => b"Usage: broil k3s delivery check <target> [--non-interactive] [--format table|json]\n\nObserve replica sync, local readers and token services on every member.\n",
        "" => b"Usage: broil k3s <command> [args...]\n\nManage declared K3s infrastructure, its registry and releases.\n\nCommands:\n  access            Verify or explicitly export isolated administrator access.\n  backup            Create, inspect and restore protected cluster backups.\n  create            Create and verify the declared cluster and infrastructure.\n  credentials       Inspect and reconcile protected infrastructure consumers.\n  delivery          Inspect delivery evidence and replica health.\n  diagnose          Collect bounded typed diagnostics for one component.\n  list              List declared targets in the active environment.\n  node              Join, drain, remove and replace owned members.\n  nodes             Observe member identities and readiness.\n  operation         Inspect, recover and clean up recorded infrastructure operations.\n  plan              Preview one action; live observation requires --observe.\n  purge             Delete only the approved unheld owned persistent data.\n  reconcile         Observe and converge owned infrastructure without implicit removal.\n  registry          Manage the declared persistent registry service.\n  release           Prepare, deliver, apply and roll back recorded application releases.\n  remove            Remove owned cluster services while retaining persistent data.\n  services          Inspect bounded service metadata and infrastructure ownership.\n  show              Inspect one target declaration without external access.\n  status            Observe cluster, node and declared-service readiness separately.\n  upgrade           Apply one supported K3s transition with backup and readiness gates.\n  workloads         Inspect bounded workload metadata without release actions.\n",
        "node" => b"Usage: broil k3s node <command> [args...]\n\nJoin, drain, remove and replace owned members.\n\nCommands:\n  drain             Drain one owned member while respecting disruption policy.\n  join              Join one declared member through the ordered membership gates.\n  join-agents       Join remaining declared agents in bounded ordered waves.\n  remove            Remove one owned member while preserving retained data.\n  replace           Join the declared machine of one removed member.\n  uncordon          Return a drained member to scheduling.\n",
        "credentials" => b"Usage: broil k3s credentials <command> [args...]\n\nInspect and reconcile protected infrastructure consumers.\n\nCommands:\n  inspect           Inspect credential references and observed access state without values.\n  reconcile         Reconcile one protected infrastructure consumer and verify access.\n",
        "access" => b"Usage: broil k3s access <command> [args...]\n\nVerify or explicitly export isolated administrator access.\n\nCommands:\n  check             Verify isolated administrative access to the selected cluster.\n  export            Write explicitly requested private administrator access to a new file.\n",
        "backup" => b"Usage: broil k3s backup <command> [args...]\n\nCreate, inspect and restore protected cluster backups.\n\nCommands:\n  create            Capture and verify an encrypted off-node cluster recovery bundle.\n  list              Inspect recorded cluster backup identities and verification times.\n  restore           Restore the selected cluster bundle into the approved owned destination.\n",
        "operation" => b"Usage: broil k3s operation <command> [args...]\n\nInspect, recover and clean up recorded infrastructure operations.\n\nCommands:\n  list              List this target's recorded infrastructure operations.\n  prune             Remove the approved settled operation and release records outside the retention policy, with their attempt records on every member.\n  resume            Observe unresolved work without replaying its effects.\n  retry             Start an explicitly approved retry of one observed recoverable step.\n  show              Inspect one recorded request and its ordered observations.\n",
        "registry" => b"Usage: broil k3s registry <command> [args...]\n\nManage the declared persistent registry service.\n\nCommands:\n  backup            Capture a fenced protected registry backup with its hold ledger.\n  inspect           Observe the registry writer, replicas, readers, storage and endpoint.\n  maintenance       Plan and execute fenced registry cleanup.\n  reconcile         Create or converge the declared owned registry service.\n  remove            Remove the owned registry service while retaining its storage and holds.\n  restore           Restore approved registry content, ownership and access dependencies.\n  retention         Manage immutable-content protection by explicit owner.\n  upgrade           Apply one proved registry transition while preserving content and holds.\n",
        "registry retention" => b"Usage: broil k3s registry retention <command> [args...]\n\nManage immutable-content protection by explicit owner.\n\nCommands:\n  hold              Protect a verified artifact closure for one explicit owner and purpose.\n  list              Inspect recorded immutable-content holds without granting deletion.\n  release           Release only the approved holder's protection without deleting content.\n",
        "registry maintenance" => b"Usage: broil k3s registry maintenance <command> [args...]\n\nPlan and execute fenced registry cleanup.\n\nCommands:\n  plan              Observe and propose bounded registry cleanup without deleting content.\n  run               Revalidate and execute approved cleanup under the actual writer fence.\n",
        "release" => b"Usage: broil k3s release <command> [args...]\n\nPrepare, deliver, apply and roll back recorded application releases.\n\nCommands:\n  apply             Apply a delivered release and verify its health.\n  deliver           Pull and pin a release's images on its required nodes.\n  deploy            Prepare, deliver and apply one release of an application.\n  list              List an application's recorded releases.\n  prepare           Record an immutable release from declared manifests and image records.\n  retain            Unpin images of releases that are neither active nor rollback.\n  rollback          Re-apply the recorded rollback release and verify its health.\n  show              Inspect one recorded release and its evidence.\n  status            Observe the active and rollback releases on the cluster.\n",
        "delivery" => b"Usage: broil k3s delivery <command> [args...]\n\nInspect delivery evidence and replica health.\n\nCommands:\n  check             Observe replica sync, local readers and token services on every member.\n  report            Report recorded per-node delivery measurements.\n",
        _=>unreachable!("closed K3s help topic"),
    }
}
