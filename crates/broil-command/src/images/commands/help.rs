// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

pub fn help(path: &str) -> &'static [u8] {
    match path {
        "" => br#"Usage: broil image <command> [args...]

Build, publish and inspect project images.

Commands:
  build     Build selected images and their dependencies
  builder   Access and manage declared builders
  graph     Inspect the image dependency graph
  publish   Publish retained image content
  record    Inspect immutable artifact records
  resume    Observe and close recorded recovery windows
  settle    Choose a recorded publication binding
  status    Rebuild and inspect operation status
"#,
        "record" => br#"Usage: broil image record <command> [args...]

Inspect immutable artifact records.

Commands:
  list   List validated artifact IDs
  show   Show one artifact record by ID
"#,
        "builder" => br#"Usage: broil image builder <command> [args...]

Access and manage declared builders.

Commands:
  access      Inspect an authenticated builder endpoint
  inspect     Inspect managed ownership and the endpoint
  reconcile   Reconcile a managed builder
  remove      Remove a managed service, retaining storage unless purged
  setup       Set up a managed builder from a verified archive
"#,
        "graph" => br#"Usage: broil image graph --target <name>... [--platform <p>]... [--build-platform <p>] [--staging metadata|content] [--registry <name>]... [--format table|json]

Inspect one image dependency graph; no images are built.
Build platform defaults to linux/amd64 and staging to metadata.
"#,
        "build" => br#"Usage: broil image build --target <name>... --builder <name> [--platform <p>]... [--build-platform <p>] [--registry <name>]... [--refresh] [--optional-cache-reads] [--docker-daemon <socket>] [--non-interactive] [--format table|json]

Build selected images and their inferred dependencies on one builder.
An omitted build platform uses the builder probe; Docker loading is explicit.
"#,
        "publish" => br#"Usage: broil image publish --target <name> --operation <operation-id> [--registry <name>] [--artifact <artifact-id>] [--non-interactive] [--format table|json]

Publish the target's recorded retained content without rebuilding.
"#,
        "status" => br#"Usage: broil image status [--operation <operation-id>] [--format table|json]

Rebuild operation status from journals and settlement markers.
"#,
        "record list" => br#"Usage: broil image record list [--format table|json]

List committed artifact IDs after validating every listed record.
"#,
        "record show" => br#"Usage: broil image record show <artifact-id> [--format table|json]

Read one immutable record by exact ID; JSON preserves its stored encoding.
"#,
        "resume" => br#"Usage: broil image resume <operation-id> [--format table|json]

Observe recorded recovery windows without retrying an indeterminate effect.
"#,
        "settle" => br#"Usage: broil image settle <operation-id> --ambiguity <seq> --artifact <artifact-id> [--format table|json]

Choose one recorded candidate for an ambiguous publication binding.
"#,
        "builder access" => br#"Usage: broil image builder access <builder> [--non-interactive] [--format table|json]

Inspect an authenticated builder endpoint without taking lifecycle ownership.
"#,
        "builder inspect" => br#"Usage: broil image builder inspect <builder> [--non-interactive] [--format table|json]

Inspect the managed builder's ownership and endpoint.
"#,
        "builder setup" => br#"Usage: broil image builder setup <builder> --archive <path> [--arm64-emulation] [--non-interactive] [--format table|json]

Set up a managed builder from an independently verified archive.
ARM64 emulation is disabled unless explicitly requested.
"#,
        "builder reconcile" => br#"Usage: broil image builder reconcile <builder> --archive <path> [--arm64-emulation] [--non-interactive] [--format table|json]

Reconcile a managed builder using its recorded ownership.
ARM64 emulation is disabled unless explicitly requested.
"#,
        "builder remove" => br#"Usage: broil image builder remove <builder> [--purge] [--non-interactive] [--format table|json]

Remove the owned managed service; retain cache and storage unless --purge is given.
"#,
        _ => b"",
    }
}
