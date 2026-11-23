# K3s feasibility candidate

These assets support Broil's disposable infrastructure experiment. Contributors
use the experiment to establish whether the selected K3s and registry components
can meet the infrastructure contracts before production commands adopt them.
This directory does not provide a supported installer.

The internal `protected-actions.py` adapter and `action-profile.json` bind
credential inputs to already prepared inactive resources through a
request-bound protocol. `lifecycle-actions.py` is
the second profile-bound body: it serves the closed `broil-k3s-lifecycle`
protocol that activates, starts, observes and publishes the first server from
prepared generations, carrying its own copy of the writer-admission layer and
the guard's bytes as data. `service-guard.py` is the source-carried prestart
guard that `activate-server` installs beside the activation record; before
every start it re-verifies the executable, configuration, unit, tokens, log
and its own bytes and refuses a changed input with one fixed line.

The candidate keeps the official `v1.36.4+k3s1` amd64 executable unchanged.
`profile.lock.json` records its upstream revision and exact executable and airgap
archive identities, and names it as the only version for fresh installation;
no moving channel is resolved.
`published-provenance.lock.json` inventories the embedded files, bundled images
and published packaging sources, with separate references for addon inputs.
Older patch and minor versions are ineligible for fresh installation. Artifact
admission does not establish the full component closure or a supported runtime
profile.

The separately named source locks and build scripts describe the registry,
authorization and Metrics Server candidates. They do not rebuild K3s.
`coredns-image.lock.json` and the CoreDNS templates under `templates/` fix the
selected image and its resources.
`syncthing.lock.json` pins the registry replication's Syncthing v2 linux-amd64
release archive, its digest from the upstream signed checksum file, and its
executable's size and digest; the bootstrap index stages the archive as the
`syncthing` asset when a managed registry is declared.

Credentials and service state that these assets place on a host are in
external custody there: owner-only files, root-owned K3s storage and private
service logs. Python and upstream tools do not promise memory erasure. Rust
scalars and private transport buffers use the existing zeroizing owners. A
successful process exit or unlink does not prove erasure of external copies,
crash residue or backups.
