#!/usr/bin/env python3
# Copyright 2026 Broil contributors
# SPDX-License-Identifier: Apache-2.0
"""Package an explicitly inventoried candidate executable and legal inputs."""

import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def package(executable, legal, output, component, version, revision):
    output.mkdir(mode=0o700)
    blobs = output / "blobs/sha256"
    blobs.mkdir(parents=True)

    def blob(data, kind):
        identity = hashlib.sha256(data).hexdigest()
        (blobs / identity).write_bytes(data)
        return {"mediaType": "application/vnd.oci.image." + kind,
                "digest": "sha256:" + identity, "size": len(data)}

    inventory = json.loads(legal.read_bytes())
    files = {"bin/" + component: (executable.read_bytes(), 0o755)}
    for item in inventory:
        name = "usr/share/licenses/" + item["name"]
        assert not Path(name).is_absolute() and ".." not in Path(name).parts and name not in files
        data = Path(item["source"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == item["sha256"], "legal-input-identity"
        files[name] = (data, 0o644)
    files["usr/share/licenses/manifest.json"] = (encoded([
        {key: entry[key] for key in ("name", "sha256")} for entry in inventory]), 0o644)
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        directories = {str(parent) for name in files for parent in Path(name).parents if str(parent) != "."}
        for name in sorted(directories):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            archive.addfile(info)
        for name, (data, mode) in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), mode
            archive.addfile(info, io.BytesIO(data))
    layer = blob(layer.getvalue(), "layer.v1.tar")
    labels = {"org.opencontainers.image.version": version,
              "org.opencontainers.image.revision": revision,
              "io.broil.qualification": "unadopted-candidate"}
    config = blob(encoded({"architecture": "amd64", "os": "linux", "config": {
        "Entrypoint": ["/bin/" + component], "Labels": labels,
        "Env": ["OTEL_TRACES_EXPORTER=none"] if component == "distribution" else []},
        "rootfs": {"type": "layers", "diff_ids": [layer["digest"]]}}), "config.v1+json")
    manifest = blob(encoded({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "config": config, "layers": [layer]}), "manifest.v1+json")
    (output / "oci-layout").write_bytes(encoded({"imageLayoutVersion": "1.0.0"}))
    (output / "index.json").write_bytes(encoded({"schemaVersion": 2, "manifests": [{
        **manifest, "platform": {"os": "linux", "architecture": "amd64"}}]}))
    print(json.dumps({"manifest": manifest, "config": config, "layer": layer,
                      "legal_files": len(inventory), "runtime_files": ["bin/" + component]}))


if __name__ == "__main__":
    assert len(sys.argv) == 7
    package(*map(Path, sys.argv[1:4]), *sys.argv[4:])
