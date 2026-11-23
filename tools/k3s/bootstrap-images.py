#!/usr/bin/env python3
# Copyright 2026 Broil contributors
# SPDX-License-Identifier: Apache-2.0
"""Fetch only the fixed public addon closure, before any managed origin exists."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parent
NAMES = {"coredns", "traefik", "cert-manager-controller", "cert-manager-cainjector",
         "cert-manager-webhook", "cert-manager-acmesolver", "cert-manager-startupapicheck"}
ACCEPT = ", ".join(("application/vnd.oci.image.index.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.v2+json"))


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        assert target.scheme == "https" and not target.username and not target.password
        redirected = super().redirect_request(request, fp, code, message, headers, newurl)
        if target.netloc != urllib.parse.urlsplit(request.full_url).netloc:
            redirected.remove_header("Authorization")
        return redirected


class ContentMismatch(ValueError):
    pass


def acquire(url, descriptor, destination, headers=None):
    size, digest = descriptor["size"], descriptor["digest"]
    assert type(size) is int and 0 < size <= 512 * 1024**2
    assert digest.startswith("sha256:") and len(digest) == 71
    assert all(c in "0123456789abcdef" for c in digest[7:])
    if destination.exists():
        with destination.open("rb") as stream:
            assert destination.stat().st_size == size and "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest() == digest
        return
    request = urllib.request.Request(url, headers=headers or {})
    opener = urllib.request.build_opener(Redirect())
    partial = destination.with_name(destination.name + ".partial")
    output = partial.open("xb")
    deadline = time.monotonic() + 180
    try:
        with output:
            for attempt in range(3):
                try:
                    if time.monotonic() >= deadline:
                        raise TimeoutError()
                    with opener.open(request, timeout=min(30, max(0.01, deadline - time.monotonic()))) as response:
                        count, hasher = 0, hashlib.sha256()
                        while chunk := response.read(1024 * 1024):
                            if time.monotonic() >= deadline:
                                raise TimeoutError()
                            count += len(chunk)
                            assert count <= size, "addon-encoded-size"
                            output.write(chunk)
                            hasher.update(chunk)
                    if time.monotonic() >= deadline:
                        raise TimeoutError()
                    if count != size or "sha256:" + hasher.hexdigest() != digest:
                        raise ContentMismatch("addon-content-identity")
                    break
                except (ContentMismatch, http.client.IncompleteRead, urllib.error.URLError,
                        TimeoutError, ConnectionResetError) as error:
                    cause = error.reason if isinstance(error, urllib.error.URLError) else error
                    if isinstance(cause, ssl.SSLCertVerificationError) or (
                            isinstance(cause, ssl.SSLError) and cause.reason != "TLSV1_ALERT_INTERNAL_ERROR"):
                        raise
                    if isinstance(error, urllib.error.HTTPError) and error.code != 429 and error.code < 500:
                        raise
                    if attempt == 2 or time.monotonic() >= deadline:
                        raise
                    output.seek(0)
                    output.truncate()
                    print(json.dumps({"event": "public-addon-download-retry", "attempt": attempt + 1}), flush=True)
                    time.sleep(min(attempt + 1, max(0, deadline - time.monotonic())))
            output.flush()
            os.fsync(output.fileno())
        os.link(partial, destination, follow_symlinks=False)
    finally:
        partial.unlink()


def image(name, lock, destination):
    assert name in NAMES and not destination.exists()
    assert lock["registry"] in ("registry-1.docker.io", "quay.io")
    repository = lock["repository"]
    expected = ("coredns/coredns" if name == "coredns" else "library/traefik" if name == "traefik"
                else "jetstack/" + name)
    assert repository == expected
    destination.mkdir(mode=0o700)
    layout = destination / "layout"
    blobs = layout / "blobs/sha256"
    blobs.mkdir(parents=True)
    headers = {"Accept": ACCEPT}
    if lock["registry"] == "registry-1.docker.io":
        query = urllib.parse.urlencode({"service": "registry.docker.io", "scope": "repository:" + repository + ":pull"})
        with urllib.request.urlopen("https://auth.docker.io/token?" + query, timeout=30) as response:
            data = response.read(65537)
        assert len(data) <= 65536
        # The anonymous pull token stays in this acquisition process and is not
        # written into the public bundle, provenance or command arguments.
        headers["Authorization"] = "Bearer " + json.loads(data)["token"]
    base = "https://" + lock["registry"] + "/v2/" + repository
    acquire(base + "/manifests/" + lock["index"]["digest"], lock["index"], destination / "index-upstream.json", headers)
    index = json.loads((destination / "index-upstream.json").read_bytes())
    selected = [m for m in index["manifests"] if m.get("platform", {}).get("os") == "linux"
                and m["platform"].get("architecture") == "amd64"]
    assert len(selected) == 1
    assert all(selected[0][k] == lock["manifest"][k] for k in ("digest", "size", "mediaType"))
    manifest = lock["manifest"]
    acquire(base + "/manifests/" + manifest["digest"], manifest, blobs / manifest["digest"][7:], headers)
    raw = json.loads((blobs / manifest["digest"][7:]).read_bytes())
    assert raw["config"] == lock["config"] and raw["layers"] == lock["layers"]
    assert len(raw["layers"]) <= 32
    for descriptor in (raw["config"], *raw["layers"]):
        acquire(base + "/blobs/" + descriptor["digest"], descriptor, blobs / descriptor["digest"][7:], headers)
    config = json.loads((blobs / raw["config"]["digest"][7:]).read_bytes())
    assert config["os"] == "linux" and config["architecture"] == "amd64"
    runtime = lock["runtime_repository"] + "@" + manifest["digest"]
    entry = {**{k: manifest[k] for k in ("digest", "size", "mediaType")},
             "platform": {"os": "linux", "architecture": "amd64"},
             "annotations": {"io.containerd.image.name": lock["runtime_repository"] + ":broil-proof"}}
    (layout / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [entry]}, sort_keys=True, separators=(",", ":")))
    (layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
    archive = destination.parent / (name + ".tar")
    with tarfile.open(archive, "x", format=tarfile.USTAR_FORMAT) as output:
        for path in sorted(layout.rglob("*")):
            if not path.is_file():
                continue
            info = tarfile.TarInfo(str(path.relative_to(layout)))
            info.mode, info.size = 0o644, path.stat().st_size
            with path.open("rb") as data:
                output.addfile(info, data)
    with archive.open("rb") as data:
        digest = hashlib.file_digest(data, "sha256").hexdigest()
    return {"name": archive.name, "size": archive.stat().st_size, "sha256": digest,
            "image": runtime, "manifest": manifest}


def prepare(destination):
    lock = json.loads((ROOT / "addon-images.lock.json").read_bytes())
    assert lock["schema"] == 1 and set(lock["images"]) == NAMES
    destination.mkdir(mode=0o700)
    result = [image(name, lock["images"][name], destination / name) for name in sorted(NAMES)]
    pin = lock["cert_manager_manifest"]
    acquire(pin["url"], {"size": pin["size"], "digest": "sha256:" + pin["sha256"]},
            destination / "cert-manager.yaml")
    (destination / "verified-public-bundle.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return result


def verify_public_bundles(directory):
    pins = json.loads((ROOT / "addon-bundles.lock.json").read_bytes())["assets"]
    if {p["name"] for p in pins} != {name + ".tar" for name in NAMES}:
        raise ValueError("addon-bundle-selection")
    for pin in pins:
        path = directory / pin["name"]
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size != pin["size"]:
            raise ValueError("addon-bundle-file")
        with path.open("rb") as data:
            if hashlib.file_digest(data, "sha256").hexdigest() != pin["sha256"]:
                raise ValueError("addon-bundle-content")
    manifest = directory / "cert-manager.yaml"
    pin = json.loads((ROOT / "addon-images.lock.json").read_bytes())["cert_manager_manifest"]
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_nlink != 1 or manifest.stat().st_size != pin["size"]:
        raise ValueError("cert-manager-manifest-file")
    with manifest.open("rb") as data:
        if hashlib.file_digest(data, "sha256").hexdigest() != pin["sha256"]:
            raise ValueError("cert-manager-manifest-content")
    return pins


def verify_derived_bundles(directory):
    definitions = json.loads((ROOT / "derived-images.lock.json").read_bytes())["images"]
    if set(definitions) != {"metrics-server", "auth", "distribution"}:
        raise ValueError("derived-component-selection")
    paths = []
    for name, pin in definitions.items():
        path = directory / (name + ".tar")
        descriptors = [pin[key] for key in ("manifest", "config", "layer")]
        expected = {"blobs/sha256/" + d["digest"][7:] for d in descriptors} | {"index.json", "oci-layout"}
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1 \
                or path.stat().st_size > sum(d["size"] for d in descriptors) + 32768:
            raise ValueError("derived-bundle-size")
        with tarfile.open(path, mode="r:") as archive:
            members = []
            for _ in range(len(expected) + 1):
                member = archive.next()
                if member is None:
                    break
                members.append(member)
            if len(members) != len(expected) or {m.name for m in members} != expected \
                    or not all(m.isfile() and m.uid == 0 and m.gid == 0 and m.mode == 0o644 for m in members):
                raise ValueError("derived-bundle-members")
            for descriptor in descriptors:
                member = archive.getmember("blobs/sha256/" + descriptor["digest"][7:])
                if member.size != descriptor["size"]:
                    raise ValueError("derived-blob-size")
                with archive.extractfile(member) as data:
                    if "sha256:" + hashlib.file_digest(data, "sha256").hexdigest() != descriptor["digest"]:
                        raise ValueError("derived-blob-identity")
            with archive.extractfile("index.json") as data:
                raw = data.read(4097)
            with archive.extractfile("oci-layout") as data:
                if data.read(257) != b'{"imageLayoutVersion":"1.0.0"}':
                    raise ValueError("derived-layout-identity")
            entry = {**pin["manifest"], "platform": {"os": "linux", "architecture": "amd64"},
                     "annotations": {"io.containerd.image.name": "broil.invalid/candidate/" + name + ":broil-proof"}}
            if len(raw) > 4096 or json.loads(raw) != {"schemaVersion": 2, "manifests": [entry]}:
                raise ValueError("derived-index-identity")
        paths.append(path)
    return paths


if __name__ == "__main__":
    import sys
    assert sys.argv[1:] == ["prepare"]
    print(json.dumps({"event": "published-addon-inputs-verified", "adopted": False,
                      "assets": prepare(Path("/opt/broil-k3s-addon-inputs"))}, sort_keys=True))
