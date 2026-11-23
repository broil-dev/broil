#!/usr/bin/env python3
"""Create Broil's deterministic release tar.gz archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import sys
import tarfile
from pathlib import Path


SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
SAFE_TARGET = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._+-]*$")


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        fail(f"cannot read {label} at {path}: {exc}")


def resolve_under_root(root: Path, value: str, label: str) -> Path:
    rel = Path(value)
    if rel.is_absolute() or ".." in rel.parts:
        fail(f"{label} must be a repository-relative path")

    path = (root / rel).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        fail(f"{label} escapes repository root")
    return path


def relative_manifest_path(root: Path, path: Path, label: str) -> str:
    try:
        rel = path.resolve().relative_to(root)
    except ValueError:
        fail(f"{label} must be under repository root")

    rendered = rel.as_posix()
    if rendered.startswith("/") or "/../" in f"/{rendered}/":
        fail(f"{label} is not safe for manifest use")
    return rendered


def reject_manifest_string(value: str, label: str, root: Path) -> None:
    if not value:
        fail(f"{label} must not be empty")
    if "\x00" in value or "\n" in value and label != "builder.rustc_version":
        fail(f"{label} contains an unsupported control character")
    if str(root) in value:
        fail(f"{label} contains the local checkout path")
    if value.startswith("/") or value.startswith("~/"):
        fail(f"{label} looks like a local path")


def parse_workspace_version(root: Path, explicit: str | None) -> str:
    if explicit:
        version = explicit
    else:
        cargo_toml = root / "Cargo.toml"
        version = parse_workspace_version_from_toml(cargo_toml)

    if not SAFE_COMPONENT.fullmatch(version):
        fail("package version is empty or contains unsafe path characters")
    return version


def parse_workspace_version_from_toml(cargo_toml: Path) -> str:
    try:
        import tomllib  # type: ignore[attr-defined]
    except ModuleNotFoundError:
        return parse_workspace_version_fallback(cargo_toml)

    try:
        data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
        value = data["workspace"]["package"]["version"]
    except (OSError, KeyError, TypeError, ValueError) as exc:
        fail(f"cannot read [workspace.package].version from Cargo.toml: {exc}")

    if not isinstance(value, str):
        fail("[workspace.package].version must be a string")
    return value


def parse_workspace_version_fallback(cargo_toml: Path) -> str:
    in_workspace_package = False

    try:
        lines = cargo_toml.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        fail(f"cannot read Cargo.toml: {exc}")

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            in_workspace_package = stripped == "[workspace.package]"
            continue
        if in_workspace_package:
            match = re.fullmatch(r'version\s*=\s*"([^"]+)"', stripped)
            if match:
                return match.group(1)

    fail("cannot find [workspace.package].version in Cargo.toml")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--target-triple", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--notice-path", required=True)
    parser.add_argument("--builder-definition-path", required=True)
    parser.add_argument("--builder-image-identity", required=True)
    parser.add_argument("--builder-rustc-version", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--source-date-epoch", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--package-version")
    return parser.parse_args()


def tar_info(path: str, mode: int, size: int, mtime: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(path)
    info.size = size
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = mtime
    return info


def add_bytes(tar: tarfile.TarFile, path: str, data: bytes, mode: int, mtime: int) -> None:
    tar.addfile(tar_info(path, mode, len(data), mtime), io.BytesIO(data))


def write_archive(archive_path: Path, entries: list[tuple[str, bytes, int]], mtime: int) -> None:
    tmp_path = archive_path.with_name(f"{archive_path.name}.tmp")
    tmp_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with tmp_path.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=mtime) as gz:
                with tarfile.open(fileobj=gz, mode="w|", format=tarfile.USTAR_FORMAT) as tar:
                    for path, data, mode in entries:
                        add_bytes(tar, path, data, mode, mtime)
        os.replace(tmp_path, archive_path)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def main() -> None:
    args = parse_args()
    root = Path(args.root).resolve()

    if not root.is_dir():
        fail("repository root does not exist")
    if not SAFE_TARGET.fullmatch(args.target_triple):
        fail("target triple contains unsafe path characters")
    if not args.source_date_epoch.isdigit():
        fail("source date epoch must be a non-negative integer")

    mtime = int(args.source_date_epoch)
    version = parse_workspace_version(root, args.package_version)
    package_name = f"broil-{version}-{args.target_triple}.tar.gz"
    prefix = f"broil-{version}-{args.target_triple}"

    for component, label in ((package_name, "package name"), (prefix, "archive prefix")):
        if "/" in component or not SAFE_COMPONENT.fullmatch(component):
            fail(f"{label} contains unsafe path characters")

    binary_path = resolve_under_root(root, args.binary, "binary path")
    notice_path = resolve_under_root(root, args.notice_path, "notice path")
    builder_path = resolve_under_root(root, args.builder_definition_path, "builder definition path")
    license_path = root / "LICENSE"
    cargo_lock_path = root / "Cargo.lock"

    binary = read_bytes(binary_path, "canonical binary")
    license_bytes = read_bytes(license_path, "LICENSE")
    notices = read_bytes(notice_path, "THIRD-PARTY-NOTICES.md")
    cargo_lock = read_bytes(cargo_lock_path, "Cargo.lock")

    license_sha = sha256_bytes(license_bytes)
    notices_sha = sha256_bytes(notices)

    if license_sha != sha256_bytes(read_bytes(root / "LICENSE", "repository-root LICENSE")):
        fail("carried LICENSE does not match repository-root LICENSE")
    if notices_sha != sha256_bytes(read_bytes(notice_path, "target-matched notice")):
        fail("carried notices do not match the target-matched notice")

    builder_definition_rel = relative_manifest_path(root, builder_path, "builder definition path")
    notice_rel = relative_manifest_path(root, notice_path, "notice path")
    binary_archive_path = f"{prefix}/broil"
    manifest_archive_path = f"{prefix}/manifest.json"

    manifest = {
        "format_version": 1,
        "package_format": "tar.gz",
        "package_name": package_name,
        "target_triple": args.target_triple,
        "source_revision": args.source_revision,
        "source_date_epoch": mtime,
        "cargo_lock_sha256": sha256_bytes(cargo_lock),
        "builder": {
            "definition_path": builder_definition_rel,
            "image_identity": args.builder_image_identity,
            "rustc_version": args.builder_rustc_version,
        },
        "binary": {
            "path": binary_archive_path,
            "sha256": sha256_bytes(binary),
            "size": len(binary),
        },
        "legal": {
            "license_sha256": license_sha,
            "notices_path": notice_rel,
            "notices_sha256": notices_sha,
        },
    }

    for label, value in (
        ("package_name", package_name),
        ("target_triple", args.target_triple),
        ("source_revision", args.source_revision),
        ("builder.definition_path", builder_definition_rel),
        ("builder.image_identity", args.builder_image_identity),
        ("builder.rustc_version", args.builder_rustc_version),
        ("binary.path", binary_archive_path),
        ("legal.notices_path", notice_rel),
    ):
        reject_manifest_string(str(value), label, root)

    manifest_bytes = (json.dumps(manifest, ensure_ascii=True, indent=2) + "\n").encode("utf-8")

    entries = sorted(
        [
            (f"{prefix}/LICENSE", license_bytes, 0o644),
            (f"{prefix}/THIRD-PARTY-NOTICES.md", notices, 0o644),
            (binary_archive_path, binary, 0o755),
            (manifest_archive_path, manifest_bytes, 0o644),
        ],
        key=lambda item: item[0],
    )

    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = root / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    archive_path = output_dir / package_name
    write_archive(archive_path, entries, mtime)

    archive_sha = sha256_bytes(read_bytes(archive_path, "archive"))
    checksum_path = output_dir / "SHA256SUMS"
    checksum_path.write_text(f"{archive_sha}  {package_name}\n", encoding="utf-8")

    print(f"archive={archive_path}")
    print(f"archive_sha256={archive_sha}")
    print(f"checksums={checksum_path}")


if __name__ == "__main__":
    main()
