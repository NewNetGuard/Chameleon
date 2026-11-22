#!/usr/bin/env python3
# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
"""Unencrypted Ed25519 keys and detached signatures of release bytes."""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import subprocess
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from check_release_contents import check_release

ROOT = Path(__file__).resolve().parent.parent
PRIVATE_NAME = "chameleon-release-private.pem"
PUBLIC_NAME = "chameleon-release.pub"
DEFAULT_KEYS = Path.home() / "Desktop" / "Chameleon-Keys"


def outside_project(path: Path) -> Path:
    path = path.resolve()
    if path == ROOT or ROOT in path.parents:
        raise ValueError("Private keys must be stored outside the Chameleon project")
    return path


def write_new(path: Path, data: bytes, mode: int = 0o644) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def fingerprint(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "SHA256:" + hashlib.sha256(raw).hexdigest()


def generate_keys(directory: Path) -> tuple[Path, Path]:
    directory = outside_project(directory)
    # Refuse to reuse/overwrite a key directory, including after an interrupted run.
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    if os.name == "nt":
        result = subprocess.check_output(["whoami", "/user", "/fo", "csv", "/nh"], text=True)
        sid = next(csv.reader(result.strip().splitlines()))[1]
        subprocess.run(["icacls", str(directory), "/inheritance:r", "/grant:r",
                        f"*{sid}:(OI)(CI)F"], check=True, capture_output=True)
    private = Ed25519PrivateKey.generate()
    private_path, public_path = directory / PRIVATE_NAME, directory / PUBLIC_NAME
    write_new(private_path, private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()), 0o600)
    write_new(public_path, private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return private_path, public_path


def load_private(path: Path) -> Ed25519PrivateKey:
    data = outside_project(path).read_bytes()
    if not data.startswith(b"-----BEGIN PRIVATE KEY-----"):
        raise ValueError("Expected an unencrypted PKCS#8 private key")
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Expected an Ed25519 private key")
    return key


def load_public(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Expected an Ed25519 public key")
    return key


def sign_archive(archive: Path, key: Ed25519PrivateKey) -> Path:
    check_release(archive)
    signature_path = Path(str(archive) + ".sig")
    data = archive.read_bytes()
    signature = key.sign(data)
    key.public_key().verify(signature, data)
    write_new(signature_path, signature)
    return signature_path


def verify_archive(archive: Path, key: Ed25519PublicKey) -> None:
    signature = Path(str(archive) + ".sig").read_bytes()
    if len(signature) != 64:
        raise ValueError("Expected a 64-byte Ed25519 signature")
    key.verify(signature, archive.read_bytes())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("keygen", help="Create a NEW key pair without a password")
    generate.add_argument("--key-dir", type=Path, default=DEFAULT_KEYS)
    sign = commands.add_parser("sign", help="Sign finished archives; never overwrites signatures")
    sign.add_argument("--key", type=Path, default=DEFAULT_KEYS / PRIVATE_NAME)
    sign.add_argument("archives", type=Path, nargs="+")
    verify = commands.add_parser("verify", help="Verify using an independently trusted public key")
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("archives", type=Path, nargs="+")
    show = commands.add_parser("fingerprint", help="Show the SHA-256 fingerprint of a public key")
    show.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "keygen":
            outside_project(args.key_dir)
            if args.key_dir.exists():
                raise ValueError("Key directory already exists; refusing to overwrite")
            private, public = generate_keys(args.key_dir)
            print(f"Private key: {private}\nPublic key: {public}")
            print(fingerprint(load_public(public)))
        elif args.command == "sign":
            for archive in args.archives:
                if Path(str(archive) + ".sig").exists():
                    raise ValueError(f"Signature already exists: {archive.name}.sig")
                check_release(archive)
            key = load_private(args.key)
            print("Signing key:", fingerprint(key.public_key()))
            for archive in args.archives:
                print("Signed:", sign_archive(archive, key))
        else:
            key = load_public(args.public_key)
            print("Public key:", fingerprint(key))
            if args.command == "verify":
                for archive in args.archives:
                    verify_archive(archive, key)
                    print(f"VALID: {archive.name}")
    except InvalidSignature:
        print("INVALID: archive or signature changed, or the public key is wrong", file=sys.stderr)
        return 1
    except (ValueError, OSError, TypeError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("Cancelled", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
