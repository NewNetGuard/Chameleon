# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
"""Only disposable test keys; never access the official key directory."""
import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import release_sign as signing
from check_release_contents import check_release


class ReleaseSigningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="chameleon-signing-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.private, self.public = signing.generate_keys(self.root / "keys")
        self.key = signing.load_private(self.private)
        self.zip = self.root / "windows.zip"
        with zipfile.ZipFile(self.zip, "w") as archive:
            archive.writestr("release/VERSION", "1.2.1\n")
        self.tar = self.root / "linux.tar.gz"
        with tarfile.open(self.tar, "w:gz") as archive:
            member = tarfile.TarInfo("release/VERSION")
            member.size = 6
            archive.addfile(member, io.BytesIO(b"1.2.1\n"))

    def test_roundtrip_both_archive_formats_and_cli(self):
        for path in (self.zip, self.tar):
            signature = signing.sign_archive(path, self.key)
            self.assertEqual(64, len(signature.read_bytes()))
            signing.verify_archive(path, signing.load_public(self.public))
        result = subprocess.run([sys.executable, str(Path(signing.__file__)), "verify",
                                 "--public-key", str(self.public), str(self.zip), str(self.tar)],
                                capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(2, result.stdout.count("VALID:"))

    def test_private_key_works_without_password(self):
        data = self.private.read_bytes()
        self.assertTrue(data.startswith(b"-----BEGIN PRIVATE KEY-----"))
        key = serialization.load_pem_private_key(data, password=None)
        self.assertIsInstance(key, Ed25519PrivateKey)

    def test_archive_tamper_fails(self):
        signing.sign_archive(self.zip, self.key)
        self.zip.write_bytes(self.zip.read_bytes() + b"tampered")
        with self.assertRaises(InvalidSignature):
            signing.verify_archive(self.zip, self.key.public_key())

    def test_wrong_public_key_fails(self):
        signing.sign_archive(self.zip, self.key)
        with self.assertRaises(InvalidSignature):
            signing.verify_archive(self.zip, Ed25519PrivateKey.generate().public_key())

    def test_signature_tamper_and_truncation_fail(self):
        path = signing.sign_archive(self.zip, self.key)
        data = path.read_bytes()
        path.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        with self.assertRaises(InvalidSignature):
            signing.verify_archive(self.zip, self.key.public_key())
        path.write_bytes(data[:20])
        with self.assertRaises(ValueError):
            signing.verify_archive(self.zip, self.key.public_key())

    def test_no_key_or_signature_overwrite(self):
        original = self.private.read_bytes()
        with self.assertRaises(FileExistsError):
            signing.generate_keys(self.private.parent)
        self.assertEqual(original, self.private.read_bytes())
        signing.sign_archive(self.zip, self.key)
        with self.assertRaises(FileExistsError):
            signing.sign_archive(self.zip, self.key)

    def test_private_key_inside_project_is_refused(self):
        with self.assertRaises(ValueError):
            signing.outside_project(signing.ROOT / "Chameleon-Keys" / "private.pem")

    def test_encrypted_key_is_refused_without_prompt(self):
        path = self.root / "encrypted.pem"
        path.write_bytes(self.key.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8,
                         serialization.BestAvailableEncryption(b"test password only")))
        with self.assertRaises(ValueError):
            signing.load_private(path)

    def test_secret_names_and_disguised_private_pem_blocked(self):
        for name in ("release/Chameleon-Keys/anything.txt", "release/private.key", "release/key.pk8",
                     "release/.env", "release/innocent.txt"):
            with self.subTest(name=name):
                path = self.root / "bad.zip"
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr(name, self.private.read_bytes())
                with self.assertRaises(ValueError):
                    signing.sign_archive(path, self.key)
                self.assertFalse(Path(str(path) + ".sig").exists())

    def test_tar_and_staging_guard(self):
        stage = self.root / "stage"
        stage.mkdir()
        (stage / "innocent.txt").write_bytes(self.private.read_bytes())
        with self.assertRaises(ValueError):
            check_release(stage)
        with tarfile.open(self.tar, "w:gz") as archive:
            archive.add(stage / "innocent.txt", arcname="innocent.txt")
        with self.assertRaises(ValueError):
            check_release(self.tar)

    def test_keygen_and_sign_cli_without_password(self):
        destination = self.root / "cli-keys"
        result = subprocess.run([sys.executable, str(Path(signing.__file__)), "keygen",
                                 "--key-dir", str(destination)], input="",
                                capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        result = subprocess.run([sys.executable, str(Path(signing.__file__)), "sign",
                                 "--key", str(destination / signing.PRIVATE_NAME),
                                 str(self.zip), str(self.tar)], input="",
                                capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        key = signing.load_public(destination / signing.PUBLIC_NAME)
        signing.verify_archive(self.zip, key)
        signing.verify_archive(self.tar, key)


if __name__ == "__main__":
    unittest.main()
