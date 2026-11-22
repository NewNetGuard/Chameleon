# Chameleon release signatures

Release signing is separate from the tunnel protocol, SSH keys and Windows
Authenticode. It does not change the application or remove SmartScreen warnings.
The maintainer signs official archives with the private key kept outside the
project. Verify a downloaded archive against the official public key before
extracting it or starting an installer with elevated privileges.

## Install the tooling dependency

Run from the Chameleon source directory with Python 3.10 or newer:

```powershell
python -m pip install -r tools/requirements-release-signing.txt
```

On Linux use `python3`, preferably in a virtual environment. This dependency is
only for the signing/verification tool and does not modify Chameleon's runtime.

## Create the official key — only after maintainer approval

On Windows, the default directory is `Desktop/Chameleon-Keys` under the current
user's home, outside the project. The directory must not already exist; existing
keys are never overwritten. Run locally in an interactive terminal:

```powershell
python tools/release_sign.py keygen
```

No password is requested when creating the key or signing archives. On Windows
the directory is `%USERPROFILE%\Desktop\Chameleon-Keys\`; on Linux,
`~/Desktop/Chameleon-Keys/`.

The command creates:

- `chameleon-release-private.pem`: unencrypted Ed25519 private key in PKCS#8 PEM.
  Keep it outside the project and never publish it.
- `chameleon-release.pub`: public key in PEM SubjectPublicKeyInfo. Safe to publish.

Windows directory inheritance is disabled and access is granted to the current
user. On Linux, directory/private-file permissions are 0700/0600. Keep a secure
backup of the private key. Anyone with a copy can sign releases; a lost key cannot
be recovered from the public key. This is a separate Chameleon key, not the key
of another project.

## Sign the finished archives

Build both packages first. Signing never rebuilds or modifies archive contents.

```powershell
python tools/release_sign.py sign dist/chameleon-windows-1.2.1.zip dist/chameleon-panel-1.2.1.tar.gz
```

No password is needed. The command checks the packages for private
key material and writes one detached `.sig` file beside each archive. Existing
signatures are not overwritten. If rebuilding the same version, preserve/remove
obsolete signatures deliberately and sign the final bytes again.

To use a different external directory, pass `--key PATH_TO_PRIVATE_KEY`.
On Linux provide that option explicitly. The same key signs both archive formats.

## Verify before installation

Obtain the [Chameleon public key](chameleon-release.pub) from the trusted source
repository and compare its fingerprint against a value you trust independently
of the archive download. The current Chameleon release key fingerprint is
`SHA256:eccc641a68e98bc0102e3907bc43aacaaa749c3693b23fef5a60567ed13cee41`.

```powershell
python tools/release_sign.py fingerprint --public-key docs/chameleon-release.pub
python tools/release_sign.py verify --public-key docs/chameleon-release.pub dist/chameleon-windows-1.2.1.zip
```

The `.sig` files must be beside their archives. `VALID` and exit code 0 mean that
all supplied archives match the supplied public key; changed archives, wrong
keys, missing/changed signatures return nonzero. On Linux replace `python` with
`python3`. Verification never needs the private key.

Format: standard Ed25519 over the **exact archive bytes**, with a raw 64-byte
detached signature. This is not Ed25519ph and not a signature over the SHA-256
text file. The public-key fingerprint is SHA-256 of its raw 32 bytes, in hex.
Archive filenames and version labels are not signed metadata; users must choose
the expected release. SHA-256 sidecars remain useful for transfer checks but
do not replace the signatures.

Publish the archives, their `.sig` and `.sha256` files, the public key and its
trusted fingerprint. Never publish the private key or the key
directory. No commit/tag/release or upload is performed by these commands.

## Packaging protection and tests

`.gitignore` excludes the key directory and private-key formats. Ignore rules
can be bypassed by force-adding files, so they are not a secret vault.
Both build scripts check their staging directories before archiving. Signing
also checks archive members for key directories, private filenames and PEM
private-key blocks, even under an innocent filename. This is defense against
accidental inclusion, not a detector for every possible encoding of a secret.

```powershell
python tools/check_release_contents.py dist/chameleon-windows-1.2.1.zip dist/chameleon-panel-1.2.1.tar.gz
python -m unittest discover -s tools -p test_release_sign.py -v
```

Tests create disposable keys only in the operating system's temporary directory,
use no password, and remove them afterwards. They never use or create the
official key directory.
