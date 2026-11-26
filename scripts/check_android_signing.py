#!/usr/bin/env python3
"""Check approved Android key identity and usability without exporting private keys.

Passwords are supplied only through named environment variables, never argv.
The only diagnostic key material is a public certificate SHA-256 fingerprint.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def verify_identity(certificate, expected):
    pinned = expected.get('certificateSha256', '')
    if not re.fullmatch('[0-9a-f]{64}', pinned):
        raise ValueError('release identity must pin a lowercase SHA-256 certificate digest')
    observed = hashlib.sha256(certificate).hexdigest()
    if observed != pinned:
        raise ValueError(f'Wrong Android signing key: expected {pinned}, observed {observed}. Restore the approved keystore; do not change the pin to silence this refusal.')
    return observed


def preflight(keystore, expected, environ=None, run=subprocess.run):
    env = dict(os.environ if environ is None else environ)
    alias = env.get('RBQ_KEY_ALIAS') or 'rbq'
    if not env.get('RBQ_STORE_PASSWORD') or not env.get('RBQ_KEY_PASSWORD'):
        raise ValueError('RBQ_STORE_PASSWORD and RBQ_KEY_PASSWORD must both be configured')
    if keystore.is_symlink() or not keystore.is_file():
        raise ValueError('keystore must be an existing regular file, not a symlink')
    if keystore.stat().st_mode & 0o077:
        raise ValueError('keystore must not be group/world accessible (use mode 0600)')
    common = ['keytool', '-J-Duser.language=en', '-J-Duser.country=US', '-keystore', str(keystore),
              '-storepass:env', 'RBQ_STORE_PASSWORD', '-alias', alias]

    def checked(command):
        result = run(command, env=env, capture_output=True, timeout=30)
        if result.returncode:
            # keytool errors may contain aliases/paths. Do not relay raw diagnostics.
            raise ValueError('keystore operation failed; check keystore, alias and password environment variables')
        return result.stdout

    certificate = checked(common + ['-exportcert'])
    fingerprint = verify_identity(certificate, expected)
    entry = checked(common + ['-list']).decode(errors='replace')
    if 'PrivateKeyEntry' not in entry:
        raise ValueError('configured alias is not a private-key entry')
    # A CSR proves private-key/password access. It neither exports the key nor
    # changes the keystore; its public output is discarded, not logged/uploaded.
    checked(common + ['-certreq', '-keypass:env', 'RBQ_KEY_PASSWORD'])
    return fingerprint


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--keystore', type=Path, required=True)
    parser.add_argument('--identity', type=Path, default=ROOT / 'release/android-signing.json')
    parser.add_argument('--decode-ci-secret', action='store_true', help='decode RBQ_KEYSTORE_B64 to a new mode-0600 runner file')
    args = parser.parse_args()
    created = False
    try:
        if args.decode_ci_secret:
            encoded = os.environ.get('RBQ_KEYSTORE_B64', '')
            if not encoded:
                raise ValueError('RBQ_KEYSTORE_B64 is not configured')
            try:
                raw = base64.b64decode(encoded, validate=True)
            except ValueError:
                raise ValueError('RBQ_KEYSTORE_B64 is not valid base64') from None
            fd = os.open(args.keystore, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
        expected = json.loads(args.identity.read_text())
        fingerprint = preflight(args.keystore, expected)
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        if created:
            args.keystore.unlink(missing_ok=True)
        # These errors are ours, not keytool output or secret-bearing argv.
        parser.exit(1, f'Android signing preflight refused: {error}\n')
    print(f'Approved Android signing identity and private-key access verified: {fingerprint}')


if __name__ == '__main__':
    main()
