#!/usr/bin/env python3
"""Verify a release APK and prepare a candidate inventory for www.ragbaz.

Private keys are not read. APK signing happens in Gradle, OpenPGP signing in
the operator's gpg-agent, and CI signs release.json using Sigstore OIDC.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def run(args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True, stderr=subprocess.PIPE)


def apk_shape(badging, expected, version):
    package = re.search(r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'", badging, re.M)
    if not package or package[1] != expected['packageName'] or package[3] != version:
        raise ValueError('APK package/version does not match the release')
    if not 0 < int(package[2]) <= 2100000000:
        raise ValueError('APK versionCode is outside the Android/Play update range')
    if 'application-debuggable' in badging:
        raise ValueError('Debuggable APK is not a release')
    minimum = re.search(r"^sdkVersion:'([0-9]+)'", badging, re.M)
    target = re.search(r"^targetSdkVersion:'([0-9]+)'", badging, re.M)
    native = re.search(r"^native-code: (.+)$", badging, re.M)
    abis = re.findall(r"'([^']+)'", native[1]) if native else []
    if not minimum or not target or set(abis) != {'arm64-v8a', 'armeabi-v7a', 'x86_64'}:
        raise ValueError('APK must contain the declared universal architectures and SDK metadata')
    return {'schema': 'ragbaz.android-release/1', 'packageName': package[1],
            'versionCode': int(package[2]), 'versionName': package[3],
            'minSdk': int(minimum[1]), 'targetSdk': int(target[1]), 'abis': sorted(abis),
            'openpgpFingerprint': expected['openpgpFingerprint']}


def apk_metadata(badging, certificates, expected, version):
    metadata = apk_shape(badging, expected, version)
    counts = re.findall(r"^Number of signers: ([0-9]+)[ \t]*$", certificates, re.M)
    if counts != ['1']:
        raise ValueError('APK must report exactly one signer')
    # SDK <=36 used "Signer #1"; SDK37 reports scheme-labelled signers such
    # as "V2 Signer" and "V3.0 Signer". These are signature schemes, not a
    # count of independent signing identities. Never relax the pinned identity.
    labels = r"(?:Signer #[0-9]+|V[1-4](?:\.[0-9]+)? Signer(?: #[0-9]+)?)"
    report = re.compile(r"^" + labels + r":? certificate SHA-256 digest: ([0-9a-fA-F]{64})[ \t]*$")
    lines = [line for line in certificates.splitlines() if 'certificate SHA-256 digest:' in line]
    matches = [report.fullmatch(line) for line in lines]
    if not matches or any(match is None for match in matches):
        raise ValueError('Unsupported apksigner certificate report; expected legacy or scheme-labelled signer digests')
    signers = {match[1].lower() for match in matches}
    if signers != {expected['certificateSha256']}:
        observed = ', '.join(sorted(signers))
        raise ValueError(f"APK signing certificate differs from the pinned release identity: expected {expected['certificateSha256']}; observed {observed}")
    return dict(metadata, certificateSha256=next(iter(signers)))


def write_new(path, data):
    with path.open('xb') as stream:
        stream.write(data)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def prepare(args, root):
    config = json.loads((root / 'apps/rebsync-app/src-tauri/tauri.conf.json').read_text())
    expected = json.loads((root / 'release/android-signing.json').read_text())
    tag = os.environ.get('RELEASE_TAG') or os.environ.get('GITHUB_REF_NAME', '')
    if tag != 'v' + config['version'] or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag):
        raise ValueError('Use the app version tag vX.Y.Z, not a mutable branch or legacy rebeqah-v tag')
    event_ref = os.environ.get('GITHUB_REF')
    if event_ref and event_ref != 'refs/tags/' + tag:
        raise ValueError('CI signing identity must be the selected tag ref')
    commit = run(['git', 'rev-parse', 'HEAD^{commit}'], root).strip()
    tagged = run(['git', 'rev-parse', f'refs/tags/{tag}^{{commit}}'], root).strip()
    if commit != tagged or (os.environ.get('GITHUB_SHA') and os.environ['GITHUB_SHA'] != commit):
        raise ValueError('Release tag, event SHA and checked-out source must agree')
    if run(['git', 'status', '--porcelain', '--untracked-files=no'], root).strip():
        raise ValueError('Tracked source changes must be committed before preparing a release')
    if args.apk.is_symlink() or not args.apk.is_file():
        raise ValueError('APK must be a regular file, not a symlink')
    certs = run([str(args.apksigner), 'verify', '--verbose', '--print-certs', str(args.apk)])
    metadata = apk_metadata(run([str(args.aapt), 'dump', 'badging', str(args.apk)]), certs, expected, config['version'])
    public = root / expected['publicKey']
    with tempfile.TemporaryDirectory() as home:
        keys = run(['gpg', '--homedir', home, '--batch', '--with-colons', '--show-keys', str(public)])
    fingerprints = [line.split(':')[9] for line in keys.splitlines() if line.startswith('fpr:')]
    if not fingerprints or fingerprints[0] != expected['openpgpFingerprint']:
        raise ValueError('Public release key does not match the pinned fingerprint')
    args.dist.mkdir(parents=True, exist_ok=False)
    name = f"rebeqah-{config['version']}-universal-release.apk"
    target = args.dist / name
    with args.apk.open('rb') as source, target.open('xb') as dest:
        import shutil
        shutil.copyfileobj(source, dest)
    metadata.update(apk=name, sha256=digest(target), sourceCommit=commit)
    write_new(args.dist / 'android.json', (json.dumps(metadata, indent=2) + '\n').encode())
    write_new(args.dist / public.name, public.read_bytes())
    sums = ''.join(f'{digest(path)}  {path.name}\n' for path in sorted(args.dist.iterdir()))
    write_new(args.dist / 'SHA256SUMS', sums.encode())
    if args.openpgp_sign:
        # No passphrase input or private-key export: GnuPG talks to its agent.
        subprocess.run(['gpg', '--local-user', expected['openpgpFingerprint'], '--armor',
                        '--detach-sign', '--output', str(args.dist / 'SHA256SUMS.asc'),
                        str(args.dist / 'SHA256SUMS')], check=True)
    files = [{'name': path.name, 'path': f"releases/rebeqah/{config['version']}/android/{path.name}",
              'bytes': path.stat().st_size, 'sha256': digest(path)} for path in sorted(args.dist.iterdir())]
    manifest = {'schema': 'ragbaz.release/1', 'repository': 'tabenius/rebsync', 'product': 'rebeqah',
                'version': config['version'], 'platform': 'android', 'channel': 'candidate',
                'sourceCommit': commit, 'validation': {'installedSmoke': False}, 'files': files}
    write_new(args.dist / 'release.json', (json.dumps(manifest, indent=2) + '\n').encode())
    print(f'Verified signed APK and prepared candidate release {tag}; device installation not tested.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['apk', 'dist', 'apksigner', 'aapt']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--openpgp-sign', action='store_true', help='Sign checksums using the local gpg-agent; never use a passphrase file')
    prepare(parser.parse_args(), Path(__file__).resolve().parents[1])
