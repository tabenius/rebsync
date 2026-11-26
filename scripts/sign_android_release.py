#!/usr/bin/env python3
"""Explicitly sign the final non-debug APK with the already-pinned release key."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from check_android_signing import preflight
from prepare_android_release import apk_shape, apk_metadata, run

ROOT = Path(__file__).resolve().parents[1]


def sign(args, root=ROOT, execute=subprocess.run, read=run, check=preflight):
    expected = json.loads((root/'release/android-signing.json').read_text())
    config = json.loads((root/'apps/rebsync-app/src-tauri/tauri.conf.json').read_text())
    if args.apk.is_symlink() or not args.apk.is_file():
        raise ValueError('input APK must be a regular file')
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('refusing to overwrite an existing signed APK')
    check(args.keystore, expected)
    # Never apply the production key to a debug, wrong-version or wrong-package build.
    apk_shape(read([str(args.aapt),'dump','badging',str(args.apk)]),expected,config['version'])
    alias = os.environ.get('RBQ_KEY_ALIAS') or 'rbq'
    command = [str(args.apksigner),'sign','--ks',str(args.keystore),'--ks-key-alias',alias,
               '--ks-pass','env:RBQ_STORE_PASSWORD','--key-pass','env:RBQ_KEY_PASSWORD',
               '--v2-signing-enabled','true','--v3-signing-enabled','true','--v4-signing-enabled','false',
               '--debuggable-apk-permitted','false','--out',str(args.output),str(args.apk)]
    # Own the output path before handing it to apksigner; never replace user files.
    with args.output.open('xb'):
        pass
    try:
        result = execute(command,capture_output=True,timeout=120)
        if result.returncode:
            raise ValueError('apksigner failed; check approved keystore credentials (raw diagnostics suppressed)')
        certificates = read([str(args.apksigner),'verify','--verbose','--print-certs',str(args.output)])
        metadata = apk_metadata(read([str(args.aapt),'dump','badging',str(args.output)]),certificates,expected,config['version'])
    except Exception:
        args.output.unlink(missing_ok=True)
        raise
    print(f"Final APK signature verified against approved identity: {metadata['certificateSha256']}")
    return metadata


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('apk','output','keystore','apksigner','aapt'):
        parser.add_argument('--'+name,type=Path,required=True)
    try:
        sign(parser.parse_args())
    except (ValueError,OSError,subprocess.SubprocessError) as error:
        parser.exit(1,f'Final APK signing refused: {error}\n')


if __name__=='__main__':
    main()
