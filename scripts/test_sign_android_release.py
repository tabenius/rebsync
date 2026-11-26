import hashlib
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from sign_android_release import sign
from prepare_android_release import apk_metadata

BADGING = ("package: name='com.tabenius.rebeqah' versionCode='2004' versionName='0.2.4'\n"
           "sdkVersion:'24'\ntargetSdkVersion:'37'\n"
           "native-code: 'arm64-v8a' 'armeabi-v7a' 'x86_64'\n")


def root_fixture(root, fingerprint='a'*64):
    (root/'release').mkdir()
    (root/'release/android-signing.json').write_text(json.dumps({'packageName':'com.tabenius.rebeqah',
        'certificateSha256':fingerprint,'openpgpFingerprint':'B'*40}))
    (root/'apps/rebsync-app/src-tauri').mkdir(parents=True)
    (root/'apps/rebsync-app/src-tauri/tauri.conf.json').write_text(json.dumps({'version':'0.2.4'}))


class FinalSigningTests(unittest.TestCase):
    def test_explicit_signing_uses_named_env_passwords_and_reverifies_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root_fixture(root)
            apk=root/'input.apk';apk.write_bytes(b'fixture')
            args=SimpleNamespace(apk=apk,output=root/'signed.apk',keystore=root/'key.jks',apksigner=Path('apksigner'),aapt=Path('aapt'))
            execute=Mock(return_value=subprocess.CompletedProcess([],0))
            read=Mock(side_effect=[BADGING,'Number of signers: 1\nSigner #1 certificate SHA-256 digest: '+'a'*64+'\n',BADGING])
            with patch.dict(os.environ,{'RBQ_STORE_PASSWORD':'private-store','RBQ_KEY_PASSWORD':'private-key'}):
                result=sign(args,root,execute,read,Mock())
            command=execute.call_args.args[0]
            self.assertIn('env:RBQ_STORE_PASSWORD',command)
            self.assertIn('env:RBQ_KEY_PASSWORD',command)
            self.assertNotIn('private-store',command)
            self.assertNotIn('private-key',command)
            self.assertEqual(result['certificateSha256'],'a'*64)
            self.assertEqual(apk.read_bytes(),b'fixture')

    def test_wrong_debug_or_incomplete_build_is_not_signed(self):
        for badging in [BADGING+'application-debuggable\n',BADGING.replace('0.2.4','0.2.3'),BADGING.replace(" 'x86_64'",'')]:
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);root_fixture(root)
                apk=root/'input.apk';apk.write_bytes(b'fixture')
                args=SimpleNamespace(apk=apk,output=root/'signed.apk',keystore=root/'key.jks',apksigner=Path('apksigner'),aapt=Path('aapt'))
                execute=Mock()
                with self.assertRaises(ValueError):sign(args,root,execute,Mock(return_value=badging),Mock())
                execute.assert_not_called()
                self.assertFalse(args.output.exists())

    def test_bad_final_signature_is_refused_and_own_output_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root_fixture(root)
            apk=root/'input.apk';apk.write_bytes(b'fixture')
            args=SimpleNamespace(apk=apk,output=root/'signed.apk',keystore=root/'key.jks',apksigner=Path('apksigner'),aapt=Path('aapt'))
            read=Mock(side_effect=[BADGING,'Number of signers: 1\nSigner #1 certificate SHA-256 digest: '+'b'*64+'\n',BADGING])
            with self.assertRaisesRegex(ValueError,'expected .*observed'):
                sign(args,root,Mock(return_value=subprocess.CompletedProcess([],0)),read,Mock())
            self.assertFalse(args.output.exists())

    @unittest.skipUnless(os.environ.get('RBQ_SIGNING_TEST_APK') and all(shutil.which(tool) for tool in ['keytool','apksigner','aapt']),
                         'optional local real-APK fixture/JDK/Android tools not supplied')
    def test_real_signing_changes_only_a_temporary_copy_using_disposable_key(self):
        original=Path(os.environ['RBQ_SIGNING_TEST_APK'])
        before=hashlib.sha256(original.read_bytes()).hexdigest()
        tool=os.environ.get('RBQ_SIGNING_TEST_APKSIGNER') or shutil.which('apksigner')
        approved=json.loads((Path(__file__).resolve().parents[1]/'release/android-signing.json').read_text())
        # Detect SDK report-format drift using the pinned real baseline before
        # any disposable signing round-trip or expensive release build.
        apk_metadata(subprocess.check_output(['aapt','dump','badging',str(original)],text=True),
                     subprocess.check_output([tool,'verify','--verbose','--print-certs',str(original)],text=True,stderr=subprocess.PIPE),
                     approved,'0.2.4')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);key=root/'fixture.jks'
            env=dict(os.environ,RBQ_STORE_PASSWORD='disposable-fixture-pass',RBQ_KEY_PASSWORD='disposable-fixture-pass',RBQ_KEY_ALIAS='fixture')
            subprocess.run(['keytool','-genkeypair','-alias','fixture','-keyalg','RSA','-keysize','2048','-validity','1',
                            '-dname','CN=Disposable APK signing test','-keystore',str(key),'-storepass:env','RBQ_STORE_PASSWORD',
                            '-keypass:env','RBQ_KEY_PASSWORD'],env=env,check=True,capture_output=True,timeout=30)
            key.chmod(0o600)
            certificate=subprocess.check_output(['keytool','-exportcert','-alias','fixture','-keystore',str(key),
                                                  '-storepass:env','RBQ_STORE_PASSWORD'],env=env,stderr=subprocess.PIPE)
            fingerprint=hashlib.sha256(certificate).hexdigest();root_fixture(root,fingerprint)
            args=SimpleNamespace(apk=original,output=root/'signed.apk',keystore=key,apksigner=Path(tool),aapt=Path(shutil.which('aapt')))
            with patch.dict(os.environ,env):result=sign(args,root)
            self.assertEqual(result['certificateSha256'],fingerprint)
            self.assertTrue(args.output.stat().st_size>0)
        self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(),before)


if __name__=='__main__':
    if os.environ.get('RBQ_SIGNING_TEST_APK') and not all(shutil.which(tool) for tool in ['keytool','apksigner','aapt']):
        raise SystemExit('Explicit real-APK test requested but required JDK/Android tools are not on PATH')
    unittest.main()
