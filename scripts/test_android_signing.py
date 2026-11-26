import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import shutil
import unittest
from unittest.mock import Mock

from check_android_signing import preflight, verify_identity


class SigningTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('keytool'), 'JDK keytool not installed')
    def test_real_throwaway_keystore_checks_identity_and_private_key_access(self):
        # Disposable test identity only; never a product/release replacement key.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.jks'
            env = dict(os.environ, RBQ_STORE_PASSWORD='throwaway-test-password',
                       RBQ_KEY_PASSWORD='throwaway-test-password', RBQ_KEY_ALIAS='fixture')
            subprocess.run(['keytool', '-genkeypair', '-alias', 'fixture', '-keyalg', 'RSA', '-keysize', '2048',
                            '-dname', 'CN=Disposable signing test', '-validity', '1', '-keystore', str(path),
                            '-storepass:env', 'RBQ_STORE_PASSWORD', '-keypass:env', 'RBQ_KEY_PASSWORD'],
                           env=env, capture_output=True, check=True, timeout=30)
            path.chmod(0o600)
            certificate = subprocess.check_output(['keytool', '-exportcert', '-alias', 'fixture', '-keystore', str(path),
                                                    '-storepass:env', 'RBQ_STORE_PASSWORD'], env=env, stderr=subprocess.PIPE)
            expected = {'certificateSha256': hashlib.sha256(certificate).hexdigest()}
            self.assertEqual(preflight(path, expected, env), expected['certificateSha256'])
            env['RBQ_STORE_PASSWORD'] = 'wrong-test-password'
            with self.assertRaisesRegex(ValueError, 'keystore operation failed'):
                preflight(path, expected, env)

    def test_identity_is_exact_and_no_pin_is_rewritten(self):
        expected = {'certificateSha256': hashlib.sha256(b'certificate').hexdigest()}
        self.assertEqual(verify_identity(b'certificate', expected), expected['certificateSha256'])
        with self.assertRaisesRegex(ValueError, 'Restore the approved keystore'):
            verify_identity(b'wrong', expected)
        self.assertEqual(expected['certificateSha256'], hashlib.sha256(b'certificate').hexdigest())

    def test_preflight_uses_env_passwords_and_proves_private_key_access(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'key.jks'
            path.write_bytes(b'fixture')
            path.chmod(0o600)
            run = Mock(side_effect=[subprocess.CompletedProcess([], 0, b'certificate'),
                                    subprocess.CompletedProcess([], 0, b'PrivateKeyEntry'),
                                    subprocess.CompletedProcess([], 0, b'public CSR')])
            env = {'RBQ_STORE_PASSWORD': 'store-secret', 'RBQ_KEY_PASSWORD': 'key-secret'}
            preflight(path, {'certificateSha256': hashlib.sha256(b'certificate').hexdigest()}, env, run)
            self.assertEqual(run.call_count, 3)
            for call in run.call_args_list:
                argv = call.args[0]
                self.assertNotIn('store-secret', argv)
                self.assertNotIn('key-secret', argv)
            self.assertIn('-certreq', run.call_args.args[0])

    def test_refuses_missing_passwords_weak_permissions_and_wrong_key_before_signing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'key.jks'
            path.write_bytes(b'fixture')
            path.chmod(0o600)
            expected = {'certificateSha256': 'a' * 64}
            run = Mock(return_value=subprocess.CompletedProcess([], 0, b'wrong'))
            with self.assertRaisesRegex(ValueError, 'both be configured'):
                preflight(path, expected, {}, run)
            run.assert_not_called()
            env = {'RBQ_STORE_PASSWORD': 'store-secret', 'RBQ_KEY_PASSWORD': 'key-secret'}
            with self.assertRaisesRegex(ValueError, 'Wrong Android signing key'):
                preflight(path, expected, env, run)
            self.assertEqual(run.call_count, 1)
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, '0600'):
                preflight(path, expected, env, run)

    def test_workflow_checks_key_before_build_and_retains_final_apk_verification(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/rebeqah-android.yml').read_text()
        self.assertLess(workflow.index('check_android_signing.py'), workflow.index('actions/setup-node'))
        self.assertLess(workflow.index('check_android_signing.py'), workflow.index('Android SDK packages'))
        self.assertIn('prepare_android_release.py', workflow)
        self.assertIn('signing_preflight_only', workflow)
        self.assertIn('if: always()', workflow)


if __name__ == '__main__':
    unittest.main()
