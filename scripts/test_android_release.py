import unittest

from prepare_android_release import apk_metadata


class AndroidReleaseTests(unittest.TestCase):
    def setUp(self):
        self.expected = {'packageName': 'com.tabenius.rebeqah', 'certificateSha256': 'a' * 64,
                         'openpgpFingerprint': 'B' * 40}
        self.badging = ("package: name='com.tabenius.rebeqah' versionCode='2004' versionName='0.2.4'\n"
                        "sdkVersion:'24'\ntargetSdkVersion:'37'\n"
                        "native-code: 'arm64-v8a' 'armeabi-v7a' 'x86_64'\n")
        self.certs = 'Number of signers: 1\nSigner #1 certificate SHA-256 digest: ' + 'a' * 64 + '\n'

    def test_inventory_records_android_update_identity(self):
        meta = apk_metadata(self.badging, self.certs, self.expected, '0.2.4')
        self.assertEqual(meta['versionCode'], 2004)
        self.assertEqual(meta['minSdk'], 24)

    def test_wrong_certificate_is_refused(self):
        with self.assertRaises(ValueError):
            apk_metadata(self.badging, self.certs.replace('a', 'b'), self.expected, '0.2.4')

    def test_sdk37_scheme_labels_preserve_exact_identity(self):
        for label in ['V2 Signer', 'V3.0 Signer', 'V3.1 Signer', 'V3.2 Signer']:
            report = 'Number of signers: 1\n' + label + ': certificate SHA-256 digest: ' + 'a'*64 + '\n'
            self.assertEqual(apk_metadata(self.badging, report, self.expected, '0.2.4')['certificateSha256'], 'a'*64)
        report = 'Number of signers: 1\nV2 Signer: certificate SHA-256 digest: ' + 'a'*64 + '\nV3.0 Signer: certificate SHA-256 digest: ' + 'a'*64 + '\n'
        self.assertEqual(apk_metadata(self.badging, report, self.expected, '0.2.4')['certificateSha256'], 'a'*64)

    def test_multiple_mismatched_unrecognised_or_uncounted_signers_are_refused(self):
        for report in [self.certs.replace('signers: 1', 'signers: 2'),
                       self.certs.replace('Number of signers: 1\n', ''),
                       self.certs.replace('Signer #1', 'Unknown signer'),
                       self.certs + 'V3.0 Signer: certificate SHA-256 digest: ' + 'b'*64 + '\n']:
            with self.assertRaises(ValueError):apk_metadata(self.badging, report, self.expected, '0.2.4')

    def test_debug_wrong_package_version_and_incomplete_abis_are_refused(self):
        for badging in [self.badging + 'application-debuggable\n',
                        self.badging.replace('com.tabenius.rebeqah', 'com.tabenius.rebeqah.debug'),
                        self.badging.replace('0.2.4', '0.2.3'),
                        self.badging.replace(" 'x86_64'", '')]:
            with self.assertRaises(ValueError):
                apk_metadata(badging, self.certs, self.expected, '0.2.4')


if __name__ == '__main__':
    unittest.main()
