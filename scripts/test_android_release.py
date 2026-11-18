import unittest

from prepare_android_release import apk_metadata


class AndroidReleaseTests(unittest.TestCase):
    def setUp(self):
        self.expected = {'packageName': 'com.tabenius.rebeqah', 'certificateSha256': 'a' * 64,
                         'openpgpFingerprint': 'B' * 40}
        self.badging = ("package: name='com.tabenius.rebeqah' versionCode='2003' versionName='0.2.3'\n"
                        "sdkVersion:'24'\ntargetSdkVersion:'37'\n"
                        "native-code: 'arm64-v8a' 'armeabi-v7a' 'x86_64'\n")
        self.certs = 'Signer #1 certificate SHA-256 digest: ' + 'a' * 64 + '\n'

    def test_inventory_records_android_update_identity(self):
        meta = apk_metadata(self.badging, self.certs, self.expected, '0.2.3')
        self.assertEqual(meta['versionCode'], 2003)
        self.assertEqual(meta['minSdk'], 24)

    def test_wrong_certificate_is_refused(self):
        with self.assertRaises(ValueError):
            apk_metadata(self.badging, self.certs.replace('a', 'b'), self.expected, '0.2.3')

    def test_build_tools_37_v2_only_output_is_accepted(self):
        # apksigner 37 on a v2-only APK, as Gradle 9 / AGP 9 signs it.
        certs = ('Number of signers: 1\n'
                 'V2 Signer: certificate DN: CN=x\n'
                 'V2 Signer: certificate SHA-256 digest: ' + 'A' * 64 + '\n'
                 'V2 Signer: public key SHA-256 digest: ' + 'c' * 64 + '\n')
        meta = apk_metadata(self.badging, certs, self.expected, '0.2.3')
        self.assertEqual(meta['certificateSha256'], 'a' * 64)

    def test_same_signer_under_several_schemes_counts_once(self):
        certs = self.certs + 'V2 Signer: certificate SHA-256 digest: ' + 'a' * 64 + '\n'
        apk_metadata(self.badging, certs, self.expected, '0.2.3')

    def test_two_signers_or_unparsable_output_are_refused(self):
        for certs in ['Number of signers: 2\n' + self.certs,
                      self.certs + 'Signer #2 certificate SHA-256 digest: ' + 'a' * 63 + 'b\n',
                      'nothing useful\n']:
            with self.assertRaises(ValueError):
                apk_metadata(self.badging, certs, self.expected, '0.2.3')

    def test_debug_wrong_package_version_and_incomplete_abis_are_refused(self):
        for badging in [self.badging + 'application-debuggable\n',
                        self.badging.replace('com.tabenius.rebeqah', 'com.tabenius.rebeqah.debug'),
                        self.badging.replace('0.2.3', '0.2.2'),
                        self.badging.replace(" 'x86_64'", '')]:
            with self.assertRaises(ValueError):
                apk_metadata(badging, self.certs, self.expected, '0.2.3')


if __name__ == '__main__':
    unittest.main()
