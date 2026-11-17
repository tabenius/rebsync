import unittest

from prepare_android_release import apk_metadata


class AndroidReleaseTests(unittest.TestCase):
    def setUp(self):
        self.expected = {'packageName': 'com.tabenius.rebsync', 'certificateSha256': 'a' * 64,
                         'openpgpFingerprint': 'B' * 40}
        self.badging = ("package: name='com.tabenius.rebsync' versionCode='2003' versionName='0.2.3'\n"
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

    def test_debug_wrong_package_version_and_incomplete_abis_are_refused(self):
        for badging in [self.badging + 'application-debuggable\n',
                        self.badging.replace('com.tabenius.rebsync', 'com.tabenius.rebsync.debug'),
                        self.badging.replace('0.2.3', '0.2.2'),
                        self.badging.replace(" 'x86_64'", '')]:
            with self.assertRaises(ValueError):
                apk_metadata(badging, self.certs, self.expected, '0.2.3')


if __name__ == '__main__':
    unittest.main()
