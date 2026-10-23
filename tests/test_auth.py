import unittest

from run import proxy_auth_args


class ProxyAuthTests(unittest.TestCase):
    def test_auth_arguments(self):
        self.assertEqual(
            proxy_auth_args('proxyuser', 'example-secret'),
            ['--proxyauth', 'proxyuser:example-secret'],
        )

    def test_missing_credentials_are_rejected(self):
        with self.assertRaises(ValueError):
            proxy_auth_args(None, None)

    def test_partial_credentials_are_rejected(self):
        with self.assertRaises(ValueError):
            proxy_auth_args('proxyuser', None)
        with self.assertRaises(ValueError):
            proxy_auth_args(None, 'example-secret')

    def test_username_cannot_contain_colon(self):
        with self.assertRaises(ValueError):
            proxy_auth_args('proxy:user', 'example-secret')


if __name__ == '__main__':
    unittest.main()
