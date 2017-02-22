from __future__ import absolute_import

import unittest

import muCrypto


class TestSymetricCrypterKcz(unittest.TestCase):
    def test_encrypt_then_decrypt(self):
        student_crypter = muCrypto.SymetricCrypterKcz(r'rsc/keyczar_keys')

        expected = muCrypto.read_file(r'rsc/original_text.base64')

        student_crypter.encrypt(r'rsc/original_text.base64',
                                r'rsc/cifrado_sckcz.base64', input_encoding=None)

        student_crypter.decrypt(r'rsc/cifrado_sckcz.base64',
                                r'rsc/descifrado_sckcz.base64', output_encoding=None)

        actual = muCrypto.read_file(r'rsc/descifrado_sckcz.base64')
        print actual, '=', expected
        self.assertEqual(expected, actual, "Encrypting and decrypting does not recreate original input")
