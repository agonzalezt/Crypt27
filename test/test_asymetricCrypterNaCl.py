from __future__ import absolute_import

from unittest import TestCase

import muCrypto


class TestAsymetricCrypterNaCl(TestCase):
    def test_encrypt_then_decrypt(self):
        student_crypter = muCrypto.AsymetricCrypterNaCl(r'rsc/skAlumno.base64',
                                                        r'rsc/pkAlumno.base64')

        expected = muCrypto.read_file(r'rsc/original_text.base64')

        student_crypter.encrypt(r'rsc/original_text.base64',
                                r'rsc/cifrado_Alumno.base64',
                                input_encoding=None)

        student_crypter.decrypt(r'rsc/cifrado_Alumno.base64',
                                r'rsc/descifrado_Alumno.base64',
                                output_encoding=None)

        actual = muCrypto.read_file(r'rsc/descifrado_Alumno.base64')

        self.assertEqual(expected, actual, "Encrypting and decrypting does not recreate original input")
