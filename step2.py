from muCrypto import *

if __name__ == '__main__':
    try:
        symetric_crypter = SymetricCrypterNaCl(r'keys_and_files/texto_descifrado_paso2_keyczar.base64')
        message = symetric_crypter.decrypt(r'keys_and_files/texto_cifrado_paso2_nacl.base64',
                                           r'keys_and_files/texto_descifrado_paso2_nacl.base64',
                                           output_encoding=None)
        print "The message is:", message

        asymetric_crypter = AsymetricCrypterNaCl(r'keys_and_files/skAlumno.base64', r'keys_and_files/pkTutor.base64')
        asymetric_crypter.encrypt(r'keys_and_files/texto_descifrado_paso2_nacl.base64',
                                  r'keys_and_files/texto_cifrado_tutor_nacl.base64',
                                  input_encoding=None)
        print "Encryption successful!"
    except ValueError as e:
        print "Error: ", e.message


