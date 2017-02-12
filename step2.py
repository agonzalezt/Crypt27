import muCrypto

if __name__ == '__main__':
    symetricCrypter = muCrypto.SymetricCrypterNaCl(r'keys_and_files/texto_descifrado_paso2_keyczar.base64')
    message = symetricCrypter.decrypt(r'keys_and_files/texto_cifrado_paso2_nacl.base64',
                                      r'keys_and_files/texto_descifrado_paso2_nacl.base64',
                                      output_encoding=None)
    print "The message is:", message







