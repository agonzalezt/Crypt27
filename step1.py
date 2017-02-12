import muCrypto

if __name__ == '__main__':
    sym_cripter = muCrypto.SymetricCrypterKcz()
    sym_cripter.decrypt(r'keys_and_files/texto_cifrado_paso2_keyczar.base64',
                        r'keys_and_files/texto_descifrado_paso2_keyczar.base64')
