import muCrypto

if __name__ == '__main__':

    try:
        sym_cripter = muCrypto.SymetricCrypterKcz(r'keys_and_files/ficheros_clave_primaria_keyczar')
        sym_cripter.decrypt(r'keys_and_files/texto_cifrado_paso2_keyczar.base64',
                            r'keys_and_files/texto_descifrado_paso2_keyczar.base64', input_encoding=None)
        print "Decryption successful!"
    except ValueError as e:
        print "Error:", e.message

