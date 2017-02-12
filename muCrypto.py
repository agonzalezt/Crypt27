import codecs
import os

from keyczar import keyczar
from nacl import secret

'''
This module contains encapsutions of the keyczar and
pyNacl libraries
'''


def decode(obj, decoder='base64'):
    if decoder is not None:
        decoded_obj = codecs.decode(obj, encoding=decoder)
    else:
        decoded_obj = obj
    return decoded_obj

def encode(obj, encoder='base64'):
    if encoder is not None:
        encoded_obj = codecs.encode(obj, encoding=encoder)
    else:
        encoded_obj = obj
    return encoded_obj

def _assert_is_dir(loc):
    '''
    Makes sure that the given string represents a path to a directory
    by checking if its a already a directory and then creating it if it
    doesnt exist

    :param loc: The path to be checked
    :type loc: str
    :raises: ValueError: If path refers to an existing file (not dir)
    :return: None
    '''

    if os.path.exists(loc):
        if not os.path.isdir(loc):
            raise ValueError('%s must be a directory' % loc)
    else:
        os.makedirs(loc, 0o0755)


class SymetricCrypterKcz(object):
    '''
    This class represent a Symetric Crypter by encapsulating
    keyczar library's Crypter class (expects and uses base64
    encoded files)
    '''

    key_location = r"keys_and_files/ficheros_clave_primaria_keyczar";

    def __init__(self, key_location=None):
        if key_location is None:
            key_location = self.key_location
        _assert_is_dir(key_location)
        self.crypt = keyczar.Crypter.Read(key_location)

    def encrypt(self, input_path, output_path, input_encoding='base64', output_encoding='base64'):
        '''
        Encrypts the file on the path 'input_path' and places the result in the file
        'output_path' which will be created if it doesn't exist yet.

        :param output_encoding: The encoding type of the input-file
        :param input_encoding: The encoding type of the output-file
        :param input_path: Path of the file to be encrypted
        :type input_path: str
        :param output_path: Path to the file the output will be writen to
        :type output_path: str
        :return: None
        '''

        with open(input_path, mode="r") as input_buffer:
            input_str = input_buffer.read()

        plain_input = decode(input_str, input_encoding)

        cyphertext = self.crypt.Encrypt(plain_input)
        encrypted_cyphertext = encode(cyphertext, output_encoding)

        with open(output_path, mode="wb") as output_buffer:
            output_buffer.write(encrypted_cyphertext)
        return cyphertext


    def decrypt(self, input_path, output_path, input_encoding='base64', output_encoding='base64'):
        '''
        Decrypts the file on the path 'input_path' and places the result in the file
        'output_path' which will be created if it doesn't exist yet.

        :param output_encoding: The encoding type of the input-file
        :param input_encoding: The encoding type of the output-file
        :param input_path: Path of the file to be decrypted
        :type input_path: str
        :param output_path: Path to the file the output will be writen to
        :type output_path: str
        :return: None
        '''

        with open(input_path, mode="r") as input_buffer:
            cyphertext = input_buffer.read()

        decrypted_cyphertext = decode(cyphertext, input_encoding)

        plain_text = self.crypt.Decrypt(decrypted_cyphertext)

        encoded_text = encode(plain_text, output_encoding)

        with open(output_path, mode="wb") as output_buffer:
            output_buffer.write(encoded_text)
        return encoded_text


class SymetricCrypterNaCl(object):

    key_location = r'keys_and_files/texto_descifrado_paso2_keyczar.base64'

    def __init__(self, key_location=None, decoder='base64'):
        if key_location is None:
            key_location = self.key_location
        with open(key_location) as key_file:
            key = key_file.read()
        decode(key, decoder)
        self.crypt = secret.SecretBox(key)







