"""
This module contains encapsutions of the keyczar and
pyNacl libraries
"""

import codecs
import os
from json import decoder

from keyczar import keyczar
from nacl import secret, utils, public


class SymetricCrypterKcz(object):
    """
    This class represents a Symetric Crypter by encapsulating
    keyczar library's Crypter class. Accepts encodings found in
    codecs module.
    """

    def __init__(self, key_location):
        """
        Instantiates a SymetricCrypterKcz object

        :param key_location: Folder containing the keys
        """
        _assert_is_dir(key_location)
        self.crypt = keyczar.Crypter.Read(key_location)

    def encrypt(self, input_path, output_path, input_encoding='base64', output_encoding='base64'):
        """
        Encrypts the file on the path 'input_path' and places the result in the file
        'output_path' which will be created if it doesn't exist yet.

        :param output_encoding: The encoding type of the input-file
        :param input_encoding: The encoding type of the output-file
        :param input_path: Path of the file to be encrypted
        :type input_path: str
        :param output_path: Path to the file the output will be writen to
        :type output_path: str
        :return: The generated file's content
        """

        input_str = read_file(input_path)

        plain_input = decode(input_str, input_encoding)

        cyphertext = self.crypt.Encrypt(plain_input, encoder=None)
        encoded_cyphertext = encode(cyphertext, output_encoding)

        write_file(encoded_cyphertext, output_path)
        return encoded_cyphertext

    def decrypt(self, input_path, output_path, input_encoding='base64', output_encoding='base64'):
        """
        Decrypts the file on the path 'input_path' and places the result in the file
        'output_path' which will be created if it doesn't exist yet.

        :param output_encoding: The encoding type of the input-file
        :param input_encoding: The encoding type of the output-file
        :param input_path: Path of the file to be decrypted
        :type input_path: str
        :param output_path: Path to the file the output will be writen to
        :type output_path: str
        :return: The generated file's content
        """

        cyphertext = read_file(input_path)

        decrypted_cyphertext = decode(cyphertext, input_encoding)

        plain_text = self.crypt.Decrypt(decrypted_cyphertext, decoder=None)

        encoded_text = encode(plain_text, output_encoding)

        write_file(encoded_text, output_path)
        return encoded_text


class SymetricCrypterNaCl(object):
    """
    This class represents a Symetric Crypter by encapsulating
    pyNaCl library's SecretBox class. Accepts encodings found in
    codecs module.
    """
    key_location = r'keys_and_files/texto_descifrado_paso2_keyczar.base64'

    def __init__(self, key_location=None, decoder='base64'):
        """
        Instantiates a SymetricCrypterNaCl object

        :param key_location: Path to the key's file
        :type key_location: str
        :param decoder: The encoding of the key's file
        :type decoder: str
        """
        if key_location is None:
            key_location = self.key_location
        key = read_file(key_location)
        key = decode(key, decoder)
        self.crypt = secret.SecretBox(key)

    def encrypt(self, input_path, output_path, input_encoding='base64', output_encoding='base64'):
        """
        Encrypts the file on the path 'input_path' and places the result in the file
        'output_path' which will be created if it doesn't exist yet.

        :param output_encoding: The encoding type of the input-file
        :param input_encoding: The encoding type of the output-file
        :param input_path: Path of the file to be encrypted
        :type input_path: str
        :param output_path: Path to the file the output will be writen to
        :type output_path: str
        :return: The generated file's content
        """
        input_str = read_file(input_path)

        plain_input = decode(input_str, input_encoding)

        nonce = utils.random(secret.SecretBox.NONCE_SIZE)
        cyphertext = self.crypt.encrypt(plain_input, nonce)
        encrypted_cyphertext = encode(cyphertext, output_encoding)

        write_file(encrypted_cyphertext, output_path)
        return encrypted_cyphertext

    def decrypt(self, input_path, output_path, input_encoding='base64', output_encoding='base64'):
        """
        Decrypts the file on the path 'input_path' and places the result in the file
        'output_path' which will be created if it doesn't exist yet.

        :param output_encoding: The encoding type of the input-file
        :param input_encoding: The encoding type of the output-file
        :param input_path: Path of the file to be decrypted
        :type input_path: str
        :param output_path: Path to the file the output will be writen to
        :type output_path: str
        :return: The generated file's content
        """
        cyphertext = read_file(input_path)
        decrypted_cyphertext = decode(cyphertext, input_encoding)

        plain_text = self.crypt.decrypt(decrypted_cyphertext)

        encoded_text = encode(plain_text, output_encoding)

        write_file(encoded_text, output_path)
        return encoded_text


class AsymetricCrypterNaCl(object):
    """
    This class represents an Asymetric Crypter by encapsulating
    pyNaCl library's Box class. Accepts encodings found in
    codecs module.
    """
    def __init__(self, priv_k_path, pub_k_path, priv_k_encoding='base64', pub_k_encoding='base64'):
        """
        Instantiates an AsymetricCrypterNaCl object. Priv_k_path may be null if only
        used for encryption and not decryption.

        :param priv_k_path: Path of the file containing the private key
        :type priv_k_path: str
        :param pub_k_path: Path of the file containing the public key
        :type pub_k_path: str
        :param priv_k_encoding: The encoding of the private key's file
        :type priv_k_encoding: str
        :param pub_k_encoding: The encoding of the public key's file
        :type pub_k_encoding: str
        """
        priv_k_str = read_file(priv_k_path)
        priv_k_str = decode(priv_k_str, priv_k_encoding)
        priv_k = public.PrivateKey(priv_k_str)

        pub_k_str = read_file(pub_k_path)
        pub_k_str = decode(pub_k_str, pub_k_encoding)
        pub_k = public.PublicKey(pub_k_str)

        self.crypt = public.Box(priv_k, pub_k)

    def encrypt(self, input_path, output_path, input_encoding='base64', output_encoding='base64'):
        """
        Encrypts the file on the path 'input_path' and places the result in the file
        'output_path' which will be created if it doesn't exist yet.

        :param output_encoding: The encoding type of the input-file
        :param input_encoding: The encoding type of the output-file
        :param input_path: Path of the file to be encrypted
        :type input_path: str
        :param output_path: Path to the file the output will be writen to
        :type output_path: str
        :return: The generated file's content
        """

        input_str = read_file(input_path)

        plain_input = decode(input_str, input_encoding)

        nonce = utils.random(secret.SecretBox.NONCE_SIZE)
        cyphertext = self.crypt.encrypt(plain_input, nonce)
        encrypted_cyphertext = encode(cyphertext, output_encoding)

        write_file(encrypted_cyphertext, output_path)
        return encrypted_cyphertext

    def decrypt(self, input_path, output_path, input_encoding='base64', output_encoding='base64'):
        """
        Decrypts the file on the path 'input_path' and places the result in the file
        'output_path' which will be created if it doesn't exist yet.

        :param output_encoding: The encoding type of the input-file
        :param input_encoding: The encoding type of the output-file
        :param input_path: Path of the file to be decrypted
        :type input_path: str
        :param output_path: Path to the file the output will be writen to
        :type output_path: str
        :return: The generated file's content
        """
        cyphertext = read_file(input_path)

        decrypted_cyphertext = decode(cyphertext, input_encoding)
        plain_text = self.crypt.decrypt(decrypted_cyphertext)
        encoded_text = encode(plain_text, output_encoding)

        write_file(encoded_text, output_path)
        return encoded_text


def write_file(obj, location):
    """
    Write an object's binary data to a file
    :param obj:
    :param location: Path to the file
    """
    try:
        with open(location, mode="wb") as file_stream:
            file_stream.write(obj)
            return True
    except (OSError, IOError) as root_err:
        raise ValueError("Could not write to file: " + location, {"root_error": root_err})


def read_file(location):
    """
    Reads a file's binary data
    :param location: Path to the file
    :return: data
    """
    try:
        with open(location, mode="rb") as file_stream:
            return file_stream.read()
    except (OSError, IOError) as root_err:
        raise ValueError("Could not read file: " + location, {"root_error": root_err})


def decode(obj, decoder='base64'):
    """
    Decodes the given object with the specified type of encoding. None for no
    encoding

    :param obj: The object to be encoded
    :param decoder: The encoding type
    :type decoder: str
    :return: The encrypted result
    """
    if decoder is not None:
        decoded_obj = codecs.decode(obj, decoder)
    else:
        decoded_obj = obj
    return decoded_obj


def encode(obj, encoder='base64'):
    """
    Encodes the given object with the specified type of encoding. None for no
    encoding

    :param obj: The object to be encoded
    :param encoder: The encoding type
    :type encoder: str
    :return: The encrypted result
    """
    if encoder is not None:
        encoded_obj = codecs.encode(obj, encoder)
    else:
        encoded_obj = obj
    return encoded_obj


def _assert_is_dir(loc):
    """
    Makes sure that the given string represents a path to a directory
    by checking if its a already a directory and then creating it if it
    doesnt exist

    :param loc: The path to be checked
    :type loc: str
    :raises: ValueError: If path refers to an existing file (not dir)
    :return: None
    """

    if os.path.exists(loc):
        if not os.path.isdir(loc):
            raise ValueError('%s must be a directory' % loc)
