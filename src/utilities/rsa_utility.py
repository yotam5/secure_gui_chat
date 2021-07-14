from Crypto.PublicKey import RSA
import binascii
import base64
import logging
from hashlib import sha512


def generateKeyPair(length: int = 3072):
    """
        generate rsa keypair
    """
    return RSA.generate(length)


def rsaKeyToBase64String(key: bytes) -> str:
    return base64.b64encode(key).decode('ascii')


def rsaKeyFromBase64String(key: str) -> bytes:
    return base64.b64decode(key).decode('ascii')


def saveKeyToFile(key: bytes, filename: str):
    """
        save key of rsa in bytes to a file
    """
    with open(filename, 'wb') as key_file:
        key_file.write(key)


def loadKeyFromFile(filename: str):
    """
        load rsa key form file
    """
    key = None
    with open(filename, 'rb') as key_file:
        key = RSA.importKey(key_file.read())
    return key


def createAndSaveKeys(path: str):
    """
        create and dave rsa par to files
    """
    logging.debug(f"saving keys to {path}")
    key_pair = generateKeyPair()
    saveKeyToFile(key_pair.publickey().exportKey(), f"{path}/public.pem")
    saveKeyToFile(key_pair.exportKey(),  f'{path}/private.pem')


def create_signature(data: bytes, key_d, key_n):
    """
        signature data of bytes for rsa verification
        key_d = keyPair.d
        key_n = keyPair.n
    """
    hash = int.from_bytes(sha512(data).digest(), byteorder='big')
    return pow(hash, key_d, key_n)


def verify_signature(data: bytes, signature: bytes, key_e, key_n) -> bool:
    """
        verify sign data sign with private key of rsa
        key_e = keyPair.e
        key_n = keyPair.n
    """
    hash = int.from_bytes(sha512(data).digest(), byteorder='big')
    return signature == pow(signature, key_e, key_n)
