from Crypto.Cipher import AES
from typing import Tuple
import msgpack
# aes encryption with auth


def encrypt_AES_GCM(msg: bytes, secretKey: bytes) -> Tuple[bytes, ...]:
    """
        encrypt msg with secretKey and return tuple of 3 bytes
        ciphertext: the encrypted text
        aesCipher.nounce: randomly generated initial vector
        authTag: the message auth code(MAC) calculated during the encryption.
    """
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)


def decrypt_AES_GCM(encryptedMsg: Tuple[bytes, ...], secretKey: bytes) \
        -> bytes:
    """
        decrypted encrypted message using the
        tuple from the ecnryption function
    """
    (ciphertext, nonce, authTag) = encryptedMsg
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext


def encrypt_data_to_bytes(data, key: bytes) -> bytes:
    """
        get key and built in data type: list, tuple etc
        and encrypt them using aes256 after converting to bytes and
        then returned the byted encrypted data(the tuple for auth)
    """
    data = msgpack.dumps(data)
    data = encrypt_AES_GCM(data, key)
    return msgpack.dumps(data)


def decrypt_data_from_bytes(data: bytes, key: bytes):
    """
        get key and the encrypted data as bytes(that is the tuple)
        and return the decrypted value that is any built in 
        data type
    """
    data = msgpack.loads(data)
    data = decrypt_AES_GCM(data, key)
    return msgpack.loads(data)


if __name__ == "__main__":
    data = {"Data": "ok"}
    key = "1"*32
    key = key.encode('utf-8')
    data = encrypt_data_to_bytes(data, key)
    print(data)
    data = decrypt_data_from_bytes(data, key)
    print(data)