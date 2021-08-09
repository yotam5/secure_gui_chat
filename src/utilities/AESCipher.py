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
    import msgpack
    kk = 'dacfbd3c78ec70d69ef6946655bc2427d3798eb91c32b9417f0bda71fdbc3a2a'[
        :32]
    print(kk)
    kk = kk.encode('utf-8')
    gg = encrypt_AES_GCM(b'hello world', kk)
    ff = msgpack.dumps(gg)
    print(ff)
    ff = msgpack.loads(ff)
    print(ff)
    print(decrypt_AES_GCM(ff, kk))
