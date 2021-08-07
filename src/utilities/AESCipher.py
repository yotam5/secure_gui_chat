from Crypto.Cipher import AES
from typing import Tuple

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


if __name__ == "__main__":
    kk = 'dacfbd3c78ec70d69ef6946655bc2427d3798eb91c32b9417f0bda71fdbc3a2a'
    kk = kk.encode('utf-8')
    gg = encrypt_AES_GCM()