from Crypto.PublicKey import RSA
import base64
import logging
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
from Crypto.PublicKey.RSA import importKey


def generateKeyPair(length: int = 4096):
    """
        generate rsa keypair
    """
    return RSA.generate(length)

# NOTE: can i use msgpack instead of base64 for key saving? need to check


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


def create_signature(data: bytes, keypair: RSA.RsaKey) -> bytes:
    # Sign the message using the PKCS#1 v1.5 signature scheme (RSASP1)
    hash = SHA256.new(data)
    signer = PKCS115_SigScheme(keyPair)
    signature = signer.sign(hash)
    return signature


# Verify valid PKCS#1 v1.5 signature (RSAVP1)
def verify_signature(data: bytes, signature: bytes, pubKey: bytes) -> bool:
    """
        data in bytes
        signature in bytes
        pubKey bytes = pubKey.exportKey("PEM")
    """
    pubKey = RSA.importKey(pubKey)
    hash = SHA256.new(data)
    verifier = PKCS115_SigScheme(pubKey)
    try:
        verifier.verify(hash, signature)
        return True
    except Exception as e:  # InvalidSignature
        print(e)
        return False


if __name__ == "__main__":
    import pyDH
    from Crypto.Cipher import PKCS1_OAEP
    import zlib
    privateKey = pyDH.DiffieHellman()
    bytesPubKey = zlib.compress(
        str(privateKey.gen_public_key()).encode('utf-8'))

    keyPair = generateKeyPair()
    clientPubBox = PKCS1_OAEP.new(
        importKey(keyPair.publickey().exportKey('PEM')))
    cc = clientPubBox.encrypt(bytesPubKey)
    print(cc)
    """msg = 'a'*10_00000
    sig = create_signature(msg.encode(), keyPair)
    print(sig)
    print(verify_signature(b'123', sig, keyPair.publickey().exportKey("PEM")))
    """
