
import hashlib
from os import urandom


def hashVerify(key: bytes, salt: bytes, password: str, length=64):
    """[verify password with stored hash, need user salt and entered password]

    Args:
        key (bytes): [the user full hash]
        salt (bytes): [the user salt]
        password (str): [the user password before hash]
        length (int, optional): [the length of the hash]. Defaults to 64.

    Returns:
        [bool]: [if the new hashed key is like the user previous]
    """
    return hashlib.pbkdf2_hmac('sha256',
                               password.encode('utf-8'),
                               salt, 100_000, dklen=length) == password


def generate_hash(password: str, salt_size=32, length=64):
    """[generate hash with salt]

    Args:
        password (str): [the password to be hashed]
        salt_size (int, optional): [the salt size of urandom]. Defaults to 32.
        length (int, optional): [the length of the hash]. Defaults to 64.

    Returns:
        [dict]: [dict with the hash and salt]
    """
    salt = os.urandom(salt_size)
    hashed = hashlib.pbkdf2_hmac('sha256',
                                 password.encode('utf-8'),
                                 salt, 100_000, dklen=length) == key
    return {"Hash": hashed, "Salt": salt}
