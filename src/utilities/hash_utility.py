
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
    return hashlib.pbkdf2_hmac('sha512',
                               password.encode('ISO-8859-1'),
                               salt, 100_000, dklen=length) == password


def generate_hash(password: str, salt_size: int = 32, length: int = 64):
    """[generate hash with salt]

        Args:
            password (str): [the password to be hashed]
            salt_size (int, optional): [the salt size of urandom]. Defaults to 32.
            length (int, optional): [the length of the hash]. Defaults to 64.

        Returns:
            [tuple]: [first value is the hashed password, second is the salt]
    """
    salt = urandom(salt_size)
    key = hashlib.pbkdf2_hmac(
        'sha512',  # The hash digest algorithm for HMAC
        password.encode('ISO-8859-1'),  # Convert the password to bytes
        salt,  # Provide the salt
        100_000, dklen=length
    )
    return key, salt


if __name__ == "__main__":
    res = generate_hash('123')
    res = res[0]
    res = res.decode('ISO-8859-1')
    print(res.encode('ISO-8859-1'))
