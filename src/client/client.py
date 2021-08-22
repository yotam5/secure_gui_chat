# built in
import socket
import sys
import os.path
import logging
import zlib
from queue import deque

# my own
from src.utilities import rsa_utility
from src.utilities import AESCipher

# dependencies
import msgpack
import pyDH
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey.RSA import importKey
from src.utilities.config_utility import network_configuration_loader

logging.basicConfig(level=logging.DEBUG)

# NOTE: to add port forwarding automation
# NOTE: to add 2 FA with email or etc
# NOTE: to check auth using server perment pem?

"""
    FIXME:
        i need to create one thread for receving and one for sending,
        ill have queue for the receved and the data that needs to be sent
        and also ill send the msg size before the message itself,
        that will fix the problem of different sends and received at
        the same time,
        for example: is_online will send and the result
                    will be received by the thread, then
                    while iterating over the queue when data
                    with action of "is_online" the is_online function
                    will handle this
"""


class Client(object):
    def __init__(self, user_id: str = "DUMMY"):
        self.localhost: str = None
        self.port: int = None
        self.client_socket = None
        self.localhost, self.port = network_configuration_loader()
        self.port = int(self.port)
        self.user_id = user_id
        self.logged = False
        self.publicKey = None
        self.privateKey = None
        self.serverPublicKey = None
        self.directory = os.path.dirname(os.path.realpath(__file__))
        self.load_keys()
        self.decrypyor = PKCS1_OAEP.new(self.privateKey)
        self.encryptor = None
        self.__aes256key: bytes = ""
        self.my_deque = deque()

    def load_keys(self):
        """
            load the client keys if created,
            if not create and loads
        """
        if not os.path.exists('./private.pem') or \
                not os.path.exists('./public.pem'):
            logging.debug("keys not found so will be created")
            rsa_utility.createAndSaveKeys(self.directory)
        logging.debug("loading keys")
        self.publicKey = rsa_utility.loadKeyFromFile(
            f'{self.directory}/public.pem')
        self.privateKey = rsa_utility.loadKeyFromFile(
            f'{self.directory}/private.pem')
        if os.path.exists('./server.pem'):
            logging.debug("server key was found and now is loaded")
            self.serverPublicKey = rsa_utility.loadKeyFromFile('server.pem')
        else:
            logging.debug("server key was not found, handshake now being held")

    def init_connection(self):
        """
            init the client socket
        """
        logging.debug("initing connection")
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.localhost, self.port))

    def secure_connection(self):
        """
            create secure connection to the server that at
            the end the communication is based on aes encryption
        """
        self.init_connection()
        self.handshake()
        self.secure_connection_setup()

    def handshake(self):
        """
            handle rsa exchange with the server
        """
        data = {'Action': "EXCHANGE", 'PubKey':
                rsa_utility.rsaKeyToBase64String(self.publicKey.exportKey())}
        self.client_socket.send(msgpack.packb(data))
        self.serverPublicKey = self.client_socket.recv(4096)
        self.serverPublicKey = rsa_utility.rsaKeyFromBase64String(
            self.serverPublicKey)
        logging.debug(f"server key: {self.serverPublicKey}")
        self.encryptor = PKCS1_OAEP.new(importKey(self.serverPublicKey))

    def secure_connection_setup(self) -> str:
        """
            does rsa keys exchange then does diffie hellman
            algorithem to generate keys that will be used for
            AES encryption
        """

        logging.debug("secure_connection_setup was called")

        server_data = self.client_socket.recv(4096)
        if server_data in ['', b'']:  # client disconnected
            return "disconnected"  # client disconnected

        # from now on the chat is rsa encrypted
        # NOTE: should i check for rsa verification?
        # start dffie hellman
        logging.debug("start diffie hellman")

        privateKey = pyDH.DiffieHellman()
        bytesPubKey = str(privateKey.gen_public_key()).encode('utf-8')
        bytesPubKey = zlib.compress(bytesPubKey)
        data_to_send = {'Action': 'DiffieHellman', 'PubKey': bytesPubKey}
        data_to_send = msgpack.packb(data_to_send)
        logging.debug(self.decrypyor.decrypt(server_data))
        self.client_socket.send(
            self.encryptor.encrypt(data_to_send))

        logging.debug("end diffie hellman")
        server_data = msgpack.loads(self.decrypyor.decrypt(server_data))
        logging.debug(server_data)
        serverPubKey = server_data['PubKey']
        serverPubKey = int(zlib.decompress(serverPubKey).decode('utf-8'))
        secret = privateKey.gen_shared_key(serverPubKey)
        logging.debug(f"aes key is {secret}")
        self.__aes256key = secret[:32].encode('utf-8')
        return secret[:32]  # 256 bit key

    def login(self, password) -> bool:
        """
            login to server action
        """
        # need to go to user in db check if password and hash can verify
        logging.debug(f"aes key is {self.__aes256key}")
        data = {'Action': 'LOGIN', 'Data': {
            "user_id": self.user_id, "password": password}}
        data = AESCipher.encrypt_data_to_bytes(data, self.__aes256key)
        self.client_socket.send(data)
        response = self.client_socket.recv(4096)
        return msgpack.loads(response)

    def sign_up(self, password: str) -> bool:  # this not need thread
        """
            handle steps for account creation
        """
        data = {'Action': 'SIGN_UP', 'Data': {
            "user_id": self.user_id, "password": password}}
        data = AESCipher.encrypt_data_to_bytes(data, self.__aes256key)
        self.client_socket.send(data)
        answer: bool = self.client_socket.recv(4096)
        return msgpack.loads(answer)

    def send(self, text: str, username: str):  # need thread
        # encrypted_data = AESCipher.encrypt_data_to_bytes(text, )
        data = {'Action': 'PASS_TO', 'Data': {
            'user_id': username, 'text': text
        }}
        data = AESCipher.encrypt_data_to_bytes(data, self.__aes256key)
        self.client_socket.send(data)

    def recv(self):
        response = self.client_socket.recv(4096)

    def run(self):  # NOTE: need to add thread for sending/reciving
        pass

    def is_online(self, user_id: str):
        """
            ask server for user id and return boolean
            of server answer
        """
        data = {'Action': 'SEARCH', 'Data': {'user_id': user_id}}
        data = AESCipher.encrypt_data_to_bytes(data, self.__aes256key)
        self.client_socket.send(data)

        answer = self.client_socket.recv(4096)
        logging.debug(f"asked server if {user_id} is online: {answer}")
        answer = AESCipher.decrypt_data_from_bytes(answer, self.__aes256key)
        return answer

    def set_username(self, username: str):
        # set the username if not logged into the server
        self.user_id = username

    def set_password(self, password: str):
        # set the password, not needed?
        pass

    def get_username(self) -> str:
        return self.user_id

    def close(self):
        self.client_socket.close()


if __name__ == '__main__':
    a = Client("yoram")
    a.secure_connection()
    a.login("123")
    print(a.is_online('yoram'))
    a.send("hello", "jeff")
