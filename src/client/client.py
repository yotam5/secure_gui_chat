# built in
import socket
import sys
import os.path
import logging
import zlib

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
        self.init_connection()
        self.directory = os.path.dirname(os.path.realpath(__file__))
        self.load_keys()
        self.decrypyor = PKCS1_OAEP.new(self.privateKey)
        self.encryptor = None
        self.__aes256key: bytes = ""

    def load_keys(self):
        """
            load the client keys if created,
            if not create and loads
        """
        """if not os.path.exists('./private.pem') or \
                not os.path.exists('./public.pem'):
            logging.debug("keys not found so will be created")"""
        rsa_utility.createAndSaveKeys(self.directory)
        logging.debug("loading keys")
        self.publicKey = rsa_utility.loadKeyFromFile(
            f'{self.directory}/public.pem')
        self.privateKey = rsa_utility.loadKeyFromFile(
            f'{self.directory}/private.pem')
        """if os.path.exists('./server.pem'): # NOTE: is it even usful cuz of
         handshake?
            logging.debug("server key was found and now is loaded")
            self.serverPublicKey = rsa_utility.loadKeyFromFile('server.pem')
        else:
            logging.debug("server key was not found, handshake now being held")
        """

    def init_connection(self):
        """
            init the client socket
        """
        logging.debug("initing connection")
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.localhost, self.port))

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
        print(server_data)
        serverPubKey = server_data['PubKey']
        serverPubKey = int(zlib.decompress(serverPubKey).decode('utf-8'))
        secret = privateKey.gen_shared_key(serverPubKey)
        logging.debug(f"aes key is {secret}")
        self.__aes256key = secret
        return secret

    def login(self, password) -> bool:  
        """
            login to server action
        """
        # need to go to user in db check if password and hash can verify
        data = {'Action': 'LOGIN', 'Data': {
            "user_id": self.user_id, "auth_data":
                AESCipher.encrypt_AES_GCM(password, self.__aes256key)}}
        # NOTE: add verification to rsa
        self.send_data(data, encoding=True)
        response = self.client_socket.recv(4096)

    def sign_up(self):
        """
            handle steps for account creation
        """
        pass

    def send_data(self, data, encoding=False):
        """
            send data to server
        """
        data = msgpack.packb(data)
        if encoding:
            data = self.encryptor.encrypt(data)
        self.client_socket.send(data)

    def recv(self):
        response = self.client_socket.recv(4096)

    def run(self):  # NOTE: need to add thread for sending/reciving
        pass

    def close(self):
        self.client_socket.close()


if __name__ == '__main__':
    a = Client('127.0.0.2', 55555)
    a.handshake()
    a.secure_connection_setup()
    #a.login(123)
