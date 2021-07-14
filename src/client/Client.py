import socket
import msgpack
import sys
from src.utilities import rsa_utility
import os.path
import logging
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey.RSA import importKey

logging.basicConfig(level=logging.DEBUG)


class Client(object):
    def __init__(self, localhost: str, port: int, user_id: str = "DUMMY"):
        self.localhost: str = localhost
        self.port: int = port
        self.client_socket = None
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

    def hand_shake(self):
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

    def login(self, password):  # need rsa encryption
        """
            login to server action
        """
        # need to go to user in db check if password and hash can verify
        data = {'Action': 'LOGIN', 'Data': {
            "user_id": self.user_id, "password": password}}  # need to add verification of rsa
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

    def close(self):
        self.client_socket.close()


if __name__ == '__main__':
    a = Client('127.0.0.2', 55555)
    a.hand_shake()
    a.login(123)
