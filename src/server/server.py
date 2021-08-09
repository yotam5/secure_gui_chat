# built in
import socket
import threading
import logging
import os.path
import signal
from sys import exit, getsizeof
import zlib
import queue

# dependecies
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey.RSA import importKey
import pyDH
import msgpack

# my own
from src.utilities import AESCipher
from DataBaseUtility import DataBaseManager
from src.utilities import rsa_utility
from src.utilities import hash_utility
from src.utilities.config_utility import network_configuration_loader

"""
    TODO:
        LOGIN:
            challenge response?
            verification that client talks to server, by having the client
            verify the sat sign with the server private key
"""
logging.basicConfig(level=logging.DEBUG)
# note when works remember to use the device ip and not ip in conf


class Server(object):
    """
        main server class
    """

    def __init__(self):
        self.localhost, self.port = network_configuration_loader()
        self.clients = []
        self.publicKey = None
        self.privateKey = None
        self.directory = os.path.dirname(os.path.realpath(__file__))
        self.database_manager = DataBaseManager(
            f"{self.directory}/database.db")
        # idea, create a dict with usernames for msg
        signal.signal(signal.SIGINT, self.receive_sigint)
        # self.login_name_q = queue.Queue()

    def load_keys(self):
        """
            load the keys of the server or create them
            if it doesnt exist
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

    def run(self):
        """
            run the server
        """
        self.load_keys()
        self.init_connection()
        self.init_serving()
        self.close()

    def init_connection(self):
        """
            init server connection
        """
        try:
            self.server_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((str(self.localhost), int(self.port)))
            self.server_socket.listen()
        except socket.error as e:
            logging.debug(f"socket exception in init_connection: {e}")

    def init_serving(self):
        """
            init server client serving
        """
        self.serve = threading.Thread(target=self.add_client)
        self.exit = False
        self.serve.start()
        self.serve.join()  # NOTE: doesnt exit need to do something bou`t this

    def close_server(self):
        """
            closing the server, need to work on when and how
        """
        # broadcast exit?
        self.server_socket.close()

    def handshake(self, client_data: dict, client: socket.socket) -> bytes:
        """
            rsa handshake
        """
        client_pubKey = client_data['PubKey']
        client_pubKey = rsa_utility.rsaKeyFromBase64String(
            client_pubKey)
        # logging.debug(f"client pub key {client_pubKey}")
        data = rsa_utility.rsaKeyToBase64String(self.publicKey.exportKey())
        client.send(msgpack.packb(data))
        return client_pubKey

    def secure_connection_setup(self, client: socket.socket) -> str:
        """
            does rsa keys exchange then does diffie hellman
            algorithem to generate keys that will be used for
            AES encryption
        """

        logging.debug("secure_connection_setup was called")
        myBox = PKCS1_OAEP.new(self.privateKey)  # use thread lock instead?

        client_data = client.recv(4096)
        if client_data in ['', b'']:  # client disconnected
            return "disconnected"  # client disconnected

        logging.debug("start rsa exchange")
        # first action must be rsa exchange
        client_data = msgpack.loads(client_data)
        clientPubRsa, clientPubBox = self.handle_exchange(
            client_data, client)
        logging.debug("rsa connection established")

        # from now on the chat is rsa encrypted
        # NOTE: should i check for rsa verification?

        # start dffie hellman
        logging.debug("start diffie hellman")

        privateKey = pyDH.DiffieHellman()
        bytesPubKey = str(privateKey.gen_public_key()).encode('utf-8')
        bytesPubKey = zlib.compress(bytesPubKey)
        data_to_send = {'Action': 'DiffieHellman', 'PubKey': bytesPubKey}
        data_to_send = msgpack.packb(data_to_send)

        client.send(clientPubBox.encrypt(data_to_send))
        client_response = client.recv(4096)
        client_response = msgpack.loads(myBox.decrypt(client_response))
        logging.debug("end diffie hellman")
        clientPubKey = client_response['PubKey']
        clientPubKey = int(zlib.decompress(clientPubKey).decode('utf-8'))
        secret = privateKey.gen_shared_key(clientPubKey)
        logging.debug(f"aes key is {secret}")
        return secret[:32]  # 256 bit aes key

    def client_handle(self, client: socket.socket):
        """
            handle the client data and stuff?
        """
        secret = self.secure_connection_setup(client)  # aes key
        secret = secret.encode('utf-8')
        # from on here the chat between client and server is aes encrypted

        serve_client = True
        # stage 1: rsa key exchange
        # stage 2: dffie hellman algorithm for aes keys
        # stage 3: challange response for login

        while serve_client:
            client_data = client.recv(4096)
            if client_data in ['', b'']:  # client disconnected
                serve_client = False
            else:
                client_data = AESCipher.decrypt_data_from_bytes(
                    client_data, secret)
                logging.debug("handling data result")

                data_dict_keys = client_data.keys()
                client_action = client_data['Action']
                if client_action in ['LOGIN', 'SIGN_UP']:
                    login_info = client_data['Data']
                    user_id = login_info['user_id']
                    user_password = login_info['password']
                    if client_action == 'SIGN_UP':
                        generated_salted_hash = hash_utility.generate_hash(
                            client_info['password'])
                        self.database_manager.add_user()
                        self.database_manager.login(
                            login_info['user_id'], login_info['password'])
                    else:  # login
                        logging.debug("client trying to login")
                        login_result = self.handle_login(
                            user_id, user_password)
                        logging.debug(f"the login result is {login_result}")
                        client.send(msgpack.dumps(login_result))

        logging.debug(f"client disconnected")

        exit(0)  # terminate thread

    def handle_protocol(self, data: dict):
        pass
    
    def handle_signup(user_id: str, password: str) -> bool:
        """
            create a new user into the database
        """
        signup_result: bool = False
        logging.debug("client signup called")
        if not self.database_manager.is_exist(user_id):
            logging.debug(f"the user {user_id} can be created")
            self.database_manager.add_user(user_id, key, salt)
            signup_result = True
        else:
            logging.debug(f"the user {user_id} already exists")
        return signup_result

    def handle_login(self, user_id: str, password: str):
        """
            handle login into the server, correct user_id and password
        """
        logging.debug("client login handle called")

        login_result: bool = self.database_manager.login(user_id, password)
        return login_result

    def handle_exchange(self, client_data: dict, client: socket.socket):
        """
            handle rsa keys exchange with client
        """
        logging.debug("the server is doing exchange operation")
        clientPubKey = self.handshake(client_data, client)
        clientPubBox = PKCS1_OAEP.new(importKey(clientPubKey))
        return clientPubKey, clientPubBox

    def broadcast(self, data):
        """
            broadcast msg to all clients
        """
        for client in self.clients:
            client.send(data.encode('utf-8'))

    def add_client(self):
        """
            add new client connection to the server
        """
        while not self.exit:
            # NOTE: need to think about how the server will close itself
            client, addr = self.server_socket.accept()
            logging.debug("new connection have been established")
            self.clients.append(client)
            client_thread = threading.Thread(
                target=self.client_handle, args=[client])
            client_thread.start()

    def get_device_internal_ip(self):
        """
            get the internal ip and hostname for the server
        """
        host_name = socket.gethostname()
        return socket.gethostbyname(host_name + ".local")

    def receive_sigint(self, sig_num, frame):
        logging.debug("received sigint now closing server and socket")
        self.close_server()
        exit(0)


if __name__ == '__main__':
    logging.debug("starting server:")
    server = Server()
    server.run()
