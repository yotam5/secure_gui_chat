# built in
import socket
import threading
import _thread
import logging
import os.path
import signal
from sys import exit
import zlib
import re
from typing import Tuple, Dict
from queue import deque
from time import sleep

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
            !verification that client talks to server, by having the client
            verify the sat sign with the server private key!
            ! create in client send/receive thread and also encrypt all data
                that is being sent !
"""
logging.basicConfig(level=logging.DEBUG)
# note when works remember to use the device ip and not ip in conf


class Server(object):
    """
        main server class
    """

    def __init__(self):
        self.localhost, self.port = network_configuration_loader()
        self.clients: Dict[str, Tuple[socket.socket, _thread.LockType]] = {}
        self.secrets: Dict[str, bytes] = {}
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
        # NOTE: checking using the folder where the server/client
        # is using self.directory
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
        # self.close()

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
        self.serve.daemon = True
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
        client.send(msgpack.dumps(data))
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
        client_data = msgpack.loads(client_data, raw=False)
        logging.debug(f"line 141 {client_data}")
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
        data_to_send = msgpack.dumps(data_to_send)
        logging.debug(data_to_send)
        client.send(clientPubBox.encrypt(data_to_send))
        client_response = client.recv(4096)
        client_response = msgpack.loads(
            myBox.decrypt(client_response), raw=False)
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
        # function_dict = {'funcname': 'func name'}
        # can alll with dict['key'](param)
        client_name: str = ""
        my_deque = deque()
        logging.debug('start while loop to serve client')
        incoming_thread = None
        incoming_thread_stop = True

        while serve_client:
            try:
                client_msg_size = client.recv(5)
                if len(client_msg_size) != 5:
                    logging.debug(f"unvalid msg len {len(client_msg_size)}")
                    continue  # ignore, unvalid size

                logging.debug(f"size of msg {client_msg_size}")
                client_msg_size = int(msgpack.loads(client_msg_size))
                client_data = client.recv(client_msg_size)
                client_data = AESCipher.decrypt_data_from_bytes(
                    client_data, secret)
                logging.debug("handling data result")
                logging.debug(f"got from client {client_data}")
                # data_dict_keys = client_data.keys()
                client_action = client_data['Action']

                if client_action in ['LOGIN', 'SIGN_UP']:
                    login_info = client_data['Data']
                    user_id = login_info['user_id']
                    user_password = login_info['password']

                    if client_action == 'SIGN_UP':
                        signup_result = self.handle_signup(
                            user_id, user_password)
                        client.send(msgpack.dumps(signup_result))

                    else:  # login
                        logging.debug("client trying to login")
                        login_result = self.handle_login(
                            user_id, user_password)
                        logging.debug(f"the login result is {login_result}")
                        client.send(msgpack.dumps(login_result))
                        if login_result:
                            logging.debug(f"creating 2 dicts for {user_id}")
                            self.clients[user_id] = (client, threading.Lock())
                            self.secrets[user_id] = secret
                            incoming_thread_stop = False
                            incoming_thread = threading.Thread(target=self.client_incoming_thread,
                                                               args=[client_name])
                        client_name = user_id
                        logging.debug(f"thread of {client_name}!")

                elif client_action == 'PASS_TO':
                    my_deque.append(client_data)

                elif client_action == 'SEARCH':
                    data = client_data['Data']
                    logging.debug(
                        f"client trying to search user {data['user_id']}")
                    result = self.database_manager.is_online(data['user_id'])
                    response = {"Action": "SEARCH",
                                "Data": {"Result": result}}

                    logging.debug("sending SEARCH result")
                    Server.send(response, client, secret)

                elif client_action == "EXIT":
                    logging.debug("client exiting action called")
                    response = {"Action": "EXIT"}
                    Server.send(response, client, secret)

                my_deque.append("end")


            except ConnectionResetError:
                logging.debug("connection error")
                serve_client = False
            sleep(0.05)
        if client_name:
            self.database_manager.logout(client_name)
        logging.debug("client disconnected")

        exit(0)  # terminate thread

    def client_incoming_thread(self, my_deque: deque, client_name: str,
                               lock: threading.Lock):
        """
            run the thread until lock is set to aquire from the outside,
            NOTE: wont be terminated if wating for something
        """
        while lock.acquire(False):
            my_deque.append("stop")
            dequed_value = my_deque.popleft()
            while dequed_value != "stop":
                logging.debug(f"dequed data is {dequed_value}")
                data = dequed_value['Data']
                target = data['target']
                text = data['text']
                logging.debug(f"reciver is {target}")
                # NOTE: must be in dict

                if target in self.clients:

                    logging.debug(f"using {target} is a valid key")
                    receiver_socket, lock = self.clients[target]
                    not_busy = lock.acquire()  # aquire socket for sending

                    if not_busy:
                        logging.debug("client no busy, sending msg")
                        sender_data = {'Action': 'INCOMING', 'Data': {
                            'source': client_name, 'text': text
                        }}
                        target_secret = self.secrets[target]
                        Server.send(
                            sender_data, receiver_socket, target_secret)
                        lock.release()  # release
                    else:
                        logging.debug("client busy, added to queue")
                        my_deque.append(dequed_value)
                else:
                    pass
                dequed_value = my_deque.popleft()
                sleep(0.05)

    def handle_signup(self, user_id: str, password: str) -> bool:
        """
            create a new user into the database
        """
        signup_result = False
        logging.debug("client signup called")
        if not self.database_manager.is_exist(user_id):
            logging.debug(f"the user {user_id} can be created")
            # if Server.strong_password(password):
            if True:  # NOTE: just to be able for fast testing
                logging.debug("the password is stronk")
                hashed, salt = hash_utility.generate_hash(password)
                self.database_manager.add_user(user_id, hashed, salt, status=1)
                signup_result = True
            else:
                logging.debug("the password is weak")
        else:
            logging.debug(f"the user {user_id} already exists")
        return signup_result

    def handle_login(self, user_id: str, password: str) -> bool:
        """
            handle login into the server, correct user_id and password
        """
        logging.debug("client login handle called")

        login_result = self.database_manager.login(user_id, password)
        return login_result

    def handle_exchange(self, client_data: dict, client: socket.socket):
        """
            handle rsa keys exchange with client
        """
        logging.debug("the server is doing exchange operation")
        clientPubKey = self.handshake(client_data, client)
        clientPubBox = PKCS1_OAEP.new(importKey(clientPubKey))
        return clientPubKey, clientPubBox

    @staticmethod
    def strong_password(password: str) -> bool:
        result = re.match(
            '((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,30})',
            password)
        return bool(result)

    def broadcast(self, data):  # FIXME: race condition
        """
            broadcast msg to all clients
        """
        [client.send(msgpack.dumps(data)) for client in self.clients]

    def add_client(self):
        """
            add new client connection to the server
        """
        while not self.exit:
            # NOTE: need to think about how the server will close itself
            client, addr = self.server_socket.accept()
            logging.debug("new connection have been established")
            client_thread = threading.Thread(
                target=self.client_handle, args=[client])
            client_thread.start()
            sleep(0.05)
        logging.debug("add_client is exiting")
        exit(0)

    def get_device_internal_ip(self):
        """
            get the internal ip and hostname for the server
        """
        host_name = socket.gethostname()
        return socket.gethostbyname(host_name + ".local")

    @staticmethod
    def send_header(data: bytes) -> bytes:
        header = str(len(data)).zfill(4)
        return msgpack.dumps(header)

    def receive_sigint(self, sig_num, frame):
        logging.debug("received sigint now closing server and socket")
        self.close_server()
        self.exit = True
        exit(0)

    @staticmethod
    def send(data: dict, client_socket: socket.socket, aeskey: bytes):
        data = AESCipher.encrypt_data_to_bytes(data, aeskey)
        header = Server.send_header(data)
        try:
            client_socket.send(header + data)
        except Exception as e:
            logging.debug(f"error in send {e}")


if __name__ == '__main__':
    logging.debug("starting server:")
    server = Server()
    server.run()
