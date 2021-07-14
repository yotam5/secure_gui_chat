import socket
import threading
import msgpack
import logging
import os.path
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey.RSA import importKey
from sys import exit, getsizeof
from src.utilities import rsa_utility
from src.utilities import hash_utility
from src.utilities.config_utility import network_configuration_loader
from src.utilities.DataBaseUtility import DataBaseUtility


"""
    TODO:
    1-use gmail or telegram for 2fa oauth with one time password 
    2-use rsa for AES256 key exchange
    3-use bcypt instead of sha512
    4-using pysrp
    5-the signature the data to prevent man in the middle,
      to know ur talking with the real client
"""
logging.basicConfig(level=logging.DEBUG)
# note when works remember to use the device ip and not ip in conf


class Server(object):
    def __init__(self):
        self.localhost, self.port = network_configuration_loader()
        self.clients = []
        self.publicKey = None
        self.privateKey = None
        self.directory = os.path.dirname(os.path.realpath(__file__))
        self.database_manager = DataBaseUtility(
            f"{self.directory}/database.db")
        # idea, create a dict with usernames for msg

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
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((str(self.localhost), int(self.port)))
        self.server_socket.listen()

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
            idk
        """
        # broadcast exit?
        self.server_socket.close()

    def hand_shake(self, client_data: dict, client) -> bytes:
        """
            rsa hand
        """
        client_pubKey = client_data['PubKey']
        client_pubKey = rsa_utility.rsaKeyFromBase64String(
            client_pubKey)
        # logging.debug(f"client pub key {client_pubKey}")
        data = rsa_utility.rsaKeyToBase64String(self.publicKey.exportKey())
        client.send(msgpack.packb(data))
        return client_pubKey

    def client_handle(self, client):
        """
            handle the client data and stuff?
        """
        serve_client = True
        myBox = PKCS1_OAEP.new(self.privateKey)  # use thread lock instead?
        clientPubBox = None
        exchanged = False

        while serve_client:
            data = client.recv(4096)
            if data in ['', b'']:  # client disconnected
                serve_client = False
            else:
                logging.debug(f"client data size is {getsizeof(data)}")
                if clientPubBox:
                    logging.debug(
                        "the client encrypted data is being decrypted")
                    # FIXME: this is not private key erro raise
                    client_data = msgpack.loads(myBox.decrypt(data))
                else:
                    client_data = msgpack.loads(data)

                logging.debug(data)
                logging.debug("handling data result")

                data_dict_keys = data.keys()
                if 'Action' in data_dict_keys:
                    client_action = data['Action']
                    if exchanged:  # if the chat is being encrypted y'know
                        if client_action in ['LOGIN', 'SIGN_UP']:
                            login_info = client_data['Data']
                            if client_action == 'SIGN_UP':
                                generated_salted_hash = hash_utility.generate_hash(
                                    client_info['password'],)
                                self.database_manager.add_user()
                            self.database_manager.login(
                                login_info['user_id'], login_info['password'])

                    else:
                        if client_action == 'EXCHANGE':
                            clientPubKey, clientPubBox = self.handle_exchange()
                            exchanged = True
        logging.debug(f"client disconnected")

        exit(0)  # terminate thread

        def handle_signup(user_id, password):
            """
                create a new user into the database
            """
            logging.debug("client signup called")
            if not self.database_manager.is_exist(user_id):
                logging.debug(f"the user {user_id} can be created")\

                self.database_manager.add_user(user_id, key, salt)
            logging.debug(f"the user {user_id} already exists")

        def handle_login(self):
            """
                handle login into the server, correct user_id and password
            """
            logging.debug("client login handle called")
            pass

    def handle_exchange(self):
        """
            handle rsa keys exchange with client
        """
        logging.debug("the server is doing exchange operation")
        clientPubKey = self.hand_shake(data, client)
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
        while not self.exit:  # NOTE: need to think about how the server will close itself
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


if __name__ == '__main__':
    logging.debug("starting server:")
    server = Server()
    server.run()
