# built in
import socket
import os.path
from time import sleep
import logging
import zlib
from queue import deque
import threading
from typing import List

# my own
from src.utilities import rsa_utility
from src.utilities import AESCipher
from src.utilities.config_utility import network_configuration_loader

# dependencies
import msgpack
import pyDH
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey.RSA import importKey

logging.basicConfig(level=logging.DEBUG)


# NOTE: to add port forwarding automation
# NOTE: to add 2 FA with email or etc
# NOTE: to check auth using server perment pem

class Client(object):
    def __init__(self, user_id: str = "DUMMY"):
        self.localhost: str = None
        self.port: int = None
        self.client_socket: socket.socket = None
        self.localhost, self.port = network_configuration_loader()
        self.port = int(self.port)
        self.user_id = user_id
        self.connected = False
        self.publicKey = None
        self.privateKey = None
        self.serverPublicKey = None
        self.directory = os.path.dirname(os.path.realpath(__file__))
        self.load_keys()
        self.decrypyor = PKCS1_OAEP.new(self.privateKey)
        self.encryptor = None
        self.__aes256key: bytes = ""
        self.__internal_deque = deque()
        self.__external_deque = deque()
        self.my_supported_actions = [""]
        self.run_recv_thread = False
        self.recv_thread_obj = self.recv_thread_obj = threading.Thread(
            target=self.recv_thread, args=[])
        self.rec_thread_exit = True
        self.run_sending_thread = False
        self.sending_thread_obj = threading.Thread(
            target=self.sending_thread, args=[])
        self.send_thread_exit = True  # forcefully close?

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
        self.connected = True

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
        self.client_socket.send(msgpack.dumps(data))
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
        data_to_send = msgpack.dumps(data_to_send)
        # logging.debug(self.decrypyor.decrypt(server_data))
        self.client_socket.send(
            self.encryptor.encrypt(data_to_send))

        logging.debug("end diffie hellman")
        logging.debug(self.decrypyor.decrypt(server_data))
        server_data = msgpack.loads(self.decrypyor.decrypt(server_data))
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
        self.send(data)
        response = self.client_socket.recv(1024)
        response = msgpack.loads(response)

        if response:
            logging.debug("initiating recv thread in client inner")
            self.run_recv_thread = True
            self.recv_thread_obj.start()
            self.run_sending_thread = True
            self.sending_thread_obj.start()
        return response

    def sign_up(self, password: str) -> bool:  # this not need thread
        """
            handle steps for account creation
        """
        data = {'Action': 'SIGN_UP', 'Data': {
            "user_id": self.user_id, "password": password}}
        self.send(data)
        answer = self.client_socket.recv(1024)
        if answer:
            self.login(password)
        return msgpack.loads(answer)

    def send(self, data: dict, none_blocking=False):
        """
            send data to server encrypted and with header of size
        """
        if none_blocking:
            self.__internal_deque.append(data)
        else:
            data = AESCipher.encrypt_data_to_bytes(data, self.__aes256key)
            header = Client.send_header(data)
            try:
                self.client_socket.send(header + data)
                logging.debug("sent data to server")
            except Exception as e:
                logging.debug(f"error in send {e}")

    def recv_thread(self):
        """
            thread that recives messages
        """
        self.rec_thread_exit = False  # NOTE: change to recv exit
        logging.debug("recv_thread called inner client")
        while self.run_recv_thread:
            sleep(0.05)
            try:
                logging.debug("block size recv call")
                data_size = self.client_socket.recv(5)
                if len(data_size) != 5:  # FIXME: if server crashed, wont close
                    continue
            except Exception as e:
                logging.debug(f"exception in recv thread {e}")
                continue
            data_size = int(msgpack.loads(data_size))
            data = self.client_socket.recv(data_size)
            logging.debug(f"recv thread got {data}")
            # NOTE: move to a separated thread? the decrypt and handling? nah
            data = AESCipher.decrypt_data_from_bytes(data, self.__aes256key)
            if data["Action"] not in self.my_supported_actions:
                ac = data["Action"]
                logging.debug(f"unsupported action {ac}")
                self.__external_deque.append(data)
            else:
                self.__internal_deque.append(data)
        self.rec_thread_exit = True
        logging.debug("exiting recv threading in client inner")
        exit(0)

    def sending_thread(self):
        """
            thread that sends messages
        """
        while self.run_sending_thread:
            sleep(0.05)
            if self.__internal_deque:
                data_to_send = self.__internal_deque.popleft()
                logging.debug("sending data")
                self.send(data_to_send, none_blocking=False)
                logging.debug("data sent")
        logging.debug("exiting sending thread")
        exit(0)

    def create_group(self, group_name: str, group_members: List[str],
                     group_admin: str = "me"):
        """
            send to the server task of creating a group,
        """
        if group_admin == "me":
            group_admin = self.user_id
        action_to_send = {'Action': 'CREATE_GROUP', 'Data': {
            "members": group_members,
            'admin': group_admin,
            'group_name': group_name
        }}
        self.send(action_to_send, none_blocking=True)

    def edit_group(self, group_name: str, group_members: List[str],
                   group_admin: str = "me"):
        """
            send to the server task of edit existing group
        """
        if group_admin == 'me':
            group_admin == self.user_id
        action_to_send = {'Action': "EDIT_GROUP", 'Data': {
            'members': group_members,
            'admin': group_admin,
            'origin_name': group_name
        }}
        self.send(action_to_send, none_blocking=True)

    def pass_message(self, target: str, message: str):
        """
            send to the server text to pass for
            both group and user
        """
        data = {'Action': 'PASS_TO', 'Data': {
            'target': target, 'text': message}}
        self.send(data, none_blocking=True)

    def add_member(self, member: str):
        """
            send to server request to add member
        """
        action_to_send = {'Action': "ADD_MEMBER", "Data": {"user_id":
                                                           member}}
        self.send(action_to_send, none_blocking=True)

    def is_online(self, user_id: str):
        """
            ask server for user id and return boolean
            of server answer
        """
        data = {'Action': 'SEARCH', 'Data': {'user_id': user_id}}
        self.send(data, none_blocking=True)

        # NOTE: this will be handled in the thread cuz its blocking
        """        answer = self.client_socket.recv(4096)
        logging.debug(f"asked server if {user_id} is online: {answer}")
        answer = AESCipher.decrypt_data_from_bytes(answer, self.__aes256key)
        return answer"""

    def group_search(self, group_name: str, member: str = "me"):
        """
            task the server with searching a group
            that contains the current user
        """
        if member == 'me':
            member = self.user_id
        action_to_send = {'Action': 'GROUP_SEARCH',
                          'Data': {'group_name': group_name,
                                   'member_id': member}}
        self.send(action_to_send, none_blocking=True)

    def set_username(self, username: str):
        # set the username if not logged into the server
        self.user_id = username

    def set_password(self, password: str):
        # set the password, not needed?
        pass

    def get_username(self) -> str:
        return self.user_id

    def handle_internal_queue(self):
        """
            action that the client socket need to handle
        """
        pass

    def get_external_queue_task(self):
        """
            actions that the gui need to handle
        """
        if self.__external_deque:
            return self.__external_deque.popleft()
        return None

    def get_existed_group_data(self, group_name: str):
        """ ask the server to get existing group data
            the server will answer only if the asking the the admin
        """
        request = {'Action': 'GROUP_INFO_REQUEST', 'Data': {
            'group_name': group_name}}
        self.send(request, none_blocking=True)

    def close(self):
        """
            close the connection
        """
        logging.debug("client inner close call")
        if self.connected:
            self.run_recv_thread = False
            self.run_sending_thread = False
            data = {'Action': 'EXIT'}
            self.send(data)
            while not self.rec_thread_exit:
                sleep(0.05)
            self.client_socket.close()

    @staticmethod
    def send_header(data: bytes) -> bytes:
        """
            return the msg size header
        """
        header = str(len(data)).zfill(4)
        return msgpack.dumps(header)


if __name__ == '__main__':
    a = Client("yoram")
    a.secure_connection()
    a.login("123")
    a.close()
    print("end")
