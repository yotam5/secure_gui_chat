import sqlite3
import os.path
import logging
from src.utilities import hash_utility

# TODO: FIX user_id to id and the insert of hash salt etc
# TODO: for bytes can do encode and decode

logging.basicConfig(level=logging.DEBUG)


class DataBaseManager(object):
    """
        class Utility that handles the server database
    """

    def __init__(self, filename=f'./database.db'):
        self.__conn = sqlite3.connect(filename, check_same_thread=False)
        self.__cursor = self.__conn.cursor()
        self.__cursor.row_factory = sqlite3.Row  # to be able to retrive a dict

    def add_user(self, user_id: str, hashed_password: bytes,
                 salt: bytes, pubkey=b'', status=0):
        """
            add user to the database
        """
        if self.is_exist(user_id):
            logging.debug(f"user with id {user_id} exists")
            return False

        binSalt = sqlite3.Binary(salt)
        binHash = sqlite3.Binary(hashed_password)
        binPubKey = sqlite3.Binary(pubkey)

        template = """INSERT INTO users_data
                          (id, salt, hashed, public_key, online) 
                          VALUES (?, ?, ?, ?, ?);"""
        data_tuple = (user_id, binSalt, binHash, binPubKey, 1)
        self.__cursor.execute(template, data_tuple)
        self.__conn.commit()
        logging.debug(f"added user {user_id}")
        return True

    def remove_user(self, user_id):
        """
            remove user from database
        """
        if self.is_exist(user_id):
            self.__cursor.execute(
                f"DELETE FROM users_data WHERE id LIKE '{user_id}'")
            self.__conn.commit()
            logging.debug(f"user {user_id} was deleted")
            return True
        logging.debug(f"cant delete user {user_id}, the user was not found")
        return False

    def is_exist(self, user_id, selection="*"):
        """
            return the data of user_id, if user doesnt exist return None
        """
        result = self.__cursor.execute(
            f"SELECT {selection} FROM users_data WHERE id LIKE '{user_id}'")
        return result.fetchone()

    def login(self, user_id: str, password: str) -> bool:
        """
            search user with corresponding values for login
        """
        decode_keys = ["salt", "hashed"]

        user_data = self.is_exist(user_id)
        if user_data:
            user_data = dict(user_data)
            print(user_data)
            for i in user_data:
                print(type(i))
            hashed_password = user_data["hashed"]
            salt = user_data['salt']
            print(hashed_password)
            print(salt)
            if hash_utility.hash_verify(hashed_password, salt, password):
                logging.debug(f"user_id {user_id} logged to the server")
                return True
        return False

    def close(self):
        """
            close the server and commit changes i think?
        """
        self.__conn.execute("UPDATE users_data SET online = 0")
        self.__conn.commit()
        logging.debug("the DataBaseUtility is being closed")

    def __del__(self):  # bruh what
        logging.debug("the database now is closing using __del__")
        self.close()

    def _del_(self):
        logging.debug("the database now is closing using __del__")
        self.close()


if __name__ == '__main__':
    print("aa")
    test = DataBaseManager()
    test.remove_user("yoram")
    hashed, salt = hash_utility.generate_hash('123')
    print(hashed)
    print('*'*120)
    print(salt)
    test.add_user("yoram", hashed, salt, b'key_idk', 0)
    test.login('yoram', '123')
