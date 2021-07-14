import sqlite3
import os.path
import logging
# TODO: FIX user_id to id and the insert of hash salt etc
# TODO: for bytes can do encode and decode

logging.basicConfig(level=logging.DEBUG)


class DataBaseUtility(object):
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

        data_for_insertion = \
            (f"'{user_id}', '{salt.decode()}','"
             f"{hashed_password.decode()}','{pubkey.decode()}',{status}")

        print(data_for_insertion)
        self.__cursor.execute(
            f"INSERT INTO users_data VALUES ({data_for_insertion})")
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

    def login(self, user_id, password) -> bool:
        """
            search user with corresponding values for login
        """
        user_data = is_exist(user_id)
        if user_data:
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
    test = DataBaseUtility()
    test.add_user("yotam", b'123', b'123', b'key_idk', 0)
    user_data = test.is_exist('yotam')
    print(user_data['salt'])
    print("end")
