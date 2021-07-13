import sqlite3
import os.path
import logging


class DataBaseUtility(object):
    """
    [
        class Utility that handles the server database
    ]
    """

    def __init__(self, filename=f'./database.db'):
        self.__conn = sqlite3.connect(filename, check_same_thread=False)
        self.__cursor = self.__conn.cursor()

    def addUser(self, user_id, password_hash, hash_salt, status=True):
        """
            add user to the database
        """
        if self.isExist(user_id):
            print(f"user with id {user_id} exists")
            return False
        self.__cursor.execute(
            f"INSERT INTO users VALUES ('{user_id}','{password}',{str(status)})")
        self.__conn.commit()
        print(f"added user {userid}")
        return True

    def removeUser(self, user_id):
        """
            remove user from database
        """
        if self.isExist(user_id):
            self.__cursor.execute(
                f"DELETE FROM users WHERE id LIKE '{user_id}'")
            self.__conn.commit()
            print(f"user {user_id} was deleted")
            return True
        print(f"cant delete user {user_id}, the user was not found")
        return False

    def isExist(self, user_id):
        """
            return the data of user_id, if user doesnt exist return None
        """
        result = self.__cursor.execute(
            f"SELECT id FROM users WHERE id LIKE '{user_id}'").fetchone()
        return result

    def login(self, user_id, password):
        """
            search user with corresponding values for login 
        """
        result = self.__cursor.execute(
            f"SELECT * FROM users WHERE id LIKE '{user_id}' AND password LIKE '{password}'")
        data = result.fetchone()
        return data

    def close(self):
        """
            close the server and commit changes i think?
        """
        self.__conn.execute("UPDATE users_data SET status = 0")
        self.__conn.commit()
        self.__conn.close()

    def get_all(self):  # DUMB?????!
        all_values = self.__cursor.execute("SELECT * FROM users")
        all_values = all_values.fetchall()
        return all_values

    def __del__():  # bruh what
        logging.debug("the database now is closing using __del__")
        self.close()


if __name__ == '__main__':
    test = DataBaseUtiliy()
    test.addUser('Support', '123')
    test.removeUser('123')
    print(test.login('Support', '123'))
    print(test.get_all())
