import sys
# from PySide2.QtCore import QPropertyAnimation, QTimer
# from PySide2.QtGui import QColor
from PySide2.QtWidgets import QApplication, QMainWindow
from main_ui import Ui_MainWindow
import threading
from functools import partial
from time import sleep
from client import Client
import logging

logging.basicConfig(level=logging.DEBUG)

"""
    TODO:
        -need to add receving thread to client maybe use queue?
        -need when client receive add send_from in gui
"""


class MainWindow(QMainWindow, Ui_MainWindow):
    """
        Client gui
    """

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.lineEdit.returnPressed.connect(self.user_search_key_event)

        self.login_btn.clicked.connect(
            partial(self.login_signup_to_server, self.login_btn,
                    partial(self.switch_to_page_2)))

        self.sign_up_btn.clicked.connect(
            partial(self.login_signup_to_server, self.sign_up_btn,
                    partial(self.switch_to_page_2)))

        self.send_btn.clicked.connect(self.send_button)

        self.comboBox.view().pressed.connect(
            self.comboBoxEvent)

        self.client_inner = Client()
        self.show()
        self.connected_to_server = False
        self.talkingto = ""
        self.exit_safly = False
        self.client_thread_stop = False
        self.recv_queue_thread_obj = None

    def comboBoxEvent(self, index):
        """
            handle the combobox events when clicked to select a user
        """
        """AllItems = [self.comboBox.itemText(i) for i in range(self.comboBox.count())]
        print(AllItems)"""
        selected = self.comboBox.currentText()
        if self.valid_recv_selection(selected):
            logging.debug(f"talking to {selected}")
            self.talkingto = selected
        else:
            logging.debug(f"unvalid, {selected}")

    def valid_recv_selection(self, user_id: str) -> bool:
        unvalid = [self.comboBox.placeholderText(
        ), self.client_inner.get_username()]
        logging.debug(f"unvalid {unvalid} param {user_id}")
        return user_id not in unvalid

    def user_search_key_event(self):
        """
            handle enter key event to search a user
        """
        searched_usr_id = self.lineEdit.text()
        if searched_usr_id != self.client_inner.get_username():
            self.client_inner.is_online(searched_usr_id)

    def add_to_combo_box(self, item: str):
        """
            add item: str to the comboBox
            selection options
        """
        if item != '':
            AllItems = [self.comboBox.itemText(i) for i in
                        range(self.comboBox.count())]
            if item not in AllItems:
                self.comboBox.addItem(item)

    def login_signup_to_server(self, btn, function):
        """
            handle login and sign up buttons presses
        """
        original_style = btn.styleSheet()
        btn.setStyleSheet(""" border: 2px solid white;
        color: rgb(138, 226, 52);
        background-color: rgb(255, 255, 255,50);
        border-radius: 10px;
        """)
        self.repaint()

        sleep(0.2)
        # NOTE: if the password of username are empty need to handle
        # NOTE: if they are wrong need to handle with pop up, probably

        password = self.password_field.text()
        username = self.username_field.text()
        if not self.connected_to_server:
            try:
                logging.debug("creating connectin & thread")
                self.client_inner.secure_connection()
                self.connected_to_server = True
                self.recv_queue_thread_obj = threading.Thread(
                    target=self.handle_external_queue, args=[])
                self.recv_queue_thread_obj.start()
            except Exception as e:
                logging.debug(e)
                logging.debug("error while connecting to server")

        # trying to auth with password
        if self.connected_to_server:
            self.client_inner.set_username(username)
            if btn.text() == 'Login':
                result = self.client_inner.login(password)
            elif btn.text() == 'Sign Up':
                result = self.client_inner.sign_up(password)
            if result:  # if auth was affermtive
                function()
        btn.setStyleSheet(original_style)  # if the login, recolor logbtn

    def send_button(self):
        text = self.text_to_send.toPlainText()
        user_id_receiver = self.comboBox.currentText()
        logging.debug(f"{self.client_inner.get_username()} sending to {user_id_receiver}")
        if self.valid_recv_selection(user_id_receiver):
            self.message_to(text)
            data = {'Action': 'PASS_TO', 'Data': {
                'target': user_id_receiver, 'text': text}}
            self.client_inner.send(data)

    def switch_to_page_2(self, function=False):
        # if function and function():
        self.stackedWidget.setCurrentWidget(self.page_2)

    def switch_to_page_1(self):
        self.stackedWidget.setCurrentWidget(self.page_1)

    def handle_external_queue(self):
        logging.debug("handle external queue")
        while not self.client_thread_stop:
            task = self.client_inner.get_external_queue_task()
            if task:
                task_data = task["Data"]
                if task["Action"] == "SEARCH":
                    logging.debug("search action finished")
                    self.add_to_combo_box(task_data["Result"])

                elif task["Action"] == "INCOMING":
                    logging.debug("got message from someone")
                    logging.debug(task)
                    logging.debug(f"talking to {self.talkingto}")
                    if task_data["source"] != '':
                        self.message_from(task_data["text"])

        logging.debug("exiting thread in client_gui")
        self.exit_safly = True
        exit(0)

    def closeEvent(self, event):
        event.accept()
        logging.debug("the ui is being closed")
        self.client_thread_stop = True
        self.client_inner.close()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = MainWindow()
    app.exec_()
