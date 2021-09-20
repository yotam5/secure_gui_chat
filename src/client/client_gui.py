import sys
# from PySide2.QtCore import QPropertyAnimation, QTimer
# from PySide2.QtGui import QColor
from PySide2.QtWidgets import QApplication, QMainWindow, QListView, QLineEdit
from PySide2.QtCore import QThreadPool, QRect, QSize
from main_ui import Ui_MainWindow
from functools import partial
from time import sleep
import logging
from client import Client
from workers import Worker
import bubble

logging.basicConfig(level=logging.DEBUG)

"""
    TODO:
        need to add group creator window switchted from
        the chat window
        needed functionality:
            1-creating a group
            2-adding users to the group
            3-removing user from the group
            4-rename the group
            5-delete the group
            6-making admin to the group

"""


class MainWindow(QMainWindow, Ui_MainWindow):
    """
        Client gui
    """

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.user_search_line.returnPressed.connect(self.user_search_key_event)

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
        self.connected_to_server = False
        self.talkingto = ""
        self.password_field.setEchoMode(QLineEdit.Password)
        # self.exit_safly = False
        self.thread_pool = QThreadPool()
        self.thread_funcs = [self.handle_external_queue]
        self.workers = []
        self.   external_queue_worker = Worker(self.handle_external_queue)
        self.external_queue_worker.signals.progress.connect(self.message_from)
        self.workers.append(self.external_queue_worker)
        # self.external_queue_worker.signals.progress.connect(self.message_from)
        self.running = True
        self.chat = QListView(self.page_2)
        self.chat.setObjectName("chat")
        self.chat.setGeometry(QRect(480, 20, 771, 581))
        self.chat.setMinimumSize(QSize(10, 10))
        self.chat.setStyleSheet(
            "border: 3px light green; \n"
            "                  background-color: rgba(0, 255, 255, 90);\n"
            "border-radius: 10px;"
        )
        self.chat.setResizeMode(QListView.Adjust)
        self.chat.setItemDelegate(bubble.MessageDelegate())
        self.model = bubble.MessageModel()
        self.chat.setModel(self.model)
        self.show()

    def comboBoxEvent(self, index):
        """
            handle the combobox events when clicked to select a user
        """
        selected = self.comboBox.currentText()
        if self.is_valid_conversation(selected):
            logging.debug(f"talking to {selected}")
            self.talkingto = selected
        else:
            logging.debug(f"unvalid, {selected}")

    def is_valid_conversation(self, user_id: str) -> bool:
        unvalid = [self.comboBox.placeholderText(
        ), self.client_inner.get_username()]
        logging.debug(f"unvalid {unvalid} param {user_id}")
        return user_id not in unvalid

    def user_search_key_event(self):
        """
            handle enter key event to search a user
        """
        searched_usr_id = self.user_search_line.text()
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
                return True
        return False

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
                for worker in self.workers:
                    self.thread_pool.start(worker)
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
        logging.debug(
            f"{self.client_inner.get_username()} sending to {user_id_receiver}")
        if self.is_valid_conversation(user_id_receiver):
            self.message_to(text)
            data = {'Action': 'PASS_TO', 'Data': {
                'target': user_id_receiver, 'text': text}}
            self.text_to_send.setText('')
            self.client_inner.send(data)

    def switch_to_page_2(self, function=False):
        # if function and function():
        # chat screen
        self.stackedWidget.setCurrentWidget(self.page_2)

    def switch_to_page_1(self):
        # login page
        self.stackedWidget.setCurrentWidget(self.page_1)

    def switch_to_page_3(self):
        # group creator/ appender screen?
        pass

    def handle_external_queue(self, progress_callback):
        logging.debug("handle external queue")
        while self.running:
            task = self.client_inner.get_external_queue_task()
            if task:
                task_data = task["Data"]
                if task["Action"] == "SEARCH":
                    logging.debug("search action finished")
                    if not self.add_to_combo_box(task_data["Result"]):
                        unvalid_user = self.user_search_line.text()
                        indication_msg = f"no user'{unvalid_user}'"
                        self.user_search_line.setText(indication_msg)

                elif task["Action"] == "INCOMING":
                    logging.debug("got message from someone")
                    logging.debug(task)
                    logging.debug(f"talking to {self.talkingto}")
                    if self.is_valid_conversation(task_data['source']):
                        progress_callback.emit(task_data["text"])
            sleep(0.05)
        logging.debug("exiting thread in client_gui")

    def closeEvent(self, event):
        event.accept()
        logging.debug("the ui is being closed")
        self.running = False
        try:
            self.client_inner.close()
        except Exception:
            pass

    def resizeEvent(self, e):
        self.model.layoutChanged.emit()

    def message_to(self, text: str):
        self.model.add_message(bubble.USER_ME, text)

    def message_from(self, text: str):
        self.model.add_message(bubble.USER_THEM, text)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = MainWindow()
    app.exec_()
