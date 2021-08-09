import sys
from PySide2.QtCore import Qt, QPropertyAnimation, QTimer
from PySide2.QtGui import QColor
from PySide2.QtWidgets import QApplication, QMainWindow
from main_ui import Ui_MainWindow
import threading
from functools import partial
from time import sleep
from client import Client


class MainWindow(QMainWindow, Ui_MainWindow):
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

        # my data NOTE: to do login click
        self.client_inner = Client()
        self.show()
        self.connected_to_server = False

    def user_search_key_event(self):
        """
            handle enter key event to search a user
        """
        

    def login_signup_to_server(self, btn, function):
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
                self.client_inner.secure_connection()
                self.connected_to_server = True
            except Exception as e:
                print("error while connecting to server")

        # trying to auth with password
        if self.connected_to_server:
            self.client_inner.set_username(username)
            if btn.text() == 'Login':
                result: bool = self.client_inner.login(password)
            elif btn.text() == 'Sign Up':
                result: bool = self.client_inner.sign_up(password)
            if result:  # if auth was affermtive
                function()
        btn.setStyleSheet(original_style)  # if the login, recolor logbtn

    def switch_to_page_2(self, function=False):
        # if function and function():
        self.stackedWidget.setCurrentWidget(self.page_2)
        print("switch 2")

    def switch_to_page_1(self):
        self.stackedWidget.setCurrentWidget(self.page_1)
        print("switch 1")


app = QApplication(sys.argv)
w = MainWindow()
app.exec_()
