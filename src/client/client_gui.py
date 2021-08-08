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

        self.login_btn.clicked.connect(
            partial(self.clickEffect, self.login_btn,
                    partial(self.switch_to_page_2)))

        # my data NOTE: to do login click
        self.client_inner = None
        self.show()

    def clickEffect(self, btn, function, value=0):
        btn.setStyleSheet(""" border: 2px solid white;
        color: rgb(138, 226, 52);
        background-color: rgb(255, 255, 255,50);
        border-radius: 10px;
        """)
        self.repaint()
        # wait_till(value)

        sleep(0.2)
        # NOTE: if the password of username are empty need to handle
        # NOTE: if they are wrong need to handle with pop up, probably

        password = self.password_field.text()
        username = self.username_field.text()
        self.client_inner = Client(username=username)  # connect to server
        # trying to auth with password
        result = self.client_inner.login(password)
        if result:  # if auth was affermtive
            function()

    def login_task(self):
        pass

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
