import sys
from PySide2.QtCore import Qt, QPropertyAnimation, QTimer
from PySide2.QtGui import QColor
from PySide2.QtWidgets import QApplication, QMainWindow
from main_ui import Ui_MainWindow
import threading
from functools import partial
from time import sleep
from client import Client

"""
    TODO:
        handle the chat and send according to the combobox selction
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
        # self.send_btn
        self.comboBox.view().pressed.connect(
            self.comboBoxEvent)

        self.client_inner = Client()
        self.show()
        self.connected_to_server = False
        self.talkingto: str = ""

    def comboBoxEvent(self, index):
        """
            handle the combobox events when clicked to select a user
        """
        selected = self.comboBox.currentText()
        unvalid = [self.comboBox.placeholderText(), self.client_inner.get_username()]
        if selected not in unvalid:
            self.talkingto = selected
    
    
    def user_search_key_event(self):
        """
            handle enter key event to search a user
        """
        searched_usr_id = self.lineEdit.text()
        if searched_usr_id != self.client_inner.get_username():
            online = self.client_inner.is_online(searched_usr_id)
            if online:
                AllItems = [self.comboBox.itemText(i) for i in
                            range(self.comboBox.count())]
                if searched_usr_id not in AllItems:
                    self.comboBox.addItem(searched_usr_id)

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
