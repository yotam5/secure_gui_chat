import sys
from PySide2.QtCore import Qt, QPropertyAnimation, QTimer
from PySide2.QtGui import QColor
from PySide2.QtWidgets import QApplication, QMainWindow
from main_ui import Ui_MainWindow
import threading
from functools import partial
from Client import Client
from src.utilities.config_utility import network_configuration_loader


class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        self.login_btn.clicked.connect(
            partial(self.clickEffect, self.login_btn,
                    partial(self.switch_to_page_2)))

        # my data
        host, port = network_configuration_loader()
        # self.client_inner = Client('Support', host, port)
        self.show()

    def clickEffect(self, btn, function, value=0):
        btn.setStyleSheet(""" border: 2px solid white;
        color: rgb(138, 226, 52);
        background-color: rgb(255, 255, 255,50);
        border-radius: 10px;
        """)
        self.repaint()  # DAMN BOI
        # wait_till(value)
        # if self.client_inner.login('123'):
        #    function()
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
