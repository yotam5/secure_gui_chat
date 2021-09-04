# -*- coding: utf-8 -*-

################################################################################
# Form generated from reading UI file 'chat_gui3.ui'
##
# Created by: Qt User Interface Compiler version 5.15.2
##
# WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *
import bubble
import pictures


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1280, 706)
        MainWindow.setMinimumSize(QSize(10, 10))
        MainWindow.setMaximumSize(QSize(1280, 720))
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.centralwidget.setMinimumSize(QSize(10, 10))
        self.centralwidget.setMaximumSize(QSize(1280, 720))
        self.centralwidget.setAutoFillBackground(False)
        self.stackedWidget = QStackedWidget(self.centralwidget)
        self.stackedWidget.setObjectName("stackedWidget")
        self.stackedWidget.setGeometry(QRect(0, 0, 1280, 731))
        self.stackedWidget.setMinimumSize(QSize(10, 10))
        self.stackedWidget.setMaximumSize(QSize(8000, 8000))
        self.page_1 = QWidget()
        self.page_1.setObjectName("page_1")
        self.page_1.setMinimumSize(QSize(1280, 720))
        self.page_1.setMaximumSize(QSize(1280, 720))
        self.label = QLabel(self.page_1)
        self.label.setObjectName("label")
        self.label.setGeometry(QRect(0, -1, 1280, 711))
        self.label.setMinimumSize(QSize(10, 10))
        self.label.setMaximumSize(QSize(8000, 8000))
        self.label.setPixmap(QPixmap(":/newPrefix/static/login_picture.jpg"))
        self.label.setScaledContents(True)
        self.username_field = QLineEdit(self.page_1)
        self.username_field.setObjectName("username_field")
        self.username_field.setGeometry(QRect(210, 440, 351, 51))
        self.username_field.setStyleSheet(
            " border: 2px solid white;\n" " border-radius: 10px;"
        )
        self.password_field = QLineEdit(self.page_1)
        self.password_field.setObjectName("password_field")
        self.password_field.setGeometry(QRect(690, 440, 351, 51))
        self.password_field.setStyleSheet(
            " border: 2px solid white;\n" " border-radius: 10px;"
        )
        self.login_btn = QPushButton(self.page_1)
        self.login_btn.setObjectName("login_btn")
        self.login_btn.setGeometry(QRect(370, 560, 191, 61))
        self.login_btn.setStyleSheet(
            " border: 2px solid white;\n"
            "color: rgb(138, 226, 52);\n"
            "background-color: rgb(255, 255, 255,12);\n"
            " border-radius: 10px;"
        )
        self.login_btn.setAutoDefault(False)
        self.sign_up_btn = QPushButton(self.page_1)
        self.sign_up_btn.setObjectName("sign_up_btn")
        self.sign_up_btn.setGeometry(QRect(680, 560, 191, 61))
        self.sign_up_btn.setStyleSheet(
            " border: 2px solid white;\n"
            "color: rgb(138, 226, 52);\n"
            "background-color: rgb(255, 255, 255,12);\n"
            "\n"
            " border-radius: 10px;"
        )
        self.stackedWidget.addWidget(self.page_1)
        self.label.raise_()
        self.sign_up_btn.raise_()
        self.password_field.raise_()
        self.username_field.raise_()
        self.login_btn.raise_()
        self.page_2 = QWidget()
        self.page_2.setObjectName("page_2")
        self.label_2 = QLabel(self.page_2)
        self.label_2.setObjectName("label_2")
        self.label_2.setEnabled(True)
        self.label_2.setGeometry(QRect(0, -10, 1280, 720))
        self.label_2.setMinimumSize(QSize(1280, 720))
        self.label_2.setMaximumSize(QSize(1280, 720))
        self.label_2.setStyleSheet("")
        self.label_2.setPixmap(
            QPixmap(":/newPrefix/static/msg_background.jpg"))
        self.label_2.setScaledContents(True)
        self.label_2.setTextInteractionFlags(Qt.NoTextInteraction)
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

        # self.chat.setReadOnly(True)
        self.text_to_send = QTextEdit(self.page_2)
        self.text_to_send.setObjectName("text_to_send")
        self.text_to_send.setGeometry(QRect(480, 620, 591, 61))
        self.text_to_send.setMinimumSize(QSize(10, 10))
        self.text_to_send.setStyleSheet(
            "border: 3px light green; \n"
            "                  background-color: rgba(0, 255, 255, 90);\n"
            "border-radius: 10px;"
        )
        self.send_btn = QPushButton(self.page_2)
        self.send_btn.setObjectName("send_btn")
        self.send_btn.setGeometry(QRect(1080, 620, 171, 61))
        self.send_btn.setStyleSheet(
            " border: 2px solid white;\n"
            "color: rgb(7,11,55);\n"
            " border-radius: 10px;"
        )
        self.lineEdit = QLineEdit(self.page_2)
        self.lineEdit.setObjectName("lineEdit")
        self.lineEdit.setGeometry(QRect(130, 140, 241, 51))
        self.lineEdit.setStyleSheet(
            "border: 3px light green; \n"
            "                  background-color: rgba(0, 255, 255, 90);\n"
            "border-radius: 10px;"
        )
        self.comboBox = QComboBox(self.page_2)
        self.comboBox.addItem("")
        self.comboBox.setObjectName("comboBox")
        self.comboBox.setGeometry(QRect(130, 30, 251, 51))
        self.comboBox.setStyleSheet(
            "border: 3px light green; \n"
            "color: rgb(85, 87, 83);\n"
            "                  background-color: rgba(0, 255, 255, 90);\n"
            "border-radius: 10px;"
        )
        self.stackedWidget.addWidget(self.page_2)
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)

        self.login_btn.setDefault(False)

        QMetaObject.connectSlotsByName(MainWindow)

    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(
            QCoreApplication.translate("MainWindow", "MainWindow", None)
        )
        self.label.setText("")
        self.username_field.setPlaceholderText(
            QCoreApplication.translate("MainWindow", "enter username:", None)
        )
        self.password_field.setEchoMode(QLineEdit.Password)
        self.password_field.setPlaceholderText(
            QCoreApplication.translate("MainWindow", "enter password:", None)
        )
        self.login_btn.setText(
            QCoreApplication.translate("MainWindow", "Login", None))
        self.sign_up_btn.setText(
            QCoreApplication.translate("MainWindow", "Sign Up", None)
        )
        self.label_2.setText("")
        """self.chat.setHtml(
            QCoreApplication.translate(
                "MainWindow",
                '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">\n'
                '<html><head><meta name="qrichtext" content="1" /><style type="text/css">\n'
                "p, li { white-space: pre-wrap; }\n"
                "</style></head><body style=\" font-family:'Apercu Mono'; font-size:11pt; font-weight:400; font-style:normal;\">\n"
                '<p style="-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><br /></p></body></html>',
                None,
            )
        )"""
        self.text_to_send.setHtml(
            QCoreApplication.translate(
                "MainWindow",
                '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">\n'
                '<html><head><meta name="qrichtext" content="1" /><style type="text/css">\n'
                "p, li { white-space: pre-wrap; }\n"
                "</style></head><body style=\" font-family:'Apercu Mono'; font-size:11pt; font-weight:400; font-style:normal;\">\n"
                '<p style="-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;"><br /></p></body></html>',
                None,
            )
        )
        self.send_btn.setText(
            QCoreApplication.translate("MainWindow", "Send", None))
        self.lineEdit.setPlaceholderText(
            QCoreApplication.translate("MainWindow", "search user:", None)
        )

        self.comboBox.setPlaceholderText("select chat: ")
        deafult_combo = self.comboBox.placeholderText()
        self.comboBox.setItemText(
            0, QCoreApplication.translate("MainWindow", deafult_combo, None)
        )

    # retranslateUi

    def resizeEvent(self, e):
        self.model.layoutChanged.emit()

    def message_to(self, text: str):
        self.model.add_message(bubble.USER_ME, text)

    def message_from(self, text: str):
        self.model.add_message(bubble.USER_THEM, text)
