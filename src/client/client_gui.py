import sys
# from PySide2.QtCore import QPropertyAnimation, QTimer
# from PySide2.QtGui import QColor
from PySide2.QtWidgets import (QApplication,
                               QMainWindow,
                               QListView,
                               QLineEdit,
                               QListWidgetItem)
from PySide2.QtCore import QThreadPool, QRect, QSize
from main_ui import Ui_MainWindow
from functools import partial
from time import sleep
import logging
from typing import List

# mine
from client import Client
from workers import Worker
import bubble
logging.basicConfig(level=logging.DEBUG)

"""
    TODO:
        --in the client make "send" non blocking?
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
        self.user_search_line.returnPressed.connect(self.user_search_event)
        self.group_search_line.returnPressed.connect(self.group_search_event)
        self.login_btn.clicked.connect(
            partial(self.login_signup_to_server, self.login_btn,
                    partial(self.switch_to_page_2)))

        self.sign_up_btn.clicked.connect(
            partial(self.login_signup_to_server, self.sign_up_btn,
                    partial(self.switch_to_page_2)))

        self.send_btn.clicked.connect(self.send_button)

        self.comboBox.currentTextChanged.connect(self.comboBoxEvent)

        self.group_editor_btn.clicked.connect(self.switch_to_page_3)

        self.create_group_btn.clicked.connect(
            self.show_group_creator_stack)

        self.group_add_member_line.returnPressed.connect(self.add_member)

        self.apply_group_editor_btn.clicked.connect(self.apply_group_action)

        self.group_remove_member_line.returnPressed.connect(self.remove_member)

        self.exit_group_editor_btn.clicked.connect(self.reset_page_3)
        # NOTE: reset all the group ui to default

        self.client_inner = Client()
        self.connected_to_server = False
        self.talkingto = ""
        self.password_field.setEchoMode(QLineEdit.Password)
        # self.exit_safly = False
        self.thread_pool = QThreadPool()
        self.thread_funcs = [self.handle_external_queue]
        self.workers = []
        self.external_queue_worker = Worker(self.handle_external_queue)
        self.external_queue_worker.signals.progress.connect(self.message_from)
        self.workers.append(self.external_queue_worker)
        # self.external_queue_worker.signals.progress.connect(self.message_from)
        self.running = True
        self.valid_conversation = False
        self.safe_external_queue_exit = False

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

    def comboBoxEvent(self, item: str):
        """
            handle the combobox events when clicked to select a user
        """
        logging.debug(f"combo event is {item}")
        if self.is_valid_conversation(item):
            logging.debug("valid conversation")
            logging.debug(f"talking to {item}")
            self.talkingto = item
            self.valid_conversation = True
            self.model.clear()
        else:
            logging.debug(f"unvalid, {item}")
            self.valid_conversation = False

    def reset_page_3(self):
        """
            reset page 3 to default values, so after Exit
            the changes wont be saved
        """
        objs_to_reset = [self.group_remove_member_line,
                         self.group_name_line, self.group_add_member_line]
        [obj.clear() for obj in objs_to_reset]
        self.members_list.clear()
        self.switch_to_page_2()

    def is_valid_conversation(self, user_id: str) -> bool:
        """ check if the conversation is valid one """
        unvalid = [self.comboBox.placeholderText(
        ), self.client_inner.get_username()]
        logging.debug(f"unvalid {unvalid} param {user_id}")
        return user_id not in unvalid

    def user_search_event(self):
        """
            handle enter key event to search a user
        """
        searched_usr_id = self.user_search_line.text()

        if searched_usr_id != self.client_inner.get_username() and \
                not searched_usr_id.isspace():
            self.client_inner.is_online(searched_usr_id)

    def group_search_event(self):
        """
            handle enter key event to earch a group
        """
        searched_group_name = self.group_search_line.text()
        if not searched_group_name.isspace() and \
           searched_group_name != self.client_inner.get_username():
            self.client_inner.group_search(searched_group_name)

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
        # self.repaint()

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
        if True:  # self.connected_to_server:
            self.client_inner.set_username(username)
            if btn.text() == 'Login':
                result = self.client_inner.login(password)
            elif btn.text() == 'Sign Up':
                result = self.client_inner.sign_up(password)
            if result:
                function()
        btn.setStyleSheet(original_style)  # if the login, recolor logbtn

    def send_button(self):
        """ handle send button event """
        text = self.text_to_send.toPlainText()
        reciver_id = self.comboBox.currentText()
        logging.debug(
            f"{self.client_inner.get_username()} to {reciver_id}")
        if self.valid_conversation:
            self.message_to(text)
            self.text_to_send.setText('')
            self.client_inner.pass_message(reciver_id, text)

    def switch_to_page_2(self):
        """ switch to chat page """
        self.stackedWidget.setCurrentWidget(self.page_2)

    def switch_to_page_1(self):
        """ switch to login page """
        self.stackedWidget.setCurrentWidget(self.page_1)

    def switch_to_page_3(self):
        """ switch to group editor page """
        self.stackedWidget.setCurrentWidget(self.page_3)
        self.group_common_stack.setCurrentWidget(self.group_common_empty)
        self.group_action_stack.setCurrentWidget(self.select_group_action)

    def show_group_creator_stack(self):
        """ change page 3 stacks for group creating """
        self.group_action_stack.setCurrentWidget(self.empty_group_selection)
        self.repaint()
        sleep(0.2)
        self.group_common_stack.setCurrentWidget(self.group_common)

    def handle_external_queue(self, progress_callback):
        """
            handle tasks from the inner client
        """
        logging.debug("handle external queue")
        while self.running:
            sleep(0.05)
            task = self.client_inner.get_external_queue_task()
            if task:
                action = task['Action']
                task_data = task["Data"]
                # NOTE: user_id must differ from a group?
                if action == "GROUP_SEARCH":
                    logging.debug("group search action is finished")
                    have_permission = task_data['have_permission']
                    logging.debug(f"group perm data {have_permission}")
                    if have_permission:
                        logging.debug("adding group to list")
                        self.add_to_combo_box(task_data['group_name'])
                    else:
                        indication_msg = f"no assosiated group \
                            named {have_permission}"
                        self.group_search_line.setText(indication_msg)

                elif action == "SEARCH":
                    logging.debug("user search action finished")
                    logging.debug(f"usr search data {task_data}")
                    if not self.add_to_combo_box(task_data["user_exist"]):
                        unvalid_search = task_data['user_exist']
                        indication_msg = f"no user nor group named' \
                                {unvalid_search}'"
                        self.user_search_line.setText(indication_msg)

                elif action == "INCOMING":
                    logging.debug("got message from someone")
                    logging.debug(task)
                    logging.debug(f"talking to {self.talkingto}, got from ")
                    logging.debug(task)
                    if self.talkingto == task_data['source']:
                        progress_callback.emit(task_data["text"])

                elif action == 'ADD_MEMBER':
                    logging.debug(task)
                    if task_data['user_exist']:
                        member = task_data['user_id']
                        self.members_list.addItem(member)

        logging.debug("exiting thread in client_gui")
        self.safe_external_queue_exit = True
        exit(0)

    def closeEvent(self, event):
        """
            close the application when exit clicked
        """
        event.accept()
        logging.debug("the ui is being closed")
        self.running = False
        try:
            self.client_inner.close()
        except Exception:
            pass
        logging.debug("inner client closed")
        while not self.safe_external_queue_exit:
            sleep(0.05)
            continue
        logging.debug("ui closed")

    def resizeEvent(self, e):
        """
            window resize?
        """
        self.model.layoutChanged.emit()

    def add_member(self):
        """
            ask the server if member can be added(if exist)
        """
        # NOTE: make in outside of function, adding each time. O(n) + O(1)?
        current_members = self.get_group_members_list()
        member_to_add = self.group_add_member_line.text()
        can_be_added = True
        my_id = self.client_inner.get_username()
        for member in current_members:
            if member_to_add in (member.text(), my_id):
                can_be_added = False
                break
        if can_be_added:
            self.client_inner.add_member(member_to_add)

    def remove_member(self):
        # NOTE: move to thread the actions?
        """
            remove member from the list
        """
        member_to_remove = self.group_remove_member_line.text()
        # member_removed = False
        for member in self.get_group_members_list():
            if member.text() == member_to_remove:
                self.members_list.takeItem(self.members_list.row(member))
                # member_removed = True
                break
        # NOTE: if member_removed false pop up of user not found

    def apply_group_action(self):
        """
            apply the group changes to the server
        """
        valid_action = True
        group_name = self.group_name_line.text()
        group_members = self.get_group_members_list()
        group_members = [member.text() for member in group_members]
        if group_name == '':
            valid_action = False

        if valid_action:
            self.client_inner.create_group(group_name, group_members,
                                           group_admin="me")

    def get_group_members_list(self) -> List[QListWidgetItem]:
        """ return a list of the group members as widget items"""
        current_members = [self.members_list.item(x)
                           for x in range(self.members_list.count())]
        return current_members

    def message_to(self, text: str):
        """
            display str as msg to someone
        """
        self.model.add_message(bubble.USER_ME, text)

    def message_from(self, text: str):
        """
            display str as msg from someone
        """
        self.model.add_message(bubble.USER_THEM, text)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = MainWindow()
    sys.exit(app.exec_())
