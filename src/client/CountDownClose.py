#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Created on 2018年6月22日
@author: Irony
@site: https://pyqt.site , https://github.com/PyQt5
@email: 892768447@qq.com
@file: MessageBox
@description:
    make QMessageBox that can close itself with a timer 
"""

from PySide2.QtCore import QTimer
from PySide2.QtWidgets import QApplication, QMessageBox, QPushButton


class MessageBox(QMessageBox):

    def __init__(self, *args, count=10, time=1000, auto=True, **kwargs):
        super(MessageBox, self).__init__(*args, **kwargs)
        self._count = count
        self._time = time
        self._auto = auto  # Whether to close automatically
        assert count > 0  # Must be greater than 0
        assert time >= 500  # Must be >=500 milliseconds
        self.setStandardButtons(self.Close)  # Close button
        self.closeBtn = self.button(self.Close)  # Get the close button
        self.closeBtn.setText('(%s)' % count)
        self.closeBtn.setEnabled(True)
        self._timer = QTimer(self, timeout=self.doCountDown)
        self._timer.start(self._time)

    def doCountDown(self):
        self.closeBtn.setText('(%s)' % self._count)
        self._count -= 1
        if self._count <= 0:
            self.closeBtn.setText('关闭')
            self.closeBtn.setEnabled(True)
            self._timer.stop()
            if self._auto:  # Automatic shutdown
                self.accept()
                self.close()


if __name__ == '__main__':
    import sys

    app = QApplication(sys.argv)
    w = QPushButton('点击弹出对话框')
    w.resize(200, 200)
    w.show()
    w.clicked.connect(lambda: MessageBox(
        w, text='倒计时关闭对话框', auto=randrange(0, 2)).exec_())
    sys.exit(app.exec_())
