import logging
from PySide2.QtCore import (
    Slot,
    Signal,
    QObject,
    QRunnable,
)

logging.basicConfig(level=logging.DEBUG)

class WorkerKilledException(Exception):
    pass


class WorkerSignals(QObject):
    '''
    Defines the signals available from a running worker thread.

    Supported signals are:

    finished
        No data

    error
        tuple (exctype, value, traceback.format_exc() )

    result
        object data returned from processing, anything

    progress
        type it sends while thread runs

    '''

    finished = Signal()
    error = Signal(tuple)
    result = Signal(object)
    progress = Signal(object)


class Worker(QRunnable):
    '''
    Worker thread

    Inherits from QRunnable to handler worker thread setup, signals and wrapup.

    :param callback: The function callback to run on this worker thread.
                    Supplied args and kwargs will be passed through to the
                    runner.
    :type callback: function
    :param args: Arguments to pass to the callback function
    :param kwargs: Keywords to pass to the callback function

    '''

    def __init__(self, fn, *args, **kwargs):
        super(Worker, self).__init__()
        # Store constructor arguments (re-used for processing)
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()
        self.kwargs['progress_callback'] = self.signals.progress
        self.is_killed = False

    @Slot()
    def run(self):
        '''
        Initialise the runner function with passed args, kwargs.
        '''
        try:
            result = self.fn(*self.args, **self.kwargs)
        except TypeError:
            result = self.fn()
        try:
            self.signals.result.emit(result)  # Return the result of the processing
            self.signals.finished.emit()  # disconnected
        except RuntimeError:
            logging.debug("run time error")

    def kill(self):
        self.is_killed = True
