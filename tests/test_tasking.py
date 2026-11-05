"""Qt callback delays must advance real HIO deadlines without catch-up cycles."""
from time import monotonic, sleep

from PySide6.QtCore import QTimer
from hio.base import doing

from locksmith.core.tasking import QtDoist, QtTask


class DeadlineDoer(doing.Doer):
    def enter(self, *, temp=None):
        self.deadline = self.tyme + .04
        self.calls = []

    def recur(self, tyme):
        self.calls.append((tyme, tyme >= self.deadline))
        return False


def test_delayed_qt_callback_uses_elapsed_time_once_and_expires_limit(qapp):
    doer = DeadlineDoer(tock=10)
    doist = QtDoist(doers=[doer], tock=.01, real=True)
    timer = QTimer()
    started = monotonic()
    task = QtTask(doist, timer, limit=.04, tyme=7)
    timer.timeout.connect(task.run)
    timer.start(10)
    try:
        sleep(.08)  # Qt coalesces missed timeout signals while the event loop is blocked.
        qapp.processEvents()
        assert len(doer.calls) == 1 and doer.calls[0][1]
        assert doist.tyme >= 7.06
        assert task.tymer.expired and not timer.isActive()
        assert doist.tock == .01
        for _ in range(20):
            task.run()
        assert len(doer.calls) == 1  # No fixed-tick drift or catch-up recurrence.
        assert doist.tyme <= 7 + monotonic() - started
    finally:
        timer.stop()
        task.cleanup()


def test_deterministic_qt_task_keeps_hio_fixed_ticks(qapp):
    doer = DeadlineDoer(tock=0)
    doist = QtDoist(doers=[doer], tyme=3, tock=.125, real=False)
    task = QtTask(doist, QTimer())
    try:
        task.run()
        task.run()
        assert doer.calls == [(3, False), (3.125, True)]
        assert doist.tyme == 3.25 and doist.tock == .125
    finally:
        task.cleanup()
