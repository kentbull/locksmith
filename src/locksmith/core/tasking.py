# -*- encoding: utf-8 -*-
"""
locksmith.core.tasking module

Module for running hio Doers with Qt integration
"""
from time import monotonic

from PySide6.QtCore import QTimer
from hio.base import tyming, doing
from keri import help

logger = help.ogler.getLogger(__name__)


class QtDoist(doing.Doist):
    """Let elapsed monotonic time own real scheduling; retain HIO cadence."""

    def enter(self, doers=None, *, temp=None):
        if not hasattr(self, '_clock_start'):
            # Anchor once; extending the running scheduler must not reset elapsed time.
            self._clock_start, self._tyme_start = monotonic(), self.tyme
        return super().enter(doers=doers, temp=temp)

    def _synchronize(self):
        self.tyme = max(self.tyme, self._tyme_start + monotonic() - self._clock_start)

    def recur(self, deeds=None):
        if self.real:
            self._synchronize()
        return super().recur(deeds=deeds)

    def tick(self, tock=None):
        if not self.real:
            return super().tick(tock=tock)
        # HIO recur calls tick after scheduling; do not add a second time source.
        self._synchronize()
        return self.tyme


class QtTask:
    def __init__(self, doist, timer, limit=None, tyme=None):
        """
        A task that allows scheduling a HIO Doist to run KERIpy Doers in Qt event loop.

        Parameters:
            doist (doing.Doist): the Doist to run
            timer (QTimer): the Qt timer to use for periodic execution
            limit (float): optional time limit for running
            tyme (float): optional starting time
        """
        self.doist = doist
        self.timer = timer
        self.shutdown_requested = False

        self.doist.done = False

        if limit is not None:  # time limit for running if any. useful in test
            self.doist.limit = abs(float(limit))

        if tyme is not None:  # re-initialize starting tyme
            self.doist.tyme = tyme

        self.tymer = tyming.Tymer(tymth=self.doist.tymen(), duration=self.doist.limit)

        # Enter context - initialize all doers
        self.doist.enter()
        self.doist.timer.start()

    def extend(self, doers: list):
        """Add doers to the running doist"""
        self.doist.extend(doers)

    def remove(self, doers: list):
        """Remove doers from the running doist"""
        self.doist.remove(doers)

    def run(self):
        """
        Called by QTimer.timeout signal - must not block!
        This method advances all doers by one tick.
        """
        if self.shutdown_requested:
            self.timer.stop()
            return

        try:
            self.doist.recur()  # increments .tyme runs recur context

            # No sleep() calls! QTimer handles timing.
            # The timer is already configured to fire at the correct interval.

            if not self.doist.deeds:  # no deeds remaining
                self.doist.done = True
                self.timer.stop()
                logger.info("QtTask: All deeds completed")

            if self.doist.limit and self.tymer.expired:  # reached time limit
                self.timer.stop()
                logger.info("QtTask: Time limit reached")

        except KeyboardInterrupt:
            logger.info("QtTask: Keyboard interrupt")
            self.timer.stop()

        except SystemExit:
            logger.info("QtTask: System exit")
            raise

        except Exception as e:
            logger.exception(f'QtTask exception: {e}')
            self.timer.stop()
            raise

    def shutdown(self):
        """Request graceful shutdown"""
        self.shutdown_requested = True
        logger.info("QtTask: Shutdown requested")

    def cleanup(self):
        """
        Called after timer stops to cleanup Doers.
        Must be called after shutdown to properly exit all doers.
        """
        try:
            if not self.doist.done:
                logger.info("QtTask: Cleaning up doers")
            self.doist.exit()
            logger.info("QtTask: Cleanup complete")
        except Exception as ex:
            logger.error(f'QtTask cleanup exception: {str(ex)}')
            raise


def run_qt_task(doers, expire=0.0, tock=0.03125):
    """
    Helper function to create and start a QtTask with a Doist.

    Parameters:
        doers (list): List of Doer instances to run
        expire (float): Time limit for running (0.0 means no limit)
        tock (float): Time interval between ticks in seconds

    Returns:
        QtTask: The running QtTask instance
    """
    logger.info(f'Running QtTask with {len(doers)} doers')
    doist = QtDoist(doers=doers, limit=expire, tock=tock, real=True)

    timer = QTimer()
    qtask = QtTask(doist=doist, timer=timer, limit=expire)

    timer.timeout.connect(qtask.run)
    timer.start(int(tock * 1000))  # Convert seconds to milliseconds

    logger.info('QtTask launched')

    return qtask
