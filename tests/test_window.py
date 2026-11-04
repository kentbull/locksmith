"""Main-window notifications use their real Qt close lifecycle."""

from locksmith.core.apping import LocksmithApplication
from locksmith.core.configing import LocksmithConfig
from locksmith.ui.window import LocksmithWindow


def test_new_notification_replaces_the_visible_toast(qapp, tmp_path):
    config = LocksmithConfig()
    config.base = str(tmp_path)
    window = LocksmithWindow(app=LocksmithApplication(config=config))
    window.show()

    window.show_notification_toast('2026-11-04T08:00:00Z', 'First notification', 1)
    first = window.current_toast

    # Closing the old toast synchronously clears the window's reference.
    window.show_notification_toast('2026-11-04T08:00:01Z', 'Second notification', 2)
    second = window.current_toast
    assert second is not first and first.isHidden()
    assert second.message_edit.toPlainText() == 'Second notification'
    assert second.isVisible() and second.dismiss_timer.isActive()

    # The replacement still follows the same ordinary close/cleanup path.
    second.close_toast()
    assert window.current_toast is None
