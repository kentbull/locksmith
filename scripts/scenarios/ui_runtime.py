"""Run real Qt disclosure controls against the ordinary live vault and services.

Test-only UI automation. Admission and negotiated responses go through visible
buttons and selectors; protocol construction remains inside the actual dialogs.
Other operator commands retain the normal driver and are not labeled UI coverage.
"""
from dataclasses import asdict
import json
import os
from pathlib import Path
from time import monotonic

from PySide6.QtCore import Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QFileDialog, QPushButton, QLineEdit
from keri.peer import exchanging
from locksmith.driver import runtime
from locksmith.ui.window import LocksmithWindow
from locksmith.ui.navigation import Pages
from locksmith.ui.vault.menu import MenuButton

ordinary = runtime.execute


def select(combo, value):
    """Choose an existing item with keyboard events, never insert test-only options."""
    if combo.currentData() == value:
        return
    index = combo.findData(value)
    if index < 0:
        raise ValueError(f'UI does not offer the requested selection: {value}')
    combo.setFocus()
    QTest.keyClick(combo, Qt.Key.Key_Home)
    for _ in range(index):
        QTest.keyClick(combo, Qt.Key.Key_Down)
    assert combo.currentData() == value


def click(button, dialog=None):
    """Activate a visible enabled control using its ordinary keyboard path."""
    if dialog is not None:
        dialog.scroll_area.ensureWidgetVisible(button)
    if not button.isEnabled():
        raise ValueError('Requested UI control is disabled')
    button.setFocus()
    QTest.keyClick(button, Qt.Key.Key_Space)


def capture(widget, folder, name):
    """Save public rendered UI evidence, never secret-management panels."""
    folder.mkdir(parents=True, exist_ok=True)
    if not widget.grab().save(str(folder / (name + '.png'))):
        raise ValueError('Could not capture UI evidence')


def opening_file(dialog, path):
    """Type a public opening path into the active Qt file picker cooperatively."""
    deadline = monotonic() + 30

    def choose():
        """Find the active picker, avoiding dialogs retained from earlier actions."""
        picker = QApplication.activeModalWidget()
        if isinstance(picker, QFileDialog) and picker.isVisible():
            filename = picker.findChild(QLineEdit, 'fileNameEdit')
            if filename is not None:
                filename.setFocus()
                QTest.keyClick(filename, Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)
                QTest.keyClicks(filename, str(path))
                capture(picker, path.parent, 'picker-' + path.stem)
                QTest.keyClick(filename, Qt.Key.Key_Return)
                return
        if monotonic() < deadline:
            QTimer.singleShot(20, choose)

    QTimer.singleShot(20, choose)
    # Invoke modal UI only after the cooperative driver has yielded its step.
    QTimer.singleShot(0, lambda: click(dialog.disclosure.choose, dialog))


def execute(app, request):
    """Drive supported user controls and independently observe retained delivery.

    app is the actual running application; request is the same explicit local
    scenario command. This function never calls IPEX constructors or writes
    acceptance/custody rows. Its deadline bounds UI waits and existing retries.
    """
    op, prior = request.get('op'), request.get('prior')
    supported = op in ('admit', 'issue') or (prior and op in ('offer', 'grant', 'agree'))
    if not supported and op != 'inventory':
        return (yield from ordinary(app, request))
    vault = app.vault
    if op == 'issue':
        # An address-book label is local bootstrap metadata, not KEL acceptance.
        if request['recipient'] not in vault.hby.kevers:
            raise ValueError('UI recipient requires a verified KEL')
        vault.org.update(request['recipient'], {'alias': 'Scenario holder'})
    folder = Path(os.environ['RUN_DIR']) / 'ui' / app.hab.name
    if not hasattr(app, '_scenario_window'):
        window = app._scenario_window = LocksmithWindow(app=app)
        window.show()
        window.nav_manager.navigate_to(Pages.VAULT, vault_name=app.name)
    window = app._scenario_window
    parent = window.pages[Pages.VAULT]
    menu = parent.nav_menu
    credentials = next(button for button in menu.findChildren(MenuButton)
                       if button.label_text == 'Credentials')
    if credentials.isVisible():
        click(credentials)
    target = {'inventory': 'Received Credentials', 'issue': 'Issued Credentials'}.get(op, 'Activity')
    click(next(button for button in menu.findChildren(MenuButton)
               if button.label_text == target and button.isVisible()))
    page = parent.content_stack.currentWidget()
    dialog = None
    deadline = monotonic() + request.get('timeout', 60)
    try:
        if op == 'issue':
            from ui_issuance import issue
            return (yield from issue(app, page, request, folder, select, click, capture))
        if op == 'inventory':
            yield
            capture(window, folder, 'inventory')
            return (yield from ordinary(app, request))
        while not vault.exc.complete(prior):
            if monotonic() >= deadline:
                raise TimeoutError('UI prior exchange is not verified')
            yield
        click(page.tables[page.stack.currentIndex()].header.add_button)
        yield
        row = next(row for row in page._rows if row['messages'][-1].said == prior)
        direction = row['_key'][1]
        tabs = page.tabs[page.stack.currentIndex()]
        QTest.mouseClick(tabs, Qt.MouseButton.LeftButton, pos=tabs.tabRect(direction).center())
        yield
        table = page.tables[direction]
        index = next(index for index, item in enumerate(table._current_page_data)
                     if item['_key'] == row['_key'])
        cell = table.table.cellWidget(index, table.columns.index('Actions'))
        review = next(button for button in cell.findChildren(QPushButton) if button.text())
        capture(window, folder, 'activity-' + prior)
        click(review)
        yield
        dialog = page._response_dialog
        if op == 'admit':
            button = dialog.admit_button
        else:
            select(dialog.response.combo_box, op.title())
            button = dialog.send_button
        yield
        if op in ('offer', 'grant'):
            select(dialog.credential, request['credential'])
            select(dialog.disclosure.grant, request.get('from_grant'))
            if request.get('refresh'):
                click(dialog.disclosure.refresh, dialog)
                select(dialog.disclosure.source, 'derive' if request.get('derive') else
                       'supplied' if request.get('openings') else 'retained')
                if request.get('bound_event'):
                    field = dialog.disclosure.bound_event.line_edit
                    dialog.scroll_area.ensureWidgetVisible(field)
                    field.setFocus()
                    QTest.keyClicks(field, request['bound_event'])
                if request.get('openings'):
                    path = folder / ('opening-' + prior + '.cesr')
                    folder.mkdir(parents=True, exist_ok=True)
                    path.write_text(request['openings'][0])
                    opening_file(dialog, path)
                    while dialog.disclosure.opening != str(path):
                        if monotonic() >= deadline:
                            raise TimeoutError('Event-opening picker did not complete')
                        yield
        # Let the real theme's 200 ms label animation settle cooperatively.
        settled = monotonic() + 0.25
        while monotonic() < settled:
            yield
        capture(dialog, folder, op + '-' + prior)
        if op in ('offer', 'grant'):
            click(dialog.credential_details.toggle_button, dialog)
            settled = monotonic() + .25
            while monotonic() < settled:
                yield
            capture(dialog, folder, op + '-preview-' + prior)
        before = {said for (said,), _ in vault.db.outbox.getTopItemIter()}
        next_click = 0.0
        while True:
            after = {said for (said,), _ in vault.db.outbox.getTopItemIter()}
            created = after - before
            if created:
                assert len(created) == 1
                said = created.pop()
                break
            if monotonic() >= deadline:
                raise TimeoutError('UI action did not produce an authorized submission')
            error = dialog.error_label.text()
            if error and not any(text in error.lower() for text in ('waiting', 'current observer')):
                raise ValueError(error)
            if button.isEnabled() and monotonic() >= next_click:
                click(button, dialog)
                next_click = monotonic() + 1
            yield
        while True:
            record = vault.db.outbox.get((said,))
            if record.status == 'submitted':
                break
            if record.status == 'blocked':
                raise ValueError(record.error)
            if monotonic() >= deadline:
                raise TimeoutError('UI submission remains retained but not delivered')
            yield
        result = {'said': said, 'transport': asdict(record),
                  'stream': exchanging.serializeMessage(vault.hby, said).decode()}
        if op == 'admit':
            result['accepted'] = vault.db.receipts.get((app.hab.pre, prior)).status == 'accepted'
        with (folder / 'actions.jsonl').open('a') as log:
            log.write(json.dumps({'control': type(dialog).__name__, 'action': op,
                                  'prior': prior, 'said': said, 'delivery': record.status}) + '\n')
        return result
    finally:
        if dialog is not None:
            dialog.close()
            # The dialog owns its close animation and delayed completion.
            # Deleting it here invalidates its pending Qt animation callbacks.


if __name__ == '__main__':
    from locksmith.driver.__main__ import main
    QApplication.setAttribute(Qt.ApplicationAttribute.AA_DontUseNativeDialogs)
    from locksmith import resources_rc  # Register the real application's icons.
    from locksmith.ui.styles import set_global_styles
    qt = QApplication.instance() or QApplication([])
    set_global_styles(qt)
    qt.setQuitOnLastWindowClosed(False)
    runtime.execute = execute
    raise SystemExit(main())
