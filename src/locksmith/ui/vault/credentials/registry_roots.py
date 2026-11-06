"""Registry-root copies: send to members' mailboxes, or approve received copies."""
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel, QVBoxLayout, QWidget
from keri import kering
from keri.app.habbing import GroupHab

from locksmith.core import credentialing
from locksmith.ui import colors
from locksmith.ui.toolkit.widgets import LocksmithButton, LocksmithDialog, LocksmithInvertedButton
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox
from locksmith.ui.vault.credentials.presentation import identifier_name

MAILBOX, FILE = 'mailbox', 'file'


class RootSendDialog(LocksmithDialog):
    """Send one credential registry's root as ESSR copies, one per recipient member.

    Mailbox delivery is the default; a file is the fallback for an offline
    recipient. Each recipient still approves its copy explicitly.
    """

    def __init__(self, app, parent, said, *, received=False):
        self.app, self.vault, self.said = app, app.vault, said
        view = credentialing.credential(self.vault, said, received=received)
        self.registry = view['sad'].get('rd', '')
        content = QWidget()
        layout = QVBoxLayout(content)
        self.summary = QLabel('A registry root lets each recipient derive future state openings. '
                              'It grants no signing authority and admits no credential.\n'
                              f'Registry: {self.registry}')
        self.status = QLabel()
        for label in (self.summary, self.status):
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setWordWrap(True)
            layout.addWidget(label)
        self.sender = FloatingLabelComboBox('Send as')
        self.holder = FloatingLabelComboBox('Root held for')
        self.delivery = FloatingLabelComboBox('Delivery')
        for field in (self.sender, self.holder, self.delivery):
            layout.addWidget(field)
        self.delivery.addItem('Recipient mailboxes', MAILBOX)
        self.delivery.addItem('Save to file…', FILE)
        issuer, subject = view['sad'].get('i'), view['subject']
        senders = [issuer] if not received else ([subject] if subject else [])
        for pre in senders:
            hab = self.vault.hby.habByPre(pre) if pre else None
            if hab is not None:
                self.sender.addItem(identifier_name(self.vault, pre), pre)
        targets = dict.fromkeys(pre for pre in (subject, issuer) if pre
                                and (pre != issuer or isinstance(self.vault.hby.habByPre(pre), GroupHab)))
        for pre in targets:
            self.holder.addItem(identifier_name(self.vault, pre), pre)
        self.action = LocksmithButton('Send')
        close = LocksmithInvertedButton('Close')
        buttons = QHBoxLayout()
        buttons.addWidget(self.action)
        buttons.addWidget(close)
        super().__init__(parent=parent, title='Send registry root', content=content, buttons=buttons)
        close.clicked.connect(self.close)
        self.action.clicked.connect(self._act)
        self.action.setEnabled(bool(self.registry) and self.sender.currentData() is not None
                               and self.holder.currentData() is not None)
        self.fit_content(640)

    def _hab(self):
        if self.app.vault is not self.vault or self.vault.closed:
            raise ValueError('This vault is closed; open the credential again')
        return self.vault.hby.habByPre(self.sender.currentData())

    def _act(self):
        try:
            if self.delivery.currentData() == FILE:
                path, _ = QFileDialog.getSaveFileName(self, 'Save registry root copies', '', 'CESR (*.cesr)')
                if path:
                    self.export_file(path)
            else:
                self.send()
        except (ValueError, kering.KeriError) as error:
            self.status.setText(str(error))
        self.fit_content(640)

    def send(self):
        sent = self.vault.roots.send(self._hab(), self.holder.currentData(), self.registry, td=self.said)
        self.status.setText(f'Queued {len(sent)} encrypted cop{"y" if len(sent) == 1 else "ies"} '
                            'for mailbox delivery; each recipient approves its copy.')

    def export_file(self, path):
        """Write ciphertext exclusively; the sender cannot observe recipient retention."""
        copies = self.vault.roots.prepare(self._hab(), self.holder.currentData(), self.registry, td=self.said)
        with Path(path).open('xb') as output:
            for _, wire in copies:
                output.write(wire)
        self.status.setText(f'Saved {len(copies)} encrypted cop{"y" if len(copies) == 1 else "ies"}; '
                            'recipient retention unconfirmed')


class RootCopiesSection(QWidget):
    """Activity cards for received copies; nothing is retained without an explicit click."""

    def __init__(self, page):
        super().__init__()
        self.page = page
        self.buttons, self.dismiss_buttons = {}, {}
        self.error = ''
        self.box = QVBoxLayout(self)
        self.box.setContentsMargins(0, 0, 0, 0)
        self.items = []

    @property
    def vault(self):
        return self.page.vault

    def show_copies(self, items):
        while self.box.count():
            self.box.takeAt(0).widget().deleteLater()
        self.buttons.clear()
        self.dismiss_buttons.clear()
        self.items = items
        self.setVisible(bool(items or self.error))
        if not items and not self.error:
            return
        self.box.addWidget(QLabel('Registry root copies'))
        if self.error:
            error = QLabel(self.error)
            error.setTextFormat(Qt.TextFormat.PlainText)
            error.setWordWrap(True)
            error.setStyleSheet(f'color: {colors.DANGER};')
            self.box.addWidget(error)
        name = self.page._name
        for item in items:
            card = QWidget()
            row = QHBoxLayout(card)
            state = (f'Waiting for local state: {item.deferred}' if item.deferred else
                     item.error or 'Review and approve')
            text = QLabel(f'{name(item.sender)} → {name(item.gid)} · registry {item.registry[:12]}… · {state}')
            text.setTextFormat(Qt.TextFormat.PlainText)
            text.setWordWrap(True)
            text.setToolTip(f'Copy {item.said}\nRecipient {item.recipient}\nRegistry {item.registry}')
            row.addWidget(text)
            approve = LocksmithInvertedButton('Approve root')
            approve.clicked.connect(lambda checked=False, said=item.said: self.approve(said))
            dismiss = LocksmithInvertedButton('Dismiss')
            dismiss.clicked.connect(lambda checked=False, said=item.said: self.dismiss(said))
            row.addWidget(approve)
            row.addWidget(dismiss)
            self.buttons[item.said] = approve
            self.dismiss_buttons[item.said] = dismiss
            self.box.addWidget(card)

    def approve(self, said):
        """Verify and retain this one copy's root; deferred or unverified copies stay pending."""
        self.error = ''
        try:
            if self.page.app.vault is not self.vault or self.vault is None or self.vault.closed:
                raise ValueError('This vault is closed')
            self.vault.roots.approve(said)
        except (ValueError, kering.KeriError) as error:
            self.error = str(error)
        self.page.refresh()

    def dismiss(self, said):
        self.error = ''
        try:
            self.vault.roots.dismiss(said)
        except (ValueError, kering.KeriError) as error:
            self.error = str(error)
        self.page.refresh()

    def import_file(self, path):
        """File fallback: copies enter through the vault's ordinary intake and wait here."""
        self.error = ''
        try:
            if Path(path).stat().st_size > 65536:
                raise ValueError('Registry root copy file exceeds 64 KiB')
            self.vault.roots.ingest(Path(path).read_bytes())
        except (OSError, ValueError, kering.KeriError) as error:
            self.error = str(error)
        self.page.refresh()
