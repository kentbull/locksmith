"""Registry-root copies: send to members' mailboxes; list received copies still escrowed."""
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel, QVBoxLayout, QWidget
from keri import kering
from keri.help import helping
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
    """Read-only Activity list of received copies still waiting for local state.

    Received roots are retained automatically; nothing here approves or
    dismisses a copy. Escrowed copies are retried until their deadline.
    """

    def __init__(self, page):
        super().__init__()
        self.page = page
        self.error = ''
        self.message = ''
        self.box = QVBoxLayout(self)
        self.box.setContentsMargins(0, 0, 0, 0)
        self.items = []

    @property
    def vault(self):
        return self.page.vault

    def show_copies(self, items):
        while self.box.count():
            self.box.takeAt(0).widget().deleteLater()
        self.items = items
        self.setVisible(bool(items or self.error or self.message))
        for text, color in ((self.error, colors.DANGER), (self.message, None)):
            if text:
                label = QLabel(text)
                label.setTextFormat(Qt.TextFormat.PlainText)
                label.setWordWrap(True)
                if color:
                    label.setStyleSheet(f'color: {color};')
                self.box.addWidget(label)
        if not items:
            return
        self.box.addWidget(QLabel('Registry root copies waiting for local state'))
        name = self.page._name
        for item in items:
            try:
                deadline = helping.fromIso8601(item.deadline).astimezone().strftime('%b %d, %Y %H:%M')
            except (ValueError, TypeError):
                deadline = item.deadline
            text = QLabel(f'{name(item.sender)} → {name(item.gid)} · registry {item.registry[:12]}… · '
                          f'waiting for {item.waiting} · retried until {deadline}')
            text.setTextFormat(Qt.TextFormat.PlainText)
            text.setWordWrap(True)
            text.setToolTip(f'Copy {item.said}\nRecipient {item.recipient}\nRegistry {item.registry}')
            self.box.addWidget(text)

    def import_file(self, path):
        """File fallback: copies enter through the vault's ordinary intake and are accepted there."""
        self.error = self.message = ''
        try:
            if Path(path).stat().st_size > 65536:
                raise ValueError('Registry root copy file exceeds 64 KiB')
            outcome = self.vault.roots.ingest(Path(path).read_bytes())
            parts = []
            if outcome['retained']:
                parts.append('Registry root received')
            if waiting := len(outcome['waiting']):
                parts.append(f'{waiting} cop{"y" if waiting == 1 else "ies"} waiting for local state')
            self.message = '; '.join(parts)
            if outcome['refused']:
                self.error = 'Registry root copy not retained: ' + '; '.join(sorted(set(outcome['refused'].values())))
        except (OSError, ValueError, kering.KeriError) as error:
            self.error = str(error)
        self.page.refresh()
