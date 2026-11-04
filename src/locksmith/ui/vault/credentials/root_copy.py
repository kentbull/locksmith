"""Individual encrypted root files, with inspect and approve as separate actions."""
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel, QVBoxLayout, QWidget
from keri.app.habbing import GroupHab

from locksmith.core import credentialing, root_copying
from locksmith.ui.toolkit.widgets import LocksmithButton, LocksmithDialog, LocksmithInvertedButton
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox
from locksmith.ui.vault.credentials.presentation import identifier_name


class RootCopyDialog(LocksmithDialog):
    """Borrow one vault; closing discards inspected bytes and ephemeral approval."""

    def __init__(self, app, parent, said, *, received=False):
        self.app, self.vault, self.said, self.received = app, app.vault, said, received
        self.inspected = None
        content = QWidget()
        layout = QVBoxLayout(content)
        self.summary = QLabel('A registry root permits deriving future state openings. '
                              'It does not grant issuer signing authority or admit a credential.')
        self.status = QLabel()
        for label in (self.summary, self.status):
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setWordWrap(True)
            layout.addWidget(label)
        self.selection = FloatingLabelComboBox('Received disclosure' if received else 'Recipient')
        self.recipient = FloatingLabelComboBox('Local recipient')
        self.events = FloatingLabelComboBox('Held opening for accepted registry update')
        layout.addWidget(self.recipient)
        self.recipient.setVisible(received)
        layout.addWidget(self.selection)
        layout.addWidget(self.events)
        self.events.setVisible(received)
        self.choose = LocksmithInvertedButton('Inspect encrypted root file…')
        self.choose.setVisible(received)
        self.action = LocksmithButton('Approve and import' if received else 'Export encrypted root…')
        close = LocksmithInvertedButton('Cancel')
        buttons = QHBoxLayout()
        for button in (self.choose, self.action, close):
            buttons.addWidget(button)
        super().__init__(parent=parent, title='Import encrypted registry root' if received
                         else 'Export encrypted registry root', content=content, buttons=buttons)
        close.clicked.connect(self.close)
        self.choose.clicked.connect(self._choose)
        self.action.clicked.connect(self._act)
        self.finished.connect(self._cancel)
        if received:
            for hab in self.vault.hby.habs.values():
                if not isinstance(hab, GroupHab):
                    self.recipient.addItem(identifier_name(self.vault, hab.pre), hab.pre)
            for record in credentialing.admissions(self.vault, said):
                self.selection.addItem(f'{record.accepted_at} · {record.grant}', record.grant)
            self.selection.currentIndexChanged.connect(self._openings)
            self._openings()
        else:
            for pre in self.vault.hby.kevers:
                if pre not in self.vault.hby.prefixes:
                    self.selection.addItem(identifier_name(self.vault, pre), pre)
            view = credentialing.credential(self.vault, said)
            self.summary.setText(self.summary.text() + f"\nIssuer: {view['sad']['i']}\nRegistry: {view['sad'].get('rd', '')}")
        self.action.setEnabled(not received and self.selection.currentData() is not None)
        self.fit_content(640)

    def _current(self):
        if self.app.vault is not self.vault or self.vault.closed:
            raise ValueError('This vault is closed; inspect again in the current vault')

    def _openings(self, *_):
        self.events.clear()
        try:
            self._current()
            for event, proof in root_copying.held_openings(
                    self.vault, self.said, self.selection.currentData()):
                self.events.addItem(f'{event} · {proof.clan.__name__}', (event, proof))
        except Exception as error:
            self.status.setText(str(error))

    def _choose(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Inspect encrypted registry root', '', 'CESR (*.cesr)')
        if path:
            self.inspect_file(path)

    def inspect_file(self, path):
        """Inspection reads claims only; approval never follows file selection automatically."""
        self.inspected = None
        self.action.setEnabled(False)
        try:
            self._current()
            if Path(path).stat().st_size > 65536:
                raise ValueError('Encrypted root file exceeds 64 KiB')
            selected = root_copying.inspect(Path(path).read_bytes())
            self.inspected = selected
            self.status.setText(f'Unauthenticated file claims\nSender: {selected.sender}\n'
                f'Recipient: {selected.recipient}\nRegistry: {selected.registry}\nReply: {selected.said}\n'
                'Approve only the intended transfer and selected held opening. Authentication occurs during import.')
            self.action.setEnabled(True)
        except Exception as error:
            self.status.setText(str(error))
        self.fit_content(640)

    def _act(self):
        try:
            self._current()
            if self.received:
                if self.inspected is None or self.events.currentData() is None:
                    raise ValueError('Inspect a file and select an exact held opening first')
                event, proof = self.events.currentData()
                self.vault.root_copies.receive(self.inspected, self.recipient.currentData(), self.said,
                    self.selection.currentData(), event, proof)
                self.status.setText('Encrypted registry root retained and verified. Credential admission is unchanged.')
                self.action.setEnabled(False)
            else:
                path, _ = QFileDialog.getSaveFileName(self, 'Export encrypted registry root', '', 'CESR (*.cesr)')
                if path:
                    self.export_file(path)
        except Exception as error:
            self.status.setText(str(error))
        self.fit_content(640)

    def export_file(self, path):
        """Write ciphertext exclusively; the sender cannot observe recipient retention."""
        self._current()
        issuer = credentialing.credential(self.vault, self.said)['sad']['i']
        wire = self.vault.root_copies.export(self.said, issuer, self.selection.currentData())
        with Path(path).open('xb') as output:
            output.write(wire)
        self.status.setText('Encrypted copy exported; recipient retention unconfirmed')
        self.fit_content(640)

    def _cancel(self, *_):
        self.inspected = None
        self.vault.root_copies.close()
