"""Propose one exact group-admitted view for ordinary member threshold signing."""
from keri import kering
from keri.app.habbing import GroupHab
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from locksmith.core import credentialing, group_presenting
from locksmith.ui.toolkit.widgets import (
    LocksmithButton,
    LocksmithDialog,
    LocksmithInvertedButton,
)
from locksmith.ui.toolkit.widgets.fields import (
    FloatingLabelComboBox,
    FloatingLabelLineEdit,
)
from locksmith.ui.vault.credentials.presentation import identifier_name


def group_admissions(vault, said):
    """Return (group AID, admitted Grant SAID) pairs a local group can present."""
    pairs = []
    for record in credentialing.admissions(vault, said):
        grant = vault.hby.db.exns.get((record.grant,))
        if grant is not None and isinstance(vault.hby.habByPre(grant.sad['ri']), GroupHab):
            pairs.append((grant.sad['ri'], record.grant))
    return pairs


class GroupPresentationDialog(LocksmithDialog):
    """Sign this member's contribution; other members approve in Activity.

    No deadline exists until the group threshold accepts the Grant. Only the
    elected lead member then sends it; this dialog never transmits it.
    """

    def __init__(self, app, parent, credential_said):
        self.app, self.vault, self.said = app, app.vault, credential_said
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 12, 0, 0)
        layout.setSpacing(16)
        note = QLabel('Presents the exact held view admitted by the group. Other members must '
                      'approve it in Activity; the lead member sends it after the group threshold.')
        note.setWordWrap(True)
        layout.addWidget(note)
        self.view = FloatingLabelComboBox('Group and admitted view')
        for gid, grant in group_admissions(self.vault, credential_said):
            self.view.addItem(f'{identifier_name(self.vault, gid)} · {grant[:8]}…', (gid, grant))
        layout.addWidget(self.view)
        self.recipient = FloatingLabelComboBox('To')
        self.recipient.addItem('Choose a contact', None)
        peers = {contact['id'] for contact in self.vault.org.list()}
        for pre in sorted(peers - self.vault.hby.prefixes, key=lambda pre: identifier_name(self.vault, pre).casefold()):
            self.recipient.addItem(identifier_name(self.vault, pre), pre)
        layout.addWidget(self.recipient)
        self.message = FloatingLabelLineEdit('Message (optional)')
        layout.addWidget(self.message)
        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        cancel = LocksmithInvertedButton('Close')
        self.action = LocksmithButton('Sign and propose')
        buttons = QHBoxLayout()
        buttons.addStretch()
        buttons.addWidget(cancel)
        buttons.addWidget(self.action)
        super().__init__(parent, title='Present from group', content=content, buttons=buttons)
        self.fit_content(540)
        cancel.clicked.connect(self.close)
        self.action.clicked.connect(self._propose)
        self.view.currentIndexChanged.connect(self._update)
        self.recipient.currentIndexChanged.connect(self._update)
        self._update()

    def _update(self, *_):
        self.action.setEnabled(bool(self.view.currentData() and self.recipient.currentData()))

    def _propose(self):
        if self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
            self.status.setText('This vault is closed.')
            return
        self.action.setEnabled(False)
        try:
            gid, grant = self.view.currentData()
            status = group_presenting.propose(self.vault, self.vault.hby.habByPre(gid), said=self.said,
                source=grant, recipient=self.recipient.currentData(), message=self.message.line_edit.text())
        except (ValueError, kering.KeriError) as error:
            self.status.setText(str(error))
            self._update()
            return
        self.status.setText('Your signature is recorded. Waiting for other members; '
                            f'no deadline exists until threshold. Grant {status["grant"]}')
