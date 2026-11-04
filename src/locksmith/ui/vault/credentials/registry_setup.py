"""Explicit approval of authenticated live registry setup, separate from Admit."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from locksmith.ui.toolkit.widgets import LocksmithButton, LocksmithDialog, LocksmithInvertedButton
from locksmith.ui.vault.credentials.presentation import identifier_name
from locksmith.ui.vault.credentials.received.accept_grant import AcceptGrantDialog


SETUP_PHASES = {
    'approval_required': 'Approval needed',
    'waiting': 'Waiting for registry evidence',
    'refused': 'Registry setup refused',
    'verified': 'Registry setup verified',
    'expired': 'Registry setup expired',
    'cancelled': 'Registry setup cancelled',
    'interrupted': 'Registry setup interrupted',
}


class RegistrySetupDialog(LocksmithDialog):
    """Render one core-authenticated request and obtain only its explicit approval."""

    def __init__(self, page, hab, grant_said):
        self.page, self.vault = page, page.vault
        self.hab, self.grant_said = hab, grant_said
        self._listening = False
        content = QWidget()
        layout = QVBoxLayout(content)
        self.summary = QLabel()
        self.state = QLabel()
        self.error = QLabel()
        purpose = QLabel('Approving establishes shared registry state-opening keys with the issuer named above, '
                         'allowing this wallet to derive future state openings. '
                         'After verification, review and add the credential separately.')
        for label in (self.summary, self.state, purpose, self.error):
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setWordWrap(True)
            layout.addWidget(label)
        buttons = QHBoxLayout()
        close = LocksmithInvertedButton('Close')
        self.cancel = LocksmithInvertedButton('Cancel request')
        self.approve = LocksmithButton('Approve registry setup')
        self.review = LocksmithButton('Review credential')
        for button in (close, self.cancel, self.approve, self.review):
            buttons.addWidget(button)
        super().__init__(parent=page, title='Registry setup', content=content, buttons=buttons)
        close.clicked.connect(self.close)
        self.approve.clicked.connect(self._approve)
        self.cancel.clicked.connect(self._cancel)
        self.review.clicked.connect(self._review)
        self.vault.signals.doer_event.connect(self._changed)
        self._listening = True
        self.finished.connect(self._disconnect)
        self.refresh()
        self.fit_content(560)

    def _status(self):
        """Re-read the core owner; a stale widget cannot authorize another vault."""
        if not self.page._current_vault() or self.page.vault is not self.vault:
            return None
        return self.vault.auxiliary.status(self.hab.pre, self.grant_said)

    def refresh(self):
        """Show current readiness without deriving authority from displayed history."""
        status = self._status()
        self.approve.setVisible(False)
        self.cancel.setVisible(False)
        self.review.setVisible(False)
        if status is None or status['kind'] != 'dh':
            self.state.setText('This registry request is no longer available.')
            return
        self.summary.setText(
            f"From {identifier_name(self.vault, status['sender'])}\n"
            f"To {identifier_name(self.vault, status['recipient'])}\n"
            f"Credential: {status['credential']}\nGrant: {self.grant_said}")
        self.state.setText(SETUP_PHASES[status['phase']])
        self.error.setText(status['error'])
        self.approve.setVisible('approve_dh' in status['actions'])
        self.cancel.setVisible(status['phase'] == 'waiting')
        self.review.setVisible(status['phase'] == 'verified' and status['recipient'] == self.hab.pre)

    def _approve(self):
        """Approve only the authenticated request that is still actionable."""
        status = self._status()
        if status is None or 'approve_dh' not in status['actions']:
            self.refresh()
            return
        try:
            self.vault.auxiliary.approve_dh(self.hab, self.grant_said)
        except Exception as error:
            self.error.setText(str(error))
        else:
            self.refresh()
            self.page.refresh()

    def _cancel(self):
        """Abandon a running agreement without accepting the credential."""
        status = self._status()
        if status is None or status['phase'] != 'waiting':
            self.refresh()
            return
        self.vault.auxiliary.abandon(self.hab.pre, self.grant_said)
        self.refresh()
        self.page.refresh()

    def _review(self):
        """Open the ordinary review dialog; its Admit remains a separate action."""
        status = self._status()
        if status is None or status['phase'] != 'verified' or status['recipient'] != self.hab.pre:
            self.refresh()
            return
        self.close()
        self.page._response_dialog = AcceptGrantDialog(self.page.app, self.page, self.grant_said, save=False)
        self.page._response_dialog.finished.connect(self.page.refresh)
        self.page._response_dialog.open()

    def _changed(self, name, event, data):
        """Refresh only notifications for this exact local operation."""
        if (name, event) == ('Auxiliary', 'changed') and (data.get('aid'), data.get('grant')) == (
                self.hab.pre, self.grant_said):
            self.refresh()

    def _disconnect(self, *_):
        """Release the live subscription when the dialog closes."""
        if self._listening:
            self.vault.signals.doer_event.disconnect(self._changed)
            self._listening = False
