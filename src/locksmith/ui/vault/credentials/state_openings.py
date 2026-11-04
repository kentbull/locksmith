"""Explicit event-opening consent for one authenticated live presentation."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from locksmith.ui.toolkit.widgets import LocksmithButton, LocksmithDialog, LocksmithInvertedButton
from locksmith.ui.vault.credentials.presentation import identifier_name
from locksmith.ui.vault.credentials.received.accept_grant import AcceptGrantDialog


OPENING_PHASES = {
    'sending': 'Sending the selected presentation',
    'waiting_request': 'Presentation submitted; awaiting a state-opening request',
    'admitted': 'Recipient Admit verified',
    'request_required': 'State openings needed',
    'approval_required': 'Opening approval needed',
    'waiting': 'Waiting for state openings',
    'answered': 'Opening reply prepared',
    'verified': 'State openings verified',
    'refused': 'State openings refused',
    'expired': 'Opening request expired',
    'cancelled': 'Opening request cancelled',
    'interrupted': 'Opening request interrupted',
}


class StateOpeningsDialog(LocksmithDialog):
    """Request or release selected event proofs without implying credential consent."""

    def __init__(self, page, hab, grant_said):
        self.page, self.vault = page, page.vault
        self.hab, self.grant_said = hab, grant_said
        self._listening = False
        content = QWidget()
        layout = QVBoxLayout(content)
        self.summary = QLabel()
        self.state = QLabel()
        self.error = QLabel()
        self.delivery = QLabel('The reply is prepared for delivery. The recipient must still '
                               'verify it and decide whether to add the credential.')
        purpose = QLabel('Request state openings for the selected registry events in this exact presentation. '
                         'Approving sends only those event-specific proofs. '
                         'After verification, review and add the credential separately.')
        for label in (self.summary, self.state, purpose, self.delivery, self.error):
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setWordWrap(True)
            layout.addWidget(label)
        buttons = QHBoxLayout()
        close = LocksmithInvertedButton('Close')
        self.cancel = LocksmithInvertedButton('Cancel request')
        self.request = LocksmithButton('Request state openings')
        self.approve = LocksmithButton('Approve state openings')
        self.review = LocksmithButton('Review credential')
        for button in (close, self.cancel, self.request, self.approve, self.review):
            buttons.addWidget(button)
        super().__init__(parent=page, title='State openings', content=content, buttons=buttons)
        close.clicked.connect(self.close)
        self.request.clicked.connect(self._request)
        self.approve.clicked.connect(self._approve)
        self.cancel.clicked.connect(self._cancel)
        self.review.clicked.connect(self._review)
        self.vault.signals.doer_event.connect(self._changed)
        self._listening = True
        self.finished.connect(self._disconnect)
        self.refresh()
        self.fit_content(560)

    def _status(self):
        """Require the same open vault and the core's current authenticated context."""
        if not self.page._current_vault() or self.page.vault is not self.vault:
            return None
        status = self.vault.auxiliary.status(self.hab.pre, self.grant_said)
        return status if status is not None and status['kind'] == 'unblind' else None

    def refresh(self):
        """Show the selected operation without promoting reply preparation to acceptance."""
        status = self._status()
        for button in (self.request, self.approve, self.cancel, self.review):
            button.hide()
        self.delivery.hide()
        if status is None or status['kind'] != 'unblind':
            self.state.setText('This opening request is no longer available.')
            return
        self.summary.setText(
            f"Presenter: {identifier_name(self.vault, status['sender'])}\n"
            f"Recipient: {identifier_name(self.vault, status['recipient'])}\n"
            f"Credential: {status['credential']}\nPresentation: {self.grant_said}\n"
            f"Original local deadline: {status['deadline']}")
        self.state.setText(OPENING_PHASES[status['phase']])
        self.error.setText(status['error'])
        self.request.setVisible('request_openings' in status['actions'])
        self.approve.setVisible('approve_openings' in status['actions'])
        self.cancel.setVisible(status['active'] and status['phase'] in (
            'sending', 'waiting_request', 'waiting', 'approval_required', 'answered'))
        self.delivery.setVisible(status['phase'] == 'answered')
        self.review.setVisible(status['phase'] == 'verified' and status['recipient'] == self.hab.pre)

    def _request(self):
        """Explicitly authorize the recipient's event-specific proof request."""
        status = self._status()
        if status is None or 'request_openings' not in status['actions']:
            self.refresh()
            return
        try:
            self.vault.auxiliary.request_openings(self.hab, self.grant_said)
        except Exception as error:
            self.error.setText(str(error))
        else:
            self.refresh()
            self.page.refresh()

    def _approve(self):
        """Explicitly authorize the presenter's selected proof release."""
        status = self._status()
        if status is None or 'approve_openings' not in status['actions']:
            self.refresh()
            return
        try:
            self.vault.auxiliary.approve_openings(self.hab, self.grant_said)
        except Exception as error:
            self.error.setText(str(error))
        else:
            self.refresh()
            self.page.refresh()

    def _cancel(self):
        """Abandon only a running request; closing an unapproved view does nothing."""
        status = self._status()
        if status is None or not status['active'] or status['phase'] in self.vault.auxiliary.Terminal:
            self.refresh()
            return
        self.vault.auxiliary.abandon(self.hab.pre, self.grant_said)
        self.refresh()
        self.page.refresh()

    def _review(self):
        """Open ordinary credential review, preserving its separate explicit Admit."""
        status = self._status()
        if status is None or status['phase'] != 'verified' or status['recipient'] != self.hab.pre:
            self.refresh()
            return
        self.close()
        self.page._response_dialog = AcceptGrantDialog(self.page.app, self.page, self.grant_said, save=False)
        self.page._response_dialog.finished.connect(self.page.refresh)
        self.page._response_dialog.open()

    def _changed(self, name, event, data):
        """Refresh the exact local presentation on its owner's notification."""
        if (name, event) == ('Auxiliary', 'changed') and (data.get('aid'), data.get('grant')) == (
                self.hab.pre, self.grant_said):
            self.refresh()

    def _disconnect(self, *_):
        """Release the subscription when this view closes."""
        if self._listening:
            self.vault.signals.doer_event.disconnect(self._changed)
            self._listening = False
