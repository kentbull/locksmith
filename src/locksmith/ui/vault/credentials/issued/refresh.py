"""Explicit issuer consent to refresh or resume one registry commitment."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel
from keri.app.habbing import GroupHab

from locksmith.core import credentialing
from locksmith.ui.toolkit.widgets import LocksmithDialog, LocksmithButton, LocksmithInvertedButton
from locksmith.ui.toolkit.widgets.fields import FloatingLabelLineEdit
from locksmith.ui.vault.shared.witness_auth_mixin import WitnessAuthenticationPanel


class RefreshCredentialDialog(LocksmithDialog):
    """Freeze the selected commitment; a click grants only this authoring operation."""

    def __init__(self, app, credential_said, credential_schema, parent=None):
        self.app, self.vault, self.credential_said = app, app.vault, credential_said
        self._closed, self._refresh_id = False, None
        self._resume, self._expected_update = False, ''
        self._group = False
        content, error = QWidget(), ''
        layout = QVBoxLayout(content)
        notice = QLabel(f'Refresh {credential_schema}? Creates a new commitment to its current issued state. '
                        'Earlier presentations may need a new state opening. A pending update is resumed unchanged.')
        notice.setTextFormat(Qt.TextFormat.PlainText)
        notice.setWordWrap(True)
        layout.addWidget(notice)
        self.bound_event = FloatingLabelLineEdit('Exact current issuee event (optional)')
        self.bound_event.setToolTip('A new bound commitment requires a currently eligible issuee event.')
        layout.addWidget(self.bound_event)
        self.auth_panel = None
        try:
            context = credentialing.refresh_context(self.vault, credential_said)
            self._resume, self._expected_update = context['resume'], context['update'].said
            self.bound_event.setVisible(context['record'].registry_mode != 'public')
            self.bound_event.setEnabled(not self._resume)
            hab = context['hab']
            self._group = isinstance(hab, GroupHab)
            if self._group:
                notice.setText(notice.text() + ' Other members approve the exact group registry anchor '
                    'in Activity before the update completes. Retrying preserves that proposal.')
            if hab.kever.wits:
                self.auth_panel = WitnessAuthenticationPanel(app, hab, list(hab.kever.wits))
                layout.addWidget(self.auth_panel)
        except Exception as exception:
            error = str(exception)
        buttons = QHBoxLayout()
        self.cancel_button = LocksmithInvertedButton('Cancel')
        self.refresh_button = LocksmithButton('Resume state update' if self._resume else 'Refresh state commitment')
        buttons.addWidget(self.cancel_button)
        buttons.addWidget(self.refresh_button)
        super().__init__(parent=parent, title='Refresh state commitment', content=content, buttons=buttons)
        self.cancel_button.clicked.connect(self.reject)
        self.refresh_button.clicked.connect(self._refresh)
        self.vault.signals.doer_event.connect(self._on_event)
        self.finished.connect(self._finish)
        if error:
            self.refresh_button.setEnabled(False)
            self.show_error(error)
        self.fit_content(560)

    def _refresh(self):
        if self._closed or self._refresh_id is not None:
            return
        if self.app.vault is not self.vault or self.vault.closed:
            self.show_error('This vault is closed. Review the credential in the current vault.')
            return
        codes = None
        if self.auth_panel:
            valid, codes, error = self.auth_panel.validate_authentication_codes()
            if not valid:
                self.show_error(error)
                return
        self.clear_error()
        worker = credentialing.RefreshCredentialDoer(self.app, self.credential_said,
            expected_update=self._expected_update, resume=self._resume, codes=codes,
            bound_event=self.bound_event.text().strip() or None)
        self._refresh_id = worker.refresh_id
        self.refresh_button.setEnabled(False)
        self.refresh_button.setText('Waiting for group approval…' if self._group else 'Updating state commitment…')
        self.vault.extend([worker])

    def _on_event(self, name, event, data):
        if (self._closed or self.app.vault is not self.vault or self.vault.closed
                or name != 'RefreshCredentialDoer' or data.get('refresh_id') != self._refresh_id):
            return
        if event == 'credential_refreshed':
            self.accept()
        elif event == 'credential_refresh_failed':
            if data.get('update'):
                self._expected_update, self._resume = data['update'], True
                self.bound_event.setEnabled(False)
            self._refresh_id = None
            self.refresh_button.setEnabled(True)
            self.refresh_button.setText('Resume state update' if self._resume else 'Refresh state commitment')
            self.show_error(data.get('error', 'State refresh failed'))

    def _finish(self, *_):
        self._closed = True
        try:
            self.vault.signals.doer_event.disconnect(self._on_event)
        except RuntimeError:
            pass
