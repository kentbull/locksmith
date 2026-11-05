"""Explicit approval of authenticated live registry setup, separate from Admit."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QTextEdit, QVBoxLayout, QWidget
import json
from keri.help import helping

from locksmith.ui.vault.shared.witness_auth_mixin import WitnessAuthenticationPanel
from locksmith.core import grouping
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


class GroupRegistryDialog(LocksmithDialog):
    """Review one authenticated retained registry commitment before contributing."""

    def __init__(self, page, said):
        self.page, self.vault, self.said = page, page.vault, said
        wrapper, children, group = grouping.registry_proposal(self.vault, said)
        tel, anchor = [child.serder for child in children]
        self.prior = group.kever.serder.said
        content = QWidget()
        layout = QVBoxLayout(content)
        self.summary = QLabel(f'Group: {group.name} ({group.pre})\n'
            f"Registry: {tel.said if tel.ilk == 'rip' else tel.sad['rd']}\n"
            f"TEL: {tel.said} ({tel.ilk.upper()}, ordinal {tel.sad['n']})\nExact anchor: {anchor.said}")
        purpose = QLabel('Approving contributes your signature to this exact group anchor. '
            + ('RIP establishes the group-controlled registry.' if tel.ilk == 'rip' else
               'BUP records a blinded commitment. This proposal alone does not reveal the credential '
               'or its state, and transfers no derivation keys.'))
        self.error = QLabel()
        for label in (self.summary, purpose, self.error):
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setWordWrap(True)
            layout.addWidget(label)
        details = QTextEdit()
        details.setReadOnly(True)
        details.setPlainText(json.dumps({'tel': tel.sad, 'anchor': anchor.sad}, indent=2))
        layout.addWidget(details)
        self.auth_panel = None
        wits = [wit for wit in group.kever.wits if wit not in anchor.sad.get('br', [])]
        wits.extend(anchor.sad.get('ba', []))
        if wits:
            self.auth_panel = WitnessAuthenticationPanel(page.app, group, wits)
            layout.addWidget(self.auth_panel)
        buttons = QHBoxLayout()
        close = LocksmithInvertedButton('Close')
        self.approve = LocksmithButton('Approve exact registry anchor')
        buttons.addWidget(close)
        buttons.addWidget(self.approve)
        super().__init__(parent=page, title='Group registry approval', content=content, buttons=buttons)
        close.clicked.connect(self.close)
        self.approve.clicked.connect(self._approve)
        self.resize(650, 650)

    def _approve(self):
        """Closing or receiving contributes nothing; this click rechecks the parent."""
        try:
            if not self.page._current_vault() or self.page.vault is not self.vault:
                raise ValueError('This vault is closed')
            auths = {}
            if self.auth_panel:
                valid, codes, error = self.auth_panel.validate_authentication_codes()
                if not valid:
                    raise ValueError(error)
                auths = {wit: f'{code}#{helping.nowIso8601()}'
                         for wit, code in (entry.split(':', 1) for entry in codes)}
            grouping.approve_registry_proposal(self.vault, self.said, self.prior, auths=auths)
        except Exception as error:
            self.error.setText(str(error))
        else:
            self.approve.setEnabled(False)
            self.error.setText('Your contribution is queued. Group approval and registry acceptance remain separate.')
            self.page.refresh()


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
        self.purpose = QLabel()
        for label in (self.summary, self.state, self.purpose, self.error):
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setWordWrap(True)
            layout.addWidget(label)
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.hide()
        layout.addWidget(self.details)
        self._reviewed_proposal = None
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
        self._reviewed_proposal = status.get('proposal')
        self.details.setVisible(bool(status.get('group')))
        if status.get('group'):
            stage = status['stage']
            self.summary.setText(self.summary.text()
                + f"\nMember: {identifier_name(self.vault, status['member'])}"
                + f"\nDH custodian: {identifier_name(self.vault, status['custodian'])}"
                + f"\nCoordinator event: {status['coordinator'][1]}")
            self.details.setPlainText(json.dumps(status['detail'], indent=2))
            self.approve.setText('Approve exact Grant' if stage == 'grant' else 'Approve exact DH query')
            self.purpose.setText(
                'Approve this member’s signature on the displayed Grant and credential.'
                if stage == 'grant' else
                'Approve this member’s signature on the displayed public DH query.')
            self.purpose.setText(self.purpose.text()
                + ' Only the elected custodian establishes and retains this group’s derivation root. '
                  'Contributing a signature does not copy the root to this member. '
                  'Credential admission remains a separate decision.')
        else:
            self.approve.setText('Approve registry setup')
            self.purpose.setText('Approving establishes shared registry state-opening keys with the issuer named above, '
                'allowing this wallet to derive future state openings. '
                'After verification, review and add the credential separately.')
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
            if status.get('group') and status.get('proposal') != self._reviewed_proposal:
                raise ValueError('The proposal changed. Reopen this review before approving it.')
            options = {'proposal': self._reviewed_proposal} if status.get('group') else {}
            self.vault.auxiliary.approve_dh(self.hab, self.grant_said, **options)
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
