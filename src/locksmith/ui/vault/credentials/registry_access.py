"""Human approval of ordinary registry proposals and encrypted salt replies."""
import json
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QGridLayout, QHBoxLayout, QLabel,
    QPlainTextEdit, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)
from keri import kering
from keri.app.habbing import GroupHab
from keri.help import helping
from locksmith.core.salt_actions import SaltActions, SaltActionDoer
from locksmith.ui.toolkit.widgets import LocksmithButton, LocksmithDialog, LocksmithInvertedButton
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox, FloatingLabelLineEdit
from locksmith.ui.vault.credentials.presentation import identifier_name
from locksmith.ui.vault.shared.witness_auth_mixin import WitnessAuthenticationPanel


class RegistryAccessDialog(LocksmithDialog):
    """Collect explicit recipients, then freeze the exact statement for approval."""

    def __init__(self, page, action, row=None):
        """Build controls without signing, transmitting, or creating registry state."""
        self.page, self.vault, self.action = page, page.app.vault, action
        self.actions, self.row = SaltActions(self.vault), row or {}
        self.body = self.proposal = self.worker = self.auth = None
        content = QWidget()
        self.form = QVBoxLayout(content)
        self.local = FloatingLabelComboBox('Local issuer or discloser')
        self.local.addItem('Choose a local identifier', None)
        for hab in self.vault.hby.habs.values():
            if hab.accepted:
                self.local.addItem(identifier_name(self.vault, hab.pre), hab.pre)
        self.form.addWidget(self.local)
        self.name = FloatingLabelLineEdit('Registry name')
        self.form.addWidget(self.name)
        self.registry = FloatingLabelComboBox('Accepted registry')
        self.registry.addItem('Choose a registry', None)
        for (regid,), _ in self.vault.rgy.baser.heads.getTopItemIter():
            self.registry.addItem(regid, regid)
        self.form.addWidget(self.registry)
        self.recipient = FloatingLabelComboBox('Holder or discloser')
        self.recipient.addItem('Choose a known recipient', None)
        for pre in self.vault.hby.kevers:
            self.recipient.addItem(identifier_name(self.vault, pre), pre)
        self.form.addWidget(self.recipient)
        self.target = FloatingLabelLineEdit('Individual recipient AID (for a recipient group)')
        self.form.addWidget(self.target)
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.hide()
        self.form.addWidget(self.preview)
        self.explanation = QLabel('Sharing permits derivation of registry-state openings. It does not grant signing authority.')
        self.explanation.setWordWrap(True)
        self.form.addWidget(self.explanation)
        cancel = LocksmithInvertedButton('Cancel')
        self.submit = LocksmithButton('Create registry' if action == 'create' else 'Review exact statement')
        buttons = QHBoxLayout()
        buttons.addWidget(cancel)
        buttons.addWidget(self.submit)
        super().__init__(page, title={'create': 'Create registry', 'share': 'Share encrypted salt',
                                     'proposal': 'Review group proposal'}[action], content=content, buttons=buttons)
        cancel.clicked.connect(self.close)
        self.submit.clicked.connect(self._submit)
        self.name.setVisible(action == 'create')
        for widget in (self.registry, self.recipient, self.target):
            widget.setVisible(action == 'share')
        if self.row.get('party'):
            self.local.setCurrentIndex(max(0, self.local.combo_box.findData(self.row['party'])))
        if self.row.get('registry'):
            self.registry.setCurrentIndex(max(0, self.registry.combo_box.findData(self.row['registry'])))
        if action == 'proposal':
            try:
                self.body, anchor, opening = self.actions.inspect(self.row['said'])
                self.proposal = self.row['said']
                self._preview(anchor, opening)
            except kering.KeriError as ex:
                self.show_error(str(ex))
                self.submit.setEnabled(False)
        self.fit_content(720)

    def _preview(self, anchor=None, opening=None):
        """Freeze selectors while showing exactly the body that approval will sign."""
        details = dict(statement=self.body.sad)
        if anchor is not None:
            details['anchor'] = anchor.sad
        if opening is not None:
            details['public_event_opening'] = opening.qb64
        self.preview.setPlainText(json.dumps(details, indent=2))
        self.preview.show()
        for widget in (self.local, self.registry, self.recipient, self.target, self.name):
            widget.setEnabled(False)
        self.submit.setText('Approve exact statement and submit')
        self.fit_content(720)

    def _submit(self):
        """Queue only a reviewed reply/proposal or explicitly requested registry."""
        try:
            if self.vault.closed:
                raise ValueError('The vault is closed')
            if self.action == 'create':
                party, name = self.local.currentData(), self.name.text().strip()
                hab = self.actions.local(party)
                if not name:
                    raise ValueError('Enter a registry name')
                if hab.kever.wits and self.auth is None and not isinstance(hab, GroupHab):
                    self.auth = WitnessAuthenticationPanel(self.page.app, hab, list(hab.kever.wits), self)
                    self.form.addWidget(self.auth)
                    self.local.setEnabled(False)
                    self.name.setEnabled(False)
                    self.submit.setText('Authenticate and create registry')
                    self.fit_content(720)
                    return
                auths = {}
                if self.auth is not None:
                    valid, codes, error = self.auth.validate_authentication_codes()
                    if not valid:
                        raise ValueError(error)
                    # The shared panel returns witness-AID:code entries, as
                    # consumed by IssueCredentialDoer. Preserve each explicit
                    # witness binding instead of using the whole entry as OTP.
                    for entry in codes:
                        witness, code = entry.split(':', 1)
                        auths[witness] = f'{code}#{helping.nowIso8601()}'
                self.worker = SaltActionDoer(self.vault, create=(party, name), auths=auths)
            elif self.body is None:
                self.body = self.actions.prepare(self.local.currentData(), self.registry.currentData(),
                    self.recipient.currentData(), self.target.text().strip() or None)
                self._preview()
                return
            else:
                self.worker = SaltActionDoer(self.vault, self.body, proposal=self.proposal)
            self.vault.extend([self.worker])
            self.submit.setEnabled(False)
            self.page.message.setText('Action submitted. Recipient acceptance is separate from transmission.')
            self.close()
        except (kering.KeriError, ValueError, KeyError) as ex:
            self.show_error(str(ex))


class RegistryAccessPage(QWidget):
    """Show public status and explicit actions; own no processor or background timer."""

    def __init__(self, parent):
        """Use the existing VaultPage parent and its current application vault."""
        super().__init__(parent)
        self.app, self.dialog, self._vault = parent.app, None, None
        self.rows = []
        layout = QVBoxLayout(self)
        title = QLabel('Registry access')
        title.setStyleSheet('font-size: 22px; font-weight: bold;')
        layout.addWidget(title)
        help_text = QLabel('Create issuer registries and share encrypted salts for state disclosure. Sharing a salt does not grant registry signing authority.')
        help_text.setWordWrap(True)
        layout.addWidget(help_text)
        buttons = QHBoxLayout()
        for label, action in (('Create registry', 'create'), ('Share encrypted salt', 'share')):
            button = LocksmithButton(label)
            button.clicked.connect(lambda _=False, action=action: self.open_action(action))
            buttons.addWidget(button)
        refresh = LocksmithInvertedButton('Refresh')
        refresh.clicked.connect(self.refresh)
        buttons.addWidget(refresh)
        layout.addLayout(buttons)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(['Item', 'Party', 'Registry / statement', 'Progress'])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self._selection)
        layout.addWidget(self.table)
        controls = QGridLayout()
        self.action_buttons = {}
        for index, (label, action) in enumerate((('Review proposal', 'proposal'),)):
            button = LocksmithInvertedButton(label)
            button.clicked.connect(lambda _=False, action=action: self.open_action(action))
            controls.addWidget(button, index // 3, index % 3)
            self.action_buttons[action] = button
        layout.addLayout(controls)
        self.message = QLabel('Select an item to review its available actions.')
        self.message.setWordWrap(True)
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.message)
        self._selection()

    def on_show(self, **params):
        """Refresh on navigation; params are ordinary page navigation metadata."""
        self.refresh()

    def showEvent(self, event):
        """Refresh when the existing stacked navigation first displays this page."""
        super().showEvent(event)
        self.refresh()

    def refresh(self, *_):
        """Read public progress and borrow the vault's existing progress signal."""
        vault = self.app.vault
        if vault is None or vault.closed:
            self.rows = []
            self.table.setRowCount(0)
            return
        if self._vault is not vault:
            if self._vault is not None:
                try:
                    self._vault.signals.doer_event.disconnect(self._changed)
                except RuntimeError:
                    pass
            vault.signals.doer_event.connect(self._changed)
            self._vault = vault
        try:
            self.rows = SaltActions(vault).snapshot()
            self.table.setRowCount(len(self.rows))
            for index, row in enumerate(self.rows):
                progress = row.get('route', '').rsplit('/', 1)[-1]
                if row['kind'] == 'registry':
                    progress = 'Encrypted salt recorded locally' if row['root_recorded'] else 'No local salt'
                for column, value in enumerate((row['kind'].capitalize(), identifier_name(vault, row['party']),
                                                 row['registry'] or row['said'], progress)):
                    item = QTableWidgetItem(value)
                    item.setToolTip(value)
                    self.table.setItem(index, column, item)
            self.table.resizeColumnsToContents()
            self._selection()
        except kering.KeriError as ex:
            self.message.setText(str(ex))
        except Exception:
            self.message.setText('Registry access status is unavailable')

    def _changed(self, name, event, data):
        """Display existing finite-action progress; receiving signals grants no consent."""
        if name == 'RegistryAccess':
            result = data.get('result') or {}
            self.message.setText(data.get('error') or '; '.join(str(result.get(key, ''))
                                    for key in ('state', 'transport') if result.get(key)))
            self.refresh()

    def selected(self):
        """Return the selected public snapshot row, or None."""
        index = self.table.currentRow()
        return self.rows[index] if 0 <= index < len(self.rows) else None

    def _selection(self):
        """Expose only actions appropriate to the selected public item type."""
        row = self.selected() or {}
        available = dict(proposal=row.get('kind') == 'proposal')
        for action, button in self.action_buttons.items():
            button.setEnabled(available[action])

    def open_action(self, action, row=None):
        """Open one explicit action dialog; construction never signs a statement."""
        if self.app.vault is None or self.app.vault.closed:
            return
        self.dialog = RegistryAccessDialog(self, action, row or self.selected())
        self.dialog.open()

    def show_proposal(self, said):
        """Open exact retained proposal said from the existing notification entry."""
        self.refresh()
        row = next((row for row in self.rows if row['kind'] == 'proposal' and row['said'] == said), None)
        if row is not None:
            self.open_action('proposal', row)
        else:
            self.message.setText('This registry proposal is unavailable; retain its notification until evidence is ready.')
