"""Explicit registry access controls over the vault's existing protocol owners."""

import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QGridLayout, QHBoxLayout, QLabel, QPlainTextEdit,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)
from keri import kering
from keri.app import registry_salt_replies as replies
from keri.help import helping

from locksmith.core.salt_actions import SaltActions, SaltActionDoer
from locksmith.ui import colors
from locksmith.ui.toolkit.widgets import LocksmithButton, LocksmithDialog, LocksmithInvertedButton
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox, FloatingLabelLineEdit
from locksmith.ui.vault.credentials.presentation import identifier_name
from locksmith.ui.vault.shared.witness_auth_mixin import WitnessAuthenticationPanel


class RegistryAccessDialog(LocksmithDialog):
    """Collect a named local action, then show its exact public statement."""

    def __init__(self, page, action, row=None):
        """Use page's current vault; action selects one fixed registry operation."""
        self.page, self.vault, self.action = page, page.app.vault, action
        self.actions, self.row = SaltActions(self.vault), row or {}
        self.body, self.proposal, self.worker = None, None, None
        content = QWidget()
        self.form = QVBoxLayout(content)
        self.form.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.form.setSpacing(12)
        self.local = FloatingLabelComboBox('Local party approving this action')
        self.local.addItem('Choose a local party', None)
        for hab in self.vault.hby.habs.values():
            if hab.accepted:
                self.local.addItem(identifier_name(self.vault, hab.pre), hab.pre)
        self.form.addWidget(self.local)
        selected = self.row.get('party')
        if selected:
            self.local.setCurrentIndex(max(0, self.local.combo_box.findData(selected)))
        self.issuer = self._parties('Registry issuer')
        self.discloser = self._parties('Initial state discloser')
        self.recipient = self._parties('Additional entitled discloser')
        self.registry = FloatingLabelComboBox('Accepted registry')
        self.registry.addItem('Choose an accepted registry', None)
        for (regk,), _ in self.vault.rgy.baser.heads.getTopItemIter():
            rip = self.vault.rgy.store.seqEvent(regk, 0)
            if rip:
                self.registry.addItem(regk, regk)
        self.form.addWidget(self.registry)
        self.name = FloatingLabelLineEdit('Registry name')
        self.form.addWidget(self.name)
        self.maps = {}
        for key, combo, label in (('issuer', self.issuer, 'Issuer signing members, in accepted order'),
                                  ('discloser', self.discloser, 'Discloser signing members, in accepted order'),
                                  ('recipient', self.recipient, 'Additional party signing members, in accepted order')):
            heading = QLabel(label)
            field = QPlainTextEdit()
            field.setPlaceholderText('One individual member AID per line; confirm this map against accepted history')
            field.setFixedHeight(68)
            field.setStyleSheet(f'border: 1px solid {colors.BORDER}; border-radius: 6px; padding: 6px;')
            self.form.addWidget(heading)
            self.form.addWidget(field)
            self.maps[key] = (heading, field)
            combo.currentIndexChanged.connect(lambda _=None, key=key, combo=combo: self._members(key, combo))
        self.local_members_heading = QLabel('Signing members of the local party, in accepted order')
        self.local_members = QPlainTextEdit()
        self.local_members.setFixedHeight(68)
        self.form.addWidget(self.local_members_heading)
        self.form.addWidget(self.local_members)
        self.local.currentIndexChanged.connect(self._local_members)
        self.human_summary = QLabel()
        self.human_summary.setWordWrap(True)
        self.human_summary.setTextFormat(Qt.TextFormat.PlainText)
        self.human_summary.hide()
        self.form.addWidget(self.human_summary)
        self.sharing = QLabel()
        self.sharing.setWordWrap(True)
        self.sharing.setTextFormat(Qt.TextFormat.PlainText)
        self.sharing.hide()
        self.form.addWidget(self.sharing)
        self.details = LocksmithInvertedButton('Show exact statement details')
        self.details.setCheckable(True)
        self.details.clicked.connect(self._details)
        self.details.hide()
        self.form.addWidget(self.details)
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setMinimumHeight(360)
        self.preview.setMaximumHeight(420)
        self.preview.hide()
        self.form.addWidget(self.preview)
        self.explanation = QLabel('Registry access is optional. Receiving or viewing a request never approves it.')
        self.explanation.setWordWrap(True)
        self.form.addWidget(self.explanation)
        self.auth = None
        cancel = LocksmithInvertedButton('Cancel')
        self.submit = LocksmithButton('Review exact statement')
        buttons = QHBoxLayout()
        buttons.addWidget(cancel)
        buttons.addWidget(self.submit)
        titles = dict(start='Start registry access', bind='Bind registry access',
                      confirm='Confirm registry access', assign='Add state discloser',
                      recover='Recover retained agreement', proposal='Review group proposal',
                      create='Create registry', reconcile='Replicate to accepted members',
                      roster='Confirm accepted member map')
        super().__init__(page, title=titles[action], content=content, buttons=buttons)
        cancel.clicked.connect(self.close)
        self.submit.clicked.connect(self._submit)
        for widget in (self.issuer, self.discloser):
            widget.setVisible(action == 'start')
        self.recipient.setVisible(action in ('assign', 'roster'))
        if action == 'roster':
            self.local.hide()
        self.registry.setVisible(action in ('start', 'bind'))
        if action == 'start':
            self.registry.setPlaceholderText('Share public registry evidence (binding is approved separately)')
        self.name.setVisible(action == 'create')
        for key, (label, field) in self.maps.items():
            label.setVisible(action in ('assign', 'roster') if key == 'recipient' else action == 'start')
            field.setVisible(label.isVisibleTo(content))
        self.local_members_heading.setVisible(action == 'reconcile')
        self.local_members.setVisible(action == 'reconcile')
        if action == 'proposal':
            try:
                self.body, anchor, opening = self.actions.inspect(self.row['said'])
                self.proposal = self.row['said']
                self.local.setCurrentIndex(max(0, self.local.combo_box.findData(
                    anchor.pre if anchor is not None else self.body.pre)))
                self.local.setEnabled(False)
                self._show_preview(anchor, opening)
            except kering.KeriError as ex:
                self.show_error(str(ex))
                self.submit.setEnabled(False)
        elif action in ('create', 'reconcile', 'roster'):
            self.submit.setText(dict(create='Create and anchor registry',
                reconcile='Confirm member replication', roster='Confirm accepted member map')[action])
        self._local_members()
        self.form.invalidate()
        self.form.activate()
        self.fit_content(720)

    def _parties(self, label):
        """Build a known-AID choice; labels confer no signing or custody authority."""
        combo = FloatingLabelComboBox(label)
        combo.addItem('Choose an identifier', None)
        for pre in sorted(self.vault.hby.kevers, key=lambda aid: identifier_name(self.vault, aid)):
            combo.addItem(identifier_name(self.vault, pre), pre)
        self.form.addWidget(combo)
        return combo

    def _members(self, key, combo):
        """Prefill only an individual or trusted accepted ordered group mapping."""
        _, field = self.maps[key]
        try:
            field.setPlainText('\n'.join(self.actions.roster(combo.currentData())))
        except kering.KeriError as ex:
            field.clear()
            self.show_error(str(ex))

    def _local_members(self, *_):
        """Display the current accepted local map for explicit reconciliation."""
        if self.action == 'reconcile':
            try:
                self.local_members.setPlainText('\n'.join(self.actions.roster(self.local.currentData())))
            except kering.KeriError:
                self.local_members.clear()

    def _trust(self, party, text):
        """Submit the operator's explicit ordered member AIDs to core validation."""
        if not party:
            raise ValueError('Choose both parties before starting registry access')
        self.actions.trust(party, [line.strip() for line in text.splitlines() if line.strip()])

    def _show_preview(self, anchor=None, opening=None):
        """Show the exact public reply/TEL and optional public anchor/opening."""
        summary = self.actions.summary(self.body)
        lines = [summary['title'], *(role + ': ' + identifier_name(self.vault, aid)
                                   for role, aid in summary['parties'])]
        if summary['registry']:
            lines.append('Registry: ' + summary['registry'])
        lines.append(summary['capability'])
        self.human_summary.setText('\n'.join(lines))
        self.human_summary.show()
        details = dict(statement=self.body.sad)
        if self.action == 'start' and self.registry.currentData():
            details['public_evidence_to_share'] = dict(registry=self.registry.currentData(),
                notice='Public controller KEL and accepted inception only. Binding is approved separately.')
            self.sharing.setText('Share public registry evidence: ' + self.registry.currentData()
                                 + '\nPublic controller KEL and inception only. Binding is approved separately.')
            self.sharing.show()
        if anchor is not None:
            details['group_anchor'] = anchor.sad
        if opening is not None:
            details['published_event_opening'] = opening.qb64
        self.preview.setPlainText(json.dumps(details, indent=2))
        self.details.show()
        self.preview.setVisible(self.details.isChecked())
        self.submit.setText('Approve exact statement and send')
        self.explanation.setText('Approval signs exactly this statement. Group quorum, transport submission and retained custody are separate outcomes.')
        if self.action == 'recover':
            self.explanation.setText('An authenticated frame is resent unchanged. Peer acceptance is unconfirmed; changed representative state can block it. Established custody can be replicated separately.')
        for index in range(self.form.count()):
            widget = self.form.itemAt(index).widget()
            if widget is not None and widget not in (self.preview, self.explanation, self.sharing,
                                                     self.human_summary, self.details):
                widget.hide()
        self.form.invalidate()
        self.form.activate()
        self.fit_content(720)

    def _details(self, visible):
        """Show optional exact JSON without changing the displayed approval body."""
        self.preview.setVisible(visible)
        self.details.setText('Hide exact statement details' if visible else 'Show exact statement details')
        self.form.invalidate()
        self.form.activate()
        self.fit_content(720)

    def _submit(self):
        """Validate selected inputs, preview exact work, then schedule explicit approval."""
        try:
            if self.page.app.vault is not self.vault or self.vault.closed:
                raise ValueError('This vault is closed')
            if self.action == 'roster':
                self._trust(self.recipient.currentData(), self.maps['recipient'][1].toPlainText())
                self.page.message.setText('Accepted member map recorded. This grants no root entitlement.')
                self.close()
                return
            party = self.local.currentData()
            self.actions.local(party)
            if self.action == 'reconcile':
                self._trust(party, self.local_members.toPlainText())
                self.actions.service.reconcile(self.row['registry'], party)
                self.vault.salts.reconcile()
                self.page.refresh()
                self.close()
                return
            if self.action == 'create':
                name = self.name.text().strip()
                if not name:
                    raise ValueError('Enter a registry name')
                hab = self.actions.local(party)
                if hab.kever.wits and self.auth is None and not hasattr(hab, 'mhab'):
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
                    auths = {wit: f'{code}#{helping.nowIso8601()}' for wit, code in
                             (entry.split(':', 1) for entry in codes)}
                self.worker = SaltActionDoer(self.vault, create=(party, name), auths=auths)
            elif self.body is None:
                values = {}
                data = self.row.get('body').sad['a'] if self.row.get('body') else {}
                if self.action == 'start':
                    for key, combo in (('issuer', self.issuer), ('discloser', self.discloser)):
                        values[key] = combo.currentData()
                        self._trust(values[key], self.maps[key][1].toPlainText())
                    if self.registry.currentData():
                        self.actions.acceptedRegistry(self.registry.currentData(), values['issuer'])
                elif self.action == 'bind':
                    values = dict(init=self.row['said'], registry=self.registry.currentData())
                    if not values['registry']:
                        raise ValueError('Choose an accepted issuer registry')
                elif self.action == 'confirm':
                    values = dict(init=data['init'], bind=self.row['said'])
                elif self.action == 'assign':
                    recipient = self.recipient.currentData()
                    self._trust(recipient, self.maps['recipient'][1].toPlainText())
                    values = dict(origin=self.row.get('origin') or self.row['said'], recipient=recipient)
                elif self.action == 'recover':
                    values = dict(init=data.get('init', self.row['said']),
                                  statement=self.row['said'] if self.row.get('kind') == 'statement' else None)
                self.body = self.actions.prepare(self.action, party, **values)
                self._show_preview()
                return
            else:
                self.worker = SaltActionDoer(self.vault, self.body, proposal=self.proposal,
                    registryEvidence=self.registry.currentData() if self.action == 'start' else None)
            self.vault.extend([self.worker])
            self.submit.setEnabled(False)
            self.page.message.setText('Action submitted to the vault. Refresh to inspect authenticated progress.')
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
        help_text = QLabel('Establish shared future state-opening custody by explicit agreement. Registry signing authority and credential exchange remain separate.')
        help_text.setWordWrap(True)
        layout.addWidget(help_text)
        buttons = QHBoxLayout()
        for label, action in (('Create registry', 'create'), ('Start agreement', 'start'),
                              ('Confirm member map', 'roster')):
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
        for index, (label, action) in enumerate((('Review proposal', 'proposal'), ('Bind', 'bind'), ('Confirm', 'confirm'),
                              ('Add discloser', 'assign'), ('Recover exact draft', 'recover'),
                              ('Replicate members', 'reconcile'))):
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
                    progress = ('Origin recorded; ' if row['origin'] else 'No agreement; ')
                    progress += 'encrypted root recorded' if row['root_recorded'] else 'no root recorded'
                    progress += f"; deliveries {row['deliveries']}"
                    if row['error']:
                        progress += '; ' + row['error']
                elif row['kind'] == 'draft':
                    progress = 'Encrypted draft retained; explicit recovery required'
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
        route = row.get('route')
        available = dict(proposal=row.get('kind') == 'proposal', bind=route == replies.INIT_ROUTE,
                         confirm=route == replies.BIND_ROUTE,
                         assign=route == replies.CONFIRM_ROUTE or bool(row.get('origin')),
                         recover=row.get('kind') in ('draft', 'statement'),
                         reconcile=row.get('kind') == 'registry' and bool(row.get('origin')))
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
