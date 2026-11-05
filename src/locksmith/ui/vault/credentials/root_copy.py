"""Encrypted root files, with inspection and explicit transfer consent."""
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel, QVBoxLayout, QWidget
from keri.app.habbing import GroupHab

from locksmith.core import credentialing, disclosing, root_copying
from locksmith.ui.toolkit.widgets import LocksmithButton, LocksmithDialog, LocksmithInvertedButton
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox, FloatingLabelLineEdit, LocksmithPlainTextEdit
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
                f'Recipient: {selected.recipient}\nEncryption target: {selected.target}\n'
                f'Registry: {selected.registry}\nReply: {selected.said}\n'
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


class GroupRootCopyDialog(LocksmithDialog):
    """Explicit group copy files, including members with no inventory row yet."""

    def __init__(self, app, parent, *, said=None, received=False):
        self.app, self.vault = app, app.vault
        self.inspected = []
        self.proposal = None
        content = QWidget()
        layout = QVBoxLayout(content)
        notice = QLabel('Copy an existing registry root to an authorized member. '
            'This permits future state-opening derivation; it neither joins the group nor accepts a credential. '
            'The sender group must sign the exact encrypted copy, and the target member must approve import.')
        notice.setWordWrap(True)
        layout.addWidget(notice)
        self.group = FloatingLabelComboBox('Local group')
        for hab in self.vault.hby.habs.values():
            if isinstance(hab, GroupHab) and hab.accepted and hab.mhab is not None:
                self.group.addItem(identifier_name(self.vault, hab.pre), hab.pre)
        self.mode = FloatingLabelComboBox('Action')
        for label, value in (('Prepare encrypted copy', 'prepare'), ('Contribute signature', 'contribute'),
                             ('Import encrypted copy', 'import')):
            self.mode.addItem(label, value)
        self.registry = FloatingLabelLineEdit('Registry SAID')
        self.coordinator = FloatingLabelLineEdit('Accepted group coordinator event SAID')
        self.recipient = FloatingLabelComboBox('Recipient AID (root owner)')
        self.target = FloatingLabelComboBox('Encryption target member AID')
        for pre in list(self.vault.hby.kevers):
            for combo in (self.recipient, self.target):
                combo.addItem(identifier_name(self.vault, pre), pre)
        self.event_field = FloatingLabelLineEdit('Accepted BUP event SAID')
        self.opening = LocksmithPlainTextEdit('Held CESR opening for that BUP')
        for widget in (self.group, self.mode, self.registry, self.coordinator,
                       self.recipient, self.target, self.event_field, self.opening):
            layout.addWidget(widget)
        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.inspect_button = LocksmithInvertedButton('Inspect file…')
        self.action = LocksmithButton('Prepare encrypted copy…')
        close = LocksmithInvertedButton('Close')
        buttons = QHBoxLayout()
        for button in (self.inspect_button, self.action, close):
            buttons.addWidget(button)
        super().__init__(parent=parent, title='Group registry roots', content=content, buttons=buttons)
        close.clicked.connect(self.close)
        self.inspect_button.clicked.connect(self._choose)
        self.action.clicked.connect(self._act)
        self.finished.connect(self._cancel)
        self.group.currentIndexChanged.connect(self._group_changed)
        self.mode.currentIndexChanged.connect(self._mode_changed)
        self._group_changed()
        if said is not None:
            view = credentialing.credential(self.vault, said, received=received)
            self.registry.setText(view['sad'].get('rd', ''))
            aid = view['recipient'] if received else view['sad']['i']
            self.group.setCurrentIndex(self.group.combo_box.findData(aid))
            held = root_copying.held_openings(self.vault, said, view['grant'] or None)
            if held:
                self.event_field.setText(held[-1][0])
                self.opening.setPlainText(held[-1][1].qb64)
        self._mode_changed()
        self.fit_content(660)

    def _current(self):
        if self.app.vault is not self.vault or self.vault.closed:
            raise ValueError('This vault is closed; inspect again in the current vault')
        hab = self.vault.hby.habByPre(self.group.currentData())
        if not isinstance(hab, GroupHab):
            raise ValueError('Select an accepted local group')
        return hab

    def _group_changed(self, *_):
        hab = self.vault.hby.habByPre(self.group.currentData())
        if isinstance(hab, GroupHab):
            self.coordinator.setText(hab.kever.serder.said)
            self.recipient.setCurrentIndex(self.recipient.combo_box.findData(hab.pre))
            self.target.setCurrentIndex(self.target.combo_box.findData(hab.mhab.pre))

    def _mode_changed(self, *_):
        self.inspected, self.proposal = [], None
        mode = self.mode.currentData()
        self.inspect_button.setVisible(mode != 'prepare')
        for widget in (self.coordinator, self.recipient, self.target):
            widget.setVisible(mode != 'import')
        for widget in (self.event_field, self.opening):
            widget.setVisible(mode == 'import')
        self.action.setText({'prepare': 'Prepare encrypted copy…', 'contribute': 'Approve and export signature…',
                             'import': 'Approve and import'}[mode])
        self.action.setEnabled(mode == 'prepare' and self.group.currentData() is not None)
        self.status.setText('Choose the exact accepted coordinator event. Only its elected member can prepare '
            'ciphertext, and that member must already hold the root.' if mode == 'prepare' else
            'Inspect the original custodian proposal before contributing.' if mode == 'contribute' else
            'Select all signature files for one exact reply and supply its held accepted BUP opening.')
        self.fit_content(660)

    def _coordinator(self, hab):
        event = self.vault.hby.db.evts.get((hab.pre, self.coordinator.text().strip()))
        if event is None:
            raise ValueError('Select an accepted coordinator event belonging to this group')
        return event.sn, event.said

    def _choose(self):
        paths, _ = QFileDialog.getOpenFileNames(self, 'Inspect group root files', '', 'CESR (*.cesr)')
        if paths:
            self.inspect_files(paths)

    def inspect_files(self, paths):
        """Show file claims without authorizing a signature or importing a root."""
        self.inspected, self.proposal = [], None
        self.action.setEnabled(False)
        try:
            self._current()
            raws = []
            for path in paths:
                if Path(path).stat().st_size > 65536:
                    raise ValueError('Select files of at most 64 KiB each')
                raws.append(Path(path).read_bytes())
            if self.mode.currentData() == 'contribute':
                if len(raws) != 1:
                    raise ValueError('Select the single original custodian proposal')
                self.proposal = root_copying.inspect_proposal(raws[0])
                selected = self.proposal.reply
            else:
                self.inspected = [root_copying.inspect(raw) for raw in raws]
                if not self.inspected:
                    raise ValueError('Select an encrypted reply file')
                selected = self.inspected[0]
                if any(item.said != selected.said for item in self.inspected):
                    raise ValueError('All signature files must describe the same encrypted reply')
            self.registry.setText(selected.registry)
            self.status.setText(f'Unauthenticated file claims\nSender: {selected.sender}\n'
                f'Recipient: {selected.recipient}\nTarget member: {selected.target}\n'
                f'Registry: {selected.registry}\nExact reply: {selected.said}\n'
                'Authentication occurs only when you approve the selected action.')
            self.action.setEnabled(True)
        except Exception as error:
            self.inspected, self.proposal = [], None
            self.status.setText(str(error))
        self.fit_content(660)

    def export_file(self, path):
        """Export an exact group reply; preparation also writes its member proposal."""
        hab = self._current()
        path = Path(path)
        prepare = self.mode.currentData() == 'prepare'
        proposal_path = path.with_name(path.stem + '.proposal.cesr')
        if path.exists() or prepare and proposal_path.exists():
            raise ValueError('Choose new output paths; existing files are not overwritten')
        args = (hab.pre, self.registry.text().strip(), self.recipient.currentData(),
                self.target.currentData(), self._coordinator(hab))
        if prepare:
            wire, proposal = self.vault.root_copies.prepare_group(*args)
            with proposal_path.open('xb') as output:
                output.write(proposal)
        else:
            if self.proposal is None:
                raise ValueError('Inspect the exact custodian proposal first')
            wire = self.vault.root_copies.contribute_group(self.proposal.wire, *args)
        with path.open('xb') as output:
            output.write(wire)
        self.status.setText(f'Encrypted reply exported: {path}\n'
            + (f'Member approval proposal: {proposal_path}\n' if prepare else '')
            + 'Recipient retention is unconfirmed. The recipient must import sufficient signatures explicitly.')
        self.fit_content(660)

    def _act(self):
        try:
            hab = self._current()
            if self.mode.currentData() == 'import':
                if not self.inspected:
                    raise ValueError('Inspect the exact encrypted reply files first')
                self.vault.root_copies.receive_group(self.inspected[0], hab.pre,
                    self.registry.text().strip(), self.event_field.text().strip(),
                    disclosing.opening(self.opening.toPlainText().strip()), contributions=self.inspected[1:])
                self.status.setText('Existing registry root retained under the group AID. '
                    'Credential admission and signing authority are unchanged.')
                self.action.setEnabled(False)
            else:
                path, _ = QFileDialog.getSaveFileName(self, 'Export group root reply', '', 'CESR (*.cesr)')
                if path:
                    self.export_file(path)
        except Exception as error:
            self.status.setText(str(error))
        self.fit_content(660)

    def _cancel(self, *_):
        self.inspected, self.proposal = [], None
        self.vault.root_copies.close()
