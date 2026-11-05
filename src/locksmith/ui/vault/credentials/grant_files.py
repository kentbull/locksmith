"""Signed disclosed Grant files: preparation, issuer consent and local registration."""
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel, QVBoxLayout, QWidget
from keri.app.habbing import GroupHab
from keri.help import helping

from locksmith.core import credentialing, grant_files
from locksmith.ui.toolkit.widgets import LocksmithButton, LocksmithDialog, LocksmithInvertedButton
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox, FloatingLabelLineEdit
from locksmith.ui.vault.credentials.disclosure import DisclosureFields, DisclosureOptions
from locksmith.ui.vault.credentials.presentation import credential_details, identifier_name


class GrantFilesDialog(LocksmithDialog):
    """All file inspection is ephemeral; every signature/registration needs an explicit action."""

    def __init__(self, app, parent, said=None):
        self.app, self.vault, self.said, self.raw = app, app.vault, said, None
        self.contributions = []
        content = QWidget()
        layout = QVBoxLayout(content)
        self.mode = FloatingLabelComboBox('Action')
        for name, value in ([('Prepare signed presentation', 'prepare'),
                            ('Contribute to group proposal', 'contribute'),
                            ('Export prepared group Grant', 'export'),
                            ('Resume prepared presentation', 'resume')]
                            if said else [('Endorse inspected presentation', 'endorse')]):
            self.mode.addItem(name, value)
        self.identity = FloatingLabelComboBox('Local signing identifier')
        for hab in self.vault.hby.habs.values():
            self.identity.addItem(identifier_name(self.vault, hab.pre), hab.pre)
        self.recipient = FloatingLabelComboBox('Verifier')
        for pre in self.vault.hby.kevers:
            if pre not in self.vault.hby.prefixes:
                self.recipient.addItem(identifier_name(self.vault, pre), pre)
        self.message = FloatingLabelLineEdit('Message')
        self.disclosure = DisclosureOptions(self.vault)
        self.fields = DisclosureFields()
        self.preparation = FloatingLabelComboBox('Existing local preparation')
        self.preview = QWidget()
        QVBoxLayout(self.preview)
        self.status = QLabel('These signed files disclose credential material; they are not encrypted root files. '
                             'No action here sends a Grant, approves state openings or admits a credential.')
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        for widget in (self.mode, self.identity, self.recipient, self.message, self.disclosure,
                       self.fields, self.preparation, self.preview, self.status):
            layout.addWidget(widget)
        self.choose = LocksmithInvertedButton('Inspect signed Grant file…')
        self.add_contribution = LocksmithInvertedButton('Inspect issuer contribution…')
        self.deliver = LocksmithInvertedButton('Deliver selected registered Grant')
        self.action = LocksmithButton('Prepare file…' if said else 'Endorse and export…')
        close = self.close_button = LocksmithInvertedButton('Cancel')
        buttons = QHBoxLayout()
        for button in (self.choose, self.add_contribution, self.action, self.deliver, close):
            buttons.addWidget(button)
        super().__init__(parent=parent, title='Signed presentation files', content=content, buttons=buttons)
        close.clicked.connect(self.close)
        self.finished.connect(lambda *_: setattr(self, 'raw', None))
        self.finished.connect(lambda *_: self.contributions.clear())
        self.choose.clicked.connect(self._choose)
        self.add_contribution.clicked.connect(self._contribution)
        self.action.clicked.connect(self._act)
        self.deliver.clicked.connect(self._deliver)
        self.mode.currentIndexChanged.connect(self._mode)
        self.disclosure.changed.connect(self._view)
        self.fields.changed.connect(self._view)
        if said:
            self.disclosure.select(said)
            for store in (self.vault.hby.db.exns, self.vault.hby.db.epse):
                for _, body in store.getTopItemIter():
                    if (body.route == '/ipex/grant' and body.pre in self.vault.hby.prefixes
                            and body.sad['a'].get('o') == [said]
                            and self.preparation.combo_box.findData(body.said) < 0):
                        deadline = self.vault.exc.exchangeDeadline(body)
                        self.preparation.addItem(body.said + ' · ' +
                            (helping.toIso8601(deadline) if deadline else 'deadline unavailable'), body.said)
            self._view()
        self.disclosure.refresh.hide()
        self._mode()
        self.fit_content(680)

    def _current(self):
        if self.app.vault is not self.vault or self.vault.closed:
            raise ValueError('This vault is closed; inspect again in the current vault')

    def _mode(self, *_):
        mode = self.mode.currentData()
        for widget in (self.disclosure, self.fields, self.recipient, self.message):
            widget.setVisible(mode != 'endorse')
        self.preparation.setVisible(mode in ('resume', 'export'))
        self.choose.setVisible(mode not in ('prepare', 'export'))
        self.add_contribution.setVisible(mode == 'endorse')
        self.deliver.setVisible(mode == 'resume')
        self.action.setText({'prepare': 'Prepare file…', 'endorse': 'Endorse and export…',
                             'contribute': 'Sign and export group proposal…',
                             'export': 'Export thresholded Grant…',
                             'resume': 'Register endorsed Grant locally'}[mode])
        self.raw = None
        self.contributions.clear()

    def _view(self, *_):
        if not self.said:
            return
        try:
            self._current()
            view = credentialing.credential(self.vault, self.said, grant=self.disclosure.grant.currentData())
            self.fields.select((self.said, view['grant']), view['sad'])
            if self.fields.body.count():
                self.fields.body.itemAt(0).widget().setText('Reveal selected held sections; none preserves the exact held view.')
            self.identity.setCurrentIndex(self.identity.combo_box.findData(view['recipient']))
        except Exception as error:
            self.status.setText(str(error))

    def _choose(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Inspect signed presentation', '', 'CESR (*.cesr)')
        if path:
            self.inspect_file(path)

    def inspect_file(self, path):
        self.raw = None
        try:
            self._current()
            with Path(path).open('rb') as source:
                raw = source.read(1048577)
            if self.mode.currentData() == 'contribute':
                packet = grant_files.inspect_proposal(raw)
                item = packet.nests[0]
            else:
                item = grant_files.inspect(raw)
            self.status.setText(f"Unauthenticated file claims\nGrant: {item.serder.said}\n"
                f"Discloser: {item.serder.pre}\nVerifier: {item.serder.sad['ri']}\n"
                f"Signed at: {item.serder.stamp}\nMessage: {item.serder.sad['a'].get('m', '')}\n"
                'Registries: ' + ', '.join(dict.fromkeys(node.serder.regid for node in item.nests if node.serder.regid)))
            layout = self.preview.layout()
            while layout.count():
                layout.takeAt(0).widget().deleteLater()
            for node in item.nests:
                layout.addWidget(credential_details(self.vault, node.serder.sad))
            self.raw = raw
            self.contributions.clear()
        except Exception as error:
            self.status.setText(str(error))
        self.fit_content(680)

    def _contribution(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Inspect issuer contribution', '', 'CESR (*.cesr)')
        if not path:
            return
        try:
            self._current()
            if self.raw is None:
                raise ValueError('Inspect the original prepared Grant first')
            with Path(path).open('rb') as source:
                raw = source.read(1048577)
            original, item = grant_files.inspect(self.raw), grant_files.inspect(raw)
            if item.serder.raw != original.serder.raw or grant_files.nodes(item) != grant_files.nodes(original):
                raise ValueError('Contribution changes the displayed Grant or nested proof')
            self.contributions.append(raw)
            self.status.setText(self.status.text() + f'\nInspected issuer contribution {len(self.contributions)}; authentication occurs on approval.')
        except Exception as error:
            self.status.setText(str(error))

    def _options(self):
        return dict(aid=self.identity.currentData(), said=self.said,
            source=self.disclosure.grant.currentData(), recipient=self.recipient.currentData(),
            message=self.message.text(), paths=self.fields.paths())

    def write_file(self, path):
        """Explicit file action, retaining the native body and original deadline."""
        self._current()
        if self.mode.currentData() == 'prepare':
            hab = self.vault.hby.habByPre(self.identity.currentData())
            if isinstance(hab, GroupHab):
                said, _, raw, deadline = grant_files.prepare_group(self.vault, **self._options())
            else:
                said, raw, deadline = grant_files.prepare(self.vault, **self._options())
            status = f'Prepared {said}\nOriginal deadline: {deadline}\nNot sent or approved for state-opening replies.'
            if isinstance(hab, GroupHab):
                status += '\nGroup proposal: collect member contributions before exporting the thresholded Grant.'
            self.preparation.addItem(said, said)
        elif self.mode.currentData() == 'contribute':
            if self.raw is None:
                raise ValueError('Inspect the exact group proposal first')
            said, _, raw, deadline = grant_files.contribute_group(self.vault, self.raw, **self._options())
            self.preparation.addItem(said, said)
            status = f'Contributed to exact Grant {said}; original deadline: {deadline}.\nExport the prepared Grant once its sender threshold is complete.'
        elif self.mode.currentData() == 'export':
            raw, deadline = grant_files.export_prepared(self.vault, self.preparation.currentData(), **self._options())
            status = f'Sender threshold complete; original deadline: {deadline}. Issuer endorsement can be collected separately.'
        elif self.mode.currentData() == 'endorse':
            if self.raw is None:
                raise ValueError('Inspect the exact signed Grant before endorsing')
            item = grant_files.inspect(self.raw)
            raw = grant_files.endorse(self.vault, self.raw, issuer=self.identity.currentData(),
                grant=item.serder.said, sender=item.serder.pre, recipient=item.serder.sad['ri'],
                contributions=self.contributions)
            complete = grant_files.endorsement_complete(self.vault, raw)
            status = (f'Issuer endorsed the unchanged Grant {item.serder.said}; not sent.' if complete else
                      f'Issuer signature contributed to {item.serder.said}; incomplete group threshold. Share this contribution with another issuer member alongside the original Grant.')
        else:
            raise ValueError('Resume registers an existing preparation; it does not create another signed file')
        with Path(path).open('xb') as output:
            output.write(raw)
        self.status.setText(status)
        self.fit_content(680)

    def _act(self):
        try:
            self._current()
            if self.mode.currentData() == 'resume':
                if self.raw is None:
                    raise ValueError('Select an existing local preparation, then inspect its endorsed file')
                _, deadline = grant_files.resume(self.vault, self.raw,
                    grant=self.preparation.currentData(), **self._options())
                self.status.setText(f'Final endorsed Grant registered locally. Original deadline: {deadline}\n'
                                    'Delivery, state-opening responses and credential admission remain unapproved.')
            else:
                path, _ = QFileDialog.getSaveFileName(self, self.action.text(), '', 'CESR (*.cesr)')
                if path:
                    self.write_file(path)
        except Exception as error:
            self.status.setText(str(error))
        self.fit_content(680)

    def _deliver(self):
        """Authorize transport only; Activity obtains separate proof-release approval."""
        try:
            self._current()
            options = self._options()
            hab = self.vault.hby.habByPre(options.pop('aid'))
            if hab is None:
                raise ValueError('Select the local discloser')
            self.vault.auxiliary.deliver_prepared(hab, self.preparation.currentData(), **options)
            self.close_button.setText('Close')
            self.status.setText('Delivery authorized for the exact registered Grant. '
                'Review state openings in Activity when the recipient requests them; release needs separate approval.')
        except Exception as error:
            self.status.setText(str(error))
        self.fit_content(680)
