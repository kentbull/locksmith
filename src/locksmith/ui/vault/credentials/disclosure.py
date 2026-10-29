"""Explicit retained-view and optional state-opening controls for presentation.

Local wallet UX over credentialing.admissions and the existing composer options.
Selecting a grant never merges information from another grant. Refreshing state
never adds credential attributes or shares a derivation salt with the recipient.
"""
from pathlib import Path

from PySide6.QtCore import Signal, QSignalBlocker
from PySide6.QtWidgets import QWidget, QVBoxLayout, QFileDialog, QLabel
from locksmith.core import credentialing
from locksmith.ui.toolkit.widgets import LocksmithInvertedButton, LocksmithCheckbox
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox, FloatingLabelLineEdit


class DisclosureOptions(QWidget):
    """Keep content selection separate from optional registry-state capabilities."""

    changed = Signal()

    def __init__(self, vault, parent=None):
        """Borrow vault for admission references; create no custody provider."""
        super().__init__(parent)
        self.vault, self.said, self.opening = vault, None, None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.grant_field = FloatingLabelComboBox('Material to present')
        self.grant = self.grant_field.combo_box
        self.grant.setAccessibleName('Received disclosure')
        layout.addWidget(self.grant_field)
        self.refresh = LocksmithCheckbox('Use current registry-state evidence')
        layout.addWidget(self.refresh)
        self.source_field = FloatingLabelComboBox('Registry-state opening source')
        self.source = self.source_field.combo_box
        self.source.setAccessibleName('Registry-state opening source')
        self.source.addItem('Use an opening already held', 'retained')
        self.source.addItem('Use a supplied event opening', 'supplied')
        self.source.addItem('Derive with provisioned registry custody', 'derive')
        layout.addWidget(self.source_field)
        self.bound_event = FloatingLabelLineEdit('Exact issuee event (optional)')
        self.bound_event.setToolTip('Select the accepted issuee KEL digest used by this bound opening; blank derives unbound state.')
        self.bound_event.line_edit.textChanged.connect(lambda *_: self.changed.emit())
        layout.addWidget(self.bound_event)
        self.choose = LocksmithInvertedButton('Choose event-opening file…')
        self.choose.clicked.connect(self._choose)
        layout.addWidget(self.choose)
        self.note = QLabel('This shares an event-specific state opening. The registry salt stays private; '
                           'withheld credential fields stay hidden.')
        self.note.setWordWrap(True)
        layout.addWidget(self.note)
        self.grant_field.currentIndexChanged.connect(lambda *_: self.changed.emit())
        self.refresh.toggled.connect(self._update)
        self.source.currentIndexChanged.connect(self._update)
        self._update()

    def select(self, said):
        """List only exact issued/admitted views of said, original receipt first."""
        if said == self.said:
            return
        self.said = said
        with QSignalBlocker(self.grant_field):
            self.grant.clear()
            if said:
                if self.vault.db.issued.get((said,)):
                    self.grant.addItem('Issued material', None)
                for record in credentialing.admissions(self.vault, said):
                    stamp = record.accepted_at or 'Earlier admission'
                    self.grant.addItem(f'{stamp} · {record.grant[:12]}…', record.grant)
        self.refresh.setChecked(False)
        self.source.setCurrentIndex(0)
        self.opening = None
        self.bound_event.line_edit.clear()
        self.choose.setText('Choose event-opening file…')
        self.choose.setToolTip('')

    def _update(self, *_):
        """Show advanced opening controls only when state refresh is selected."""
        enabled = self.refresh.isChecked()
        self.source_field.setVisible(enabled)
        self.bound_event.setVisible(enabled and self.source.currentData() == 'derive')
        self.note.setVisible(enabled)
        self.choose.setVisible(enabled and self.source.currentData() == 'supplied')
        self.changed.emit()

    def _choose(self):
        """Choose a public event opening; no salt import is hidden in this action."""
        path, _ = QFileDialog.getOpenFileName(self, 'Choose event-specific opening', '', 'CESR files (*.cesr);;All files (*)')
        if path:
            self.opening = path
            self.choose.setText('Event-opening file selected')
            self.choose.setToolTip(Path(path).name)
            self.changed.emit()

    def selection(self):
        """Return explicit composer options, validating selected file availability."""
        result = {'from_grant': self.grant.currentData()}
        if self.refresh.isChecked():
            result['refresh'] = True
            source = self.source.currentData()
            if source == 'derive':
                result['derive'] = True
                if event := self.bound_event.text().strip():
                    result['bound_event'] = event
            elif source == 'supplied':
                if not self.opening:
                    raise ValueError('Choose the event-specific opening to disclose')
                with Path(self.opening).open("rb") as stream:
                    raw = stream.read(16385)
                if not raw or len(raw) > 16384:
                    raise ValueError('Choose a bounded CESR event opening')
                result['openings'] = [raw]
        return result


class DisclosureFields(QWidget):
    """Choose supported committed attribute sections already present in a view."""

    changed = Signal()

    def __init__(self, parent=None):
        """Start with metadata-only Offer; each checked section reveals its values."""
        super().__init__(parent)
        self.key, self.fields = None, []
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(0, 0, 0, 0)

    def select(self, key, sad):
        """Populate from one exact view, never from fuller cached attributes.

        key identifies the selected credential/admission pair; sad is its retained
        body. Only expanded committed sections can be independently selected by
        this control. Empty selection preserves the existing metadata Offer.
        """
        if key == self.key:
            return
        self.key, self.fields = key, []
        while self.body.count():
            self.body.takeAt(0).widget().deleteLater()
        label = QLabel('Reveal these held sections in the offer (optional)')
        self.body.addWidget(label)
        attrs = sad.get('a', {})
        for name, value in attrs.items() if isinstance(attrs, dict) else ():
            if isinstance(value, dict) and 'd' in value and 'u' in value:
                field = LocksmithCheckbox(name)
                field.setAccessibleName('Disclose ' + name)
                field.toggled.connect(lambda *_: self.changed.emit())
                self.body.addWidget(field)
                self.fields.append((f'a/{name}/', field))
        self.setVisible(bool(self.fields))

    def paths(self):
        """Return only the sections explicitly checked in the current view."""
        return [path for path, field in self.fields if field.isChecked()]
