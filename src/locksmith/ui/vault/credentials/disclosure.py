"""Explicit retained-view and optional state-opening controls for presentation.

Local wallet UX over credentialing.admissions and the existing composer options.
Selecting a grant never merges information from another grant. Refreshing state
never adds credential attributes or shares a derivation salt with the recipient.
"""
from pathlib import Path

from PySide6.QtCore import Signal, QSignalBlocker
from PySide6.QtWidgets import QWidget, QVBoxLayout, QComboBox, QCheckBox, QPushButton, QFileDialog, QLabel
from locksmith.core import credentialing


class DisclosureOptions(QWidget):
    """Keep content selection separate from optional registry-state capabilities."""

    changed = Signal()

    def __init__(self, vault, parent=None):
        """Borrow vault for admission references; create no custody provider."""
        super().__init__(parent)
        self.vault, self.said, self.opening = vault, None, None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(QLabel('Material to present'))
        self.grant = QComboBox()
        self.grant.setAccessibleName('Received disclosure')
        layout.addWidget(self.grant)
        self.refresh = QCheckBox('Use current registry-state evidence')
        layout.addWidget(self.refresh)
        self.source = QComboBox()
        self.source.setAccessibleName('Registry-state opening source')
        self.source.addItem('Use an opening already held', 'retained')
        self.source.addItem('Use a supplied event opening', 'supplied')
        self.source.addItem('Derive with provisioned registry custody', 'derive')
        layout.addWidget(self.source)
        self.choose = QPushButton('Choose event-opening file…')
        self.choose.clicked.connect(self._choose)
        layout.addWidget(self.choose)
        self.note = QLabel('Registry-state proof does not reveal withheld credential fields. '
                           'Derivation uses local custody; it does not send the salt.')
        self.note.setWordWrap(True)
        layout.addWidget(self.note)
        self.grant.currentIndexChanged.connect(self.changed.emit)
        self.refresh.toggled.connect(self._update)
        self.source.currentIndexChanged.connect(self._update)
        self._update()

    def select(self, said):
        """List only exact issued/admitted views of said, original receipt first."""
        if said == self.said:
            return
        self.said = said
        with QSignalBlocker(self.grant):
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
        self.choose.setText('Choose event-opening file…')

    def _update(self, *_):
        """Show advanced opening controls only when state refresh is selected."""
        enabled = self.refresh.isChecked()
        self.source.setVisible(enabled)
        self.note.setVisible(enabled)
        self.choose.setVisible(enabled and self.source.currentData() == 'supplied')
        self.changed.emit()

    def _choose(self):
        """Choose a public event opening; no salt import is hidden in this action."""
        path, _ = QFileDialog.getOpenFileName(self, 'Choose event-specific opening', '', 'CESR files (*.cesr);;All files (*)')
        if path:
            self.opening = path
            self.choose.setText(Path(path).name)
            self.changed.emit()

    def selection(self):
        """Return explicit composer options, validating selected file availability."""
        result = {'from_grant': self.grant.currentData()}
        if self.refresh.isChecked():
            result['refresh'] = True
            source = self.source.currentData()
            if source == 'derive':
                result['derive'] = True
            elif source == 'supplied':
                if not self.opening:
                    raise ValueError('Choose the event-specific opening to disclose')
                with Path(self.opening).open("rb") as stream:
                    raw = stream.read(16385)
                if not raw or len(raw) > 16384:
                    raise ValueError('Choose a bounded CESR event opening')
                result['openings'] = [raw]
        return result
