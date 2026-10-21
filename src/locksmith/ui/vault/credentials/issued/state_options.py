"""Explicit registry publication capability choices for the issuance form."""
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel

from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox
from locksmith.ui.vault.credentials.presentation import identifier_name


class StatePublicationOptions(QWidget):
    """Select public status, event openings, or optional future-opening custody."""

    def __init__(self, vault, parent=None):
        """Build controls over known identifiers without opening custody stores."""
        super().__init__(parent)
        self.registry = True
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.mode = FloatingLabelComboBox('Registry state publication')
        for label, value in [('Public state', 'public'),
                             ('Blinded state with individual openings', 'blinded'),
                             ('Blinded state with future-opening derivation', 'derived')]:
            self.mode.addItem(label, value)
        self.mode.setCurrentIndex(1)  # Preserve the established issuance default.
        layout.addWidget(self.mode)
        self.discloser = FloatingLabelComboBox('Designated state discloser')
        self.discloser.addItem('Issuer retains derivation locally', None)
        for prefix in vault.hby.kevers:
            self.discloser.addItem(identifier_name(vault, prefix), prefix)
        layout.addWidget(self.discloser)
        self.help = QLabel()
        self.help.setWordWrap(True)
        layout.addWidget(self.help)
        self.mode.currentIndexChanged.connect(self._refresh)
        self._refresh()

    def set_registry(self, enabled):
        """Hide inapplicable state controls for anchor/signature authentication."""
        self.registry = enabled
        self.setVisible(enabled)
        self._refresh()

    def _refresh(self, *_):
        """Explain the selected capability without implying salt transfer or delegation."""
        mode = self.mode.currentData()
        self.discloser.setVisible(self.registry and mode == 'derived')
        self.help.setText({
            'public': 'Registry status is public. No blinding secret is created.',
            'blinded': 'Presentations reveal the specific state opening they need.',
            'derived': 'Requires encrypted custody. Selecting a discloser does not send a secret or establish delegation; provision that capability separately.',
        }[mode])

    def selection(self):
        """Return only applicable explicit inputs for IssueCredentialDoer."""
        if not self.registry:
            return {}
        mode = self.mode.currentData()
        return {'registry_mode': mode,
                'discloser': self.discloser.currentData() if mode == 'derived' else None}
