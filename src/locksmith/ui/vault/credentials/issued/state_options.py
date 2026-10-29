"""Explicit registry publication capability choices for the issuance form."""
from PySide6.QtCore import QSignalBlocker
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel

from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox, FloatingLabelLineEdit
from locksmith.ui.vault.credentials.presentation import identifier_name


class StatePublicationOptions(QWidget):
    """Select public status, event openings, or optional future-opening custody."""

    def __init__(self, vault, parent=None):
        """Build controls over known identifiers without opening custody stores."""
        super().__init__(parent)
        self.vault = vault
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
        self.established = FloatingLabelComboBox('Established registry')
        self.established.addItem('Choose an established registry', None)
        layout.addWidget(self.established)
        self.party = QLabel()
        self.party.setWordWrap(True)
        layout.addWidget(self.party)
        self.bound_event = FloatingLabelLineEdit('Exact current issuee event (optional)')
        self.bound_event.setToolTip('Binds the state opening to a verified current issuee KEL event; does not transfer authority.')
        layout.addWidget(self.bound_event)
        self.help = QLabel()
        self.help.setWordWrap(True)
        layout.addWidget(self.help)
        self.mode.currentIndexChanged.connect(self._refresh)
        self.established.currentIndexChanged.connect(self._refresh)
        self._refresh()

    def set_issuer(self, issuer):
        """Show the domain's recorded registries for the selected schema issuer.

        issuer is an AID or None. Preserve a still-eligible explicit selection;
        changing schemas never silently selects a different established root.
        This public snapshot neither decrypts custody nor promises usability.
        """
        selected = self.established.currentData()
        selected = selected['registry'] if selected else None
        with QSignalBlocker(self.established):
            self.established.clear()
            self.established.addItem('Choose an established registry', None)
            if issuer:
                for record in self.vault.salts.issuanceRegistries(issuer):
                    self.established.addItem(record['registry'], record)
                    if record['registry'] == selected:
                        self.established.setCurrentIndex(self.established.count() - 1)
        self._refresh()

    def set_registry(self, enabled):
        """Hide inapplicable state controls for anchor/signature authentication."""
        self.registry = enabled
        self.setVisible(enabled)
        self._refresh()

    def _refresh(self, *_):
        """Explain the selected capability without implying salt transfer or delegation."""
        mode = self.mode.currentData()
        self.established.setVisible(self.registry and mode == 'derived')
        self.party.setVisible(self.registry and mode == 'derived')
        record = self.established.currentData()
        self.party.setText('State discloser: ' + identifier_name(self.vault, record['discloser'])
                           if record else 'Establish registry access before using future-opening derivation.')
        self.bound_event.setVisible(self.registry and mode != 'public')
        self.help.setText({
            'public': 'The event-specific status opening is published. No reusable derivation custody is created.',
            'blinded': 'Presentations reveal the specific state opening they need.',
            'derived': 'Uses the selected registry and its established state-disclosure capability. Issuing a credential does not change or share that capability.',
        }[mode])

    def selection(self):
        """Return only applicable explicit inputs for IssueCredentialDoer."""
        if not self.registry:
            return {}
        mode = self.mode.currentData()
        result = {'registry_mode': mode, 'discloser': None}
        if mode == 'derived':
            record = self.established.currentData()
            if record is None:
                raise ValueError('Choose an established registry before derived issuance')
            result.update(registry_id=record['registry'], discloser=record['discloser'])
        if mode != 'public' and (event := self.bound_event.text().strip()):
            result['bound_event'] = event
        return result
