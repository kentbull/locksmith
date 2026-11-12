# -*- encoding: utf-8 -*-
"""
locksmith.ui.vault.credentials.issued.edge_operators module

Edge operator picker and link verdict badge for credential issuance.
"""
from PySide6.QtWidgets import QCheckBox, QLabel, QVBoxLayout, QWidget
from keri.acdc.evaluating import DelegativeEdgeOps, IssuerIdentityEdgeOps, UnaryEdgeOps

from locksmith.ui import colors
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox

# Display order and labels; NOT is unimplemented by verifiers and is not offered.
OPERATOR_LABELS = {
    'I2I': 'Issuee is my issuer (I2I)',
    'NI2I': 'No issuee check (NI2I)',
    'DI2I': 'Issuee or its delegate (DI2I)',
    'E1E': 'Same issuee (E1E)',
    'I1I': 'Same issuer (I1I)',
    'DI1I': 'Issuer or its delegate (DI1I)',
}
assert set(OPERATOR_LABELS) <= set(UnaryEdgeOps)

OPERATOR_HELP = {
    'I2I': "This credential's issuer must be the linked credential's issuee.",
    'NI2I': 'The linked credential must be valid; its issuee is not checked.',
    'DI2I': "This credential's issuer must be the linked credential's issuee or an identifier it delegated.",
    'E1E': 'Both credentials must have the same issuee.',
    'I1I': 'Both credentials must have the same issuer.',
    'DI1I': "This credential's issuer must be the linked credential's issuer or its anchored delegate.",
}

DEFAULT_HELP = ('No operator: verifiers require I2I when the linked credential has an issuee, '
                'otherwise NI2I.')

# Operators in one group conflict and the last listed wins, so the picker keeps one per group.
EXCLUSIVE_GROUPS = (tuple(DelegativeEdgeOps), tuple(IssuerIdentityEdgeOps))

VERDICT_BADGES = {
    'valid': ('✓ Valid link', colors.SUCCESS),
    'invalid': ('✗ Invalid link', colors.DANGER),
    'unknown': ('? Link not yet verifiable', colors.TEXT_SECONDARY),
}


def operator_choices(schema):
    """Return the operator tokens a leaf edge ``o`` schema permits, in display order."""
    allowed = None
    for detail in (schema, schema.get('items', {})):
        if isinstance(detail.get('enum'), list):
            allowed = {value for value in detail['enum'] if isinstance(value, str)}
        if isinstance(detail.get('const'), str):
            allowed = {detail['const']}
    return [token for token in OPERATOR_LABELS if allowed is None or token in allowed]


class EdgeOperatorPicker(QWidget):
    """Choose a leaf edge's unary operators from keripy's operator vocabulary.

    A schema whose ``o`` is an array gets a multi-select list in which the
    conflicting operators of one group are mutually exclusive; a string ``o``
    gets a single choice. An optional ``o`` offers the verifier default.
    """

    def __init__(self, label, schema, required, parent=None):
        super().__init__(parent)
        self.schema = schema
        self.required = required
        self.multiple = schema.get('type') == 'array'
        self.choices = operator_choices(schema)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        self.checks = {}
        self.combo = None
        if self.multiple:
            heading = QLabel(label)
            heading.setStyleSheet(f'font-weight: bold; font-size: 12px; color: {colors.TEXT_SECONDARY};')
            layout.addWidget(heading)
            for token in self.choices:
                check = QCheckBox(OPERATOR_LABELS[token])
                check.toggled.connect(lambda checked, token=token: self._toggled(token, checked))
                self.checks[token] = check
                layout.addWidget(check)
        else:
            self.combo = FloatingLabelComboBox(label)
            self.combo.setFixedWidth(400)
            if not required:
                self.combo.addItem('Default (verifier chooses I2I or NI2I)', None)
            for token in self.choices:
                self.combo.addItem(OPERATOR_LABELS[token], token)
            self.combo.currentIndexChanged.connect(self._update_help)
            layout.addWidget(self.combo)
        self.help = QLabel()
        self.help.setWordWrap(True)
        self.help.setFixedWidth(400)
        self.help.setStyleSheet(f'font-size: 12px; color: {colors.TEXT_SECONDARY};')
        layout.addWidget(self.help)
        self._update_help()

    def on_change(self, callback):
        """Call ``callback`` after any selection change."""
        if self.combo is not None:
            self.combo.currentIndexChanged.connect(lambda *_: callback())
        for check in self.checks.values():
            check.toggled.connect(lambda *_: callback())

    def _toggled(self, token, checked):
        if checked:
            for group in EXCLUSIVE_GROUPS:
                if token in group:
                    for other in group:
                        if other != token and other in self.checks:
                            self.checks[other].setChecked(False)
        self._update_help()

    def selected(self):
        """Return the chosen tokens in display order."""
        if self.combo is not None:
            token = self.combo.currentData()
            return [token] if token else []
        return [token for token, check in self.checks.items() if check.isChecked()]

    def value(self):
        """Return the ``o`` value to write, or ``None`` to omit it."""
        tokens = self.selected()
        if self.multiple:
            if not tokens and self.required:
                raise ValueError('Choose at least one link operator')
            return tokens or None
        return tokens[0] if tokens else None

    def select(self, tokens):
        """Select ``tokens`` (string or list) programmatically."""
        tokens = [tokens] if isinstance(tokens, str) else list(tokens)
        if self.combo is not None:
            self.combo.setCurrentIndex(self.combo.combo_box.findData(tokens[0] if tokens else None))
        else:
            for token, check in self.checks.items():
                check.setChecked(token in tokens)

    def _update_help(self, *_):
        tokens = self.selected()
        self.help.setText(' '.join(OPERATOR_HELP[token] for token in tokens) if tokens else DEFAULT_HELP)
