"""Issuance controls select an established capability without provisioning it."""

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from keri.core import SerderACDC

from locksmith.ui.vault.credentials.issued.issue import IssueCredentialDialog
from salt_helpers import establish
from test_credential_ui import schema
from test_keri_v2_compat import ipex_vaults as ipex_vaults


def test_derived_issuance_uses_explicit_established_registry(ipex_vaults, qapp):
    """A real button issues against the selected DH registry and original discloser."""
    app = ipex_vaults('derived-issuance-controls', bran='0123456789abcdefghijk')
    issuer = app.hby.makeHab(name='issuer')
    holder = app.hby.makeHab(name='holder')
    registry = establish(app.vault, issuer, holder)
    origin = app.vault.salts.state.origin(registry.regk)
    schemer = schema()
    app.hby.db.schema.pin((schemer.said,), schemer)
    app.vault.db.issuers.pin((schemer.said,), issuer.pre)
    dialog = IssueCredentialDialog(app)
    try:
        dialog.schema_dropdown.setCurrentIndex(1)
        dialog.local_radio.setChecked(True)
        dialog.recipient_dropdown.setCurrentIndex(dialog.recipient_dropdown.combo_box.findData(holder.pre))
        dialog._dynamic_field_widgets['nickname']['widget'].setText('Alice')
        options = dialog.state_options
        options.mode.setCurrentIndex(options.mode.combo_box.findData('derived'))
        # Merely possessing a root never selects it on the user's behalf.
        with pytest.raises(ValueError, match='Choose an established registry'):
            options.selection()
        assert options.established.count() == 2
        options.established.setCurrentIndex(1)
        assert options.selection() == dict(registry_mode='derived',
            registry_id=registry.regk, discloser=holder.pre)
        assert 'holder' in options.party.text()
        dialog.show()
        qapp.processEvents()
        QTest.keyClick(dialog.issue_button, Qt.Key.Key_Space)
        for _ in range(256):
            app.qtask.run()
            qapp.processEvents()
            if list(app.vault.db.issued.getTopItemIter()):
                break
        rows = list(app.vault.db.issued.getTopItemIter())
        assert len(rows) == 1
        record = rows[0][1]
        assert SerderACDC(raw=record.raw.encode()).sad['rd'] == registry.regk
        assert record.registry_mode == 'derived'
        assert app.vault.salts.state.origin(registry.regk) == origin
        assert len(app.vault.salts.state.origins()) == 1
    finally:
        dialog.close()


def test_changing_issuer_clears_inapplicable_registry_selection(ipex_vaults, qapp):
    """Schema issuer changes cannot silently substitute or reuse another issuer's root."""
    from locksmith.ui.vault.credentials.issued.state_options import StatePublicationOptions

    app = ipex_vaults('derived-registry-choice', bran='0123456789abcdefghijk')
    issuer = app.hby.makeHab(name='issuer')
    holder = app.hby.makeHab(name='holder')
    other = app.hby.makeHab(name='other')
    registry = establish(app.vault, issuer, holder)
    options = StatePublicationOptions(app.vault)
    try:
        options.set_issuer(issuer.pre)
        options.mode.setCurrentIndex(options.mode.combo_box.findData('derived'))
        options.established.setCurrentIndex(1)
        options.set_issuer(issuer.pre)
        assert options.selection()['registry_id'] == registry.regk
        options.set_issuer(other.pre)
        assert options.established.count() == 1
        with pytest.raises(ValueError, match='Choose an established registry'):
            options.selection()
        options.set_registry(False)
        assert options.selection() == {}
        assert len(app.vault.salts.state.origins()) == 1
    finally:
        options.close()
