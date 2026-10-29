"""Real vault composition and consent for simplified encrypted salt sharing."""
import pytest
from PySide6.QtWidgets import QWidget
from locksmith.core.salt_actions import SaltActionDoer, SaltActions
from locksmith.ui.vault.credentials.registry_access import RegistryAccessPage
from test_keri_v2_compat import ipex_vaults


def finish(app, worker):
    """Drive the existing vault scheduler until this finite user action ends."""
    app.vault.extend([worker])
    for _ in range(1000):
        app.qtask.run()
        if worker.done:
            break
    assert worker.done
    assert not worker.error, worker.error


def test_unencrypted_vault_composes_optional_salt_route(ipex_vaults):
    """Ordinary vault startup borrows its live Revery without opening private data."""
    app = ipex_vaults('simple-salt-plain')
    assert not app.hby.mgr.aeid
    assert app.vault.salts.service.rvy is app.vault.rvy
    assert app.vault.salts.custody.db is app.vault.db


def test_create_and_preview_freezes_exact_encrypted_reply(ipex_vaults, qapp):
    """Creation retains issuer custody; preview does not sign or send the reply."""
    app = ipex_vaults('simple-salt-encrypted', bran='0123456789abcdefghijk')
    issuer = app.hby.makeHab(name='issuer')
    holder = app.hby.makeHab(name='holder')
    worker = SaltActionDoer(app.vault, create=(issuer.pre, 'private-state'))
    finish(app, worker)
    regid = worker.result['registry']
    assert app.vault.salts.status(regid)['root_recorded']
    assert SaltActions(app.vault).snapshot()[0]['kind'] == 'registry'
    parent = QWidget()
    parent.app = app
    page = RegistryAccessPage(parent)
    page.refresh()
    try:
        page.open_action('share', dict(party=issuer.pre, registry=regid))
        dialog = page.dialog
        dialog.recipient.setCurrentIndex(dialog.recipient.combo_box.findData(holder.pre))
        dialog._submit()
        body = dialog.body
        assert body.route == '/registry/salt'
        assert body.sad['a']['recipient'] == holder.pre
        assert not dialog.recipient.isEnabled()
        assert dialog.worker is None
        assert app.hby.db.rpys.get((body.said,)) is None
        root = app.vault.salts.custody._load(regid).salt
        assert root not in dialog.preview.toPlainText()
        dialog.close()
        assert app.hby.db.rpys.get((body.said,)) is None
        sending = SaltActionDoer(app.vault, body)
        finish(app, sending)
        assert app.hby.db.rpys.get((body.said,)).raw == body.raw
        assert app.vault.salts.custody._load(regid).salt == root
    finally:
        parent.close()


@pytest.mark.real_routes
def test_encrypted_salt_http_delivery_is_verified_by_independent_vault(ipex_vaults):
    """Actual HTTP submission becomes custody only after ordinary receiver processing."""
    from time import monotonic, sleep
    from keri import kering
    from keri.core import Diger
    from salt_helpers import capture_http
    from test_keri_v2_compat import _deliver_ipex

    issuer_app = ipex_vaults('simple-http-issuer', bran='0123456789abcdefghijk')
    holder_app = ipex_vaults('simple-http-holder', bran='0123456789abcdefghijk')
    issuer = issuer_app.hby.makeHab(name='issuer')
    holder = holder_app.hby.makeHab(name='holder')
    _deliver_ipex(issuer_app.vault, holder.replay(gvrsn=kering.Vrsn_2_0))
    creation = SaltActionDoer(issuer_app.vault, create=(issuer.pre, 'shared-state'))
    finish(issuer_app, creation)
    regid = creation.result['registry']
    with capture_http() as (port, received):
        route = holder.makeLocScheme(url=f'http://127.0.0.1:{port}', version=kering.Vrsn_2_0,
                                     gvrsn=kering.Vrsn_2_0)
        route.extend(holder.makeEndRole(eid=holder.pre, role=kering.Roles.controller,
                                       version=kering.Vrsn_2_0, gvrsn=kering.Vrsn_2_0))
        _deliver_ipex(issuer_app.vault, route)
        body = SaltActions(issuer_app.vault).prepare(issuer.pre, regid, holder.pre)
        worker = SaltActionDoer(issuer_app.vault, body)
        issuer_app.vault.extend([worker])
        deadline = monotonic() + 8
        while not worker.done and monotonic() < deadline:
            issuer_app.qtask.run()
            sleep(0.001)
        assert worker.done and not worker.error, worker.error
        assert received
        assert holder_app.vault.db.custody.get((regid,)) is None
        root = issuer_app.vault.salts.custody._load(regid).salt
        assert root.encode() not in b''.join(received)
        for wire in received:
            _deliver_ipex(holder_app.vault, wire)
        assert holder_app.vault.salts.custody._load(regid).salt == root
        credential = Diger(ser=b'http-shared-registry-credential').qb64
        assert (issuer_app.vault.salts.custody.derive(regid, 1, credential, 'issued').qb64 ==
                holder_app.vault.salts.custody.derive(regid, 1, credential, 'issued').qb64)
