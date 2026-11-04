"""Public and derived authoring keep custody optional and revocation restartable."""
import pytest
from hio.base import doing
from keri import kering
from keri.acdc import Registrar, acdcmap, messaging
from keri.core import BoundState, Saider, SerderACDC
from keri.peer import exchanging

from locksmith.core import credentialing, disclosing, ipexing, registry_authoring
from test_credentialing import _load_schema
from test_keri_v2_compat import ipex_vaults as ipex_vaults


@pytest.mark.parametrize('mode,bound', [('public', False), ('blinded', False),
    ('blinded', True)])
def test_registry_mode_survives_reopen_and_revocation_retry(ipex_vaults, mode, bound):
    """Use actual issue/revoke doers, core anchors and encrypted derived custody."""
    password = '0123456789abcdefghijk' if mode == 'derived' else None
    app = ipex_vaults('author-' + mode, bran=password)
    issuer, holder = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='holder')
    schema = _load_schema(app, issuer)
    events = []
    app.vault.signals.doer_event.connect(lambda name, event, data: events.append((event, data)))
    worker = credentialing.IssueCredentialDoer(app, schema.said, holder.pre,
        {'LEI': 'example'}, registry_mode=mode,
        discloser=holder.pre if mode == 'derived' else None,
        bound_event=holder.kever.serder.said if bound else None)
    doing.Doist(doers=[worker], tock=0.03125, limit=3).do()
    assert events[-1][0] == 'credential_issued', events
    said = events[-1][1]['credential_said']
    record = app.vault.db.issued.get((said,))
    view = credentialing.credential(app.vault, said)
    regid = view['sad']['rd']
    assert record.registry_mode == mode and view['status']['et'] == 'issued'
    assert not list(app.hby.mgr.ks.rroots.getTopItemIter())
    assert record.blinder
    head = app.vault.rgy.store.headEvent(regid)
    assert head.ilk == 'bup'
    assert bool(app.vault.rgy.store.opening(head.said)) is (mode == 'public')
    assert bool(app.vault.rgy.store.opening(head.said)) is (mode == 'public')
    issued_opening = disclosing.opening(record.blinder)
    grant, atc = ipexing.grant(app.vault, issuer, said, holder.pre)
    ipexing.prepare(app.vault, issuer, grant, atc)
    ipexing.admit(app.vault, holder, grant.said)
    admitted = app.vault.db.accepted.get((said,))
    historical = exchanging.serializeMessage(app.hby, grant.said)
    original = record.raw, record.created_at, record.registry_mode
    # Refresh the issuer's commitment without rewriting the holder's admitted view.
    stale_refresh = credentialing.RefreshCredentialDoer(app, said, expected_update=record.update)
    refresh = credentialing.RefreshCredentialDoer(app, said, expected_update=record.update)
    doing.Doist(doers=[refresh], tock=.03125, limit=3).do()
    assert events[-1][0] == 'credential_refreshed', events
    record = app.vault.db.issued.get((said,))
    assert (record.raw, record.created_at, record.registry_mode) == original
    assert app.vault.rgy.store.headEvent(regid).sn == 2
    assert app.vault.db.accepted.get((said,)) == admitted
    assert exchanging.serializeMessage(app.hby, grant.said) == historical
    doing.Doist(doers=[stale_refresh], tock=.03125, limit=3).do()
    assert events[-1][0] == 'credential_refresh_failed'
    assert issuer.kever.sn == 3
    app.close_vault()
    app = ipex_vaults('author-' + mode, bran=password)
    app.vault.signals.doer_event.connect(lambda name, event, data: events.append((event, data)))
    issuer = app.hby.habByName('issuer')
    coordinates = {}
    if bound:
        holder = app.hby.habByName('holder')
        holder.rotate()
        stale_bound = credentialing.RefreshCredentialDoer(app, said, expected_update=record.update)
        doing.Doist(doers=[stale_bound], tock=.03125, limit=3).do()
        assert events[-1][0] == 'credential_refresh_failed'
        stale = credentialing.RevokeCredentialDoer(app, said)
        doing.Doist(doers=[stale], tock=.03125, limit=3).do()
        assert issuer.kever.sn == 3
        assert app.vault.rgy.store.headEvent(regid).sn == 2
        coordinates = dict(bound_event=holder.kever.serder.said)
    for _ in range(2):
        worker = credentialing.RevokeCredentialDoer(app, said, **coordinates)
        doing.Doist(doers=[worker], tock=0.03125, limit=3).do()
        assert credentialing.credential(app.vault, said)['status']['et'] == 'revoked'
        # Inception plus registry inception, issuance, refresh and revocation anchors.
        assert issuer.kever.sn == 4
        record = app.vault.db.issued.get((said,))
        if mode == 'public':
            opening = disclosing.opening(record.blinder)
            assert opening.state == 'revoked'
            assert app.vault.rgy.store.opening(
                app.vault.rgy.store.headEvent(regid).said).qb64 == opening.qb64
            assert app.vault.rgy.store.opening(
                app.vault.rgy.store.headEvent(regid).said).qb64 == opening.qb64
            assert not list(app.hby.mgr.ks.rroots.getTopItemIter())
            # A holder's retained issuance proof is augmented only by the
            # accepted public head opening after an observer refresh.
            assert credentialing.credential_state(
                app.vault, SerderACDC(raw=record.raw.encode()),
                blinders=[issued_opening]).state == 'revoked'
        else:
            opening = disclosing.opening(record.blinder)
            assert opening.state == 'revoked'
        if bound:
            opening = disclosing.opening(record.blinder)
            assert opening.clan == BoundState and opening.bd == holder.kever.serder.said
    refused = credentialing.RefreshCredentialDoer(app, said, expected_update=record.update)
    doing.Doist(doers=[refused], tock=.03125, limit=3).do()
    assert events[-1][0] == 'credential_refresh_failed'
    assert issuer.kever.sn == 4


@pytest.mark.real_routes
def test_refresh_dialog_resumes_same_witnessed_commitment_after_reopen(ipex_vaults, qapp):
    """Interrupt real HTTP receipts, then resume the exact durable BUP and KEL anchor."""
    import socket
    from time import monotonic, sleep
    from keri.app import habbing, indirecting, storing
    from keri.db import openLMDB
    from locksmith.core.receipting import LocksmithReceiptor
    from locksmith.ui.vault.credentials.issued.refresh import RefreshCredentialDialog
    from test_credentialing import _issue
    from test_keri_v2_compat import _deliver_ipex

    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    with habbing.openHab(name='refresh-witness', transferable=False, temp=True,
                         version=kering.Vrsn_2_0) as (whby, witness), \
            openLMDB(cls=storing.Mailboxer, name='refresh-witness') as mailbox:
        server = doing.Doist(doers=indirecting.setupWitness(
            whby, alias=witness.name, mbx=mailbox, tcpPort=None, httpPort=port,
            version=kering.Vrsn_2_0), tock=.03125)
        server.enter()
        try:
            # Give the issuer a real HTTP witness before opening the refresh control.
            app = ipex_vaults('refresh-http')
            issuer = app.hby.makeHab(name='issuer')
            schema = _load_schema(app, issuer)
            said = _issue(app, schema, issuer)
            _deliver_ipex(app.vault, witness.replay(gvrsn=kering.Vrsn_2_0) + witness.makeLocScheme(
                url=f'http://127.0.0.1:{port}', scheme='http'))
            issuer.rotate(adds=[witness.pre], toad=1)
            receiptor = LocksmithReceiptor(hby=app.hby)
            receipts = doing.Doist(doers=[receiptor], tock=.03125)
            receipts.enter()
            try:
                receiptor.msgs.append(dict(pre=issuer.pre, sn=issuer.kever.sn))
                deadline = monotonic() + 10
                while not app.hby.db.fullyWitnessed(issuer.kever.serder) and monotonic() < deadline:
                    server.recur()
                    receipts.recur()
                    sleep(.001)
                assert app.hby.db.fullyWitnessed(issuer.kever.serder)
            finally:
                receipts.exit()
            original = app.vault.db.issued.get((said,))
            # Opening the dialog grants no consent; only the explicit click starts work.
            dialog = RefreshCredentialDialog(app, said, 'Witnessed credential')
            dialog.open()
            qapp.processEvents()
            assert dialog.auth_panel is not None
            assert dialog.auth_panel.isVisible() and dialog.refresh_button.isVisible()
            assert dialog.bound_event.text() == ''
            assert app.vault.db.issued.get((said,)) == original
            for field in dialog.auth_panel.passcode_fields.values():
                field.setText('123456')
            dialog.refresh_button.click()
            operation = dialog._refresh_id
            dialog.refresh_button.click()
            assert dialog._refresh_id == operation and not dialog.refresh_button.isEnabled()
            for _ in range(32):
                app.qtask.run()  # Deliberately leave the actual witness server unadvanced.
                if app.vault.db.issued.get((said,)).update != original.update and issuer.kever.sn == 4:
                    break
            pending = app.vault.db.issued.get((said,))
            assert pending.update != original.update and issuer.kever.sn == 4
            assert credentialing.refresh_context(app.vault, said)['resume']
            stale = RefreshCredentialDialog(app, said, 'Witnessed credential')
            assert stale.refresh_button.text() == 'Resume state update'
            app.close_vault()
            stale.refresh_button.click()
            assert stale._refresh_id is None
            stale.close()
            dialog.close()
            # Reopen and collect receipts for the same saved BUP and KEL anchor.
            app = ipex_vaults('refresh-http')
            issuer = app.hby.habByName('issuer')
            resumed = RefreshCredentialDialog(app, said, 'Witnessed credential')
            assert resumed.refresh_button.text() == 'Resume state update'
            for field in resumed.auth_panel.passcode_fields.values():
                field.setText('123456')
            resumed.refresh_button.click()
            deadline = monotonic() + 15
            while not resumed._closed and monotonic() < deadline:
                server.recur()
                app.qtask.run()
                qapp.processEvents()
                sleep(.001)
            assert resumed._closed
            current = app.vault.db.issued.get((said,))
            assert (current.update, current.blinder, current.stream) == (pending.update, pending.blinder, pending.stream)
            assert (current.raw, current.created_at) == (original.raw, original.created_at)
            assert issuer.kever.sn == 4 and credentialing.credential(app.vault, said)['status']['et'] == 'issued'
            # Late acceptance makes an exact retry succeed without authoring again.
            completed = credentialing.RefreshCredentialDoer(
                app, said, expected_update=pending.update, resume=True)
            events = []
            app.vault.signals.doer_event.connect(lambda name, event, data: events.append((event, data)))
            doing.Doist(doers=[completed], tock=.03125, limit=1).do()
            assert completed.done and not completed.deeds and issuer.kever.sn == 4
            assert events[-1][0] == 'credential_refreshed'
        finally:
            server.exit()


def test_historical_upd_remains_parseable_but_cannot_author_or_claim_standing(ipex_vaults):
    """Keep migration input readable while refusing it as current product state."""
    app = ipex_vaults('historical-upd')
    issuer = app.hby.makeHab(name='issuer')
    registry = Registrar(rgy=app.vault.rgy).makeRegistry('historical', issuer.pre)
    rip = app.vault.rgy.store.event(registry.regk)
    issuer.interact(data=[dict(i=registry.regk, s=rip.sad['n'], d=rip.said)])
    assert registry.anchorMsg(rip.said)
    acdc = acdcmap(israid=issuer.pre, regid=registry.regk,
                   attribute={'d': '', 'value': 'legacy'})
    update = messaging.update(registry.regk, rip.said, acdc.said, 'issued', sn=1)
    with pytest.raises(kering.ValidationError, match='Unsupported registry event type upd'):
        registry.processEvent(update)
    # Model an exact row written by an older wallet without asking the current
    # acceptor to reinterpret or accept that signed historical event.
    app.vault.rgy.store.putEvent(update)
    saider = Saider(qb64=update.said)
    app.vault.rgy.baser.tels.pin(keys=registry.regk, on=1, val=saider)
    app.vault.rgy.baser.heads.pin(keys=registry.regk, val=saider)
    with pytest.raises(kering.ConfigurationError, match='upd heads'):
        credentialing.credential_state(app.vault, acdc)
    with pytest.raises(kering.ConfigurationError, match='upd heads'):
        registry_authoring.stage(app.vault, registry, acdc, 'revoked', 'public')


def test_unencrypted_derived_issuance_refuses_before_registry_authorship(ipex_vaults):
    app = ipex_vaults('unencrypted-root')
    issuer, holder = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='holder')
    schema = _load_schema(app, issuer)
    events = []
    app.vault.signals.doer_event.connect(lambda name, event, data: events.append((event, data)))
    worker = credentialing.IssueCredentialDoer(app, schema.said, holder.pre,
        {'LEI': 'example'}, registry_mode='derived', discloser=holder.pre)
    doing.Doist(doers=[worker], tock=.03125, limit=3).do()
    assert events[-1][0] == 'credential_issuance_failed'
    assert 'encrypted, unlocked vault' in events[-1][1]['error']
    assert app.vault.rgy.regs == {}
    assert issuer.kever.sn == 0
    assert not list(app.hby.mgr.ks.rroots.getTopItemIter())
