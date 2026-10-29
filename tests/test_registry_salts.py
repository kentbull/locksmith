"""Optional salt custody reuses ordinary vault verification and Keeper storage."""

import pytest
from hio.base import doing
from keri import kering
from keri.acdc import acdcmap
from keri.app.essring import envelope
from keri.app.registry_salt_service import ROUTES
from keri.app.replying import parseReply
from keri.core import Diger, reply

from locksmith.core import credentialing, registry_authoring
from locksmith.core.salt_actions import SaltActions
from test_credentialing import _load_schema
from test_keri_v2_compat import _deliver_ipex, ipex_vaults
from salt_helpers import establish


def test_vault_borrows_live_reply_owner_without_opening_private_root(ipex_vaults):
    """Ordinary unencrypted startup registers the route on the existing Revery."""
    app = ipex_vaults('optional-salts')
    vault, salts = app.vault, app.vault.salts
    assert not app.hby.mgr.aeid
    assert salts.service.rvy is vault.rvy is vault.mux.rvy
    assert vault.mbx.parser.kvy is vault.kvy is vault.mux.kvy
    assert vault.mux.rtr is vault.rvy.rtr
    assert vault.kvy.kramer is vault.kramer
    assert vault.hby.db.kramCTYP.get('~').sl == 300000
    for route in ROUTES:
        assert vault.rvy.rtr._find(route)[0].resource is salts.service
    assert salts.custody.db is vault.hby.ks
    assert salts.status(Diger(ser=b'unknown registry').qb64) == dict(root_recorded=False)


def test_exact_salt_routes_keep_kram_while_ordinary_routes_remain_exempt(ipex_vaults):
    """Exercise real KRAM intake without dispatching deliberately empty bodies."""
    app = ipex_vaults('salt-route-policy')
    vault = app.vault
    sender = app.hby.makeHab(name='sender')
    ordinary = ('/end/role/add', '/end/role/cut', '/loc/scheme',
                f'/ksn/{sender.pre}', f'/watcher/{sender.pre}/add',
                f'/watcher/{sender.pre}/cut')
    for route in (*ROUTES, *ordinary):
        body = reply(pre=sender.pre, route=route, data={},
                     stamp='2001-01-01T00:00:00.000000+00:00',
                     version=kering.Vrsn_2_0, kind=kering.Kinds.json)
        parsed = parseReply(vault.mbx.parser,
                            sender.endorse(body, gvrsn=kering.Vrsn_2_0), {route})
        result = vault.kramer.intake(body, vars(parsed).copy())
        assert (result is body) is (route in ordinary)
        assert app.hby.db.kramMSGC.get((sender.pre, body.said)) is None
    # Legacy VDR TSNs are absent from ACDC-v2 Rever. Oobiery has its own
    # unchanged parser and is not registered on this vault's live Revery.
    for route in (f'/tsn/registry/{sender.pre}', f'/tsn/credential/{sender.pre}', '/introduce'):
        assert vault.rvy.rtr._find(route)[0] is None



def test_corrupt_custody_does_not_stop_ordinary_vault_processing(ipex_vaults):
    """Only an operation that opens the private row fails on corrupt ciphertext."""
    app = ipex_vaults('bad-optional-custody', bran='0123456789abcdefghijk')
    issuer, peer = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='peer')
    registry = establish(app.vault, issuer, peer)
    table = app.vault.hby.ks.custody
    row = table.get((registry.regk,))
    row.cipher = 'invalid cipher'
    table.pin((registry.regk,), row)
    with pytest.raises((kering.AuthError, kering.ValidationError)):
        app.vault.salts.custody.derive(registry.regk, 1, Diger(ser=b'credential').qb64, 'issued')
    ordinary = issuer.makeEndRole(eid=peer.pre, role=kering.Roles.controller,
        version=kering.Vrsn_2_0, gvrsn=kering.Vrsn_2_0)
    _deliver_ipex(app.vault, ordinary)
    for _ in range(40):
        app.qtask.run()
    assert app.hby.db.ends.get((issuer.pre, kering.Roles.controller, peer.pre)).allowed
    assert not app.vault.done and app.vault.db.opened and app.hby.db.opened


def test_essr_selects_addressed_alias_and_retains_authenticated_salt(ipex_vaults):
    """A second local alias receives its encrypted copy through ordinary intake."""
    source = ipex_vaults('salt-essr-source', bran='0123456789abcdefghijk')
    target = ipex_vaults('salt-essr-target', bran='abcdefghijk0123456789')
    issuer = source.hby.makeHab(name='issuer')
    target.hby.makeHab(name='other-local')
    discloser = target.hby.makeHab(name='discloser')
    _deliver_ipex(source.vault, discloser.replay(gvrsn=kering.Vrsn_2_0))
    registry = establish(source.vault, issuer, discloser)
    actions = SaltActions(source.vault)
    for body, atc in actions.publicEvidence(registry.regk, issuer.pre):
        _deliver_ipex(target.vault, body.raw + atc)
    body = actions.prepare(issuer.pre, registry.regk, discloser.pre)
    sealed = envelope(issuer, issuer.endorse(body, gvrsn=kering.Vrsn_2_0), discloser.pre,
        discloser.kever.verfers[0], version=kering.Vrsn_2_0,
        establishment=(discloser.kever.lastEst.s, discloser.kever.lastEst.d))
    _deliver_ipex(target.vault, sealed)
    assert target.hby.db.rpys.get((body.said,)).raw == body.raw
    assert target.hby.db.kramMSGC.get((issuer.pre, body.said)) is not None
    assert target.vault.salts.custody._load(registry.regk).salt == source.vault.salts.custody._load(registry.regk).salt


def test_derived_issuance_requires_explicit_registry_before_authoring(ipex_vaults):
    """Missing selection produces no random root, orphan rip, credential or anchor."""
    app = ipex_vaults('derived-requires-registry')
    issuer, holder = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='holder')
    schema = _load_schema(app, issuer)
    events = []
    app.vault.signals.doer_event.connect(lambda name, event, data: events.append((event, data)))
    doer = credentialing.IssueCredentialDoer(app, schema.said, holder.pre,
        {'LEI': 'example'}, registry_mode='derived', discloser=holder.pre)
    doing.Doist(doers=[doer], limit=1).do()
    assert 'established registry' in events[-1][1]['error']
    assert issuer.kever.sn == 0 and app.vault.rgy.regs == {}
    assert not list(app.vault.db.issued.getTopItemIter())
    assert not list(app.vault.hby.ks.custody.getTopItemIter())



def test_local_root_supports_derived_authoring_without_additional_agreement(ipex_vaults):
    """Accepted registry and encrypted root suffice for issuer derivation."""
    app = ipex_vaults('local-root', bran='0123456789abcdefghijk')
    issuer, peer = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='peer')
    registry = establish(app.vault, issuer, peer)
    before = app.vault.hby.ks.custody.get((registry.regk,))
    acdc = acdcmap(israid=issuer.pre, regid=registry.regk, attribute=dict(d='', value='test'))
    opening, event, _ = registry_authoring.stage(app.vault, registry, acdc, 'issued', 'derived')
    assert event.ilk == 'bup' and event.sad['n'] == '1'
    assert opening.qb64 == app.vault.salts.custody.derive(registry.regk, 1, acdc.said, 'issued').qb64
    assert app.vault.hby.ks.custody.get((registry.regk,)) == before
    assert app.vault.rgy.store.headEvent(registry.regk).sn == 0


def test_custody_status_reopens_without_decryption(ipex_vaults):
    """Inventory of encrypted rows is public local state, not recipient authority."""
    app = ipex_vaults('reopen-custody', bran='0123456789abcdefghijk')
    issuer, peer = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='peer')
    registry = establish(app.vault, issuer, peer)
    regid, issuer_id, peer_id = registry.regk, issuer.pre, peer.pre
    before = app.vault.salts.status(regid)
    assert before == dict(root_recorded=True)
    app.close_vault()
    app = ipex_vaults('reopen-custody', bran='0123456789abcdefghijk')
    app.hby.mgr.decrypter = None
    assert app.vault.salts.status(regid) == before
    expected = dict(registry=regid, issuer=issuer_id)
    assert app.vault.salts.issuanceRegistries() == [expected]
    assert app.vault.salts.issuanceRegistries(issuer_id) == [expected]
    assert app.vault.salts.issuanceRegistries(peer_id) == []
