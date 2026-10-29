"""Optional vault composition delegates salt protocol authority to current KERIpy."""

import pytest
from hio.base import doing
from keri import kering
from keri.acdc import Registrar, acdcmap
from keri.app import registry_salt_replies as replies, registry_salts
from keri.app.essring import envelope
from keri.app.registry_salt_service import ROUTES
from keri.app.replying import parseReply
from keri.core import Diger, reply

from locksmith.core import credentialing, disclosing, registry_authoring
from test_credentialing import _load_schema
from test_keri_v2_compat import _deliver_ipex, ipex_vaults
from salt_helpers import establish


def test_vault_borrows_one_live_owner_and_opens_no_private_root(ipex_vaults):
    """An ordinary unencrypted vault opens without optional custody capability."""
    app = ipex_vaults('optional-salts')
    vault, salts = app.vault, app.vault.salts
    assert not app.hby.mgr.aeid
    assert salts.service.parser is vault.mbx.parser
    assert salts.service.rvy is vault.rvy is vault.mux.rvy
    assert salts.service.parser.kvy is vault.kvy is vault.mux.kvy
    assert vault.mux.rtr is vault.rvy.rtr
    assert vault.kvy.kramer is vault.kramer
    assert vault.hby.db.kramCTYP.get('~').sl == 300000
    for route in ROUTES:
        assert vault.rvy.rtr._find(route)[0].resource is salts.service
        probe = reply(pre=Diger(ser=b'probe').qb64, route=route, data={},
                      version=kering.Vrsn_2_0, kind=kering.Kinds.json)
        assert not any(vault.kramer.denial(probe).startswith(prefix) for prefix in vault.kramer.denials)
    assert vault.rvy.rtr._find(replies.INIT_ROUTE + '/extra')[0] is None
    assert salts.state.db is vault.db is salts.custody.db
    assert all(getattr(vault.db, name).db is vault.db for name in (
        'saltPending', 'saltOrigins', 'saltDeliveries', 'saltRosters', 'saltProofs',
        'saltAssignments', 'saltReceipts', 'saltAttempts'))
    assert salts.status(Diger(ser=b'unknown registry').qb64) == dict(
        origin=None, root_recorded=False, deliveries={}, receipt_pending=0, error='')
    assert not salts.workers


def test_live_profile_freshness_preserves_ordinary_reply_exception(ipex_vaults):
    """Stale salt replies remain blocked; ordinary endpoint replies retain their policy."""
    app = ipex_vaults('salt-freshness')
    issuer, discloser = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='discloser')
    service = app.vault.salts.service
    for hab in (issuer, discloser):
        service.trustRoster(hab.pre, [hab.pre])
    public, _ = registry_salts.generateKeypair()
    stale = replies.initReply(sender=issuer.pre, issuer=issuer.pre, discloser=discloser.pre,
        rep=issuer.pre, est=dict(s='0', d=issuer.kever.lastEst.d), key=public.qb64,
        stamp='2001-01-01T00:00:00.000000+00:00')
    app.vault.mbx.parser.parse(ims=issuer.endorse(stale, gvrsn=kering.Vrsn_2_0), local=False)
    assert app.vault.salts.state.proof(stale.said) is None
    ordinary = reply(pre=issuer.pre, route='/end/role/add',
        data=dict(cid=issuer.pre, role=kering.Roles.controller, eid=discloser.pre),
        stamp=stale.stamp, version=kering.Vrsn_2_0, kind=kering.Kinds.json)
    app.vault.mbx.parser.parse(ims=issuer.endorse(ordinary, gvrsn=kering.Vrsn_2_0), local=False)
    assert app.hby.db.ends.get((issuer.pre, kering.Roles.controller, discloser.pre)).allowed
    assert not list(app.vault.db.saltPending.getTopItemIter())
    assert not list(app.vault.db.custody.getTopItemIter())


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


def test_bad_optional_state_cannot_stop_vault_verification(ipex_vaults):
    """Corrupt optional public metadata stops its owner, not the vault scheduler."""
    app = ipex_vaults('bad-optional-salt-state')
    table = app.vault.db.saltOrigins
    with app.vault.db.env.begin(write=True) as txn:
        txn.put(table._tokey((Diger(ser=b'bad optional row').qb64,)), b'not JSON', db=table.sdb)
    for _ in range(40):
        app.qtask.run()
    assert app.vault.salts.done
    assert app.vault.salts.errors['_runtime'] == 'Optional registry-root processing is unavailable'
    assert not app.vault.done and app.vault.db.opened and app.hby.db.opened


def test_essr_selects_exact_local_alias_without_implicit_consent(ipex_vaults):
    """An unsolicited request to a second local member creates no private state."""
    source = ipex_vaults('salt-essr-source')
    target = ipex_vaults('salt-essr-target')
    issuer = source.hby.makeHab(name='issuer')
    target.hby.makeHab(name='other-local')
    discloser = target.hby.makeHab(name='discloser')
    target.vault.mbx.parser.parse(ims=issuer.replay(gvrsn=kering.Vrsn_2_0), local=False)
    for hab in (issuer, discloser):
        target.vault.salts.service.trustRoster(hab.pre, [hab.pre])
    public, _ = registry_salts.generateKeypair()
    body = replies.initReply(sender=issuer.pre, issuer=issuer.pre, discloser=discloser.pre,
        rep=issuer.pre, est=dict(s='0', d=issuer.kever.lastEst.d), key=public.qb64)
    sealed = envelope(issuer, issuer.endorse(body, gvrsn=kering.Vrsn_2_0), discloser.pre,
        discloser.kever.verfers[0], version=kering.Vrsn_2_0,
        establishment=(discloser.kever.lastEst.s, discloser.kever.lastEst.d))
    _deliver_ipex(target.vault, sealed)
    assert target.vault.salts.state.proof(body.said) is not None
    assert target.hby.db.kramMSGC.get((issuer.pre, body.said)) is not None
    assert not list(target.vault.db.saltPending.getTopItemIter())
    assert not list(target.vault.db.saltOrigins.getTopItemIter())
    assert not list(target.vault.db.custody.getTopItemIter())


def test_derived_issuance_requires_explicit_established_registry_before_authoring(ipex_vaults):
    """Missing agreement produces no random root, orphan rip, credential or anchor."""
    app = ipex_vaults('derived-requires-origin')
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
    assert not list(app.vault.db.custody.getTopItemIter())


def test_historical_random_custody_is_not_new_established_authority(ipex_vaults):
    """Retain old explicit custody, but require DH origin for new derived authoring."""
    app = ipex_vaults('historical-root', bran='0123456789abcdefghijk')
    issuer, discloser = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='discloser')
    registry = Registrar(rgy=app.vault.rgy).makeRegistry(name='historical', prefix=issuer.pre)
    rip = app.vault.rgy.store.event(registry.regk)
    issuer.interact(data=[dict(i=registry.regk, s=rip.sad['n'], d=rip.said)])
    assert registry.anchorMsg(rip.said)
    disclosing.custody(app.vault).createCustody(registry.regk, discloser.pre)
    before = app.vault.db.custody.get((registry.regk,))
    acdc = acdcmap(israid=issuer.pre, regid=registry.regk, attribute=dict(d='', value='test'))
    with pytest.raises(kering.ConfigurationError, match='Establish the registry root'):
        registry_authoring.stage(app.vault, registry, acdc, 'issued', 'derived')
    assert app.vault.db.custody.get((registry.regk,)) == before
    assert app.vault.rgy.store.headEvent(registry.regk).sn == 0


def test_established_origin_reopens_as_public_status_without_decryption(ipex_vaults):
    """Core DH retention shares the vault transaction boundary and survives reopen."""
    app = ipex_vaults('reopen-established', bran='0123456789abcdefghijk')
    issuer, discloser = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='discloser')
    registry = establish(app.vault, issuer, discloser)
    before = app.vault.salts.status(registry.regk)
    assert before['origin'] and before['root_recorded']
    owner = app.vault.salts
    owner.reconcile()
    owner.reconcile()
    workers = tuple(owner.workers.values())
    assert workers
    app.close_vault()
    assert not owner.deeds and all(not worker.deeds and not worker.active for worker in workers)
    app = ipex_vaults('reopen-established', bran='0123456789abcdefghijk')
    app.hby.mgr.decrypter = None  # Public progress never unlocks the optional root.
    assert app.vault.salts.status(registry.regk) == before
    expected = dict(registry=registry.regk, issuer=issuer.pre,
                    discloser=discloser.pre, origin=before['origin'])
    assert app.vault.salts.issuanceRegistries() == [expected]
    assert app.vault.salts.issuanceRegistries(issuer.pre) == [expected]
    assert app.vault.salts.issuanceRegistries(discloser.pre) == []
    cipher = app.vault.db.custody.get((registry.regk,))
    app.vault.db.custody.rem((registry.regk,))
    assert app.vault.salts.issuanceRegistries() == []
    app.vault.db.custody.pin((registry.regk,), cipher)
    assert app.vault.salts.service.parser is app.vault.mbx.parser
