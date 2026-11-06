"""Registry roots reach group newcomers as ESSR copies that are retained automatically."""
from types import SimpleNamespace

from keri import kering
from keri.acdc import Registrar, acdcmap
from keri.core import Parser, Salter

from locksmith.core import evidence
from test_ipex_policy import _introduce
from test_keri_v2_compat import _deliver_ipex, ipex_vaults as ipex_vaults

V2 = kering.Vrsn_2_0
BRAN = '0123456789abcdefghijk'


def _local(app, raw):
    app.vault.mbx.parser.parse(ims=bytearray(raw), local=True)
    app.hby.kvy.processEscrows()
    app.vault.kvy.processEscrows()


def _rotated_group(ipex_vaults, *, newcomer_has_tel=True):
    """Issuer's credential to group A/B; an accepted rotation then adds C.

    A holds the registry root as the group's former DH custodian. C's next
    key is committed in the inception, so the rotation can add it.
    """
    issuer, alice, bob, carol = [ipex_vaults(f'roots-{name}', bran=BRAN)
                                 for name in ('issuer', 'alice', 'bob', 'carol')]
    apps = (issuer, alice, bob, carol)
    habs = [app.hby.makeHab(name=f'roots-{name}-member')
            for app, name in zip(apps, ('issuer', 'alice', 'bob', 'carol'))]
    for app in apps:
        for other in apps:
            if other is not app:
                _introduce(other, app)
    ih, ah, bh, ch = habs
    mids, rmids = [ah.pre, bh.pre], [ah.pre, bh.pre, ch.pre]
    groups = [app.hby.makeGroupHab(group='roots', mhab=hab, smids=mids, rmids=rmids,
                                   isith='2', nsith='2', version=V2)
              for app, hab in ((alice, ah), (bob, bh))]
    partials = [group.msgOwnInception(allowPartiallySigned=True, gvrsn=V2) for group in groups]
    for app in (alice, bob):
        for raw in partials:
            _local(app, raw)
    gid = groups[0].pre
    for app in (issuer, carol):
        _deliver_ipex(app.vault, groups[0].replay(gvrsn=V2))
        assert gid in app.hby.kevers

    registrar = Registrar(rgy=issuer.vault.rgy)
    registry = registrar.makeRegistry('roots', ih.pre)
    rip = issuer.vault.rgy.store.event(registry.regk)
    ih.interact(data=[dict(i=registry.regk, s=rip.sad['n'], d=rip.said)])
    assert registry.anchorMsg(rip.said)
    root = Salter()
    acdc = acdcmap(israid=ih.pre, iseaid=gid, regid=registry.regk, attribute=dict(d='', role='member'))
    _, event = registrar.issue(registry, acdc, salt=root.qb64, state='issued')
    ih.interact(data=[dict(i=registry.regk, s=event.sad['n'], d=event.said)])
    assert registry.anchorMsg(event.said)
    tel = evidence.clone(issuer.vault, registry.regk)
    for app in (alice, bob, carol):
        _introduce(issuer, app)
        if app is not carol or newcomer_has_tel:
            _deliver_ipex(app.vault, tel)
            assert app.vault.rgy.store.headEvent(registry.regk).said == event.said
    # Alice is the former DH custodian: she retained the root and answered the
    # Dhke replicate cue, which queued Bob's copy and kept the credential hint.
    alice.hby.mgr.putRegistryRoot(gid, registry.regk, root)
    alice.vault.roots.replicate(groups[0], [registry.regk], {registry.regk: acdc.said})
    alice.vault.auxiliary.process()
    event, = _sent(alice)
    assert event['dest'] == bh.pre
    _deliver_ipex(bob.vault, event['serder'].raw + event['attachment'])
    assert bob.vault.roots.pending() == []
    assert bob.hby.mgr.getRegistryRoot(gid, registry.regk).qb64 == root.qb64

    # Every member rotates its own keys; the accepted group rotation adds Carol.
    current = ((alice, ah), (bob, bh), (carol, ch))
    for app, hab in current:
        kel = hab.rotate(framed=False, gvrsn=V2)
        for other in apps:
            if other is not app:
                _deliver_ipex(other.vault, kel)
    carol_group = carol.hby.joinGroupHab(pre=gid, group='roots', mhab=ch, smids=rmids, rmids=rmids)
    joined = [groups[0], groups[1], carol_group]
    wires = [joined[0].rotate(smids=rmids, rmids=rmids,
                              verfers=[hab.kever.verfers[0] for _, hab in current],
                              digers=[hab.kever.ndigers[0] for _, hab in current],
                              isith='2', nsith='2', framed=False, gvrsn=V2)]
    rotation = Parser(version=V2).parseOne(ims=bytearray(wires[0]), processive=False).serder
    for group in joined[1:]:
        wires.append(group.rotate(serder=rotation, smids=rmids, rmids=rmids, framed=False, gvrsn=V2))
    for app, _ in current:
        for raw in wires:
            _local(app, raw)
        assert app.hby.kevers[gid].serder.said == rotation.said
    return SimpleNamespace(issuer=issuer, alice=alice, bob=bob, carol=carol, ah=ah, bh=bh, ch=ch,
                           gid=gid, registry=registry.regk, root=root, rotation=rotation.said, tel=tel)


def _sent(app):
    evts = app.vault.postman.evts
    events = [event for event in evts if event['serder'].route == '/registry/root']
    for event in events:
        evts.remove(event)
    return events


def _notes(app):
    return [note for _, note in app.vault.notifier.noter.notes.getTopItemIter()
            if note.attrs.get('r') == '/exn/registry/root']


def test_rotation_witnesser_catches_a_newcomer_up_and_arrival_retains_the_root(ipex_vaults):
    w = _rotated_group(ipex_vaults)
    alice, bob, carol = w.alice, w.bob, w.carol
    # Only the rotation's elected witnesser sends, exactly once per rotation.
    bob.vault.auxiliary.process()
    assert not _sent(bob)
    alice.vault.auxiliary.process()
    event, = _sent(alice)
    assert (event['dest'], event['topic'], event['hab'].pre) == (w.ch.pre, 'credential', w.ah.pre)
    assert w.root.qb64b not in event['serder'].raw + event['attachment']
    assert alice.vault.db.rootRotations.get(keys=(w.gid, w.rotation)) == w.ah.pre
    assert not list(alice.vault.db.rootSends.getTopItemIter())
    alice.vault.auxiliary.process()
    assert not _sent(alice)

    # Arrival verifies and retains the root with no approval step and one informational note.
    _deliver_ipex(carol.vault, event['serder'].raw + event['attachment'])
    assert carol.hby.mgr.getRegistryRoot(w.gid, w.registry).qb64 == w.root.qb64
    assert carol.vault.roots.pending() == []
    note, = _notes(carol)
    assert (note.attrs['d'], note.attrs['gid'], note.attrs['rd']) == (event['serder'].said, w.gid, w.registry)
    assert 'deferred' not in note.attrs
    # A duplicate delivery is idempotent and adds no note; the root survives restart.
    _deliver_ipex(carol.vault, event['serder'].raw + event['attachment'])
    assert len(_notes(carol)) == 1
    carol.close_vault()
    carol = ipex_vaults('roots-carol', bran=BRAN)
    assert carol.hby.mgr.getRegistryRoot(w.gid, w.registry).qb64 == w.root.qb64
    assert carol.vault.roots.pending() == []


def test_copy_escrows_until_the_newcomer_has_the_registry(ipex_vaults):
    w = _rotated_group(ipex_vaults, newcomer_has_tel=False)
    alice, carol = w.alice, w.carol
    alice.vault.auxiliary.process()
    event, = _sent(alice)
    _deliver_ipex(carol.vault, event['serder'].raw + event['attachment'])
    copy, = carol.vault.roots.pending()
    assert copy.said == event['serder'].said and 'registry' in copy.waiting and copy.deadline
    assert carol.hby.mgr.getRegistryRoot(w.gid, w.registry) is None
    assert not _notes(carol)
    # The vault's escrow loop retries the copy; without the registry it stays escrowed.
    carol.vault.mbx.exchanger.processEscrow()
    assert [item.said for item in carol.vault.roots.pending()] == [copy.said]

    # The registry state arrives later; the same escrowed copy verifies without a resend.
    _deliver_ipex(carol.vault, w.tel)
    assert carol.vault.mbx.exchanger is carol.vault.exc
    carol.vault.mbx.exchanger.processEscrow()
    assert carol.hby.mgr.getRegistryRoot(w.gid, w.registry).qb64 == w.root.qb64
    assert carol.vault.roots.pending() == []
    note, = _notes(carol)
    assert note.attrs['d'] == copy.said
