"""Public and derived authoring keep custody optional and revocation restartable."""
import pytest
from hio.base import doing
from keri import kering
from keri.acdc import Registrar, acdcmap, messaging
from keri.core import BoundState, Saider, SerderACDC
from keri.acdc.regeventing import _blindCandidates

from locksmith.core import credentialing, disclosing, registry_authoring
from test_credentialing import _load_schema
from test_keri_v2_compat import ipex_vaults as ipex_vaults
from salt_helpers import establish


def test_derived_reuses_accepted_registry_after_update_without_reanchoring_inception(ipex_vaults):
    """Each reuse adds only its new bup anchor and preserves accepted inception."""
    app = ipex_vaults('derived-reuse', bran='0123456789abcdefghijk')
    issuer, holder = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='holder')
    schema = _load_schema(app, issuer)
    registry = establish(app.vault, issuer, holder)
    rip = app.vault.rgy.store.seqEvent(registry.regk, 0)
    inception_anchor = tuple(item.qb64 for item in app.vault.rgy.store.anchor(rip.said))
    events = []
    anchored = []

    class Issuer(credentialing.IssueCredentialDoer):
        def anchor(self, registry, event, receiptor, auths):
            anchored.append(event.said)
            yield from super().anchor(registry, event, receiptor, auths)

    app.vault.signals.doer_event.connect(lambda name, event, data: events.append((event, data)))
    for ordinal in (1, 2):
        worker = Issuer(app, schema.said, holder.pre,
            {'LEI': f'example-{ordinal}'}, registry_mode='derived', registry_id=registry.regk)
        doing.Doist(doers=[worker], tock=.03125, limit=3).do()
        assert events[-1][0] == 'credential_issued', events
        assert app.vault.rgy.store.headEvent(registry.regk).sn == ordinal
        assert issuer.kever.sn == ordinal + 1
        assert tuple(item.qb64 for item in app.vault.rgy.store.anchor(rip.said)) == inception_anchor
        assert len(anchored) == ordinal and rip.said not in anchored
    assert len(app.vault.rgy.regs) == 1


@pytest.mark.parametrize('mode,bound', [('public', False), ('blinded', False),
    ('derived', False), ('blinded', True), ('derived', True)])
def test_registry_mode_survives_reopen_and_revocation_retry(ipex_vaults, mode, bound):
    """Use actual issue/revoke doers, core anchors and encrypted derived custody."""
    password = '0123456789abcdefghijk' if mode == 'derived' else None
    app = ipex_vaults('author-' + mode, bran=password)
    issuer, holder = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='holder')
    schema = _load_schema(app, issuer)
    registry = establish(app.vault, issuer, holder) if mode == 'derived' else None
    events = []
    app.vault.signals.doer_event.connect(lambda name, event, data: events.append((event, data)))
    worker = credentialing.IssueCredentialDoer(app, schema.said, holder.pre,
        {'LEI': 'example'}, registry_mode=mode,
        discloser=holder.pre if mode == 'derived' else None,
        registry_id=registry.regk if registry else None,
        bound_event=holder.kever.serder.said if bound else None)
    doing.Doist(doers=[worker], tock=0.03125, limit=3).do()
    assert events[-1][0] == 'credential_issued', events
    said = events[-1][1]['credential_said']
    record = app.vault.db.issued.get((said,))
    view = credentialing.credential(app.vault, said)
    regid = view['sad']['rd']
    assert record.registry_mode == mode and view['status']['et'] == 'issued'
    assert bool(list(app.vault.db.custody.getTopItemIter())) is (mode == 'derived')
    assert record.blinder
    head = app.vault.rgy.store.headEvent(regid)
    assert head.ilk == 'bup'
    assert bool(app.vault.rgy.store.opening(head.said)) is (mode == 'public')
    assert bool(app.vault.rgy.store.opening(head.said)) is (mode == 'public')
    issued_opening = _blindCandidates(record.blinder)[0]
    app.close_vault()
    app = ipex_vaults('author-' + mode, bran=password)
    issuer = app.hby.habByName('issuer')
    coordinates = {}
    if bound:
        holder = app.hby.habByName('holder')
        holder.rotate()
        stale = credentialing.RevokeCredentialDoer(app, said)
        doing.Doist(doers=[stale], tock=.03125, limit=3).do()
        assert issuer.kever.sn == 2
        assert app.vault.rgy.store.headEvent(regid).sn == 1
        coordinates = dict(bound_event=holder.kever.serder.said)
    for _ in range(2):
        worker = credentialing.RevokeCredentialDoer(app, said, **coordinates)
        doing.Doist(doers=[worker], tock=0.03125, limit=3).do()
        assert credentialing.credential(app.vault, said)['status']['et'] == 'revoked'
        # Inception, registry inception anchor, issuance anchor, revocation anchor.
        assert issuer.kever.sn == 3
        record = app.vault.db.issued.get((said,))
        if mode == 'derived':
            parameters = dict(bound=True, bsn=holder.kever.sn, bd=holder.kever.serder.said) if bound else {}
            opening = disclosing.custody(app.vault).derive(regid, 2, said, 'revoked', **parameters)
            assert opening.qb64 == record.blinder
        elif mode == 'public':
            opening, = _blindCandidates(record.blinder)
            assert opening.state == 'revoked'
            assert app.vault.rgy.store.opening(
                app.vault.rgy.store.headEvent(regid).said) == opening.qb64
            assert app.vault.rgy.store.opening(
                app.vault.rgy.store.headEvent(regid).said) == opening.qb64
            assert not list(app.vault.db.custody.getTopItemIter())
            # A holder's retained issuance proof is augmented only by the
            # accepted public head opening after an observer refresh.
            assert credentialing.credential_state(
                app.vault, SerderACDC(raw=record.raw.encode()),
                blinders=[issued_opening]).state == 'revoked'
        else:
            opening, = _blindCandidates(record.blinder)
            assert opening.state == 'revoked'
        if bound:
            opening, = _blindCandidates(record.blinder)
            assert opening.clan == BoundState and opening.bd == holder.kever.serder.said


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
    with pytest.raises(kering.ValidationError, match='upd.*retired'):
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
