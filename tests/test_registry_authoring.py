"""Public and derived authoring keep custody optional and revocation restartable."""
import pytest
from hio.base import doing
from keri.core import Blinder, BlindState

from locksmith.core import credentialing, disclosing
from test_credentialing import _load_schema
from test_keri_v2_compat import ipex_vaults as ipex_vaults


@pytest.mark.parametrize('mode', ['public', 'blinded', 'derived'])
def test_registry_mode_survives_reopen_and_revocation_retry(ipex_vaults, mode):
    """Use actual issue/revoke doers, core anchors and encrypted derived custody."""
    password = '0123456789abcdefghijk' if mode == 'derived' else None
    app = ipex_vaults('author-' + mode, bran=password)
    issuer, holder = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='holder')
    schema = _load_schema(app, issuer)
    events = []
    app.vault.signals.doer_event.connect(lambda name, event, data: events.append((event, data)))
    worker = credentialing.IssueCredentialDoer(app, schema.said, holder.pre,
        {'LEI': 'example'}, registry_mode=mode,
        discloser=holder.pre if mode == 'derived' else None)
    doing.Doist(doers=[worker], tock=0.03125, limit=3).do()
    assert events[-1][0] == 'credential_issued', events
    said = events[-1][1]['credential_said']
    record = app.vault.db.issued.get((said,))
    view = credentialing.credential(app.vault, said)
    regid = view['sad']['rd']
    assert record.registry_mode == mode and view['status']['et'] == 'issued'
    assert bool(list(app.vault.db.custody.getTopItemIter())) is (mode == 'derived')
    assert bool(record.blinder) is (mode != 'public')
    assert app.vault.rgy.store.headEvent(regid).ilk == ('upd' if mode == 'public' else 'bup')
    app.close_vault()
    app = ipex_vaults('author-' + mode, bran=password)
    issuer = app.hby.habByName('issuer')
    for _ in range(2):
        worker = credentialing.RevokeCredentialDoer(app, said)
        doing.Doist(doers=[worker], tock=0.03125, limit=3).do()
        assert credentialing.credential(app.vault, said)['status']['et'] == 'revoked'
        # Inception, registry inception anchor, issuance anchor, revocation anchor.
        assert issuer.kever.sn == 3
        record = app.vault.db.issued.get((said,))
        if mode == 'derived':
            opening = disclosing.custody(app.vault).derive(regid, 2, said, 'revoked')
            assert opening.qb64 == record.blinder
        elif mode == 'public':
            assert record.blinder == '' and not list(app.vault.db.custody.getTopItemIter())
        else:
            assert Blinder(clan=BlindState, qb64=record.blinder).state == 'revoked'
