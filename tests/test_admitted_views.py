"""A later admission cannot enrich an earlier retained disclosure."""
import pytest
from keri import kering
from keri.acdc import acdcmap, ipexing as native
from keri.core import Compactor, Noncer, SealSource, SerderKERI, messagize
from keri.peer import exchanging

from locksmith.core import credentialing, ipexing
from locksmith.db.basing import IssuedCredential
from test_credentialing import _load_schema
from test_keri_v2_compat import _deliver_ipex, ipex_vaults as ipex_vaults


def test_explicit_admitted_view_survives_fuller_grant_and_reopen(ipex_vaults, qapp):
    """Use real signed grants/admissions, then present the selected original bytes."""
    sender, receiver = ipex_vaults('view-sender'), ipex_vaults('view-receiver')
    issuer, holder = sender.hby.makeHab(name='issuer'), receiver.hby.makeHab(name='holder')
    schema = _load_schema(sender, issuer)
    receiver.hby.db.schema.pin((schema.said,), schema)
    attributes = {'d': '', 'u': Noncer().qb64, 'i': holder.pre,
                  'details': {'d': '', 'u': Noncer().qb64, 'LEI': 'private-later-value'}}
    full = acdcmap(israid=issuer.pre, uuid=Noncer().qb64, schema=schema.said, attribute=attributes)
    anchor = SerderKERI(raw=issuer.interact(data=[{'d': full.said}]))
    proof = messagize(full, bonds=[SealSource(s=anchor.snh, d=anchor.said)])
    sender.vault.db.issued.pin((full.said,), IssuedCredential(full.raw.decode(), stream=proof.decode()))
    _deliver_ipex(receiver.vault, issuer.replay(gvrsn=kering.Vrsn_2_0))
    _deliver_ipex(sender.vault, holder.replay(gvrsn=kering.Vrsn_2_0))
    block = Compactor(mad=full.sad['a'], makify=True, kind=full.kind)
    block.compact(paths=['i'])
    partial = acdcmap(israid=issuer.pre, uuid=full.sad['u'], schema=schema.said,
                      attribute=block.partials[('i',)].mad)
    assert partial.said == full.said
    first, atc = native.grant(issuer, holder.pre, 'Partial',
        origin=messagize(partial, bonds=[SealSource(s=anchor.snh, d=anchor.said)]),
        modifiers={'dp': [[[schema.said, '/', []]]]})
    _deliver_ipex(receiver.vault, ipexing.prepare(sender.vault, issuer, first, atc))
    with pytest.raises(kering.ValidationError, match='not admitted'):
        credentialing.credential(receiver.vault, full.said, grant=first.said)
    ipexing.admit(receiver.vault, holder, first.said)
    retained = credentialing.credential(receiver.vault, full.said, grant=first.said)['proof']
    later, atc = ipexing.grant(sender.vault, issuer, full.said, holder.pre, 'Full')
    _deliver_ipex(receiver.vault, ipexing.prepare(sender.vault, issuer, later, atc))
    with pytest.raises(kering.ValidationError, match='not admitted'):
        credentialing.credential(receiver.vault, full.said, grant=later.said)
    ipexing.admit(receiver.vault, holder, later.said)
    receiver.close_vault()
    receiver = ipex_vaults('view-receiver')
    holder = receiver.hby.habByName('holder')
    assert [entry.grant for entry in credentialing.admissions(receiver.vault, full.said)] == [first.said, later.said]
    assert credentialing.credential(receiver.vault, full.said, grant=first.said)['proof'] == retained
    assert isinstance(credentialing.credential(receiver.vault, full.said, grant=first.said)['sad']['a']['details'], str)
    assert credentialing.credential(receiver.vault, full.said, grant=later.said)['sad']['a']['details']['LEI'] == 'private-later-value'
    # Actual selection controls must preserve the old view after a fuller grant.
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from locksmith.ui.vault.credentials.disclosure import DisclosureOptions
    from locksmith.ui.vault.credentials.presentation import disclosed_credentials
    options = DisclosureOptions(receiver.vault)
    options.select(full.said)
    options.show()
    assert options.selection() == {'from_grant': first.said}
    assert isinstance(disclosed_credentials(receiver.vault, full.said,
        **options.selection())[0]['a']['details'], str)
    options.grant.setFocus()
    QTest.keyClick(options.grant, Qt.Key.Key_Down)
    assert options.selection() == {'from_grant': later.said}
    assert disclosed_credentials(receiver.vault, full.said,
        **options.selection())[0]['a']['details']['LEI'] == 'private-later-value'
    QTest.keyClick(options.grant, Qt.Key.Key_Up)
    assert options.selection() == {'from_grant': first.said}
    options.refresh.setChecked(True)
    options.source.setCurrentIndex(options.source.findData('supplied'))
    with pytest.raises(ValueError, match='Choose the event-specific opening'):
        options.selection()
    options.refresh.setChecked(False)
    assert options.selection() == {'from_grant': first.said}
    options.close()
    presented, atc = ipexing.grant(receiver.vault, holder, full.said, issuer.pre, from_grant=first.said)
    stream = ipexing.prepare(receiver.vault, holder, presented, atc)
    nested, = exchanging.loadParsedNestedSubstreams(receiver.hby, presented.said)
    assert nested.serder.raw == partial.raw
    assert credentialing.delete_credential(receiver.vault, full.said, received=True)
    assert credentialing.admissions(receiver.vault, full.said) == []
