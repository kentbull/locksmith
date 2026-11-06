"""A real two-member group holder presents one exact admitted view at threshold."""
from keri import kering
from keri.peer import exchanging
from test_credentialing import _issue, _load_schema
from test_ipex_policy import _introduce
from test_keri_v2_compat import _deliver_ipex
from test_keri_v2_compat import ipex_mailbox as ipex_mailbox
from test_keri_v2_compat import ipex_vaults as ipex_vaults

from locksmith.core import group_presenting, ipexing
from locksmith.ui.vault.credentials.group_presentation import group_admissions

V2 = kering.Vrsn_2_0


def _deliver_member(source, target):
    """Carry one queued member coordination message through the target's mailbox intake."""
    event = source.vault.postman.evts.popleft()
    assert event['dest'] in target.hby.habs and event['topic'] == 'multisig'
    _deliver_ipex(target.vault, event['serder'].raw + event['attachment'])


def test_group_holder_presents_admitted_view_only_at_threshold(ipex_vaults, ipex_mailbox):
    issuer, first, second, verifier = [ipex_vaults('group-present-' + role)
                                       for role in ('issuer', 'a', 'b', 'verifier')]
    apps = (issuer, first, second, verifier)
    holders = (first, second)
    ih = issuer.hby.makeHab(name='issuer')
    vh = verifier.hby.makeHab(name='verifier')
    members = [app.hby.makeHab(name=f'member-{index}') for index, app in enumerate(holders)]
    for app in apps:
        for member in members:
            _deliver_ipex(app.vault, member.replay(gvrsn=V2))
    groups = [app.hby.makeGroupHab(group='holder', mhab=member, smids=[m.pre for m in members],
                                   isith='2', nsith='2', version=V2)
              for app, member in zip(holders, members)]
    partials = [group.msgOwnInception(allowPartiallySigned=True, gvrsn=V2) for group in groups]
    for app in holders:
        for raw in partials:
            app.vault.mbx.parser.parse(ims=bytearray(raw), local=True)
        app.hby.kvy.processEscrows()
        assert app.hby.habByName('holder').kever.tholder.num == 2
    first_group, second_group = groups
    gid = first_group.pre
    for app in (issuer, verifier):
        _deliver_ipex(app.vault, first_group.replay(gvrsn=V2))
    schema = _load_schema(issuer, ih)
    for app in apps[1:]:
        app.hby.db.schema.pin((schema.said,), schema)
    for app in apps:
        for other in apps:
            if app is not other:
                _introduce(app, other)

    # An individual issuer grants to the group; both members admit it at threshold.
    said = _issue(issuer, schema, first_group, authentication='anchor')
    for app in apps[1:]:
        _introduce(issuer, app)
    exn, atc = ipexing.grant(issuer.vault, ih, said, gid)
    stream = ipexing.prepare(issuer.vault, ih, exn, atc)
    for app in holders:
        _deliver_ipex(app.vault, stream)
    source = exn.said
    ipexing.admit(first.vault, first_group, source)
    _deliver_member(first, second)
    proposed = ipexing.group_admit_proposal(second.vault, second_group, source)
    ipexing.admit(second.vault, second_group, source, proposal=proposed.said)
    _deliver_member(second, first)
    for app in holders:
        app.vault.auxiliary.process()
        assert app.vault.db.accepted.get((said,)).grant == source
        assert group_admissions(app.vault, said) == [(app.hby.habByName('holder').pre, source)]
    assert group_admissions(issuer.vault, said) == []

    # A's proposal is retained but partial: no KRAM lifetime and no delivery.
    status = group_presenting.propose(first.vault, first_group, said=said, source=source,
                                      recipient=vh.pre, message='Exact group presentation')
    presentation = status['grant']
    assert status['phase'] == 'awaiting_threshold' and status['deadline'] == ''
    assert status['contributed'] and not first.vault.exc.complete(presentation)
    first.vault.auxiliary.process()
    assert first.vault.auxiliary.status(gid, presentation)['deadline'] == ''
    assert first.vault.db.outbox.get((presentation,)) is None
    assert verifier.hby.db.exns.get((presentation,)) is None

    # B sees the same exact proposal through its mailbox and explicitly contributes.
    _deliver_member(first, second)
    row, = [row for row in second.vault.auxiliary.pending() if row['kind'] == 'presentation']
    assert row['grant'] == presentation and row['deadline'] == ''
    assert row['actions'] == ('approve_presentation',) and row['source'] == source
    contributed = second.vault.auxiliary.presenters.contribute(second_group, presentation)
    assert contributed['deadline'] and contributed['phase'] == 'complete'
    assert not second.vault.exc.lead(second_group, presentation)
    assert second.vault.db.outbox.get((presentation,)) is None

    # Threshold intake at A fixes the deadline; only the elected lead queues delivery.
    _deliver_member(second, first)
    first.vault.auxiliary.process()
    status = first.vault.auxiliary.status(gid, presentation)
    assert status['phase'] == 'submitted' and status['deadline'] == contributed['deadline']
    assert first.vault.exc.lead(first_group, presentation)
    assert first.vault.db.outbox.get((presentation,)) is not None
    grant = first.hby.db.exns.get((presentation,))
    stream = exchanging.serializeMessage(first.hby, presentation)
    # The outbox posts the group's Grant through the lead member's own transport.
    ipex_mailbox(first, verifier, members[0], grant, stream, queued=True)
    assert second.vault.db.outbox.get((presentation,)) is None

    assert verifier.vault.exc.complete(presentation)
    tsgs, _ = exchanging.verify(verifier.hby, verifier.hby.db.exns.get((presentation,)))
    assert {siger.index for pre, _, _, sigers in tsgs if pre.qb64 == gid for siger in sigers} == {0, 1}
    ipexing.admit(verifier.vault, vh, presentation)
    assert verifier.vault.db.accepted.get((said,)).grant == presentation
