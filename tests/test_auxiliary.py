"""Actual live Grants and auxiliary protocol owners, without accepted-row seeding."""
from datetime import timedelta

import pytest
from hio.base import doing
from keri.help import helping
from keri import kering
from keri.acdc import Registrar, acdcmap, grant
from keri.core import Parser, SealSource, SerderKERI, messagize, receipt

from locksmith.core import credentialing, evidence, grouping, ipexing, root_copying
from test_credentialing import _load_schema
from test_keri_v2_compat import ipex_vaults as ipex_vaults, _deliver_ipex


def pending_issuance(open_vault):
    """Three independent stores; real witness receipts authorize the fresh RIP."""
    issuer = open_vault('aux-issuer', bran='0123456789abcdefghijk')
    holder = open_vault('aux-holder', bran='0123456789abcdefghijk')
    witness = open_vault('aux-witness')
    wh = witness.hby.makeHab('witness', transferable=False)
    ih = issuer.hby.makeHab('issuer', wits=[wh.pre], toad=1, icount=2, isith='2', ncount=2, nsith='2')
    hh = holder.hby.makeHab('holder', icount=2, isith='2', ncount=2, nsith='2')
    for target in (issuer, holder):
        _deliver_ipex(target.vault, b''.join(witness.hby.db.clonePreIter(wh.pre, gvrsn=kering.Vrsn_2_0)))
    initial = ih.kever.serder
    issuer.vault.kvy.processReceipt(serder=receipt(ih.pre, initial.sn, initial.said),
        cigars=wh.sign(initial.raw, indexed=False), wigers=[], tsgs=[], local=False)
    for source, target, hab in ((issuer, holder, ih), (holder, issuer, hh)):
        _deliver_ipex(target.vault, b''.join(source.hby.db.clonePreIter(hab.pre, gvrsn=kering.Vrsn_2_0)))

    def seal(event, recipients=None):
        raw = ih.interact(data=[dict(i=registry.regk, s=event.sad['n'], d=event.said)],
                          gvrsn=kering.Vrsn_2_0)
        anchor = SerderKERI(raw=raw)
        issuer.vault.kvy.processReceipt(serder=receipt(ih.pre, anchor.sn, anchor.said),
            cigars=wh.sign(anchor.raw, indexed=False), wigers=[], tsgs=[], local=False)
        assert registry.anchorMsg(event.said)
        for vault in recipients if recipients is not None else (holder.vault,):
            _deliver_ipex(vault, b''.join(issuer.hby.db.clonePreIter(ih.pre, gvrsn=kering.Vrsn_2_0)))
            assert vault.hby.db.fullyWitnessed(vault.hby.db.evts.get((ih.pre, anchor.said)))
            _deliver_ipex(vault, messagize(event, bonds=[SealSource(s=anchor.snh, d=anchor.said)],
                                         gvrsn=kering.Vrsn_2_0))
            assert vault.rgy.store.headEvent(registry.regk).said == event.said

    registrar = Registrar(issuer.vault.rgy)
    registry = registrar.makeRegistry('fresh', ih.pre)
    seal(issuer.vault.rgy.store.event(registry.regk))
    acdc = acdcmap(israid=ih.pre, iseaid=hh.pre, regid=registry.regk,
                   attribute=dict(d='', i=hh.pre, role='holder'))
    message, attachment = grant(ih, hh.pre, 'Explicit live agreement', origin=acdc,
                                kind=kering.Kinds.json)
    return issuer, holder, ih, hh, registrar, registry, acdc, message, attachment, seal


def test_live_dh_preserves_early_query_then_accepts_the_same_grant(ipex_vaults):
    issuer, holder, ih, hh, registrar, registry, acdc, message, atc, seal = pending_issuance(ipex_vaults)
    io, ho = issuer.vault.auxiliary, holder.vault.auxiliary
    io.begin_dh(ih, message, atc)
    _, _, wire, _ = io.outgoing.popleft()
    _deliver_ipex(holder.vault, wire)
    deadline = holder.hby.db.epsd.get((message.said,)).dts
    _, _, query, _ = io.outgoing.popleft()
    _deliver_ipex(holder.vault, query)
    assert ho.status(hh.pre, message.said)['phase'] == 'approval_required'
    assert holder.hby.mgr.getRegistryRoot(hh.pre, registry.regk) is None
    assert len(ho._queries) == 1
    cache = holder.hby.db.kramMSGC.get((ih.pre, next(iter(ho._queries.values())).serder.said))
    cutoff = helping.fromIso8601(cache.mdt) + timedelta(milliseconds=cache.d + cache.ml)
    assert next(iter(ho._queries.values())).expires == cutoff
    _deliver_ipex(holder.vault, query)
    assert next(iter(ho._queries.values())).expires == cutoff
    ho.approve_dh(hh, message.said)
    assert holder.hby.db.epsd.get((message.said,)).dts == deadline
    _, _, reply, _ = ho.outgoing.popleft()
    _deliver_ipex(issuer.vault, reply)
    assert io.agreement_ready(ih.pre, message.said)
    root = issuer.hby.mgr.getRegistryRoot(ih.pre, registry.regk)
    assert root.qb64 == holder.hby.mgr.getRegistryRoot(hh.pre, registry.regk).qb64
    assert root.qb64b not in query and root.qb64b not in reply
    assert not issuer.vault.exc.complete(message.said)
    assert not holder.vault.exc.complete(message.said)
    _, event = registrar.issue(registry, acdc, salt=root.qb64)
    seal(event)
    for _ in range(2):
        io.process()
        ho.process()
    assert io.status(ih.pre, message.said)['phase'] == 'verified'
    assert ho.status(hh.pre, message.said)['phase'] == 'verified'
    assert holder.hby.db.exns.get((message.said,)).raw == message.raw
    assert holder.vault.db.accepted.get((acdc.said,)) is None
    ipexing.admit(holder.vault, hh, message.said)
    assert holder.vault.db.accepted.get((acdc.said,)).grant == message.said


def test_partial_query_signatures_do_not_authorize_agreement(ipex_vaults):
    issuer, holder, ih, hh, _, registry, _, message, atc, _ = pending_issuance(ipex_vaults)
    io, ho = issuer.vault.auxiliary, holder.vault.auxiliary
    io.begin_dh(ih, message, atc)
    _, _, wire, _ = io.outgoing.popleft()
    _deliver_ipex(holder.vault, wire)
    _, _, query, _ = io.outgoing.popleft()
    parsed = Parser(version=kering.Vrsn_2_0).parseOne(ims=bytearray(query), processive=False)
    signatures = ih.sign(parsed.serder.raw)
    partial = messagize(parsed.serder, lsgs=[(ih.kever.prefixer, signatures[:1])], gvrsn=kering.Vrsn_2_0)
    _deliver_ipex(holder.vault, partial)
    assert not ho._queries
    ho.approve_dh(hh, message.said)
    assert holder.hby.mgr.getRegistryRoot(hh.pre, registry.regk) is None
    _deliver_ipex(holder.vault, query)
    assert holder.hby.mgr.getRegistryRoot(hh.pre, registry.regk) is not None
    assert ho.outgoing


def test_original_query_deadline_and_cancelled_agreement_do_not_restart(ipex_vaults, monkeypatch):
    issuer, holder, ih, hh, _, registry, _, message, atc, _ = pending_issuance(ipex_vaults)
    io, ho = issuer.vault.auxiliary, holder.vault.auxiliary
    io.begin_dh(ih, message, atc)
    _, _, wire, _ = io.outgoing.popleft()
    _deliver_ipex(holder.vault, wire)
    _, _, query, _ = io.outgoing.popleft()
    _deliver_ipex(holder.vault, query)
    cutoff = next(iter(ho._queries.values())).expires
    monkeypatch.setattr(helping, 'nowUTC', lambda: cutoff + timedelta(milliseconds=1))
    ho.process()
    assert not ho._queries
    assert ho.status(hh.pre, message.said)['phase'] == 'expired'
    with pytest.raises(kering.ValidationError):
        ho.approve_dh(hh, message.said)
    assert holder.hby.mgr.getRegistryRoot(hh.pre, registry.regk) is None
    io.abandon(ih.pre, message.said)
    with pytest.raises(ValueError):
        io.begin_dh(ih, message, atc)
    assert io.status(ih.pre, message.said)['phase'] == 'cancelled'
    assert not io.outgoing


def test_definitive_finish_refusal_keeps_encrypted_roots_and_no_admission(ipex_vaults):
    issuer, holder, ih, hh, registrar, registry, acdc, message, atc, seal = pending_issuance(ipex_vaults)
    io, ho = issuer.vault.auxiliary, holder.vault.auxiliary
    io.begin_dh(ih, message, atc)
    _, _, wire, _ = io.outgoing.popleft()
    _deliver_ipex(holder.vault, wire)
    ho.approve_dh(hh, message.said)
    _, _, query, _ = io.outgoing.popleft()
    _deliver_ipex(holder.vault, query)
    _, _, reply, _ = ho.outgoing.popleft()
    _deliver_ipex(issuer.vault, reply)
    root = issuer.hby.mgr.getRegistryRoot(ih.pre, registry.regk)
    _, event = registrar.issue(registry, acdc, state='revoked', salt=root.qb64)
    seal(event)
    io.process()
    ho.process()
    assert io.status(ih.pre, message.said)['phase'] == 'refused'
    assert ho.status(hh.pre, message.said)['phase'] == 'refused'
    assert issuer.hby.mgr.getRegistryRoot(ih.pre, registry.regk).qb64 == root.qb64
    with pytest.raises(kering.ValidationError):
        ho.approve_dh(hh, message.said)
    assert holder.vault.db.accepted.get((acdc.said,)) is None


def test_issuance_worker_finishes_dh_and_cancellation_drops_live_authority(ipex_vaults):
    """Run the application worker; closing it must abandon unfinished approval."""
    issuer = ipex_vaults('worker-issuer', bran='0123456789abcdefghijk')
    holder = ipex_vaults('worker-holder', bran='0123456789abcdefghijk')
    ih, hh = issuer.hby.makeHab('issuer'), holder.hby.makeHab('holder')
    schema = _load_schema(issuer, ih)
    holder.hby.db.schema.pin((schema.said,), schema)
    for source, target, hab in ((issuer, holder, ih), (holder, issuer, hh)):
        _deliver_ipex(target.vault, hab.replay(gvrsn=kering.Vrsn_2_0))
    events = []
    issuer.vault.signals.doer_event.connect(lambda *args: events.append(args))
    worker = credentialing.IssueCredentialDoer(issuer, schema.said, hh.pre,
        {'LEI': '254900OPPU84GM83MG36'}, registry_mode='derived')
    scheduler = doing.Doist(doers=[worker], tock=0.03125)
    scheduler.enter()
    io, ho = issuer.vault.auxiliary, holder.vault.auxiliary
    try:
        # The worker authors and accepts RIP before preparing its exact Grant.
        for _ in range(100):
            scheduler.recur()
            if io.operations:
                break
        operation, = io.operations.values()
        said, grant_said = operation.grant.sad['a']['o'][0], operation.grant.said
        regk = next(iter(issuer.vault.rgy.regs))
        _deliver_ipex(holder.vault, evidence.clone(issuer.vault, regk))
        _, _, wire, _ = io.outgoing.popleft()
        _deliver_ipex(holder.vault, wire)
        _, _, query, _ = io.outgoing.popleft()
        _deliver_ipex(holder.vault, query)
        assert not list(issuer.vault.db.issued.getTopItemIter())
        ho.approve_dh(hh, grant_said)
        _, _, reply, _ = ho.outgoing.popleft()
        _deliver_ipex(issuer.vault, reply)
        for _ in range(100):
            scheduler.recur()
            if worker.done:
                break
        assert worker.done
        assert events[-1][1] == 'credential_issued', events
        assert io.status(ih.pre, grant_said)['phase'] == 'verified'
        _deliver_ipex(holder.vault, evidence.clone(issuer.vault, regk))
        ho.process()
        assert ho.status(hh.pre, grant_said)['phase'] == 'verified'
        assert holder.vault.db.accepted.get((said,)) is None
        ipexing.admit(holder.vault, hh, grant_said)
        retained = credentialing.credential(holder.vault, said, grant=grant_said)['proof']
        root = holder.hby.mgr.getRegistryRoot(hh.pre, regk).qb64
    finally:
        scheduler.exit()

    # Cancelling an issuance worker interrupts its native operation, not history.
    cancelled = credentialing.IssueCredentialDoer(issuer, schema.said, hh.pre,
        {'LEI': 'cancelled'}, registry_mode='derived')
    scheduler = doing.Doist(doers=[cancelled], tock=0.03125)
    scheduler.enter()
    try:
        for _ in range(100):
            scheduler.recur()
            if len(io.operations) == 2:
                break
        pending = next(op for op in io.operations.values() if op.grant.said != grant_said)
        assert pending.phase == 'waiting'
        _, registries = issuer.vault.exc.pendingGrant(pending.grant.said,
            xid=pending.xid, sender=ih.pre, recipient=hh.pre)
        _deliver_ipex(holder.vault, evidence.clone(issuer.vault, registries[0]))
        _, _, wire, _ = io.outgoing.popleft()
        _deliver_ipex(holder.vault, wire)
        _, _, query, _ = io.outgoing.popleft()
        _deliver_ipex(holder.vault, query)
        ho.approve_dh(hh, pending.grant.said)
    finally:
        scheduler.exit()
    assert pending.phase == 'cancelled'
    assert not io.outgoing
    assert pending.protocol._operations[pending.xid]['abandoned']

    # A vault close drops an unfinished recipient approval and its queued reply.
    unfinished = ho.operations[(hh.pre, pending.grant.said)]
    config = holder.hby.cf.get()
    config['kram']['enabled'] = False
    custom = [[2, 0], 'qry', 'local/custom']
    config['kram']['denials'].append(custom)
    holder.hby.cf.put(config)
    holder.close_vault()
    assert unfinished.phase == 'interrupted'
    assert unfinished.protocol._operations[unfinished.xid]['abandoned']
    assert not ho.outgoing
    holder = ipex_vaults('worker-holder', bran='0123456789abcdefghijk')
    hh = holder.hby.habByName('holder')
    assert not holder.vault.auxiliary.operations
    assert holder.hby.mgr.getRegistryRoot(hh.pre, regk).qb64 == root
    assert credentialing.credential(holder.vault, said, grant=grant_said)['proof'] == retained
    assert holder.hby.cf.get()['kram'] == config['kram']


def test_group_derived_worker_requires_member_consent_and_keeps_custody_local(ipex_vaults, qapp, tmp_path):
    """Independent issuer and holder groups approve setup, then separately accept."""
    issuer, peer, holder, holder_peer = [ipex_vaults(name, bran='0123456789abcdefghijk')
        for name in ('group-dh-lead', 'group-dh-peer', 'group-dh-holder', 'group-dh-holder-peer')]
    issuers = (issuer, peer)
    holders = (holder, holder_peer)
    apps = (*issuers, *holders)

    def make_group(parties, alias):
        members = [app.hby.makeHab(f'{alias}-member-{index}') for index, app in enumerate(parties)]
        for app in apps:
            for member in members:
                _deliver_ipex(app.vault, member.replay(gvrsn=kering.Vrsn_2_0))
        groups = [app.hby.makeGroupHab(group=alias, mhab=member, smids=[m.pre for m in members],
                                       isith='2', nsith='2', version=kering.Vrsn_2_0)
                  for app, member in zip(parties, members)]
        partials = [group.msgOwnInception(allowPartiallySigned=True, gvrsn=kering.Vrsn_2_0) for group in groups]
        for app in parties:
            for raw in partials:
                app.vault.mbx.parser.parse(ims=bytearray(raw), local=True)
            app.hby.kvy.processEscrows()
            assert app.hby.habByName(alias).kever.tholder.num == 2
        for app in apps:
            if app not in parties:
                _deliver_ipex(app.vault, groups[0].replay(gvrsn=kering.Vrsn_2_0))
        return members, groups

    members, groups = make_group(issuers, 'issuer')
    holder_members, holder_groups = make_group(holders, 'holder')
    hh, hph = holder_groups
    schema = _load_schema(issuer, groups[0])
    for app in (peer, *holders):
        app.hby.db.schema.pin((schema.said,), schema)
    events = []
    issuer.vault.signals.doer_event.connect(lambda *args: events.append(args))
    worker = credentialing.IssueCredentialDoer(issuer, schema.said, hh.pre,
        {'LEI': '254900OPPU84GM83MG36'}, registry_mode='derived')
    scheduler = doing.Doist(doers=[worker], tock=.03125)
    scheduler.enter()
    io, po, ho, hpo = [app.vault.auxiliary for app in apps]

    def advance(until):
        for _ in range(100):
            if until():
                return
            scheduler.recur()
            for app in apps:
                app.vault.mux.kvy.processEscrows()
                app.vault.counselor.processEscrows()
                app.vault.rgy.processEscrows()
                app.vault.auxiliary.process()
            failures = [data for _, event, data in events if event.endswith('_failed')]
            assert not failures, failures
        assert until(), events

    def deliver_member(source, target):
        event = source.vault.postman.evts.popleft()
        assert event['dest'] in target.hby.habs and event['topic'] == 'multisig'
        _deliver_ipex(target.vault, event['serder'].raw + event['attachment'])

    wires = []

    def deliver_aux(source, target, topic):
        _, destination, raw, selected_topic = source.vault.auxiliary.outgoing.popleft()
        assert destination in target.hby.habs and selected_topic == topic
        wires.append(raw)
        _deliver_ipex(target.vault, raw)
        return raw

    try:
        # The fresh RIP needs actual member approval before there can be a live Grant.
        advance(lambda: bool(issuer.vault.postman.evts))
        deliver_member(issuer, peer)
        rip_proposal, = grouping.pending_registry_proposals(peer.vault)
        _, children, _ = grouping.registry_proposal(peer.vault, rip_proposal.said)
        rip = children[0].serder
        assert not io.operations and not po.operations
        grouping.approve_registry_proposal(peer.vault, rip_proposal.said, groups[1].kever.serder.said)
        deliver_member(peer, issuer)
        advance(lambda: bool(io.operations))
        assert groups[0].witnesser(sn=children[1].serder.sn, dig=children[1].serder.said)
        for app in holders:
            _deliver_ipex(app.vault, groups[0].replay(gvrsn=kering.Vrsn_2_0))
            _deliver_ipex(app.vault, evidence.clone(issuer.vault, rip.said))
        operation, = io.operations.values()
        message = operation.grant
        gid, grant_said = groups[0].pre, message.said
        original = message.raw
        deadline = io.status(gid, grant_said)['deadline']
        assert deadline and all(topic == 'multisig' for _, _, _, topic in io.outgoing)
        deliver_aux(issuer, peer, 'multisig')
        po.process()
        selected = po.status(gid, grant_said)
        assert selected['stage'] == 'grant' and selected['actions'] == ('approve_dh',)
        assert selected['custodian'] == members[0].pre
        assert selected['coordinator'] == (children[1].serder.sn, children[1].serder.said)
        assert not io.outgoing and not po.outgoing and not ho.operations
        assert all(app.hby.mgr.getRegistryRoot(gid, rip.said) is None for app in issuers)

        # One setup decision authorizes the Grant and its scoped DH contribution.
        po.approve_dh(groups[1], grant_said, proposal=selected['proposal'])
        deliver_aux(peer, issuer, 'multisig')
        advance(lambda: any(topic == 'multisig' for _, _, _, topic in io.outgoing))
        deliver_aux(issuer, holder, 'credential')
        holder_deadline = holder.hby.db.epsd.get((grant_said,)).dts
        deliver_aux(issuer, peer, 'multisig')
        po.process()
        selected = po.status(gid, grant_said)
        assert selected['stage'] == 'query' and selected['actions'] == ()
        assert selected['contributed']
        # The issuer still waits for the actual query signature threshold.
        assert not any(topic == 'reply' for _, _, _, topic in io.outgoing)
        assert holder.hby.mgr.getRegistryRoot(hh.pre, rip.said) is None
        deliver_aux(peer, issuer, 'multisig')
        advance(lambda: any(topic == 'reply' for _, _, _, topic in io.outgoing))
        deliver_aux(issuer, holder, 'reply')
        assert ho.status(hh.pre, grant_said)['phase'] == 'approval_required'
        ho.approve_dh(hh, grant_said, proposal=grant_said)
        assert not any(destination == gid and topic == 'reply'
                       for _, destination, _, topic in ho.outgoing)
        deliver_aux(holder, holder_peer, 'credential')
        peer_deadline = holder_peer.hby.db.epsd.get((grant_said,)).dts
        deliver_aux(holder, holder_peer, 'reply')
        deliver_aux(holder, holder_peer, 'multisig')
        hpo.process()
        selected = hpo.status(hph.pre, grant_said)
        assert selected['role'] == 'holder' and selected['actions'] == ('approve_dh',)
        assert selected['custodian'] == holder_members[0].pre
        assert not hpo.outgoing
        assert all(app.vault.db.receipts.get((hh.pre, grant_said)) is None for app in holders)
        # One setup decision per holder automatically contributes the exact custodian reply.
        hpo.approve_dh(hph, grant_said, proposal=grant_said)
        assert not any(destination == gid and topic == 'reply'
                       for _, destination, _, topic in ho.outgoing)
        deliver_aux(holder_peer, holder, 'multisig')
        advance(lambda: any(destination == gid and topic == 'reply'
                            for _, destination, _, topic in ho.outgoing))
        deliver_aux(holder, issuer, 'reply')

        # Successful DH retains custody only at the elected issuer and holder; BUP remains unaccepted.
        advance(lambda: bool(issuer.vault.postman.evts))
        root = issuer.hby.mgr.getRegistryRoot(gid, rip.said)
        assert root is not None and root.qb64 == holder.hby.mgr.getRegistryRoot(hh.pre, rip.said).qb64
        assert peer.hby.mgr.getRegistryRoot(gid, rip.said) is None
        assert holder_peer.hby.mgr.getRegistryRoot(hph.pre, rip.said) is None
        assert all(root.qb64b not in wire for wire in wires)
        assert not issuer.vault.exc.complete(grant_said) and not holder.vault.exc.complete(grant_said)
        assert not worker.done and not any(event == 'credential_issued' for _, event, _ in events)
        deliver_member(issuer, peer)
        bup_proposal, = grouping.pending_registry_proposals(peer.vault)
        assert bup_proposal.route == '/multisig/bup'
        _, update, _ = grouping.registry_proposal(peer.vault, bup_proposal.said)
        bup = update[0].serder
        assert all(app.vault.rgy.store.seqEvent(rip.said, 1) is None for app in issuers)
        assert operation.grant.raw == original and io.status(gid, grant_said)['deadline'] == deadline
        assert holder.hby.db.epsd.get((grant_said,)).dts == holder_deadline
        assert holder_peer.hby.db.epsd.get((grant_said,)).dts == peer_deadline
        grouping.approve_registry_proposal(peer.vault, bup_proposal.said, groups[1].kever.serder.said)
        deliver_member(peer, issuer)
        advance(lambda: worker.done)
        assert events[-1][1] == 'credential_issued', events
        assert io.status(gid, grant_said)['phase'] == 'verified'
        assert all(app.vault.rgy.store.seqEvent(rip.said, 1).raw == bup.raw for app in issuers)
        deliver_aux(issuer, holder, 'credential')
        for app in holders:
            _deliver_ipex(app.vault, evidence.clone(issuer.vault, rip.said))
        ho.process()
        assert ho.status(hh.pre, grant_said)['phase'] == 'verified'
        assert not holder_peer.vault.exc.complete(grant_said)
        # Public proof verifies the nonlead's exact Grant without copying either registry root.
        deliver_aux(holder, holder_peer, 'multisig')
        hpo.process()
        assert hpo.status(hph.pre, grant_said)['phase'] == 'verified'
        for app, cutoff in zip(holders, (holder_deadline, peer_deadline)):
            assert app.hby.db.exns.get((grant_said,)).raw == original
            assert app.hby.db.epsd.get((grant_said,)).dts == cutoff
            assert app.vault.db.accepted.get((message.sad['a']['o'][0],)) is None
            assert app.vault.db.receipts.get((hh.pre, grant_said)) is None
        assert peer.hby.mgr.getRegistryRoot(gid, rip.said) is None
        assert holder_peer.hby.mgr.getRegistryRoot(hph.pre, rip.said) is None
        assert all(root.qb64b not in wire for wire in wires)
        # Acceptance is a later group decision; one signature adds neither holder's inventory.
        admitted, _ = ipexing.admit(holder.vault, hh, grant_said)
        assert holder.vault.db.receipts.get((hh.pre, grant_said)).status == 'preparing'
        assert all(app.vault.db.accepted.get((message.sad['a']['o'][0],)) is None for app in holders)
        deliver_member(holder, holder_peer)
        proposed = ipexing.group_admit_proposal(holder_peer.vault, hph, grant_said)
        assert proposed.raw == admitted.raw
        contributed, _ = ipexing.admit(holder_peer.vault, hph, grant_said, proposal=proposed.said)
        assert contributed.raw == admitted.raw
        deliver_member(holder_peer, holder)
        advance(lambda: all(app.vault.db.accepted.get((message.sad['a']['o'][0],)) is not None for app in holders))
        for app in holders:
            accepted = app.vault.db.accepted.get((message.sad['a']['o'][0],))
            assert accepted.grant == grant_said and accepted.admit == admitted.said

        # Root copying is a later explicit file operation; it changes neither admission nor held proof.
        credential_said = message.sad['a']['o'][0]
        historical = [(app.vault.db.accepted.get((credential_said,)),
                       credentialing.credential(app.vault, credential_said, grant=grant_said)['proof'])
                      for app in holders]
        event, opening = root_copying.held_openings(holder.vault, credential_said, grant_said)[0]
        assert event == bup.said

        def prepare_copy(source, target, author, recipient, member):
            coordinator = (author.kever.sn, author.kever.serder.said)
            partial, proposal = source.vault.root_copies.prepare_group(
                author.pre, rip.said, recipient.pre, member.pre, coordinator)
            selected = root_copying.inspect(partial)
            body = SerderKERI(raw=partial)
            wrapper = Parser(version=kering.Vrsn_2_0).parseOneBare(
                ims=bytearray(proposal), processive=False)
            assert wrapper.serder.route == '/multisig/rpy' and wrapper.serder.pre == author.mhab.pre
            assert wrapper.nests[0].serder.raw == body.raw
            assert selected.sender == author.pre and selected.recipient == recipient.pre
            assert selected.target == member.pre
            assert target.hby.mgr.getRegistryRoot(recipient.pre, rip.said) is None
            with pytest.raises(kering.ValidationError):
                target.vault.root_copies.receive_group(selected, recipient.pre, rip.said, event, opening)
            assert target.hby.mgr.getRegistryRoot(recipient.pre, rip.said) is None
            assert target.vault.root_copies.active is None
            contributed = target.vault.root_copies.contribute_group(
                proposal, recipient.pre, rip.said, recipient.pre, member.pre, coordinator)
            assert SerderKERI(raw=contributed).raw == body.raw
            assert target.hby.mgr.getRegistryRoot(recipient.pre, rip.said) is None
            assert all(root.qb64b not in raw for raw in (partial, proposal, contributed))
            return selected, contributed

        selected, contribution = prepare_copy(holder, holder_peer, hh, hph, holder_members[1])
        result = holder_peer.vault.root_copies.receive_group(selected, hph.pre, rip.said, event, opening,
            contributions=(root_copying.inspect(contribution),))
        assert result == selected.said and holder_peer.vault.root_copies.active is None
        assert holder_peer.hby.mgr.getRegistryRoot(hph.pre, rip.said).qb64 == root.qb64
        # The issuer peer naturally has no inventory row; native accepted BUP/opening evidence suffices.
        assert peer.vault.db.issued.get((credential_said,)) is None
        assert peer.vault.db.accepted.get((credential_said,)) is None
        selected, contribution = prepare_copy(issuer, peer, groups[0], groups[1], members[1])
        from PySide6.QtCore import Qt
        from PySide6.QtTest import QTest
        from PySide6.QtWidgets import QWidget
        from locksmith.ui.vault.credentials.root_copy import GroupRootCopyDialog
        partial_path, signatures_path = tmp_path / 'partial.cesr', tmp_path / 'signatures.cesr'
        partial_path.write_bytes(selected.wire)
        signatures_path.write_bytes(contribution)
        parent = QWidget()
        imported = GroupRootCopyDialog(peer, parent)
        imported.open()
        imported.group.setCurrentIndex(imported.group.combo_box.findData(groups[1].pre))
        imported.mode.setCurrentIndex(imported.mode.combo_box.findData('import'))
        imported.event_field.setText(event)
        imported.opening.setPlainText(opening.qb64)
        imported.inspect_files([partial_path, signatures_path])
        qapp.processEvents()
        assert imported.action.isEnabled(), imported.status.text()
        assert peer.hby.mgr.getRegistryRoot(gid, rip.said) is None
        QTest.mouseClick(imported.action, Qt.MouseButton.LeftButton)
        assert 'retained under the group AID' in imported.status.text(), imported.status.text()
        assert peer.hby.mgr.getRegistryRoot(gid, rip.said).qb64 == root.qb64
        assert peer.vault.root_copies.active is None
        imported.close()
        assert peer.vault.db.issued.get((credential_said,)) is None
        assert peer.vault.db.accepted.get((credential_said,)) is None
        for app, (admission, proof) in zip(holders, historical):
            assert app.vault.db.accepted.get((credential_said,)) == admission
            assert credentialing.credential(app.vault, credential_said, grant=grant_said)['proof'] == proof

        # Refresh stages one update, then an interrupted worker resumes the same TEL and anchor.
        scheduler.exit()
        refreshed = credentialing.RefreshCredentialDoer(issuer, credential_said, expected_update=bup.said)
        scheduler = doing.Doist(doers=[refreshed], tock=.03125)
        scheduler.enter()
        advance(lambda: bool(issuer.vault.postman.evts))
        deliver_member(issuer, peer)
        proposed = grouping.pending_registry_proposals(peer.vault)[-1]
        _, pending, _ = grouping.registry_proposal(peer.vault, proposed.said)
        refresh_tel, refresh_anchor = [child.serder for child in pending]
        assert refresh_tel.sad['p'] == bup.said and refresh_tel.sn == 2
        retained_update = issuer.vault.db.issued.get((credential_said,))
        retained_signatures = [siger.qb64 for siger in issuer.hby.db.sigs.get((gid, refresh_anchor.said))]
        assert retained_update.update == refresh_tel.said
        assert all(app.vault.rgy.store.seqEvent(rip.said, 2) is None for app in issuers)
        assert not any(event == 'credential_refreshed' for _, event, _ in events)
        scheduler.exit()
        resumed = credentialing.RefreshCredentialDoer(issuer, credential_said,
            expected_update=refresh_tel.said, resume=True)
        scheduler = doing.Doist(doers=[resumed], tock=.03125)
        scheduler.enter()
        advance(lambda: bool(issuer.vault.postman.evts))
        retry = issuer.vault.postman.evts[0]
        repeated = Parser(version=kering.Vrsn_2_0).parseOneBare(
            ims=bytearray(retry['serder'].raw + retry['attachment']), processive=False)
        assert [child.serder.raw for child in repeated.nests] == [refresh_tel.raw, refresh_anchor.raw]
        assert issuer.vault.db.issued.get((credential_said,)) == retained_update
        assert [siger.qb64 for siger in issuer.hby.db.sigs.get((gid, refresh_anchor.said))] == retained_signatures
        seal = dict(i=rip.said, s=refresh_tel.sad['n'], d=refresh_tel.said)
        assert [event.said for _, event in issuer.hby.db.evts.getTopItemIter(keys=(gid,))
                if seal in event.seals] == [refresh_anchor.said]
        assert not any(event == 'credential_refreshed' for _, event, _ in events)
        deliver_member(issuer, peer)
        proposed = [proposal for proposal in grouping.pending_registry_proposals(peer.vault)
                    if proposal.sad['a']['tel'] == refresh_tel.said][-1]
        grouping.approve_registry_proposal(peer.vault, proposed.said, groups[1].kever.serder.said)
        deliver_member(peer, issuer)
        advance(lambda: resumed.done)
        assert any(event == 'credential_refreshed' for _, event, _ in events)
        assert all(app.vault.rgy.store.seqEvent(rip.said, 2).raw == refresh_tel.raw for app in issuers)
        for app, (admission, proof) in zip(holders, historical):
            _deliver_ipex(app.vault, evidence.clone(issuer.vault, rip.said))
            assert app.vault.db.accepted.get((credential_said,)) == admission
            assert credentialing.credential(app.vault, credential_said, grant=grant_said)['proof'] == proof

        # Revocation is another exact BUP and needs a separate peer approval.
        scheduler.exit()
        revoked = credentialing.RevokeCredentialDoer(issuer, credential_said)
        scheduler = doing.Doist(doers=[revoked], tock=.03125)
        scheduler.enter()
        advance(lambda: bool(issuer.vault.postman.evts))
        deliver_member(issuer, peer)
        proposed = grouping.pending_registry_proposals(peer.vault)[-1]
        _, pending, _ = grouping.registry_proposal(peer.vault, proposed.said)
        revoke_tel = pending[0].serder
        assert revoke_tel.sad['p'] == refresh_tel.said and revoke_tel.sn == 3
        assert all(app.vault.rgy.store.seqEvent(rip.said, 3) is None for app in issuers)
        assert not any(event == 'credential_revoked' for _, event, _ in events)
        grouping.approve_registry_proposal(peer.vault, proposed.said, groups[1].kever.serder.said)
        deliver_member(peer, issuer)
        advance(lambda: revoked.done)
        assert any(event == 'credential_revoked' for _, event, _ in events)
        assert credentialing.credential(issuer.vault, credential_said)['status']['et'] == 'revoked'
        assert all(app.vault.rgy.store.seqEvent(rip.said, 3).raw == revoke_tel.raw for app in issuers)
        for app, (admission, proof) in zip(holders, historical):
            _deliver_ipex(app.vault, evidence.clone(issuer.vault, rip.said))
            assert app.vault.db.accepted.get((credential_said,)) == admission
            assert credentialing.credential(app.vault, credential_said, grant=grant_said)['proof'] == proof
    finally:
        scheduler.exit()
