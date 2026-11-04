"""Actual live Grants and auxiliary protocol owners, without accepted-row seeding."""
from datetime import timedelta

import pytest
from hio.base import doing
from keri.help import helping
from keri import kering
from keri.acdc import Registrar, acdcmap, grant
from keri.core import Parser, SealSource, SerderKERI, messagize, receipt

from locksmith.core import credentialing, evidence, ipexing
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

    def seal(event):
        raw = ih.interact(data=[dict(i=registry.regk, s=event.sad['n'], d=event.said)],
                          gvrsn=kering.Vrsn_2_0)
        anchor = SerderKERI(raw=raw)
        issuer.vault.kvy.processReceipt(serder=receipt(ih.pre, anchor.sn, anchor.said),
            cigars=wh.sign(anchor.raw, indexed=False), wigers=[], tsgs=[], local=False)
        assert registry.anchorMsg(event.said)
        _deliver_ipex(holder.vault, b''.join(issuer.hby.db.clonePreIter(ih.pre, gvrsn=kering.Vrsn_2_0)))
        assert holder.hby.db.fullyWitnessed(holder.hby.db.evts.get((ih.pre, anchor.said)))
        _deliver_ipex(holder.vault, messagize(event, bonds=[SealSource(s=anchor.snh, d=anchor.said)],
                                            gvrsn=kering.Vrsn_2_0))
        assert holder.vault.rgy.store.headEvent(registry.regk).said == event.said

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
