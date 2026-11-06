"""Actual live Grants and auxiliary protocol owners, without accepted-row seeding."""
from datetime import timedelta

import pytest
from hio.base import doing
from keri.help import helping
from keri import kering
from keri.acdc import Registrar, acdcmap, grant
from keri.core import Parser, SealSource, SerderKERI, messagize, receipt
from keri.peer import exchanging

from locksmith.core import auxiliary, credentialing, evidence, group_presenting, grouping, ipexing, root_copying
from test_credentialing import _load_schema
from test_keri_v2_compat import ipex_vaults as ipex_vaults, _deliver_ipex


def sent(item):
    """Return the bytes an outgoing item transmits; a query is signed as it is sent."""
    wire = item[2]
    return wire() if callable(wire) else wire


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
    item = io.outgoing.popleft()
    key = item[0]
    operation = io.operations[key]
    query = sent(item)
    # The first delivery could not reach the listener; retry the same approved query.
    operation.query_retry_at = 0
    io.process()
    assert list(io.outgoing) == [item]
    io.process()
    assert len(io.outgoing) == 1
    retried = sent(io.outgoing.popleft())
    assert issuer.hby.db.epsd.get((message.said,)).dts == deadline
    _deliver_ipex(holder.vault, retried)
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
    io.outgoing.append(operation.query)
    _deliver_ipex(issuer.vault, reply)
    assert io.agreement_ready(ih.pre, message.said)
    # A queued query becomes obsolete when the real reply completes agreement.
    queued_key, queued_dest, queued_wire, queued_topic = io.outgoing.popleft()
    delivery = auxiliary._Delivery(io, queued_key, queued_dest, queued_wire, queued_topic)
    before = operation.phase, operation.error
    doing.Doist(tock=.03125, real=False, limit=.1).do(doers=[delivery])
    assert delivery.done and (operation.phase, operation.error) == before
    operation.query_retry_at = 0
    io.process()
    assert not io.outgoing
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


def _tighten_kram(vault):
    """Give this recipient the 1 s drift and 5 s lifetime of the E5 run."""
    ctyp = vault.hby.db.kramCTYP.get('~')
    ctyp.d, ctyp.sl, ctyp.ll, ctyp.xl = 1000, 5000, 5000, 5000
    ctyp.psl, ctyp.pll, ctyp.pxl = 5000, 5000, 5000
    vault.hby.db.kramCTYP.pin('~', ctyp)


def _query_dt(wire):
    return helping.fromIso8601(
        Parser(version=kering.Vrsn_2_0).parseOne(ims=bytearray(wire), processive=False).serder.ked['dt'])


def test_dh_query_is_signed_when_its_delivery_starts_not_when_queued(ipex_vaults, monkeypatch):
    issuer, holder, ih, hh, _, _, _, message, atc, _ = pending_issuance(ipex_vaults)
    io, ho = issuer.vault.auxiliary, holder.vault.auxiliary
    _tighten_kram(holder.vault)
    io.begin_dh(ih, message, atc)
    grant_item, query_item = io.outgoing.popleft(), io.outgoing.popleft()
    assert callable(query_item[2])
    _deliver_ipex(holder.vault, sent(grant_item))
    # What a query timestamped at operation creation would carry once the Grant delivery stalls.
    stale = sent(query_item)
    now = helping.nowUTC()
    monkeypatch.setattr(helping, 'nowUTC', lambda: now + timedelta(seconds=22))
    _deliver_ipex(holder.vault, stale)
    assert not ho._queries
    fresh = sent(query_item)
    assert _query_dt(fresh) - _query_dt(stale) >= timedelta(seconds=22)
    assert fresh != stale
    _deliver_ipex(holder.vault, fresh)
    assert len(ho._queries) == 1
    assert next(iter(ho._queries.values())).serder.raw == bytes(Parser(version=kering.Vrsn_2_0).parseOne(
        ims=bytearray(fresh), processive=False).serder.raw)


def test_refused_dh_query_is_replaced_with_a_fresh_one_until_the_grant_deadline(ipex_vaults, monkeypatch):
    issuer, holder, ih, hh, _, _, _, message, atc, _ = pending_issuance(ipex_vaults)
    io, ho = issuer.vault.auxiliary, holder.vault.auxiliary
    _tighten_kram(holder.vault)
    io.begin_dh(ih, message, atc)
    _deliver_ipex(holder.vault, sent(io.outgoing.popleft()))
    item = io.outgoing.popleft()
    key = item[0]
    operation = io.operations[key]
    deadline = issuer.hby.db.epsd.get((message.said,)).dts
    clock = [helping.nowUTC()]
    monkeypatch.setattr(helping, 'nowUTC', lambda: clock[0])

    def attempt():
        """Run the real delivery owner; no transport is configured, so it is not accepted."""
        delivery = auxiliary._Delivery(io, *io.outgoing.popleft())
        doing.Doist(tock=.03125, real=False, limit=.2).do(doers=[delivery])
        assert delivery.done and callable(delivery.item[2]) and isinstance(delivery.wire, bytes)
        return delivery.wire

    io.outgoing.appendleft(item)
    first = attempt()
    assert operation.phase == 'waiting'
    clock[0] += timedelta(seconds=22)
    operation.query_retry_at = 0
    io.process()
    assert list(io.outgoing) == [item]
    second = attempt()
    parsed = [Parser(version=kering.Vrsn_2_0).parseOne(ims=bytearray(wire), processive=False).serder
              for wire in (first, second)]
    assert parsed[0].said != parsed[1].said and parsed[0].ked['q'] == parsed[1].ked['q']
    assert _query_dt(second) - _query_dt(first) >= timedelta(seconds=22)
    assert issuer.hby.db.epsd.get((message.said,)).dts == deadline
    _deliver_ipex(holder.vault, second)
    assert len(ho._queries) == 1

    # The Grant's accepted lifetime is never extended: past it, retry ends with a clear error.
    clock[0] = issuer.vault.exc.exchangeDeadline(message) + timedelta(seconds=1)
    operation.query_retry_at = 0
    io.process()
    assert operation.phase == 'expired' and operation.error == 'The original Grant deadline has elapsed'
    assert not io.outgoing
    with pytest.raises(kering.ValidationError):
        item[2]()


def _stall_issuer_transport(patch, ih, hh):
    """Route the issuer's live deliveries to a real HTTP client that never gets a response.

    Returns the transport messengers each delivery builds, so a test can check
    that the delivery frame released them."""
    from hio.core.http import clienting
    from keri.app import forwarding
    messengers = []
    deliver = forwarding.StreamPoster.deliver

    def record(poster):
        doers = deliver(poster)
        messengers.extend(doers)
        return doers

    patch.setattr(forwarding.StreamPoster, 'deliver', record)
    patch.setattr(ipexing, '_require_route', lambda *args, **kwa: None)
    patch.setattr(ih, 'endsFor', lambda pre: {
        kering.Roles.controller: {hh.pre: {'http': 'http://127.0.0.1:9999'}}})
    patch.setattr(clienting.Client, 'reopen', lambda *args, **kwa: None)
    patch.setattr(clienting.Client, 'service', lambda *args, **kwa: None)
    return messengers


def _second_grant(issuer, ih, hh):
    return grant(ih, hh.pre, 'Second live agreement', origin=acdcmap(
        israid=ih.pre, iseaid=hh.pre, regid=next(iter(issuer.vault.rgy.regs)),
        attribute=dict(d='', i=hh.pre, role='holder')), kind=kering.Kinds.json)


def _inflight(app, io, messengers):
    """Run the production scheduler until a delivery holds an open transport."""
    for _ in range(100):
        app.qtask.run()
        if messengers:
            assert io._delivery is not None and not io._delivery.done
            return io._delivery
    pytest.fail('No auxiliary delivery reached its transport')


def _reaped(app, io, delivery):
    for _ in range(20):
        app.qtask.run()
        if delivery not in io.doers:
            return
    pytest.fail('The finished auxiliary delivery was never removed')


def _count_exits(patch, io):
    calls = []
    exit = io.exit

    def counted(*args, **kwa):
        calls.append(kwa.get('deeds', args[0] if args else None))
        return exit(*args, **kwa)

    patch.setattr(io, 'exit', counted)
    return calls


def test_cancelling_an_inflight_delivery_stops_it_next_tick_without_closing_the_owner(
        ipex_vaults, monkeypatch):
    """Cancel is a state transition; the run loop alone removes its delivery child."""
    issuer, holder, ih, hh, _, _, _, message, atc, _ = pending_issuance(ipex_vaults)
    io = issuer.vault.auxiliary
    with monkeypatch.context() as patch:
        messengers = _stall_issuer_transport(patch, ih, hh)
        io.begin_dh(ih, message, atc)
        message2, atc2 = _second_grant(issuer, ih, hh)
        io.begin_dh(ih, message2, atc2)
        delivery = _inflight(issuer, io, messengers)
        assert delivery.key == (ih.pre, message.said)
        exits = _count_exits(patch, io)
        io.abandon(ih.pre, message.said)
        # Termination touches no scheduler state; the delivery observes it.
        assert io._delivery is delivery and delivery in io.doers
        assert not any(item[0] == delivery.key for item in io.outgoing)
        _reaped(issuer, io, delivery)
    assert io.status(ih.pre, message.said)['phase'] == 'cancelled'
    assert delivery.done and delivery is not io._delivery
    assert all(not messenger.deeds for messenger in messengers)
    # The reap went through HIO remove() exactly once and did not close the table.
    assert len(exits) == 1 and exits[0] is not None
    assert io.status(ih.pre, message2.said)['phase'] not in io.Terminal
    assert io._delivery is None or io._delivery.key == (ih.pre, message2.said)


def test_expiry_during_an_inflight_delivery_stops_and_reaps_it(ipex_vaults, monkeypatch):
    issuer, holder, ih, hh, _, _, _, message, atc, _ = pending_issuance(ipex_vaults)
    io = issuer.vault.auxiliary
    with monkeypatch.context() as patch:
        messengers = _stall_issuer_transport(patch, ih, hh)
        io.begin_dh(ih, message, atc)
        delivery = _inflight(issuer, io, messengers)
        late = issuer.vault.exc.exchangeDeadline(message) + timedelta(seconds=1)
        patch.setattr(helping, 'nowUTC', lambda: late)
        _reaped(issuer, io, delivery)
        operation = io.operations[delivery.key]
        assert operation.phase == 'expired'
        assert operation.error == 'The original Grant deadline has elapsed'
        assert delivery.done and io._delivery is None and not io.outgoing
        assert list(io.doers) == [io.doers[0]] and len(io.deeds) == 1
        assert all(not messenger.deeds for messenger in messengers)


def test_repeated_deliveries_do_not_accumulate_scheduler_children(ipex_vaults):
    """Every delivery the run loop extends, it also removes."""
    issuer, holder, ih, hh, _, _, _, message, atc, _ = pending_issuance(ipex_vaults)
    io = issuer.vault.auxiliary
    io.begin_dh(ih, message, atc)
    seen = set()
    # No route is known, so each attempt ends at once and the query is retried each second.
    for _ in range(200):
        issuer.qtask.run()
        assert len(io.doers) <= 2
        if io._delivery is not None:
            seen.add(id(io._delivery))
    assert len(seen) >= 4
    io.abandon(ih.pre, message.said)
    for _ in range(10):
        issuer.qtask.run()
    assert io._delivery is None
    assert len(io.doers) == 1 and len(io.deeds) == 1


def test_vault_close_interrupts_waiting_and_inflight_operations_once(ipex_vaults, monkeypatch):
    """Close runs one HIO exit cascade: no re-entrant remove, no view updates, stores closed."""
    issuer, holder, ih, hh, _, _, _, message, atc, _ = pending_issuance(ipex_vaults)
    vault, io = issuer.vault, issuer.vault.auxiliary
    with monkeypatch.context() as patch:
        messengers = _stall_issuer_transport(patch, ih, hh)
        io.begin_dh(ih, message, atc)
        message2, atc2 = _second_grant(issuer, ih, hh)
        io.begin_dh(ih, message2, atc2)
        delivery = _inflight(issuer, io, messengers)
        waiting = io.operations[(ih.pre, message2.said)]
        assert waiting.phase == 'waiting' and any(item[0] == (ih.pre, message2.said) for item in io.outgoing)
        events = []
        vault.signals.doer_event.connect(lambda *args: events.append(args))
        exits = _count_exits(patch, io)
        issuer.close_vault()
    assert [operation.phase for operation in io.operations.values()] == ['interrupted', 'interrupted']
    assert not io.outgoing and not io.deeds and not delivery.deeds
    assert all(not messenger.deeds for messenger in messengers)
    assert exits == [None]  # Only the owner's own exit; nothing removed a child during close.
    assert not any(args[0] == 'Auxiliary' for args in events), events
    assert vault.closed and not vault.db.opened and not vault.hby.db.opened
    assert issuer.vault is None and issuer.qtask is None


def test_issuance_worker_waiting_for_agreement_closes_with_the_vault(ipex_vaults):
    """The worker is a later Vault child, so it abandons before the operation table closes."""
    issuer = ipex_vaults('closing-worker-issuer', bran='0123456789abcdefghijk')
    holder = ipex_vaults('closing-worker-holder', bran='0123456789abcdefghijk')
    ih, hh = issuer.hby.makeHab('issuer'), holder.hby.makeHab('holder')
    schema = _load_schema(issuer, ih)
    _deliver_ipex(issuer.vault, hh.replay(gvrsn=kering.Vrsn_2_0))
    vault, io = issuer.vault, issuer.vault.auxiliary
    events = []
    vault.signals.doer_event.connect(lambda *args: events.append(args))
    worker = credentialing.IssueCredentialDoer(issuer, schema.said, hh.pre,
        {'LEI': '254900OPPU84GM83MG36'}, registry_mode='derived')
    vault.extend([worker])
    for _ in range(200):
        issuer.qtask.run()
        if io.operations:
            break
    operation, = io.operations.values()
    for _ in range(10):
        issuer.qtask.run()
    assert not worker.done and operation.phase not in io.Terminal
    issuer.close_vault()
    assert operation.phase == 'cancelled'
    assert not any(args[1] == 'credential_issuance_failed' for args in events), events
    assert vault.closed and not vault.db.opened and not vault.hby.db.opened
    assert issuer.vault is None


def test_partial_query_signatures_do_not_authorize_agreement(ipex_vaults):
    issuer, holder, ih, hh, _, registry, _, message, atc, _ = pending_issuance(ipex_vaults)
    io, ho = issuer.vault.auxiliary, holder.vault.auxiliary
    io.begin_dh(ih, message, atc)
    _, _, wire, _ = io.outgoing.popleft()
    _deliver_ipex(holder.vault, wire)
    query = sent(io.outgoing.popleft())
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
    query = sent(io.outgoing.popleft())
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
    query = sent(io.outgoing.popleft())
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
        query = sent(io.outgoing.popleft())
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
        # The issuer itself publishes the anchored issued BUP to the issuee, once.
        publication, = [item for item in io.outgoing if item[3] == 'credential']
        io.outgoing.remove(publication)
        key, destination, wire, _ = publication
        assert key == (ih.pre, grant_said) and destination == hh.pre
        published = Parser(version=kering.Vrsn_2_0).parseOne(ims=bytearray(wire), processive=False).serder
        assert published.ilk == 'bup' and published.said == issuer.vault.rgy.store.headEvent(regk).said
        io.process()
        assert not [item for item in io.outgoing if item[3] == 'credential']
        assert ho.status(hh.pre, grant_said)['phase'] != 'verified'
        _deliver_ipex(holder.vault, ih.replay(gvrsn=kering.Vrsn_2_0) + wire)
        ho.process()
        assert ho.status(hh.pre, grant_said)['phase'] == 'verified'
        assert holder.vault.db.accepted.get((said,)) is None
        ipexing.admit(holder.vault, hh, grant_said)
        retained = credentialing.credential(holder.vault, said, grant=grant_said)['proof']
        root = holder.hby.mgr.getRegistryRoot(hh.pre, regk).qb64
    finally:
        scheduler.exit()

    # Cancelling an issuance worker interrupts its core operation, not history.
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
        query = sent(io.outgoing.popleft())
        _deliver_ipex(holder.vault, query)
        ho.approve_dh(hh, pending.grant.said)
    finally:
        scheduler.exit()
    assert pending.phase == 'cancelled'
    assert not io.outgoing
    with pytest.raises(kering.ValidationError, match='unavailable, terminated or expired'):
        pending.protocol.complete(pending.xid)  # Core refuses an abandoned operation.

    # A vault close drops an unfinished recipient approval and its queued reply.
    unfinished = ho.operations[(hh.pre, pending.grant.said)]
    config = holder.hby.cf.get()
    config['kram']['enabled'] = False
    custom = [[2, 0], 'qry', 'local/custom']
    config['kram']['denials'].append(custom)
    holder.hby.cf.put(config)
    holder.close_vault()
    assert unfinished.phase == 'interrupted'
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
        outgoing = source.vault.auxiliary.outgoing
        item = outgoing.popleft()
        # A slow loop can queue an exact DH query retry; delivery drops it once agreement completes.
        while item[2] in wires and any(op.query == item for op in source.vault.auxiliary.operations.values()):
            item = outgoing.popleft()
        _, destination, raw, selected_topic = item
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
        # A partial group Grant has no accepted KRAM lifetime before threshold intake.
        status = io.status(gid, grant_said)
        assert status['phase'] == 'waiting' and not status['deadline']
        assert all(topic == 'multisig' for _, _, _, topic in io.outgoing)
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
        deadline = io.status(gid, grant_said)['deadline']
        assert deadline
        deliver_aux(issuer, holder, 'credential')
        holder_deadline = holder.vault.exc.exchangeDeadline(message)
        assert holder_deadline is not None
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
        peer_deadline = holder_peer.vault.exc.exchangeDeadline(message)
        assert peer_deadline is not None
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
        assert holder.vault.exc.exchangeDeadline(message) == holder_deadline
        assert holder_peer.vault.exc.exchangeDeadline(message) == peer_deadline
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
            assert app.vault.exc.exchangeDeadline(message) == cutoff
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
        # The issuer peer naturally has no inventory row; core accepted BUP/opening evidence suffices.
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

        # The holder group presents its exact admitted view at ordinary member threshold.
        status = group_presenting.propose(holder.vault, hh, said=credential_said, source=grant_said,
                                          recipient=gid, message='Exact group presentation')
        presentation = status['grant']
        assert status['phase'] == 'awaiting_threshold' and status['deadline'] == ''
        original_presentation = holder.hby.db.epse.get((presentation,))
        deliver_member(holder, holder_peer)
        assert hpo.status(hph.pre, presentation)['actions'] == ('approve_presentation',)
        assert holder.vault.db.outbox.get((presentation,)) is None
        hpo.presenters.contribute(hph, presentation)
        deliver_member(holder_peer, holder)
        ho.process()
        hpo.process()
        # Threshold intake fixes the lifetime; the stale held proof keeps the Grant pending.
        status = ho.presenters.snapshot(ho.presenters.entries[(hh.pre, presentation)])
        assert status['phase'] == 'submitted' and status['deadline']
        peer_status = hpo.presenters.snapshot(hpo.presenters.entries[(hph.pre, presentation)])
        assert peer_status['phase'] == 'complete' and peer_status['deadline'] == status['deadline']
        assert not holder.vault.exc.complete(presentation)
        presentation_deadline = holder.vault.exc.exchangeDeadline(original_presentation)
        # Only the elected lead delivers, through the live owner rather than the outbox.
        delivery = ho.operations[(hh.pre, presentation)]
        assert delivery.kind == 'unblind' and not delivery.release_approved
        assert (hph.pre, presentation) not in hpo.operations
        assert holder.vault.db.outbox.get((presentation,)) is None
        registered = delivery.wire
        complete_sender = Parser(version=kering.Vrsn_2_0).parseOneBare(
            ims=bytearray(registered), processive=False)
        assert complete_sender.serder.raw == original_presentation.raw
        assert {siger.index for pre, _, _, sigers in complete_sender.tsgs
                if pre.qb64 == hh.pre for siger in sigers} == {0, 1}
        assert holder_peer.vault.db.outbox.get((presentation,)) is None
        assert holder.hby.db.erpy.get((presentation,)) is None
        assert issuer.hby.db.exns.get((presentation,)) is None
        for app, (admission, proof) in zip(holders, historical):
            assert app.vault.db.accepted.get((credential_said,)) == admission
            assert credentialing.credential(app.vault, credential_said, grant=grant_said)['proof'] == proof

        # Group Unblind starts with delivery, then separate requester and proof-release consent.
        assert deliver_aux(holder, issuer, 'credential') == registered
        recipient_deadline = issuer.vault.exc.exchangeDeadline(original_presentation)
        io.request_openings(groups[0], presentation, proposer=members[0].pre)
        assert not any(destination == hh.pre and topic == 'reply'
                       for _, destination, _, topic in io.outgoing)
        deliver_aux(issuer, peer, 'credential')
        verifier_peer_deadline = peer.vault.exc.exchangeDeadline(original_presentation)
        deliver_aux(issuer, peer, 'multisig')
        assert po.openings.pending[(gid, presentation)]
        assert (gid, presentation) not in po.operations and not po.outgoing
        po.request_openings(groups[1], presentation, proposer=members[0].pre)
        assert not any(destination == hh.pre and topic == 'reply'
                       for _, destination, _, topic in io.outgoing)
        deliver_aux(peer, issuer, 'multisig')
        advance(lambda: any(destination == hh.pre and topic == 'reply'
                            for _, destination, _, topic in io.outgoing))
        query = deliver_aux(issuer, holder, 'reply')
        query_item = Parser(version=kering.Vrsn_2_0).parseOneBare(ims=bytearray(query), processive=False)
        query_indices = {siger.index for _, sigers in query_item.lsgs for siger in sigers}
        query_indices.update(siger.index for pre, _, _, sigers in query_item.tsgs
                             if pre.qb64 == gid for siger in sigers)
        assert query_indices == {0, 1}
        # Delivery alone never approved proof release.
        assert ho.operations[(hh.pre, presentation)].group is None and not delivery.release_approved
        assert not ho.outgoing and (hph.pre, presentation) not in hpo.operations
        ho.approve_openings(hh, presentation, proposer=holder_members[0].pre)
        deliver_aux(holder, holder_peer, 'credential')
        deliver_aux(holder, holder_peer, 'reply')
        deliver_aux(holder, holder_peer, 'multisig')
        assert hpo.openings.pending[(hph.pre, presentation)]
        assert (hph.pre, presentation) not in hpo.operations and not hpo.outgoing
        hpo.approve_openings(hph, presentation, proposer=holder_members[0].pre)
        assert not any(destination == gid and topic == 'reply'
                       for _, destination, _, topic in ho.outgoing)
        forwarded = deliver_aux(holder_peer, holder, 'reply')
        assert Parser(version=kering.Vrsn_2_0).parseOneBare(
            ims=bytearray(forwarded), processive=False).serder.raw == query_item.serder.raw
        deliver_aux(holder_peer, holder, 'multisig')
        advance(lambda: any(destination == gid and topic == 'reply'
                            for _, destination, _, topic in ho.outgoing))
        reply = deliver_aux(holder, issuer, 'reply')
        reply_item = Parser(version=kering.Vrsn_2_0).parseOneBare(ims=bytearray(reply), processive=False)
        assert {siger.index for pre, _, _, sigers in reply_item.tsgs
                if pre.qb64 == hh.pre for siger in sigers} == {0, 1}
        deliver_aux(issuer, peer, 'reply')
        advance(lambda: all(app.vault.exc.complete(presentation) for app in issuers))
        for app, cutoff in zip(issuers, (recipient_deadline, verifier_peer_deadline)):
            assert app.hby.db.exns.get((presentation,)).raw == original_presentation.raw
            assert app.vault.exc.exchangeDeadline(original_presentation) == cutoff
            assert app.vault.auxiliary.status(gid, presentation)['phase'] == 'verified'
            assert app.vault.db.receipts.get((gid, presentation)) is None
            assert app.vault.db.accepted.get((credential_said,)) is None
        assert holder.vault.exc.exchangeDeadline(original_presentation) == presentation_deadline
        assert all(root.qb64b not in wire for wire in wires)
        for app, (admission, proof) in zip(holders, historical):
            assert app.vault.db.accepted.get((credential_said,)) == admission
            assert credentialing.credential(app.vault, credential_said, grant=grant_said)['proof'] == proof

        # Verified state proof does not Admit; both verifier members separately accept one exact response.
        presentation_admit, _ = ipexing.admit(issuer.vault, groups[0], presentation)
        assert all(app.vault.db.accepted.get((credential_said,)) is None for app in issuers)
        deliver_member(issuer, peer)
        proposed_admit = ipexing.group_admit_proposal(peer.vault, groups[1], presentation)
        assert proposed_admit.raw == presentation_admit.raw
        response, _ = ipexing.admit(peer.vault, groups[1], presentation, proposal=proposed_admit.said)
        assert response.raw == presentation_admit.raw
        deliver_member(peer, issuer)
        advance(lambda: all(app.vault.db.accepted.get((credential_said,)) is not None for app in issuers))
        for app in issuers:
            accepted = app.vault.db.accepted.get((credential_said,))
            assert accepted.grant == presentation and accepted.admit == presentation_admit.said

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
