"""Real live presentations acquire exact openings without changing held views."""
from datetime import timedelta

import pytest
from hio.base import doing
from keri import kering
from keri.acdc import regeventing
from keri.core import Parser, SealSource, SerderACDC, messagize
from keri.help import helping
from keri.peer import exchanging

from locksmith.core import auxiliary, credentialing, evidence, ipexing
from test_auxiliary import pending_issuance, sent
from test_keri_v2_compat import ipex_vaults as ipex_vaults, _deliver_ipex


def live_presentation(open_vault, *, blinded=False, accepted=False, state='issued'):
    """Admit a witnessed issuance, then send its exact held view in a NEW Grant."""
    issuer, holder, ih, hh, registrar, registry, acdc, issuance, atc, seal = pending_issuance(open_vault)
    io, ho = issuer.vault.auxiliary, holder.vault.auxiliary
    io.begin_dh(ih, issuance, atc)
    _, _, wire, _ = io.outgoing.popleft()
    _deliver_ipex(holder.vault, wire)
    ho.approve_dh(hh, issuance.said)
    query = sent(io.outgoing.popleft())
    _deliver_ipex(holder.vault, query)
    _, _, reply, _ = ho.outgoing.popleft()
    _deliver_ipex(issuer.vault, reply)
    root = issuer.hby.mgr.getRegistryRoot(ih.pre, registry.regk)
    _, first = registrar.issue(registry, acdc, salt=root.qb64)
    seal(first)
    io.process()
    ho.process()
    ipexing.admit(holder.vault, hh, issuance.said)
    retained = credentialing.credential(holder.vault, acdc.said, grant=issuance.said)['proof']

    verifier = open_vault('opening-verifier', bran='0123456789abcdefghijk')
    vh = verifier.hby.makeHab('verifier', icount=2, isith='2', ncount=2, nsith='2')
    for wit in ih.kever.wits:
        _deliver_ipex(verifier.vault, b''.join(issuer.hby.db.clonePreIter(wit, gvrsn=kering.Vrsn_2_0)))
    _deliver_ipex(verifier.vault, evidence.clone(issuer.vault, registry.regk))
    _deliver_ipex(verifier.vault, hh.replay(gvrsn=kering.Vrsn_2_0))
    _deliver_ipex(holder.vault, vh.replay(gvrsn=kering.Vrsn_2_0))

    # Presenter still knows a valid issued head. The verifier independently
    # receives a newer witnessed head before receiving this unchanged held view.
    opening, event = registrar.issue(registry, acdc, state=state,
                                    **({} if blinded else {'salt': root.qb64}))
    if accepted:
        # Exercise the same Offer/Agree/Grant chain as Received Credentials -> Offer.
        for hab, target in ((hh, verifier.vault), (vh, holder.vault)):
            _deliver_ipex(target, hab.makeLocScheme(url='http://127.0.0.1:1', scheme='http')
                          + hab.makeEndRole(eid=hab.pre, role='mailbox'))
        offer = ipexing.start(holder.vault, hh, vh.pre, 'Offer',
            credential_said=acdc.said, from_grant=issuance.said)
        _deliver_ipex(verifier.vault, exchanging.serializeMessage(holder.hby, offer))
        agree = ipexing.respond(verifier.vault, offer, 'Agree')
        _deliver_ipex(holder.vault, exchanging.serializeMessage(verifier.hby, agree))
        selected = ipexing.respond(holder.vault, agree, 'Grant',
            credential_said=acdc.said, from_grant=issuance.said)
        message = holder.hby.db.exns.get((selected,))
        wire = exchanging.serializeMessage(holder.hby, selected)
        _deliver_ipex(verifier.vault, wire)
        assert verifier.vault.exc.complete(message.said)
        assert not any(row['grant'] == message.said for row in verifier.vault.auxiliary.pending(vh))
    else:
        message, attachment = ipexing.grant(holder.vault, hh, acdc.said, vh.pre,
            from_grant=issuance.said)
        wire = ipexing.prepare(holder.vault, hh, message, attachment)
    seal(event, recipients=(verifier.vault,))
    # Public source KEL support travels independently of the stale TEL view.
    _deliver_ipex(holder.vault, b''.join(issuer.hby.db.clonePreIter(ih.pre, gvrsn=kering.Vrsn_2_0)))
    if not accepted:
        _deliver_ipex(verifier.vault, wire)
    assert holder.vault.exc.complete(message.said)
    assert verifier.vault.exc.complete(message.said) == accepted
    return holder, verifier, hh, vh, acdc, registry, issuance, retained, message, event, opening


def test_unblind_query_is_signed_when_sent_and_replaced_until_the_grant_deadline(ipex_vaults, monkeypatch):
    holder, verifier, hh, vh, _, registry, _, _, message, event, _ = live_presentation(ipex_vaults)
    ho, vo = holder.vault.auxiliary, verifier.vault.auxiliary
    vo.request_openings(vh, message.said)
    item = vo.outgoing.popleft()
    operation = vo.operations[item[0]]
    assert callable(item[2])
    clock = [helping.nowUTC()]
    monkeypatch.setattr(helping, 'nowUTC', lambda: clock[0])
    first = sent(item)
    clock[0] += timedelta(seconds=22)
    vo.outgoing.append(item)
    # The real delivery owner signs as its slot starts; no transport is configured here.
    delivery = auxiliary._Delivery(vo, *vo.outgoing.popleft())
    doing.Doist(tock=.03125, real=False, limit=.2).do(doers=[delivery])
    assert delivery.done and operation.phase == 'waiting' and isinstance(delivery.wire, bytes)
    parsed = [Parser(version=kering.Vrsn_2_0).parseOne(ims=bytearray(wire), processive=False)
              for wire in (first, delivery.wire)]
    assert parsed[0].serder.said != parsed[1].serder.said
    assert parsed[0].serder.ked['q'] == parsed[1].serder.ked['q']
    assert [nest.serder.said for nest in parsed[1].nests] == [event.said]
    assert (helping.fromIso8601(parsed[1].serder.ked['dt'])
            - helping.fromIso8601(parsed[0].serder.ked['dt'])) >= timedelta(seconds=22)
    # An unauthenticated, failed query is requeued and signed again.
    operation.query_retry_at = 0
    vo.process()
    assert list(vo.outgoing) == [item]
    _deliver_ipex(holder.vault, sent(vo.outgoing.popleft()))
    assert len(ho._queries) == 1
    clock[0] = verifier.vault.exc.exchangeDeadline(message) + timedelta(seconds=1)
    operation.query_retry_at = 0
    vo.process()
    assert operation.phase == 'expired' and operation.error == 'The original Grant deadline has elapsed'
    assert not vo.outgoing


def test_live_unblind_waits_for_presenter_consent_and_repairs_same_grant(ipex_vaults):
    holder, verifier, hh, vh, acdc, registry, issuance, retained, message, event, opening = live_presentation(ipex_vaults)
    ho, vo = holder.vault.auxiliary, verifier.vault.auxiliary
    vo.request_openings(vh, message.said)
    query = sent(vo.outgoing.popleft())
    request = Parser(version=kering.Vrsn_2_0).parseOne(ims=bytearray(query), processive=False)
    assert [nest.serder.said for nest in request.nests] == [event.said]
    _deliver_ipex(holder.vault, query)
    cutoff = next(iter(ho._queries.values())).expires
    assert ho.status(hh.pre, message.said)['actions'] == ('approve_openings',)
    assert not ho.outgoing
    assert holder.vault.rgy.store.headEvent(registry.regk).sn == 1
    _deliver_ipex(holder.vault, query)
    assert next(iter(ho._queries.values())).expires == cutoff

    ho.approve_openings(hh, message.said)
    assert ho.status(hh.pre, message.said)['phase'] == 'answered'
    _, _, reply, _ = ho.outgoing.popleft()
    response = Parser(version=kering.Vrsn_2_0).parseOne(ims=bytearray(reply), processive=False)
    assert response.serder.sad['a']['re'] == {registry.regk: [event.said]}
    assert len(response.bsqs) == 1 and not response.bsss and not response.nests
    assert b''.join(part.qb64b for part in response.bsqs[0]) == opening.qb64b
    root = holder.hby.mgr.getRegistryRoot(hh.pre, registry.regk)
    assert root.qb64b not in reply
    # The real two-key presenter supplies the opening with its first signature.
    # Completing the threshold must preserve that proof without another copy.
    pre, number, diger, signatures = response.tsgs[0]
    response.tsgs = [(pre, number, diger, signatures[:1])]
    _deliver_ipex(verifier.vault, exchanging.serializeParsedSubstream(response))
    assert vo.status(vh.pre, message.said)['phase'] == 'waiting'
    assert not verifier.vault.exc.complete(message.said)
    response.tsgs = [(pre, number, diger, signatures[1:])]
    response.bsqs = []
    _deliver_ipex(verifier.vault, exchanging.serializeParsedSubstream(response))
    assert vo.status(vh.pre, message.said)['phase'] == 'verified', vo.status(vh.pre, message.said)
    assert verifier.hby.db.exns.get((message.said,)).raw == message.raw
    assert verifier.hby.mgr.getRegistryRoot(vh.pre, registry.regk) is None
    assert verifier.vault.db.accepted.get((acdc.said,)) is None
    assert credentialing.credential(holder.vault, acdc.said, grant=issuance.said)['proof'] == retained
    ipexing.admit(verifier.vault, vh, message.said)
    assert verifier.vault.db.accepted.get((acdc.said,)).grant == message.said
    with pytest.raises(kering.ValidationError):
        ho.request_openings(hh, issuance.said)


def test_missing_exact_opening_waits_without_renewing_request(ipex_vaults):
    holder, verifier, hh, vh, _, registry, _, _, message, event, opening = live_presentation(ipex_vaults, blinded=True)
    ho, vo = holder.vault.auxiliary, verifier.vault.auxiliary
    vo.request_openings(vh, message.said)
    query = sent(vo.outgoing.popleft())
    _deliver_ipex(holder.vault, query)
    cutoff = next(iter(ho._queries.values())).expires
    ho.approve_openings(hh, message.said)
    assert ho.status(hh.pre, message.said)['phase'] == 'waiting'
    assert ho.status(hh.pre, message.said)['error']
    assert not ho.outgoing
    assert holder.vault.rgy.store.headEvent(registry.regk).said == event.said
    # Explicitly held exact proof is independently verified before retention.
    regeventing.vetBlind(opening, blid=event.sad['b'])
    holder.vault.rgy.store.putOpening(event.said, opening)
    ho.process()
    assert ho.status(hh.pre, message.said)['phase'] == 'answered'
    assert ho._query_deadlines[('/ipex/unblind', vh.pre, message.said)] == cutoff
    _, _, reply, _ = ho.outgoing.popleft()
    _deliver_ipex(verifier.vault, reply)
    assert vo.status(vh.pre, message.said)['phase'] == 'verified'


def test_cancelled_request_and_expired_presenter_consent_do_not_resume(ipex_vaults, monkeypatch):
    holder, verifier, hh, vh, _, _, _, _, message, _, _ = live_presentation(ipex_vaults)
    ho, vo = holder.vault.auxiliary, verifier.vault.auxiliary
    vo.request_openings(vh, message.said)
    query = sent(vo.outgoing.popleft())
    _deliver_ipex(holder.vault, query)
    cutoff = next(iter(ho._queries.values())).expires
    vo.abandon(vh.pre, message.said)
    with pytest.raises(kering.ValidationError):
        vo.request_openings(vh, message.said)
    monkeypatch.setattr(helping, 'nowUTC', lambda: cutoff + timedelta(milliseconds=1))
    ho.process()
    assert not ho._queries and not ho.outgoing
    with pytest.raises(kering.ValidationError):
        ho.approve_openings(hh, message.said)


def test_accepted_live_grant_rechecks_after_newer_witnessed_head(ipex_vaults):
    holder, verifier, hh, vh, acdc, registry, issuance, retained, message, event, _ = live_presentation(ipex_vaults, accepted=True)
    ho, vo = holder.vault.auxiliary, verifier.vault.auxiliary
    agree = verifier.hby.db.exns.get((message.sad['p'],))
    assert agree.route == '/ipex/agree'
    assert message.sad['x'] == agree.sad['p'] != message.said
    # Acceptance clears signature-escrow timing; the accepted KRAM row owns the deadline.
    deadline = verifier.vault.exc.exchangeDeadline(message)
    assert deadline is not None
    previous = exchanging.serializeParsedSubstream(exchanging.loadParsedNestedSubstreams(verifier.hby, message.said)[0])
    assert next(row for row in vo.pending(vh) if row['grant'] == message.said)['phase'] == 'request_required'
    vo.request_openings(vh, message.said)
    query = sent(vo.outgoing.popleft())
    _deliver_ipex(holder.vault, query)
    ho.approve_openings(hh, message.said)
    _, _, reply, _ = ho.outgoing.popleft()
    _deliver_ipex(verifier.vault, reply)
    status = vo.status(vh.pre, message.said)
    assert status['phase'] == 'verified', status
    assert verifier.hby.db.exns.get((message.said,)).raw == message.raw
    assert verifier.vault.exc.exchangeDeadline(message) == deadline
    assert verifier.hby.db.erpy.get((agree.said,)).qb64 == message.said
    updated = exchanging.serializeParsedSubstream(exchanging.loadParsedNestedSubstreams(verifier.hby, message.said)[0])
    assert updated != previous
    observed = verifier.hby.db.exrs.get((message.said, acdc.said))
    assert (observed.regid, observed.said, observed.sn, observed.state) == (registry.regk, event.said, 2, 'issued')
    assert verifier.vault.db.accepted.get((acdc.said,)) is None
    assert credentialing.credential(holder.vault, acdc.said, grant=issuance.said)['proof'] == retained
    ipexing.admit(verifier.vault, vh, message.said)


def _holder_observes_head(holder, verifier, registry, event):
    """The holder's Observer poll acquires the witnessed head the verifier already holds."""
    store = verifier.vault.rgy.store
    issuer = store.seqEvent(registry.regk, 0).israid
    wire = bytearray()
    for raw in store.cloneTelIter(registry.regk):
        serder = SerderACDC(raw=raw)
        sn, said = regeventing.vetAnchor(serder, db=verifier.hby.db, issuer=issuer)
        wire += messagize(serder, bonds=[SealSource(s=f'{sn:x}', d=said)], gvrsn=kering.Vrsn_2_0)
    _deliver_ipex(holder.vault, bytes(wire))
    assert holder.vault.rgy.store.headEvent(registry.regk).said == event.said


def _send_saved_grant(holder, message):
    """Queue the holder's already-authored Grant and run one outbox pass."""
    from hio.base import doing
    from locksmith.db.basing import IpexSubmission
    holder.vault.db.outbox.pin((message.said,), IpexSubmission())
    sender = ipexing.SendIpexDoer(holder.vault, message.said)
    doing.Doist(doers=[sender], tock=0.03125, limit=1).do()
    return holder.vault.db.outbox.get((message.said,))


def test_revoked_after_authoring_grant_is_refused_not_retried(ipex_vaults, monkeypatch):
    """A holder that can open the revoked head must end the wait with a reason."""
    holder, verifier, _, _, acdc, registry, _, _, message, event, _ = live_presentation(ipex_vaults, state='revoked')
    _holder_observes_head(holder, verifier, registry, event)
    monkeypatch.setattr(ipexing.forwarding, 'StreamPoster',
                        lambda **kwa: pytest.fail('A revoked Grant reached network delivery'))
    outbox = _send_saved_grant(holder, message)
    assert outbox.status == 'refused'
    assert outbox.error == f'Credential is revoked (registry event 2/{event.said})'
    assert outbox.attempts == 0
    assert not ipexing._due(outbox, 1e12)
    with pytest.raises(credentialing.CredentialRevoked, match='revoked'):
        ipexing._validate_grant_graph(holder.vault, message.said)


def test_unopenable_newer_event_keeps_grant_waiting(ipex_vaults):
    """Unknown is not revoked: without the opening the outbox keeps waiting."""
    holder, verifier, _, _, _, registry, _, _, message, event, _ = live_presentation(
        ipex_vaults, blinded=True, state='revoked')
    _holder_observes_head(holder, verifier, registry, event)
    outbox = _send_saved_grant(holder, message)
    assert outbox.status == 'waiting_evidence'
    assert 'openings' in outbox.error
    nests = exchanging.loadParsedNestedSubstreams(holder.hby, message.said)
    assert credentialing.revoked_event(holder.vault, nests) is None


def test_composer_names_known_revoked_state(ipex_vaults):
    holder, verifier, _, _, acdc, registry, issuance, _, _, event, _ = live_presentation(ipex_vaults, state='revoked')
    _holder_observes_head(holder, verifier, registry, event)
    with pytest.raises(credentialing.CredentialRevoked, match=f'Credential is revoked .registry event 2/{event.said}'):
        ipexing._credential_evidence(holder.vault, acdc.said, from_grant=issuance.said)
    with pytest.raises(credentialing.CredentialRevoked, match='Credential is revoked'):
        ipexing._credential_evidence(holder.vault, acdc.said, from_grant=issuance.said,
                                     refresh=True, derive=True)


def test_composer_asks_for_current_evidence_when_newer_event_is_unopenable(ipex_vaults):
    holder, verifier, _, _, acdc, registry, issuance, _, _, event, _ = live_presentation(
        ipex_vaults, blinded=True, state='revoked')
    _holder_observes_head(holder, verifier, registry, event)
    for options in ({}, {'refresh': True}):
        with pytest.raises(kering.ValidationError) as error:
            ipexing._credential_evidence(holder.vault, acdc.said, from_grant=issuance.said, **options)
        assert 'presentation requires current verified issued state' in str(error.value)
        assert 'Use current registry-state evidence' in str(error.value)
        assert 'requires exactly one disclosure' not in str(error.value)


def test_presenter_status_shows_no_approval_before_a_request(ipex_vaults):
    holder, verifier, hh, vh, _, _, _, _, message, _, _ = live_presentation(ipex_vaults)
    ho, vo = holder.vault.auxiliary, verifier.vault.auxiliary
    assert ho.status(hh.pre, message.said) is None
    assert not any(row['grant'] == message.said for row in ho.pending(hh))
    vo.request_openings(vh, message.said)
    query = sent(vo.outgoing.popleft())
    _deliver_ipex(holder.vault, query)
    assert ho.status(hh.pre, message.said)['actions'] == ('approve_openings',)
