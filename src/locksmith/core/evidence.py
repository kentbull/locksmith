"""Public KEL/TEL transport composed from the vault's native verifiers.

Network lifetime belongs to RegistrySyncDoer. Response bodies are independently
verified; observer timestamps and headers are not protocol authority.
"""
import json
from types import SimpleNamespace

from keri import kering
from keri.acdc import regeventing
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import (Blinder, BlindState, BoundState, Codens, Counter, Kevery,
                       Parser, SerderACDC, SerderKERI, query)
from keri.help import helping


def processor(vault):
    """Borrow the native Regery and a strict KEL intake sharing the vault Kramer."""
    if getattr(vault, 'evidence', None) is None:
        kvy = Kevery(db=vault.hby.db, lax=False, local=False,
                     kramer=getattr(vault, 'kramer', None))
        vault.evidence = SimpleNamespace(kvy=kvy, parser=Parser(
            kvy=kvy, rgy=vault.rgy, local=False, version=kering.Vrsn_2_0))
    return vault.evidence


def signed_query(hab, route, attributes):
    """Sign the service request with the selected local habitat."""
    serder = query(pre=hab.pre, route=route, query=attributes,
                   stamp=helping.nowIso8601(), version=kering.Vrsn_2_0)
    return bytes(hab.endorse(serder, last=True, framed=False, gvrsn=kering.Vrsn_2_0))


def clone(vault, regk):
    """Publish owned accepted history and explicitly public issuance openings.

    Native TEL cloning stays body-only. Arbitrary held openings and Keeper roots
    never enter public transport.
    """
    rip = vault.rgy.store.seqEvent(regk, 0)
    if rip is None or rip.israid not in vault.hby.prefixes:
        raise kering.ValidationError('Only an owned accepted registry can be published')
    stream = bytearray()
    stream.extend(b''.join(vault.hby.db.cloneDelegation(vault.hby.kevers[rip.israid],
                                                     gvrsn=kering.Vrsn_2_0)))
    stream.extend(b''.join(vault.hby.db.clonePreIter(rip.israid, gvrsn=kering.Vrsn_2_0)))
    public = {record.update: record.blinder for _, record in vault.db.issued.getTopItemIter()
              if record.registry_mode == 'public' and record.update and record.blinder}
    from locksmith.core.disclosing import opening
    for raw in vault.rgy.store.cloneTelIter(regk):
        event = SerderACDC(raw=raw)
        disclosed = b''
        if event.said in public:
            candidate = opening(public[event.said])
            regeventing.vetBlind(candidate, blid=event.sad['b'])
            disclosed = Blinder.enclose([candidate])
        stream.extend(event.raw)
        stream.extend(Counter.enclose(qb64=disclosed, code=Codens.AttachmentGroup,
                                      version=kering.Vrsn_2_0))
    return bytes(stream)


def receive(vault, regk, raw, headers):
    """Independently verify the exact scoped response and its advertised TEL tip.

    The body itself selects the head. No Observer-* header or age claim permits
    acceptance. Missing KEL, conflicting history, unrelated TEL and rollback fail
    closed; native dependency escrows remain owned by the vault.
    """
    if headers.get('content-type', '').split(';')[0] != CESR_CONTENT_TYPE:
        raise kering.ValidationError('Registry evidence must be CESR')
    ims = bytearray(raw)
    parsed = Parser(version=kering.Vrsn_2_0).parse(ims=ims, processive=False)
    if ims or not parsed:
        raise kering.ValidationError('Incomplete registry evidence response')
    events, openings = [], []
    for nest in parsed:
        event = nest.serder
        if isinstance(event, SerderACDC):
            if event.ilk not in ('rip', 'bup') or (event.said if event.ilk == 'rip' else event.sad['rd']) != regk:
                raise kering.ValidationError('Response contains an unrelated registry')
            events.append(event)
            supplied = [(clan, values) for clan, groups in ((BlindState, nest.bsqs), (BoundState, nest.bsss))
                        for values in groups]
            if supplied:
                if event.ilk != 'bup' or len(supplied) != 1:
                    raise kering.ValidationError('Only a BUP may carry one opening')
                clan, values = supplied[0]
                candidate = Blinder(data=clan(*values))
                regeventing.vetBlind(candidate, blid=event.sad['b'])
                openings.append((event, candidate))
        elif not isinstance(event, SerderKERI) or event.ilk not in ('icp', 'dip', 'rot', 'drt', 'ixn', 'rct'):
            raise kering.ValidationError('Response contains unsupported evidence')
    if not events or [event.sn for event in events] != list(range(len(events))):
        raise kering.ValidationError('Response requires one complete ordered TEL')
    processor(vault).parser.parse(ims=bytearray(raw), local=False, version=kering.Vrsn_2_0)
    processor(vault).kvy.processEscrows()
    vault.rgy.processEscrows()
    for event in events:
        accepted = vault.rgy.store.seqEvent(regk, event.sn)
        if accepted is None or accepted.said != event.said:
            raise kering.ValidationError('Registry evidence failed independent verification')
    head = vault.rgy.store.headEvent(regk)
    if head is None or head.said != events[-1].said:
        raise kering.ValidationError('Response head does not match accepted registry head')
    # Explicit response openings are retained only after exact accepted membership.
    for event, candidate in openings:
        vault.rgy.store.putOpening(event.said, candidate)
    return head


def sync(worker):
    """Drive one authenticated request through the finite cancellable Qt client."""
    vault, hab, regk = worker.vault, worker.hab, worker.regk
    if worker.registrar_url:
        stream = clone(vault, regk)
        body = signed_query(hab, 'tels/publish', {'stream': stream.decode('ascii')})
        raw = yield from worker._request(worker.registrar_url.rstrip('/') + '/ingest',
                                         body, CESR_CONTENT_TYPE)
        result = json.loads(raw)
        head = vault.rgy.store.headEvent(regk)
        if (not isinstance(result, dict) or result.get('pending') or result.get('rejected')
                or result.get('heads', {}).get(regk) != head.said):
            raise kering.ValidationError('The registrar has not accepted the complete registry')
        worker.result = result
        return 'registry_published'
    raw = yield from worker._request(worker.observer_url.rstrip('/') + '/',
                                     signed_query(hab, 'tels', {'i': regk}), CESR_CONTENT_TYPE)
    worker.result = receive(vault, regk, raw, worker.response_headers)
    return 'registry_loaded'
