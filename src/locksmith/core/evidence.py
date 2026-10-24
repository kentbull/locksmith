"""Full KEL/TEL service profile over the vault's borrowed core processors.

Adapted from KERIpy EvidenceProcessor and public_evidence.Request at 7671c088.
Network scheduling stays in RegistrySyncDoer; this module neither writes accepted
rows nor owns stores, a Kramer, or a pruning task.
"""
import json
from math import isfinite
from time import monotonic

from keri import kering
from keri.acdc.regeventing import Rever
from keri.app.evidencing import EvidenceProcessor, signedQuery
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import Kevery
from keri.help import helping


def processor(vault):
    """Return the vault-scoped strict public-evidence adapter.

    Args:
        vault: Open wallet runtime owning Habery, Regery and optional Kramer.

    Returns:
        EvidenceProcessor: Borrowed verifier composition, cached for this vault.

    The dedicated strict KEL intake shares the vault's Kramer and stores. It does
    not relax the existing mailbox policy or create a second maintenance owner.
    """
    if getattr(vault, 'evidence', None) is None:
        kvy = Kevery(db=vault.hby.db, lax=False, local=False,
                     kramer=getattr(vault, 'kramer', None))
        rever = Rever(db=vault.hby.db, reger=vault.rgy.baser)
        vault.evidence = EvidenceProcessor(vault.hby, kvy=kvy, rever=rever)
    return vault.evidence


def receive(vault, regk, raw, headers, *, maximum_age=15.0):
    """Authenticate a full reply and bind freshness to its exact accepted head.

    Args:
        vault: Receiver owning verified evidence stores.
        regk: Requested registry identifier.
        raw: Complete supporting KEL and framed native TEL bytes.
        headers: Lowercase HTTP header map from the configured observer endpoint.
        maximum_age: Positive finite maximum receiver observation age in seconds.

    Returns:
        SerderACDC: Exact verified registry head advertised by this response.

    Raises:
        ValidationError: Missing/stale metadata, incomplete/conflicting evidence,
            or advertised head mismatch. Valid evidence may remain retained even
            when the response cannot establish freshness.
    """
    if not isfinite(maximum_age) or maximum_age <= 0:
        raise ValueError('Observation age must be positive and finite')
    if (headers.get('observer-evidence-state') != 'fresh'
            or headers.get('content-type', '').split(';')[0] != CESR_CONTENT_TYPE):
        raise kering.ValidationError('Observer evidence is not fresh CESR')
    remaining(headers, maximum_age=maximum_age)
    result = processor(vault).ingest(raw)
    head = vault.rgy.store.headEvent(regk)
    if (result['pending'] or result['rejected'] or head is None
            or head.said != headers.get('observer-registry-head')
            or result['heads'].get(regk) != head.said):
        raise kering.ValidationError('Observer evidence failed independent verification')
    return head


def remaining(headers, *, maximum_age=15.0):
    """Return usable observation lifetime without restarting its freshness clock.

    headers contain the configured observer's verified response metadata;
    maximum_age is the receiver policy in seconds. Invalid, future or stale
    observations raise ValidationError. Cache callers convert the remainder to
    a monotonic deadline, retaining the exact source and head independently.
    """
    try:
        age = (helping.nowUTC() - helping.fromIso8601(headers['observer-observed-at'])).total_seconds()
    except (KeyError, TypeError, ValueError) as ex:
        raise kering.ValidationError('Observer observation time is invalid') from ex
    if not 0 <= age <= maximum_age:
        raise kering.ValidationError('Observer observation is stale or in the future')
    return maximum_age - age


def sync(worker):
    """Drive one signed full-evidence request through the existing Qt client.

    Args:
        worker: RegistrySyncDoer owning the finite request and cancellation path.

    Yields:
        float: Existing nonblocking network progress.

    Returns:
        str: Successful UI event name after worker.result is authenticated.

    Reader/publisher KEL introduction is a deployment bootstrap requirement of
    this profile; a wallet query cannot change the observer's acquisition loop.
    """
    vault, hab, regk = worker.vault, worker.hab, worker.regk
    if worker.registrar_url:
        rip = vault.rgy.store.seqEvent(regk, 0)
        if rip is None or rip.israid != hab.pre:
            raise ValueError('Only the registry issuer can publish this registry')
        stream = processor(vault).clone([regk])
        body = signedQuery(hab, 'tels/publish', {'stream': stream.decode('ascii')})
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
                                     signedQuery(hab, 'tels', {'i': regk}), CESR_CONTENT_TYPE)
    worker.result = receive(vault, regk, raw, worker.response_headers)
    worker.fresh_until = monotonic() + remaining(worker.response_headers)
    return 'registry_loaded'
