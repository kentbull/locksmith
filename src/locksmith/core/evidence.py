"""Full KEL/TEL service evidence over the vault's borrowed core processors.

Adapted from KERIpy EvidenceProcessor and public_evidence.Request at 7671c088.
Network scheduling stays in RegistrySyncDoer; this module neither writes accepted
rows nor owns stores, a Kramer, or a pruning task.
"""
import json

from keri import kering
from keri.acdc.regeventing import Rever
from keri.app.evidencing import EvidenceProcessor, signedQuery
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import Kevery


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


def receive(vault, regk, raw, headers):
    """Verify a CESR response for the requested registry using ordinary processors.

    Args:
        vault: Receiver owning the existing evidence stores.
        regk: Requested registry identifier.
        raw: Complete supporting KEL and registry TEL bytes.
        headers: HTTP headers used only to check the CESR media type.

    Returns:
        SerderACDC: Accepted registry head represented by the response.

    Raises:
        ValidationError: Wrong media type, unresolved/rejected evidence, or a
            response that does not match the requested local registry head.
    """
    if headers.get('content-type', '').split(';')[0] != CESR_CONTENT_TYPE:
        raise kering.ValidationError('Registry response requires CESR evidence')
    result = processor(vault).ingest(raw)
    head = vault.rgy.store.headEvent(regk)
    if (result['pending'] or result['rejected'] or head is None
            or result['heads'].get(regk) != head.said):
        raise kering.ValidationError('Registry evidence failed independent verification')
    return head


def sync(worker):
    """Drive one signed full-evidence request through the existing Qt client.

    Args:
        worker: RegistrySyncDoer owning the finite request and cancellation path.

    Yields:
        float: Existing nonblocking network progress.

    Returns:
        str: Successful UI event name after worker.result is authenticated.

    Reader/publisher KEL introduction is a deployment bootstrap requirement of
    this service; a wallet query cannot change the observer's acquisition loop.
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
    return 'registry_loaded'
