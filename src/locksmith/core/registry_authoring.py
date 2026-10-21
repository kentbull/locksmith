"""Explicit native state-publication modes using the existing core authoring API.

Public upd and derived bup composition adapt KERIpy NativeAuthor at a6539208.
The legacy per-event blinded mode still uses Registrar.issue. All branches stage
through Registry.processEvent; receipt collection and acceptance remain separate.
"""
from keri import kering
from keri.acdc import Registrar, messaging
from keri.core import Counter, Codens, messagize

from locksmith.core.disclosing import custody

MODES = ('public', 'blinded', 'derived')


def stage(vault, registry, acdc, state, mode):
    """Stage one state update and return its exact event-specific disclosure.

    Args:
        vault: Issuer's open evidence/optional custody owner.
        registry: Accepted local issuer registry.
        acdc: Credential being issued or revoked.
        state: Native state string, such as issued or revoked.
        mode: public (no secret), blinded (one random opening), or derived
            (explicit previously provisioned per-registry custody).

    Returns:
        tuple: Opening or None, staged TEL event, and credential proof bytes.

    Missing derived custody fails; it never falls back to a random salt. No mode
    writes accepted rows or obtains witness receipts here.
    """
    if mode not in MODES:
        raise ValueError('Choose public, blinded or derived registry state')
    head = registry.store.headEvent(registry.regk)
    if head is None:
        raise kering.MissingAnchorError('Registry inception has not been accepted')
    if mode == 'blinded':
        opening, event = Registrar(rgy=vault.rgy).issue(registry, acdc, state=state)
    else:
        opening = (custody(vault).derive(registry.regk, head.sn + 1, acdc.said, state)
                   if mode == 'derived' else None)
        event = (messaging.blindate(registry.regk, head.said, opening.said, sn=head.sn + 1)
                 if opening else messaging.update(registry.regk, head.said, acdc.said,
                                                  state, sn=head.sn + 1))
        registry.processEvent(event)
    proof = (messagize(acdc, bonds=[opening.data], framed=False) if opening else
             acdc.raw + Counter(Codens.AttachmentGroup, count=0, version=kering.Vrsn_2_0).qb64b)
    return opening, event, proof
