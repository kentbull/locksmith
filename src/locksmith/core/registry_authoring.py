"""Explicit ACDC v2 registry state-publication modes using the existing core authoring API.

Public upd and derived bup composition adapt KERIpy AcdcV2Author
(named NativeAuthor at historical commit a6539208).
The legacy per-event blinded mode still uses Registrar.issue. All branches stage
through Registry.processEvent; receipt collection and acceptance remain separate.
"""
from keri import kering
from keri.acdc import Registrar, messaging
from keri.app.credential_disclosing import boundEvent
from keri.core import Counter, Codens, messagize

from locksmith.core.disclosing import custody

MODES = ('public', 'blinded', 'derived')


def bound_options(vault, acdc, event):
    """Validate the explicit current issuee event before authoring a bound update.

    vault owns verified KEL evidence; acdc supplies the issuee; event is the exact
    operator-selected digest. Reproducing historical openings uses boundEvent
    directly instead. This authoring constraint follows AcdcV2Author.update.
    """
    if not event:
        return {}
    options = boundEvent(vault.hby, acdc, event)
    if vault.hby.kevers[acdc.iseaid].serder.said != event:
        raise kering.ConfigurationError('New bound update requires the known current issuee event')
    return options


def stage(vault, registry, acdc, state, mode, *, bound_event=None):
    """Stage one state update and return its exact event-specific disclosure.

    Args:
        vault: Issuer's open evidence/optional custody owner.
        registry: Accepted local issuer registry.
        acdc: Credential being issued or revoked.
        state: ACDC v2 registry state string, such as issued or revoked.
        mode: public (no secret), blinded (one random opening), or derived
            (explicit previously provisioned per-registry custody).
        bound_event: Optional exact current issuee KEL event for blinded state.

    Returns:
        tuple: Opening or None, staged TEL event, and credential proof bytes.

    Missing derived custody fails; it never falls back to a random salt. No mode
    writes accepted rows or obtains witness receipts here.
    """
    if mode not in MODES:
        raise ValueError('Choose public, blinded or derived registry state')
    if bound_event and mode == 'public':
        raise ValueError('Bound state requires blinded publication')
    coordinates = bound_options(vault, acdc, bound_event)
    head = registry.store.headEvent(registry.regk)
    if head is None:
        raise kering.MissingAnchorError('Registry inception has not been accepted')
    if mode == 'blinded':
        opening, event = Registrar(rgy=vault.rgy).issue(registry, acdc, state=state, **coordinates)
    else:
        opening = (custody(vault).derive(registry.regk, head.sn + 1, acdc.said, state, **coordinates)
                   if mode == 'derived' else None)
        event = (messaging.blindate(registry.regk, head.said, opening.said, sn=head.sn + 1)
                 if opening else messaging.update(registry.regk, head.said, acdc.said,
                                                  state, sn=head.sn + 1))
        registry.processEvent(event)
    proof = (messagize(acdc, bonds=[opening.data], framed=False) if opening else
             acdc.raw + Counter(Codens.AttachmentGroup, count=0, version=kering.Vrsn_2_0).qb64b)
    return opening, event, proof
