"""Explicit ACDC v2 ``bup`` state-publication modes.

Public mode retains and publishes one random event opening. Blinded mode gives
that opening only to selected disclosures, while derived mode uses separately
provisioned custody. All branches stage through Registry.processEvent; receipt
collection and acceptance remain separate.
"""
from keri import kering
from keri.acdc import Registrar, messaging
from keri.app.credential_disclosing import boundEvent
from keri.core import messagize

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
        mode: public (published opening), blinded (selected opening), or derived
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
    if head.ilk == 'upd':
        raise kering.ConfigurationError('Historical upd heads cannot author current ACDC v2 standing')
    if mode in ('public', 'blinded'):
        opening, event = Registrar(rgy=vault.rgy).issue(registry, acdc, state=state, **coordinates)
        if mode == 'public':
            vault.rgy.store.retainOpening(event, opening)
    else:
        opening = custody(vault).derive(registry.regk, head.sn + 1, acdc.said,
                                        state, **coordinates)
        event = messaging.blindate(registry.regk, head.said, opening.said,
                                   sn=head.sn + 1)
        registry.processEvent(event)
    proof = messagize(acdc, bonds=[opening.data], framed=False)
    return opening, event, proof
