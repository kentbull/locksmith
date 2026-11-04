"""Select held disclosures and optional registry-opening capabilities.

The compaction path adapts KERIpy ExchangeDoer at a6539208. Opening composition
uses native registry vetting; existing encrypted roots belong to Keeper.
These are local wallet controls, not a new delegation or provisioning protocol.
"""
from dataclasses import replace
from copy import deepcopy

from keri import kering
from keri.acdc import regeventing
from keri.core import (Blinder, BlindState, BoundState, Compactor, Parser, SerderACDC,
                       Number, messagize)
from keri.peer import exchanging


def opening(raw):
    """Decode exactly one complete event opening, preserving its primitive bytes."""
    wire = raw.qb64 if isinstance(raw, Blinder) else raw.decode() if isinstance(raw, bytes) else raw
    for clan in (BlindState, BoundState):
        try:
            candidate = Blinder(clan=clan, qb64=wire)
        except (kering.KeriError, ValueError, TypeError):
            continue
        if candidate.qb64 == wire:
            return candidate
    raise kering.ValidationError('Supply exactly one complete CESR opening')


def bound_options(vault, acdc, event):
    """Resolve the explicitly selected digest to its accepted Issuee KEL coordinate."""
    body = vault.hby.db.evts.get((acdc.iseaid, event)) if acdc.iseaid else None
    if (body is None or vault.hby.db.kels.getLast(keys=acdc.iseaid, on=body.sn) != event
            or not vault.hby.db.fullyWitnessed(body)):
        raise kering.MissingAnchorError('Selected Issuee event is not accepted and fully witnessed')
    return dict(bound=True, bsn=body.sn, bd=body.said)


def registry_root(vault, aid, regid):
    """Read an existing authorized local scope; new roots belong to futureDhke."""
    if aid not in vault.hby.prefixes:
        raise kering.ConfigurationError('Registry derivation requires a local identifier')
    if vault.rgy.store.seqEvent(regid, 0) is None:
        raise kering.MissingChainError('Registry derivation requires an accepted inception')
    try:
        root = vault.hby.mgr.getRegistryRoot(aid, regid)
    except ValueError as error:
        raise kering.AuthError('Retained registry root cannot be unlocked') from error
    if root is None:
        raise kering.ConfigurationError('No provisioned registry root for this local identifier')
    return root


def material(vault, view, *, paths=(), refresh=False, openings=(), derive=False, bound_event=None):
    """Transform one retained view without reading fuller inventory or sections.

    Args:
        vault: Current evidence owner; custody is consulted only with derive=True.
        view: Credential/proof dictionary from credentialing.credential.
        paths: Requested attribute paths rooted at a; empty retains the exact view.
        refresh: Select proofs for current accepted history, retaining the content.
        openings: Explicit event-specific CESR Blinder bytes, never registry salts.
        derive: Explicit authorization to use provisioned per-registry custody.
        bound_event: Exact accepted issuee event for bound derivation; never an
            implicit current-head substitution or a registry timestamp.

    Returns:
        dict: New view with exact selected proof and freshly checked authentication.

    Raises:
        ValidationError: Unsupported selection or malformed retained proof.
        KeriError: Missing/wrong opening, custody failure or authentication failure.
            Unrelated ordinary presentations remain usable.
    """
    if bound_event and not derive:
        raise ValueError('A bound event requires explicit derivation')
    if (openings or derive) and not refresh:
        raise ValueError('New openings or derivation require explicit state refresh')
    raw = bytearray(view['proof'])
    nodes = Parser(version=kering.Vrsn_2_0).parse(ims=raw, processive=False)
    if raw or len(nodes) != 1 or not isinstance(nodes[0].serder, SerderACDC):
        raise kering.ValidationError('Invalid retained credential evidence')
    node = nodes[0]
    credential = node.serder
    if refresh:
        regid = credential.sad.get('rd')
        if not regid:
            raise kering.ValidationError('Disclosure has no issuer registry reference')
        retained = [Blinder(clan=clan, qb64=b''.join(part.qb64b for part in proof))
                    for clan, groups in ((BlindState, node.bsqs), (BoundState, node.bsss))
                    for proof in groups]
        retained.extend(opening(raw) for raw in openings)
        rip = vault.rgy.store.seqEvent(regid, 0)
        head = vault.rgy.store.headEvent(regid)
        if rip is None or head is None:
            raise kering.MissingChainError('Missing accepted registry history')
        updates = [vault.rgy.store.seqEvent(regid, sn) for sn in range(1, head.sn + 1)]
        if any(update is None for update in updates):
            raise kering.MissingChainError('Incomplete accepted registry history')
        if derive:
            aids = {aid for aid in (credential.iseaid, credential.israid) if aid in vault.hby.prefixes}
            if len(aids) != 1:
                raise kering.ConfigurationError('Derivation requires one local credential controller')
            root = registry_root(vault, aids.pop(), regid)
            coordinates = bound_options(vault, credential, bound_event) if bound_event else {}
            for update in reversed(updates):
                if any(item.said == update.sad['b'] for item in retained):
                    continue
                candidate = Blinder.unblind(update.sad['b'], salt=root.qb64,
                    sn=update.sn, acdc=credential.said, states=['issued', 'revoked'],
                    bound=bool(coordinates),
                    bounds=[(coordinates['bsn'], coordinates['bd'])] if coordinates else None)
                if candidate is None:
                    candidate = Blinder.unblind(update.sad['b'], salt=root.qb64,
                        sn=update.sn, acdc='', states=[''], bound=bool(coordinates),
                        bounds=[(0, '')] if coordinates else None)
                if candidate is None:
                    raise kering.ValidationError('Root and explicit coordinates do not open the selected registry')
                retained.append(candidate)
        # Selection is explicit: never hydrate from arbitrary locally held openings.
        unique = {item.qb64: item for item in retained}
        regeventing.vetBinds(rip, updates, db=vault.hby.db, blinders=unique.values(),
                             target=credential.said, acdc=credential)
        raw = messagize(credential, bonds=[item.data for item in unique.values()], framed=False)
        node = Parser(version=kering.Vrsn_2_0).parseOne(ims=bytearray(raw), processive=False)
    node = replace(node, serder=select(credential, paths))
    from locksmith.core.credentialing import authentication
    return dict(view, sad=node.serder.sad, proof=exchanging.serializeParsedSubstream(node),
                status=authentication(vault, node))


def select(credential, paths=()):
    """Select committed attributes without making a registry-state claim.

    credential is the exact retained SerderACDC; paths are supported a/ paths.
    This pure operation is shared by Offer previews and authenticated Grant
    composition. It cannot recover withheld values or change the original SAID.
    """
    if paths and list(paths) not in ([''],):
        if (not isinstance(credential.sad.get('a'), dict)
                or any(not path.startswith('a/') for path in paths)):
            raise ValueError('This form selects expanded attribute paths beginning with a/')
        block = Compactor(mad=deepcopy(credential.sad['a']), makify=True, kind=credential.kind)
        block.compact(paths=list(paths), root='a')
        sad = dict(credential.sad, a=dict(block.partials[tuple(paths)].mad))
        selected = SerderACDC(sad=sad, kind=credential.kind, makify=True)
        if selected.said != credential.said:
            raise kering.ValidationError('Disclosure changed the credential commitment')
        return selected
    return credential
