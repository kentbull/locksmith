"""Select held disclosures and optional registry-opening capabilities.

The compaction path adapts KERIpy ExchangeDoer at a6539208. Opening composition
uses its shared registryProof helper; secret storage reuses RegistryCustody.
These are local wallet controls, not a new delegation or provisioning protocol.
"""
from dataclasses import replace
from copy import deepcopy

from keri import kering
from keri.acdc.regeventing import issuerRegistry, _blindCandidates
from keri.app.credential_disclosing import registryProof
from keri.app.registry_custody import RegistryCustody
from keri.core import Blinder, BlindState, BoundState, Compactor, Parser, SerderACDC
from keri.peer import exchanging


def custody(vault):
    """Compose optional encrypted derivation over the wallet's existing table.

    Args:
        vault: Open vault owning Habery, Regery and LocksmithBaser.

    Returns:
        RegistryCustody: Adapter that authenticates Keeper only when used. Merely
            viewing or presenting held material never calls this function.
    """
    return RegistryCustody(vault.hby, vault.rgy, db=vault.db)


def material(vault, view, *, paths=(), refresh=False, openings=(), derive=False):
    """Transform one retained view without reading fuller inventory or sections.

    Args:
        vault: Current evidence owner; custody is consulted only with derive=True.
        view: Credential/proof dictionary from credentialing.credential.
        paths: Requested attribute paths rooted at a; empty retains the exact view.
        refresh: Select proofs for current accepted history, retaining the content.
        openings: Explicit event-specific CESR Blinder bytes, never registry salts.
        derive: Explicit authorization to use provisioned per-registry custody.

    Returns:
        dict: New view with exact selected proof and freshly checked authentication.

    Raises:
        ValidationError: Unsupported selection or malformed retained proof.
        KeriError: Missing/wrong opening, custody failure or authentication failure.
            Unrelated ordinary presentations remain usable.
    """
    if (openings or derive) and not refresh:
        raise ValueError('New openings or derivation require explicit state refresh')
    raw = bytearray(view['proof'])
    nodes = Parser(version=kering.Vrsn_2_0).parse(ims=raw, processive=False)
    if raw or len(nodes) != 1 or not isinstance(nodes[0].serder, SerderACDC):
        raise kering.ValidationError('Invalid retained credential evidence')
    node = nodes[0]
    credential = node.serder
    if refresh:
        regid = issuerRegistry(credential)
        if not regid:
            sources = {pre.qb64 for pre, _, _ in node.ssts
                       if vault.rgy.store.seqEvent(pre.qb64, 0) is not None}
            if len(sources) != 1:
                raise kering.ValidationError('Disclosure has no unique issuer registry reference')
            regid = sources.pop()
        retained = [Blinder(clan=clan, qb64=b''.join(part.qb64b for part in proof))
                    for clan, groups in ((BlindState, node.bsqs), (BoundState, node.bsss))
                    for proof in groups]
        for raw_opening in openings:
            candidates = _blindCandidates(raw_opening)
            if len(candidates) != 1:
                raise kering.ValidationError('Supply exactly one CESR opening per value')
            retained.append(candidates[0])
        provider = custody(vault) if derive else None
        def derive_opening(update, target, state):
            """Derive only this selected registry's event-specific candidate."""
            return provider.derive(regid, update.sn, target, state)
        raw = registryProof(vault.hby, vault.rgy, credential, regid, retained=retained,
                            derive=derive_opening if provider else None)
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
