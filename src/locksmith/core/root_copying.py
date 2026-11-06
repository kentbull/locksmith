"""Explicit encrypted-file copies of existing roots; core RegistrySalt owns retention."""
from dataclasses import dataclass

from keri import kering
from keri.acdc.salting import RegistrySalt
from keri.app.grouping import multisigRpyExn
from keri.app.habbing import GroupHab, groupElection
from keri.core import Blinder, BlindState, BoundState, Cipher, MtrDex, Parser, SerderKERI, messagize
from keri.peer import exchanging

from locksmith.core import credentialing, ipexing


@dataclass(frozen=True)
class InspectedCopy:
    """Untrusted file claims, retained byte-for-byte until explicit approval."""
    wire: bytes
    said: str
    sender: str
    recipient: str
    registry: str
    target: str


@dataclass(frozen=True)
class InspectedProposal:
    """Unauthenticated group proposal claims; inspection grants no signing consent."""
    wire: bytes
    sender: str
    reply: InspectedCopy


def inspect(raw):
    """Parse one finite v2 reply without dispatch, authentication or replay writes."""
    if not raw or len(raw) > 65536:
        raise ValueError('Select one encrypted registry-root reply (at most 64 KiB)')
    stream = bytearray(raw)
    frame = Parser(version=kering.Vrsn_2_0).parseOneBare(
        ims=stream, framed=True, processive=False)
    body = frame.serder
    data = body.sad.get('a', {})
    if (stream or not isinstance(body, SerderKERI) or body.pvrsn != kering.Vrsn_2_0
            or body.ilk != 'rpy' or body.route != RegistrySalt.Route
            or not isinstance(data, dict) or set(data) != {'registry', 'recipient', 'target', 'cipher'}
            or any(not isinstance(value, str) for value in data.values())):
        raise kering.ValidationError('Expected exactly one encrypted registry-root reply')
    return InspectedCopy(bytes(raw), body.said, body.pre, data['recipient'], data['registry'], data['target'])


def inspect_proposal(raw):
    """Inspect one ordinary multisig/rpy envelope without dispatch or replay writes."""
    if not raw or len(raw) > 65536:
        raise ValueError('Select one group root-copy proposal (at most 64 KiB)')
    stream = bytearray(raw)
    frame = Parser(version=kering.Vrsn_2_0).parseOneBare(ims=stream, framed=True, processive=False)
    wrapper = frame.serder
    if (stream or not isinstance(wrapper, SerderKERI) or wrapper.pvrsn != kering.Vrsn_2_0
            or wrapper.ilk not in ('xip', 'exn') or wrapper.route != '/multisig/rpy'
            or len(frame.nests) != 1
            or any(value for name, value in vars(frame).items()
                   if name not in ('serder', 'tsgs', 'cigars', 'nests', 'local'))):
        raise kering.ValidationError('Expected one v2 multisig registry-root proposal')
    selected = inspect(exchanging.serializeParsedSubstream(frame.nests[0]))
    if wrapper.sad['a'] != dict(gid=selected.sender, rpy=selected.said):
        raise kering.ValidationError('Group proposal does not commit to this exact reply')
    return InspectedProposal(bytes(raw), wrapper.pre, selected)


def held_openings(vault, said, grant):
    """Enumerate accepted BUPs opened by the selected issued or exact admitted view."""
    if not grant and vault.db.issued.get((said,)) is None:
        raise ValueError('Select a local issued credential or an exact admitted disclosure')
    view = credentialing.credential(vault, said, grant=grant)
    stream = bytearray(view['proof'])
    node = Parser(version=kering.Vrsn_2_0).parseOneBare(
        ims=stream, framed=True, processive=False)
    if stream or grant and view['grant'] != grant:
        raise ValueError('Select one exact admitted credential disclosure')
    regid = node.serder.sad.get('rd')
    proofs = [Blinder(clan=clan, qb64=b''.join(part.qb64b for part in proof))
              for clan, groups in ((BlindState, node.bsqs), (BoundState, node.bsss))
              for proof in groups]
    head = vault.rgy.store.headEvent(regid) if regid else None
    if head is None:
        return []
    return [(event.said, proof) for sn in range(1, head.sn + 1) if head
            and (event := vault.rgy.store.seqEvent(regid, sn)) is not None and event.ilk == 'bup'
            for proof in proofs if proof.said == event.sad['b']]


class RootCopies:
    """One vault route, active only during a synchronous explicitly approved import.

    Inspecting never dispatches. The existing mailbox Parser/KRAM/Revery decides
    authentication; only core True for this invocation's exact SAID is success.
    There is no pending-operation persistence or implicit escrow retry authority.
    """

    def __init__(self, vault):
        self.vault = vault
        self.active = None
        self.received = None
        self.error = ''
        vault.rvy.rtr.addRoute(RegistrySalt.Route, self, attachments=True)

    def _hab(self, aid):
        ipexing._require_vault(self.vault)
        hab = self.vault.hby.habByPre(aid)
        if hab is None or isinstance(hab, GroupHab):
            raise ValueError('Select an individual identifier in this open vault')
        return hab

    def _group(self, aid):
        ipexing._require_vault(self.vault)
        hab = self.vault.hby.habByPre(aid)
        if (not isinstance(hab, GroupHab) or not hab.accepted or hab.mhab is None
                or hab.mhab.kever.fetchLatestContribTo(verfers=hab.kever.verfers) is None):
            raise ValueError('Select an accepted group with this local member currently signing')
        return hab

    def prepare_group(self, aid, registry, recipient, target, coordinator):
        """Prepare existing-root ciphertext and its member-authenticated proposal.

        Returned reply bytes carry only this member's contribution. Ordinary
        current group signatures must authorize the same body before receipt.
        The caller selects an exact accepted coordinator; there is no fallback.
        """
        hab = self._group(aid)
        if not isinstance(coordinator, tuple) or len(coordinator) != 2:
            raise ValueError('Select the exact accepted coordinator (sequence, SAID)')
        wire = RegistrySalt(hab, self.vault.rgy).prepare(
            registry, recipient, target, coordinator=coordinator)
        wrapper, atc = multisigRpyExn(hab, rpy=wire, version=kering.Vrsn_2_0)
        return bytes(wire), bytes(wrapper.raw + atc)

    def contribute_group(self, proposal, aid, registry, recipient, target, coordinator):
        """Authenticate the selected custodian's envelope, then sign unchanged ciphertext.

        This finite file action does not dispatch the reply or authorize import.
        Core attachment verification owns the envelope's signature threshold;
        RegistrySalt owns accepted registry authority and current target scope.
        """
        inspected = inspect_proposal(proposal)
        hab = self._group(aid)
        if not isinstance(coordinator, tuple) or len(coordinator) != 2:
            raise ValueError('Select the exact accepted coordinator (sequence, SAID)')
        selection = groupElection(hab, sn=coordinator[0], dig=coordinator[1])
        if selection is None:
            raise kering.ValidationError('Coordinator lacks accepted group threshold evidence')
        frame = Parser(version=kering.Vrsn_2_0).parseOneBare(
            ims=bytearray(inspected.wire), framed=True, processive=False)
        wrapper, child = frame.serder, frame.nests[0]
        valid, cigars, _, invalid, missing = exchanging.verifyAttachments(
            self.vault.hby, wrapper, tsgs=frame.tsgs, cigars=frame.cigars)
        if (not wrapper.verify() or invalid or missing
                or not (any(pre.qb64 == wrapper.pre for pre, _, _, _ in valid)
                        or any(cigar.verfer.qb64 == wrapper.pre for cigar in cigars))
                or any(pre.qb64 != wrapper.pre for pre, _, _, _ in frame.tsgs)
                or any(cigar.verfer.qb64 != wrapper.pre for cigar in frame.cigars)):
            raise kering.ValidationError('Group root proposal lacks authenticated member authority')
        establishment, index = selection
        proposer = self.vault.hby.kevers.get(wrapper.pre)
        contribution = proposer.fetchLatestContribTo(verfers=establishment.verfers) if proposer else None
        if (contribution is None or contribution[1] != index
                or proposer.fetchLatestContribTo(verfers=hab.kever.verfers) is None):
            raise kering.ValidationError('Proposal author is not the selected current group custodian')
        current = hab.kever.lastEst
        if (child.serder.pre != aid or not child.serder.verify() or not child.tsgs
                or any(value for name, value in vars(child).items()
                       if name not in ('serder', 'tsgs', 'local'))
                or any(pre.qb64 != aid or number.sn != current.s or diger.qb64 != current.d
                       for pre, number, diger, _ in child.tsgs)):
            raise kering.ValidationError('Root contribution requires the group\'s current establishment')
        selected = inspected.reply
        if (selected.sender, selected.registry, selected.recipient, selected.target) != (aid, registry, recipient, target):
            raise kering.ValidationError('Root proposal differs from the selected transfer scope')
        registry_salt = RegistrySalt(hab, self.vault.rgy)
        registry_salt._unlocked()
        registry_salt._scope(registry, aid, recipient, target)
        cipher = Cipher(qb64=child.serder.sad['a']['cipher'])
        if cipher.code != MtrDex.X25519_Cipher_Salt or cipher.qb64 != child.serder.sad['a']['cipher']:
            raise kering.ValidationError('Root proposal requires an encrypted Salt128 ciphertext')
        signed = hab.endorse(child.serder, gvrsn=kering.Vrsn_2_0)
        local = Parser(version=kering.Vrsn_2_0).parseOneBare(
            ims=bytearray(signed), framed=True, processive=False)
        return bytes(messagize(child.serder, tsgs=[*child.tsgs, *local.tsgs], gvrsn=kering.Vrsn_2_0))

    def export(self, said, issuer, recipient):
        """Create encrypted CESR only; exporting makes no recipient-retention claim."""
        hab = self._hab(issuer)
        view = credentialing.credential(self.vault, said)
        if (not self.vault.db.issued.get((said,)) or view['sad']['i'] != issuer
                or not view['sad'].get('rd')):
            raise ValueError('Select this issuer\'s registry-backed issued credential')
        if recipient not in self.vault.hby.kevers:
            raise ValueError('Introduce the recipient before exporting an encrypted root')
        # Core preparation requires accepted authority, current keys and an existing root.
        return RegistrySalt(hab, self.vault.rgy).prepare(view['sad']['rd'], recipient, recipient)

    def receive(self, selected, recipient, said, grant, event, opening):
        """Approve one inspected file against a selected held opening, then abandon."""
        if not isinstance(selected, InspectedCopy) or inspect(selected.wire) != selected:
            raise ValueError('Inspect the exact encrypted reply before approving import')
        hab = self._hab(recipient)
        view = credentialing.credential(self.vault, said, grant=grant)
        original = self.vault.hby.db.exns.get((grant,))
        if (selected.recipient != hab.pre or view['sad'].get('rd') != selected.registry or original is None
                or original.sad['ri'] != hab.pre
                or selected.target != hab.pre
                or not isinstance(opening, Blinder)
                or not any(event == held and opening.qb64 == proof.qb64
                           for held, proof in held_openings(self.vault, said, grant))):
            raise ValueError('Select this recipient\'s exact admission and held accepted BUP opening')
        return self._receive((selected,), hab, event, opening)

    def receive_group(self, selected, aid, registry, event, opening, *, contributions=()):
        """Approve exact group-targeted files against an explicitly held BUP opening.

        No wallet inventory row is necessary. Core accepted KEL/TEL, the
        current target member, author threshold and decrypted-root opening
        verification decide retention under the recipient group AID.
        """
        hab = self._group(aid)
        files = (selected, *contributions)
        body = None
        for item in files:
            if not isinstance(item, InspectedCopy) or inspect(item.wire) != item:
                raise ValueError('Inspect every exact root contribution before approving import')
            raw = Parser(version=kering.Vrsn_2_0).parseOneBare(
                ims=bytearray(item.wire), framed=True, processive=False).serder.raw
            if body is not None and raw != body:
                raise kering.ValidationError('Root contributions must sign the identical encrypted reply body')
            body = raw
            if (item.recipient, item.target, item.registry) != (hab.pre, hab.mhab.pre, registry):
                raise kering.ValidationError('Root copy must target this member of the selected recipient group')
        return self._receive(files, hab, event, opening)

    def _receive(self, files, hab, event, opening):
        selected = files[0]
        if self.active is not None:
            raise ValueError('Another root import is active')
        registry_salt = RegistrySalt(hab, self.vault.rgy)
        self.received, self.error = None, ''
        self.active = (registry_salt, selected)
        try:
            registry_salt.approve(selected.registry, selected.sender, event=event, opening=opening)
            for item in files:
                self.vault.mbx.parser.parse(ims=bytearray(item.wire), version=kering.Vrsn_2_0)
            if self.received != selected.said:
                raise kering.ValidationError(self.error or
                    'Encrypted root was not retained; verify current sender keys, public evidence and message age')
            return selected.said
        finally:
            self.close()

    def processReply(self, *, serder, **kwa):
        """Observe successful retention, never a prior reply row or an existing root."""
        ipexing._require_vault(self.vault)
        if self.active is None or self.active[1].said != serder.said:
            raise kering.ValidationError('Registry-root reply has no exact current approval')
        try:
            if self.active[0].processReply(serder=serder, **kwa) is True:
                self.received = serder.said
        except kering.KeriError as error:
            self.error = str(error)
            raise

    def close(self):
        """Drop receive consent on completion, refusal, cancellation or vault close."""
        if self.active is not None:
            registry_salt, selected = self.active
            registry_salt.abandon(selected.registry, selected.sender)
            self.active = None
