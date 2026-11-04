"""Explicit encrypted-file copies of existing roots; native RegistrySalt owns retention."""
from dataclasses import dataclass

from keri import kering
from keri.acdc.salting import RegistrySalt
from keri.app.habbing import GroupHab
from keri.core import Blinder, BlindState, BoundState, Parser, SerderKERI

from locksmith.core import credentialing, ipexing


@dataclass(frozen=True)
class InspectedCopy:
    """Untrusted file claims, retained byte-for-byte until explicit approval."""
    wire: bytes
    said: str
    sender: str
    recipient: str
    registry: str


def inspect(raw):
    """Parse one finite native reply without dispatch, authentication or replay writes."""
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
            or any(not isinstance(value, str) for value in data.values())
            or data['target'] != data['recipient']):
        raise kering.ValidationError('Expected exactly one individual encrypted registry-root reply')
    return InspectedCopy(bytes(raw), body.said, body.pre, data['recipient'], data['registry'])


def held_openings(vault, said, grant):
    """Enumerate accepted BUPs opened by this exact admitted view, without hydration."""
    view = credentialing.credential(vault, said, grant=grant)
    stream = bytearray(view['proof'])
    node = Parser(version=kering.Vrsn_2_0).parseOneBare(
        ims=stream, framed=True, processive=False)
    if stream or not grant or view['grant'] != grant:
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
    authentication; only native True for this invocation's exact SAID is success.
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

    def export(self, said, issuer, recipient):
        """Create encrypted CESR only; exporting makes no recipient-retention claim."""
        hab = self._hab(issuer)
        view = credentialing.credential(self.vault, said)
        if (not self.vault.db.issued.get((said,)) or view['sad']['i'] != issuer
                or not view['sad'].get('rd')):
            raise ValueError('Select this issuer\'s registry-backed issued credential')
        if recipient not in self.vault.hby.kevers:
            raise ValueError('Introduce the recipient before exporting an encrypted root')
        # Native preparation requires accepted authority, current keys and an existing root.
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
                or not isinstance(opening, Blinder)
                or not any(event == held and opening.qb64 == proof.qb64
                           for held, proof in held_openings(self.vault, said, grant))):
            raise ValueError('Select this recipient\'s exact admission and held accepted BUP opening')
        if self.active is not None:
            raise ValueError('Another root import is active')
        native = RegistrySalt(hab, self.vault.rgy)
        self.received, self.error = None, ''
        self.active = (native, selected)
        try:
            native.approve(selected.registry, selected.sender, event=event, opening=opening)
            self.vault.mbx.parser.parse(ims=bytearray(selected.wire), version=kering.Vrsn_2_0)
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
            native, selected = self.active
            native.abandon(selected.registry, selected.sender)
            self.active = None
