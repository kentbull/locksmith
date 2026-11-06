"""Registry-root replication to group members over KERIpy's ESSR ``/registry/root``.

Core ``salting.RegistryRoot`` owns the wire, authorization, pending storage and
verified retention. This adapter is a member of the Auxiliary operation table:
it answers the Dhke ``replicate`` cue and accepted group rotations by queueing
the copies this member owes, sends them from the run loop through the vault's
mailbox ``postman``, and approves received copies only on explicit request.
"""
from dataclasses import dataclass

from keri import help, kering
from keri.acdc.salting import RegistryRoot, RootDeferred, RootUnverified
from keri.app.habbing import GroupHab
from keri.core import Blinder, BlindState, BoundState, Parser, SerderACDC

from locksmith.core import credentialing, ipexing

logger = help.ogler.getLogger(__name__)

Limit = 65536


def held_openings(vault, said, grant):
    """Enumerate accepted BUPs opened by the selected issued or exact admitted view."""
    if not grant and vault.db.issued.get((said,)) is None:
        raise ValueError('Select a local issued credential or an exact admitted disclosure')
    view = credentialing.credential(vault, said, grant=grant)
    stream = bytearray(view['proof'])
    node = Parser(version=kering.Vrsn_2_0).parseOneBare(ims=stream, framed=True, processive=False)
    if stream or grant and view['grant'] != grant:
        raise ValueError('Select one exact admitted credential disclosure')
    regid = node.serder.sad.get('rd')
    proofs = [Blinder(clan=clan, qb64=b''.join(part.qb64b for part in proof))
              for clan, groups in ((BlindState, node.bsqs), (BoundState, node.bsss))
              for proof in groups]
    head = vault.rgy.store.headEvent(regid) if regid else None
    if head is None:
        return []
    return [(event.said, proof) for sn in range(1, head.sn + 1)
            if (event := vault.rgy.store.seqEvent(regid, sn)) is not None and event.ilk == 'bup'
            for proof in proofs if proof.said == event.sad['b']]


def inspect(raw):
    """Return the exchange SAIDs of a file holding only ``/registry/root`` copies.

    Parsing here neither dispatches nor authenticates; the vault's ordinary
    Parser, KRAM and Exchanger path decides what is stored.
    """
    if not raw or len(raw) > Limit:
        raise ValueError(f'Select one registry root copy file (at most {Limit // 1024} KiB)')
    stream, saids = bytearray(raw), []
    while stream:
        serder = Parser(version=kering.Vrsn_2_0).parseOneBare(
            ims=stream, framed=True, processive=False).serder
        if serder.ilk != 'exn' or serder.route != RegistryRoot.Route:
            raise kering.ValidationError('Expected only registry root copy exchanges')
        saids.append(serder.said)
    return saids


@dataclass(frozen=True)
class Copy:
    """One stored copy addressed to a local member, as the Activity view shows it."""
    said: str
    sender: str
    recipient: str
    gid: str
    registry: str
    dt: str
    deferred: str = ''
    error: str = ''


class RootReplicas:
    """Queue, send and approve registry-root copies for one vault.

    Owed copies persist in the vault database until core ``prepare`` either
    succeeds or refuses them, so a copy whose registry update is not yet
    accepted here (the custodian derives the root before the BUP exists)
    waits across restarts. Nothing is retained from a received copy until
    ``approve``.
    """

    def __init__(self, owner):
        self.owner = owner
        self.vault = owner.vault
        self.core = RegistryRoot(self.vault.hby, self.vault.rgy, self.vault.notifier)
        self.vault.exc.addHandler(self.core)
        self._rotations = set()  # (gid, rotation) already examined in this session.
        self.closed = False

    # owed copies

    def owe(self, gid, registry, recipient, td=''):
        """Record one copy this member owes ``recipient`` for holder ``gid``."""
        self.vault.db.rootSends.pin(keys=(gid, registry, recipient), val=td or '')

    def replicate(self, hab, registries, hints=None):
        """Answer the Dhke ``replicate`` cue: every other current member gets each root."""
        if not isinstance(hab, GroupHab) or hab.mhab is None:
            return
        hints = hints or {}
        for registry in registries:
            if hints.get(registry):
                self.vault.db.rootHints.pin(keys=(hab.pre, registry), val=hints[registry])
            for member in self.core.members(hab.pre):
                if member != hab.mhab.pre:
                    self.owe(hab.pre, registry, member, hints.get(registry, ''))

    def catch_up(self, hab, rotation):
        """Owe every held root to each newcomer of one accepted group rotation."""
        held = self.core.held(hab.pre)
        for member in self.core.newcomers(hab, rotation):
            for registry in held:
                self.owe(hab.pre, registry, member, self._hint(registry, hab.pre))
        self.vault.db.rootRotations.pin(keys=(hab.pre, rotation), val=hab.mhab.pre)

    def _hint(self, registry, gid=None):
        """Return a local ACDC SAID in ``registry`` for commitment reproduction, or ''."""
        if gid is not None and (said := self.vault.db.rootHints.get(keys=(gid, registry))):
            return said
        for (said,), record in self.vault.db.issued.getTopItemIter():
            if SerderACDC(raw=record.raw.encode()).sad.get('rd') == registry:
                return said
        for (said,), _ in self.vault.db.accepted.getTopItemIter():
            try:
                if credentialing.credential(self.vault, said, received=True)['sad'].get('rd') == registry:
                    return said
            except (kering.KeriError, ValueError, KeyError, StopIteration):
                continue
        return ''

    def owed(self):
        return [(*keys, td) for keys, td in self.vault.db.rootSends.getTopItemIter()]

    # run loop

    def process(self):
        """Examine newly accepted group rotations, then send whatever is now preparable."""
        if self.closed:
            return
        for hab in list(self.vault.hby.habs.values()):
            if not isinstance(hab, GroupHab) or hab.mhab is None or not hab.accepted:
                continue
            est = hab.kever.lastEst
            key = (hab.pre, est.d)
            if est.s == 0 or key in self._rotations:
                continue
            self._rotations.add(key)
            if self.vault.db.rootRotations.get(keys=key) is not None:
                continue
            try:
                # Only the rotation's elected witnesser catches newcomers up automatically.
                if self.core.witnesser(hab, est.d):
                    self.catch_up(hab, est.d)
            except kering.KeriError as error:
                logger.info('Registry root catch-up for %s rotation %s skipped: %s', hab.pre, est.d, error)
        for gid, registry, recipient, td in self.owed():
            self._flush(gid, registry, recipient, td)

    def _flush(self, gid, registry, recipient, td):
        hab = self.vault.hby.habs.get(gid)
        keys = (gid, registry, recipient)
        if not isinstance(hab, GroupHab) or hab.mhab is None:
            self.vault.db.rootSends.rem(keys=keys)
            return
        try:
            wire = self.core.prepare(hab.mhab, recipient, gid, registry, td=td or None)
        except RootDeferred:
            return  # The registry update or member state is not yet accepted here.
        except (kering.KeriError, ValueError) as error:
            logger.info('Registry root copy to %s for %s refused: %s', recipient, registry, error)
            self.vault.db.rootSends.rem(keys=keys)
            return
        self.post(hab.mhab, recipient, wire)
        self.vault.db.rootSends.rem(keys=keys)

    def post(self, sender, recipient, wire):
        """Queue one prepared copy on the recipient's mailbox through the vault postman."""
        serder = Parser(version=kering.Vrsn_2_0).parseOneBare(
            ims=bytearray(wire), processive=False).serder
        self.vault.postman.send(hab=sender, dest=recipient, topic='credential', serder=serder,
                                attachment=bytes(wire[serder.size:]), stream=True)
        return serder.said

    # explicit sends

    def recipients(self, hab, gid):
        """Return the member AIDs ``hab`` would send ``gid``'s root to."""
        sender = hab.mhab.pre if isinstance(hab, GroupHab) else hab.pre
        members = self.core.members(gid)
        return [member for member in members if member != sender] if members else [gid]

    def prepare(self, hab, gid, registry, *, td=None):
        """Return [(recipient, wire)] copies of ``registry``'s root held for ``gid`` or issued by ``hab``."""
        ipexing._require_vault(self.vault, hab)
        sender = hab.mhab if isinstance(hab, GroupHab) else hab
        recipients = self.recipients(hab, gid)
        if not recipients:
            raise ValueError('No current member can receive this registry root')
        return [(recipient, self.core.prepare(sender, recipient, gid, registry,
                                              td=td or self._hint(registry, gid) or None))
                for recipient in recipients]

    def send(self, hab, gid, registry, *, td=None):
        """Send copies to every recipient's mailbox; returns the queued exchange SAIDs."""
        sender = hab.mhab if isinstance(hab, GroupHab) else hab
        return [self.post(sender, recipient, wire)
                for recipient, wire in self.prepare(hab, gid, registry, td=td)]

    # receiving

    def ingest(self, raw):
        """Parse a file of copies through the ordinary vault intake; return the stored SAIDs."""
        ipexing._require_vault(self.vault)
        saids = inspect(raw)
        self.vault.mbx.parser.parse(ims=bytearray(raw), version=kering.Vrsn_2_0)
        stored = [said for said in saids if self.vault.hby.db.exns.get(keys=(said,)) is not None]
        if not stored:
            raise kering.ValidationError('No registry root copy in this file is addressed to this vault')
        return stored

    def _noted(self):
        return {note.attrs.get('d') for _, note in self.vault.notifier.noter.notes.getTopItemIter()
                if note.attrs.get('r') == RegistryRoot.Note}

    def pending(self):
        """Copies awaiting explicit approval, with the local state each still needs."""
        ipexing._require_vault(self.vault)
        noted, items = self._noted(), []
        for item in self.core.pending():
            if item['said'] not in noted:
                continue  # Dismissed.
            deferred = ''
            try:
                if item['gid'] != item['recipient'] and not isinstance(
                        self.vault.hby.habs.get(item['gid']), GroupHab):
                    raise RootDeferred('the holder group is not yet local')
                self.core.authorize(item['sender'], item['recipient'], item['gid'], item['registry'])
            except RootDeferred as error:
                deferred = str(error)
            except (kering.KeriError, ValueError) as error:
                item.setdefault('error', str(error))
            items.append(Copy(item['said'], item['sender'], item['recipient'], item['gid'],
                              item['registry'], item['dt'] or '', deferred, item.get('error', '')))
        return items

    def approve(self, said):
        """Explicitly approve one stored copy: core verifies, then retains the root.

        A held opening for an accepted update of the copy's registry is used
        when the sender's hint cannot reproduce the commitment. RootDeferred
        and RootUnverified leave the copy pending.
        """
        ipexing._require_vault(self.vault)
        try:
            return self.core.receive(said)
        except RootDeferred:
            raise
        except RootUnverified as error:
            unverified = error
        copy = next((item for item in self.core.pending() if item['said'] == said), None)
        for event, opening in self._openings(copy['registry'] if copy else None):
            try:
                return self.core.receive(said, event=event, opening=opening)
            except RootDeferred:
                raise
            except RootUnverified:
                continue
        raise unverified

    def _openings(self, registry):
        if registry is None:
            return []
        found = []
        for store, received in ((self.vault.db.issued, False), (self.vault.db.accepted, True)):
            for (said,), record in store.getTopItemIter():
                grant = record.grant if received else None
                try:
                    found.extend(held_openings(self.vault, said, grant)
                                 if credentialing.credential(self.vault, said, grant=grant)['sad'].get('rd')
                                 == registry else [])
                except (kering.KeriError, ValueError, KeyError, StopIteration):
                    continue
        return found

    def dismiss(self, said):
        """Hide one copy from Activity; the exchange store keeps it."""
        return self.core.dismiss(said)

    def close(self):
        """Stop sending for this session; owed copies stay in the vault database."""
        self.closed = True
