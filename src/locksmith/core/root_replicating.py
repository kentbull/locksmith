"""Registry-root replication to group members over KERIpy's ESSR ``/registry/root``.

Core ``salting.RegistryRoot`` owns the wire, authorization, escrow and
verified retention. Received copies are accepted automatically: core retains a
copy that verifies on arrival and escrows the rest in ``Baser.rrpe``, which the
vault's ``Exchanger.processEscrow`` retries. This adapter is a member of the
Auxiliary operation table: it answers the Dhke ``replicate`` cue and accepted
group rotations by queueing the copies this member owes, sends them from the
run loop through the vault's mailbox ``postman``, and retries escrowed copies
with openings held in local credential proofs.
"""
import time
from dataclasses import dataclass

from keri import help, kering
from keri.acdc.salting import RegistryRoot, RootDeferred, RootRefused, RootUnverified
from keri.app.habbing import GroupHab
from keri.core import Blinder, BlindState, BoundState, Parser, SerderACDC

from locksmith.core import credentialing, ipexing

logger = help.ogler.getLogger(__name__)

Limit = 65536
OpeningRetry = 60.0  # seconds between held-opening retries of one escrowed copy


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
    """One escrowed copy addressed to a local member, waiting for local state."""
    said: str
    sender: str
    recipient: str
    gid: str
    registry: str
    dt: str
    deadline: str
    waiting: str = ''


class RootReplicas:
    """Queue and send registry-root copies for one vault; retry received ones.

    Owed copies persist in the vault database until core ``prepare``
    succeeds or core authorization refuses them, so a copy whose registry
    update or its anchor is not yet accepted here (the custodian derives the
    root before the BUP exists) waits across passes and restarts. A group
    rotation is marked examined only once its owed copies are recorded.
    Received copies need no approval: core retains each verifiable root on
    arrival or from its escrow.
    """

    def __init__(self, owner):
        self.owner = owner
        self.vault = owner.vault
        self.core = RegistryRoot(self.vault.hby, self.vault.rgy, self.vault.notifier)
        self.vault.exc.addHandler(self.core)
        self._rotations = set()  # (gid, rotation) decided in this session.
        self._reported = set()  # rotations and owed copies whose wait is already logged.
        self._retried = {}  # escrowed copy SAID -> monotonic time of its last held-opening retry
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
            if self.vault.db.rootRotations.get(keys=key) is not None:
                self._rotations.add(key)
                continue
            try:
                # Only the rotation's elected witnesser catches newcomers up automatically.
                if self.core.witnesser(hab, est.d):
                    self.catch_up(hab, est.d)
            except kering.KeriError as error:
                # Usually a member KEL that is not yet local; examine it again next pass.
                self._report(key, 'Registry root catch-up for %s rotation %s waits: %s',
                             hab.pre, est.d, error)
                continue
            self._rotations.add(key)  # Decided: owed copies are recorded or none are owed.
            self._reported.discard(key)
        for gid, registry, recipient, td in self.owed():
            self._flush(gid, registry, recipient, td)
        self.retry()

    def _flush(self, gid, registry, recipient, td):
        hab = self.vault.hby.habs.get(gid)
        keys = (gid, registry, recipient)
        if not isinstance(hab, GroupHab) or hab.mhab is None:
            self.vault.db.rootSends.rem(keys=keys)
            return
        try:
            wire = self.core.prepare(hab.mhab, recipient, gid, registry, td=td or None)
        except RootUnverified as error:  # Includes RootDeferred.
            self._report(keys, 'Registry root copy to %s for %s waits: %s', recipient, registry, error)
            return  # The registry update, its anchor or member state is not yet accepted here.
        except kering.ValidationError as error:
            if not isinstance(error, RootRefused) and self._authorized(hab, recipient, gid, registry):
                # Authorized, so the failure is local state still arriving, such as the
                # head update's issuer anchor or this member's own copy of the root.
                self._report(keys, 'Registry root copy to %s for %s waits: %s', recipient, registry, error)
                return
            self._drop(keys, error)
            return
        except (kering.KeriError, ValueError) as error:
            self._drop(keys, error)
            return
        self.post(hab.mhab, recipient, wire)
        self.vault.db.rootSends.rem(keys=keys)
        self._reported.discard(keys)

    def _authorized(self, hab, recipient, gid, registry):
        """True unless core authorization refuses this copy outright."""
        try:
            self.core.authorize(hab.mhab.pre, recipient, gid, registry)
        except RootDeferred:
            return True
        except (kering.KeriError, ValueError):
            return False
        return True

    def _drop(self, keys, error):
        gid, registry, recipient = keys
        logger.warning('Registry root copy to %s for %s refused and dropped: %s', recipient, registry, error)
        self.vault.db.rootSends.rem(keys=keys)
        self._reported.discard(keys)

    def _report(self, key, message, *args):
        """Log a waiting item once per session; it is retried every pass."""
        if key not in self._reported:
            self._reported.add(key)
            logger.info(message, *args)

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
        """Parse a file of copies through the ordinary vault intake and report each outcome.

        Core retains each verifiable root during the parse and escrows the
        rest. Returns ``dict(retained=[...], waiting=[...], refused={said: reason})``.
        """
        ipexing._require_vault(self.vault)
        saids = inspect(raw)
        self.vault.mbx.parser.parse(ims=bytearray(raw), version=kering.Vrsn_2_0)
        stored = [said for said in saids if self.vault.hby.db.exns.get(keys=(said,)) is not None]
        if not stored:
            raise kering.ValidationError('No registry root copy in this file is addressed to this vault')
        for said in stored:
            self._retried.pop(said, None)
        self.retry()
        outcome = dict(retained=[], waiting=[], refused={})
        for said in stored:
            if self.vault.hby.db.rrpe.get(keys=(said,)) is not None:
                outcome['waiting'].append(said)
                continue
            try:  # Not escrowed: either retained now or already, or refused.
                self.core.receive(said)
                outcome['retained'].append(said)
            except (kering.KeriError, ValueError) as error:
                outcome['refused'][said] = str(error)
        return outcome

    def pending(self):
        """Escrowed copies still waiting for local state, with what each still needs."""
        ipexing._require_vault(self.vault)
        items = []
        for item in self.core.pending():
            waiting = 'opening evidence'
            try:
                if item['gid'] != item['recipient'] and not isinstance(
                        self.vault.hby.habs.get(item['gid']), GroupHab):
                    raise RootDeferred('the holder group is not yet local')
                self.core.authorize(item['sender'], item['recipient'], item['gid'], item['registry'])
            except RootDeferred as error:
                waiting = str(error)
            except (kering.KeriError, ValueError):
                pass  # The next escrow attempt refuses and drops this copy.
            items.append(Copy(item['said'], item['sender'], item['recipient'], item['gid'],
                              item['registry'], item['dt'] or '', item['deadline'], waiting))
        return items

    def retry(self):
        """Retry escrowed copies with openings held in local credential proofs.

        Core verifies a copy against the sender's ``td`` hint or a registry
        store opening. A copy sent without either can still verify against an
        opening this vault holds in an issued or accepted credential's proof.
        Each copy is retried at most once per ``OpeningRetry`` seconds.
        """
        if self.closed or self.vault.closed:
            return
        now = time.monotonic()
        for item in self.core.pending():
            said = item['said']
            if now - self._retried.get(said, -OpeningRetry) < OpeningRetry:
                continue
            self._retried[said] = now
            for event, opening in self._openings(item['registry']):
                try:
                    self.core.receive(said, event=event, opening=opening)
                except RootDeferred:
                    break  # Local state is missing; the escrow loop retries.
                except RootUnverified:
                    continue
                except (kering.KeriError, ValueError) as error:
                    logger.info('Registry root copy %s not retained: %s', said, error)
                    break
                break
        escrowed = {said for (said,), _ in self.vault.hby.db.rrpe.getTopItemIter()}
        self._retried = {said: at for said, at in self._retried.items() if said in escrowed}

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

    def close(self):
        """Stop sending for this session; owed copies stay in the vault database."""
        self.closed = True
