"""Ordinary group threshold for one exact admitted-view presentation.

Mirrors KERIpy ``cli/common/grouppresenting.py``: members coordinate through
ordinary ``/multisig/exn`` wrappers parsed by the vault's KRAM-enabled mailbox
parser. A partial proposal has no accepted KRAM lifetime; only threshold intake
assigns ``exchangeDeadline``. One elected lead then sends through the outbox.
"""
from dataclasses import dataclass, field

from keri import kering
from keri.acdc import chaining
from keri.acdc import ipexing as native
from keri.app.grouping import multisigExn
from keri.app.habbing import GroupHab
from keri.core import Parser, Prefixer, SealEvent, messagize
from keri.help import helping
from keri.peer import exchanging

from locksmith.core import credentialing, disclosing, ipexing

V2 = kering.Vrsn_2_0
Route = '/multisig/exn'
Errors = (kering.KeriError, ValueError, KeyError, TypeError, AttributeError, IndexError)


@dataclass
class _Presentation:
    """One exact group Grant matched to this member's own admitted view."""
    hab: object
    grant: object
    proofs: list
    source: str
    paths: tuple
    contributors: set = field(default_factory=set)
    ready: bool = False
    submitted: bool = False
    terminal: str = ''
    error: str = ''

    @property
    def contributed(self):
        return self.hab.mhab.pre in self.contributors


def _hab(vault, aid):
    ipexing._require_vault(vault)
    hab = vault.hby.habByPre(aid)
    if (not isinstance(hab, GroupHab) or not hab.accepted or hab.mhab is None
            or hab.mhab.pre not in hab.db.signingMembers(pre=hab.pre)
            or hab.mhab.kever.fetchLatestContribTo(verfers=hab.kever.verfers) is None):
        raise ValueError('Select a local group with a current signing contribution')
    return hab


def _selection(vault, hab, said, source, paths):
    """Load this member's exact admitted view of the group's own Grant."""
    record = credentialing.admission(vault, said, source)
    original = vault.hby.db.exns.get((source,))
    admit = vault.hby.db.exns.get((record.admit,))
    xid = lambda message: message.said if message.ilk == 'xip' else message.sad['x']
    if (original.pvrsn != V2 or admit.pvrsn != V2
            or original.sad['ri'] != hab.pre or xid(admit) != xid(original)
            or original.sad['a'].get('ax', [False])[0]
            or (terminal := vault.hby.db.erpy.get((source,))) is None
            or terminal.qb64 != admit.said):
        raise ValueError('Select this group\'s exact v2 Grant and accepted Admit')
    selected = exchanging.loadParsedNestedSubstreams(vault.hby, source)
    if selected[0].serder.said != said:
        raise ValueError('Selected admission has a different origin')
    if paths:
        selected[0].serder = disclosing.select(selected[0].serder, paths)
    plan = ipexing._disclosure_plan(said, {node.serder.said: node.serder.sad for node in selected})
    if paths:
        plan[0][0][2] = list(paths)
    return original, selected, plan


def _issued_source(vault, source):
    _, _, verdict, records = vault.exc.reverifyGrant(source)
    if (not (verdict.verdict == chaining.Verdicts.valid
             or verdict.verdict == chaining.Verdicts.unknown and verdict.retryable)
            or any(record.state != 'issued' for record in records.values())):
        raise kering.ValidationError('Presentation requires issued state or retryable unknown current evidence')


def _matches(vault, hab, grant, proofs, *, said, source, paths):
    """Require the exact body and proofs this member would build from its own view."""
    _, selected, plan = _selection(vault, hab, said, source, paths)
    if (grant.pvrsn != V2 or grant.ilk != 'xip' or grant.route != '/ipex/grant'
            or grant.pre != hab.pre or grant.sad.get('p') or grant.sad['q'] != dict(dp=plan)
            or set(grant.sad['a']) != {'m', 'o'} or grant.sad['a']['o'] != [said]
            or proofs != [exchanging.serializeParsedSubstream(node) for node in selected]):
        raise kering.ValidationError('Group presentation differs from this member\'s exact admitted view')


def propose(vault, hab, *, said, source, recipient, message='', paths=()):
    """First member consent: sign, retain and broadcast one exact partial Grant.

    The returned snapshot has no deadline; threshold intake assigns it.
    """
    hab = _hab(vault, hab.pre)
    paths = tuple(paths)
    original, selected, plan = _selection(vault, hab, said, source, paths)
    if recipient not in vault.hby.kevers or recipient == hab.pre:
        raise ValueError('Introduce the selected verifier before presenting')
    _issued_source(vault, original.said)
    ipexing._require_presenter(selected[0].serder, hab.pre, recipient, vault=vault)
    streams = [exchanging.serializeParsedSubstream(node) for node in selected]
    grant, atc = native.grant(hab, recipient, message, origin=streams[0],
        artifacts=streams[1:] or None, modifiers=dict(dp=plan), kind=kering.Kinds.json,
        gvrsn=V2)
    presenters = vault.auxiliary.presenters
    entry = presenters.submit_wrapper(hab, bytes(grant.raw + atc))
    return presenters.snapshot(entry)


class GroupPresenters:
    """Observe retained group presentation wrappers; never a replacement route handler."""

    def __init__(self, owner):
        self.owner, self.vault = owner, owner.vault
        self.entries = {}
        self.ignored = set()

    def _source(self, hab, grant, proofs):
        said = grant.sad['a']['o'][0]
        paths = tuple(grant.sad['q']['dp'][0][0][2])
        for record in credentialing.admissions(self.vault, said):
            try:
                _matches(self.vault, hab, grant, proofs, said=said, source=record.grant, paths=paths)
            except Errors:
                continue
            return record.grant, paths
        raise kering.ValidationError('Group presentation does not match a local admitted view')

    def _read(self, wrapper):
        """Validate one retained wrapper and register its exact Grant."""
        if wrapper.pvrsn != V2 or wrapper.route != Route or not self.vault.exc.complete(wrapper.said):
            raise kering.ValidationError('Select an authenticated v2 group Grant wrapper')
        children = exchanging.loadParsedNestedSubstreams(self.vault.hby, wrapper.said)
        self.vault.mux.validate(wrapper, nests=children)
        child = children[0]
        grant = child.serder
        hab = self.vault.hby.habByPre(wrapper.sad['a']['gid'])
        if (not isinstance(hab, GroupHab) or hab.mhab is None or grant.route != '/ipex/grant'
                or grant.ilk != 'xip' or grant.pre != hab.pre or not child.nests
                or child.nests[0].serder.israid == hab.pre
                or any(value for name, value in vars(child).items()
                       if name not in ('serder', 'tsgs', 'nests', 'local'))):
            raise kering.ValidationError('Wrapper is not a group admitted-view presentation')
        proofs = [exchanging.serializeParsedSubstream(node) for node in child.nests]
        key = (hab.pre, grant.said)
        entry = self.entries.get(key)
        if entry is None:
            source, paths = self._source(hab, grant, proofs)
            entry = _Presentation(hab, grant, proofs, source, paths)
            self.entries[key] = entry
            if not self.vault.exc.complete(grant.said):
                # The wrapper already passed the KRAM-enabled parser and Multiplexor;
                # this scoped child-only pass establishes the partial-signature escrow
                # that KRAM would otherwise drop as a duplicate. It adds no signature.
                Parser(version=V2, kvy=self.vault.hby.kvy, exc=self.vault.exc,
                       rvy=self.vault.hby.rvy, rgy=self.vault.rgy, local=True
                       ).parse(ims=exchanging.serializeParsedSubstream(child), local=True)
        elif entry.grant.raw != grant.raw or entry.proofs != proofs:
            raise kering.ValidationError('Group presentation changed its original disclosure')
        entry.contributors.add(wrapper.pre)
        return entry

    def scan(self):
        for _, wrapper in self.vault.hby.db.exns.getTopItemIter():
            if wrapper.route != Route or wrapper.said in self.ignored:
                continue
            try:
                children = exchanging.loadParsedNestedSubstreams(self.vault.hby, wrapper.said)
                hab = self.vault.hby.habByPre(wrapper.sad['a'].get('gid'))
                if (not isinstance(hab, GroupHab) or len(children) != 1
                        or children[0].serder.route != '/ipex/grant'
                        or not children[0].nests or children[0].nests[0].serder.israid == hab.pre):
                    self.ignored.add(wrapper.said)
                    continue
                self._read(wrapper)
            except Errors:
                continue  # Evidence or this member's admission may still arrive.

    def submit_wrapper(self, hab, signed):
        """Wrap this member's signed Grant, retain it through KRAM and broadcast."""
        wrapper, atc = multisigExn(hab, signed, version=V2)
        self.vault.mbx.parser.parse(ims=bytearray(wrapper.raw + atc), local=True)
        entry = self._read(wrapper)
        for member in hab.db.signingMembers(pre=hab.pre):
            if member != hab.mhab.pre:
                self.vault.postman.send(src=hab.mhab.pre, dest=member, topic='multisig',
                                        serder=wrapper, attachment=atc, stream=True)
        self.progress(entry)
        return entry

    def snapshot(self, entry):
        grant, hab = entry.grant, entry.hab
        deadline = self.vault.exc.exchangeDeadline(grant)
        complete = self.vault.exc.complete(grant.said)
        if entry.terminal:
            phase = entry.terminal
        elif entry.submitted:
            phase = 'submitted'
        elif deadline is not None:
            # Threshold intake alone assigns the accepted KRAM lifetime.
            phase = 'expired' if helping.nowUTC() >= deadline else 'complete'
        elif not complete and self.vault.hby.db.epse.get((grant.said,)) is not None:
            phase = 'awaiting_threshold' if entry.contributed else 'approval_required'
        else:
            phase = 'expired'
        return dict(aid=hab.pre, grant=grant.said, xid=grant.said, kind='presentation', phase=phase,
                    deadline=helping.toIso8601(deadline) if deadline else '', active=not entry.terminal,
                    submitted=entry.submitted, error=entry.error,
                    actions=('approve_presentation',) if phase == 'approval_required' else (),
                    credential=grant.sad['a']['o'][0], sender=hab.pre, recipient=grant.sad['ri'],
                    group=True, member=hab.mhab.pre, contributed=entry.contributed,
                    source=entry.source, proposal=grant.said, detail=dict(grant=grant.sad))

    def contribute(self, hab, grant_said):
        """Explicit member consent to the exact reviewed proposal; never another body."""
        hab = _hab(self.vault, hab.pre)
        self.scan()
        entry = self.entries.get((hab.pre, grant_said))
        if entry is None or self.snapshot(entry)['actions'] != ('approve_presentation',):
            raise kering.ValidationError('Review this exact current group presentation before signing')
        said = entry.grant.sad['a']['o'][0]
        _matches(self.vault, hab, entry.grant, entry.proofs, said=said, source=entry.source, paths=entry.paths)
        _issued_source(self.vault, entry.source)
        signed = hab.endorse(entry.grant, last=False, framed=False, gvrsn=V2, nests=entry.proofs)
        self.submit_wrapper(hab, bytes(signed))
        return self.snapshot(entry)

    @staticmethod
    def _wire(vault, entry):
        """Serialize the exact threshold-authenticated pending Grant and its proofs."""
        grant = entry.grant
        tsgs, cigars = exchanging.verify(vault.hby, grant)
        seals = [SealEvent(i=Prefixer(qb64=keys[1]), s=number, d=diger)
                 for keys, (number, diger) in vault.hby.db.ests.getTopItemIter(keys=(grant.said, ''))]
        return bytes(messagize(grant, tsgs=tsgs or None, cigars=cigars or None,
                               bonds=seals or None, nests=entry.proofs, gvrsn=V2))

    def progress(self, entry):
        """After threshold intake, recheck scope and let only the elected lead deliver.

        An accepted Grant uses the outbox. A Grant authenticated at threshold but
        still awaiting current state openings is a live pending presentation; it
        never enters the outbox and is sent through the Auxiliary live owner.
        """
        if entry.terminal or entry.ready:
            return
        grant = entry.grant
        try:
            complete = self.vault.exc.complete(grant.said)
            deadline = self.vault.exc.exchangeDeadline(grant)
            if deadline is None:
                if complete:
                    raise kering.ValidationError('Accepted group Grant has no authenticated KRAM lifetime')
                return  # Partial: no lifetime exists before threshold intake.
            if helping.nowUTC() >= deadline:
                return
            if not complete and self.owner._presentation(entry.hab, grant.said) is None:
                return
            stored = exchanging.loadParsedNestedSubstreams(self.vault.hby, grant.said)
            if [exchanging.serializeParsedSubstream(node) for node in stored] != entry.proofs:
                raise kering.ValidationError('Threshold Grant differs from the selected proposal proofs')
            _matches(self.vault, entry.hab, grant, entry.proofs, said=grant.sad['a']['o'][0],
                     source=entry.source, paths=entry.paths)
            _issued_source(self.vault, entry.source)
            entry.ready, entry.error = True, ''
            if not self.vault.exc.lead(entry.hab, grant.said, pendingPresentation=not complete):
                return
            if complete:
                stream = exchanging.serializeMessage(self.vault.hby, grant.said)
                ipexing.submit(self.vault, entry.hab, grant, stream[grant.size:])
            else:
                self.owner.deliver_presentation(entry.hab, grant, self._wire(self.vault, entry))
            entry.submitted = True
        except credentialing.RegistryEvidencePending as error:
            entry.error = str(error)
        except Errors as error:
            entry.terminal, entry.error = 'refused', str(error)

    def process(self):
        self.scan()
        for entry in list(self.entries.values()):
            self.progress(entry)

    def clear(self):
        self.entries.clear()
        self.ignored.clear()
