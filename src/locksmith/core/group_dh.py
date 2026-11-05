"""Exact member consent for fresh group-issuer DH over the vault's native owners."""
from dataclasses import dataclass

from keri import kering
from keri.acdc import regeventing
from keri.acdc.dhking import Dhke
from keri.app.grouping import multisigExn
from keri.app.habbing import GroupHab, _groupWitnesserSelection
from keri.core import Parser, SealSource, exchange, messagize
from keri.help import helping
from keri.peer import exchanging

V2 = kering.Vrsn_2_0


def election(hab, coordinator=None):
    """Resolve core's existing accepted-event selection to its current member."""
    if not isinstance(hab, GroupHab) or not hab.accepted or hab.mhab is None:
        raise ValueError('Select an accepted local group signer')
    coordinator = coordinator or (hab.kever.sn, hab.kever.serder.said)
    selected = _groupWitnesserSelection(hab, sn=coordinator[0], dig=coordinator[1])
    if selected is None:
        raise kering.ValidationError('Group coordinator requires accepted threshold evidence')
    establishment, index = selected
    for member in hab.db.signingMembers(pre=hab.pre):
        kever = hab.db.kevers.get(member)
        contribution = kever.fetchLatestContribTo(verfers=establishment.verfers) if kever else None
        if contribution is not None and contribution[1] == index:
            return coordinator, member
    raise kering.ValidationError('The elected custodian is no longer a group signing member')


@dataclass
class _Proposal:
    hab: object
    grant: object
    child: object
    coordinator: tuple
    custodian: str
    approved: bool = False
    started: bool = False
    query: object = None
    query_signed: bool = False
    publication: bytes = b''
    interrupted: bool = False
    query_sent: bool = False

    @property
    def lead(self):
        return self.hab.mhab.pre == self.custodian


class GroupIssuers:
    """One shared query route; ordinary Multiplexor retains Grant proposals."""

    resource = '/multisig/qry'

    def __init__(self, owner):
        self.owner, self.vault = owner, owner.vault
        self.proposals = {}
        self.seen = set()
        self.vault.exc.addHandler(self)

    def _read(self, wrapper, *, authored=False):
        if (wrapper.pvrsn != V2 or wrapper.route != '/multisig/exn'
                or not self.vault.exc.complete(wrapper.said)):
            raise kering.ValidationError('Select an authenticated native group Grant wrapper')
        children = exchanging.loadParsedNestedSubstreams(self.vault.hby, wrapper.said)
        self.vault.mux.validate(wrapper, nests=children)
        child = children[0]
        grant = child.serder
        hab = self.vault.hby.habByPre(wrapper.sad['a']['gid'])
        if (not isinstance(hab, GroupHab) or not hab.accepted or hab.mhab is None
                or grant.route != '/ipex/grant' or grant.ilk != 'xip'
                or hab.mhab.pre not in hab.db.signingMembers(pre=hab.pre)
                or len(child.nests) != 1 or any(value for name, value in vars(child).items()
                    if name not in ('serder', 'tsgs', 'nests', 'local'))):
            raise kering.ValidationError('Select one fresh group issuance Grant')
        node = child.nests[0]
        body = node.serder
        if (body.pvrsn != V2 or body.ilk not in ('acm', 'act', 'acg') or not body.verify()
                or body.israid != hab.pre or body.iseaid != grant.sad['ri']
                or any(value for name, value in vars(node).items() if name not in ('serder', 'local'))
                or set(grant.sad['a']) != {'m', 'o'} or grant.sad['a']['o'] != [body.said]):
            raise kering.ValidationError('Grant requires this group issuer and exact proofless credential')
        key = (hab.pre, grant.said)
        if key in self.proposals:
            proposal = self.proposals[key]
            if (proposal.grant.raw != grant.raw or
                    exchanging.serializeParsedSubstream(proposal.child.nests[0]) !=
                    exchanging.serializeParsedSubstream(node)):
                raise kering.ValidationError('Group issuance proposal changed its original disclosure')
            return proposal
        rip = self.vault.rgy.store.headEvent(body.regid)
        if rip is None or rip.ilk != 'rip':
            raise kering.ValidationError('Group agreement requires a fresh accepted registry')
        coordinator = regeventing.vetAnchor(rip, db=hab.db, issuer=hab.pre)
        coordinator, custodian = election(hab, coordinator)
        if wrapper.pre != custodian:
            raise kering.ValidationError('The elected issuer custodian must propose this Grant')
        proposal = _Proposal(hab, grant, child, coordinator, custodian)
        proposal.interrupted = not authored and any(
            member.qb64 == hab.mhab.pre for member in hab.db.maids.get((grant.said,)))
        self.proposals[key] = proposal
        # Establish native partial-signature escrow and its put-only deadline.
        # Parsing public evidence contributes no local signature or DH approval.
        protected = Parser(version=V2, kvy=self.vault.hby.kvy, exc=self.vault.exc,
            rvy=self.vault.hby.rvy, rgy=self.vault.rgy, local=True)
        protected.parse(ims=exchanging.serializeParsedSubstream(child), local=True)
        return proposal

    def scan(self):
        for _, note in self.vault.notifier.noter.notes.getTopItemIter():
            said = note.attrs.get('d')
            if note.attrs.get('r') != '/multisig/exn' or said in self.seen:
                continue
            wrapper = self.vault.hby.db.exns.get((said,))
            if wrapper is None or not self.vault.exc.complete(said):
                continue
            try:
                self._read(wrapper)
            except (kering.KeriError, ValueError, KeyError, TypeError, AttributeError):
                continue
            self.seen.add(said)

    def partial(self, grant):
        """Whether an issuer proposal still awaits threshold intake.

        Core assigns the accepted KRAM lifetime only at threshold intake and
        bounds the partial escrow until then. DH work still requires the
        accepted deadline through pendingGrant and Dhke.
        """
        return (self.vault.exc.exchangeDeadline(grant) is None
                and self.vault.hby.db.epse.get((grant.said,)) is not None)

    def snapshot(self, proposal, operation=None):
        grant, hab = proposal.grant, proposal.hab
        deadline = self.vault.exc.exchangeDeadline(grant)
        phase = operation.phase if operation else ('interrupted' if proposal.interrupted else 'approval_required')
        stage = 'query' if proposal.approved and proposal.query is not None else 'grant'
        selected = proposal.query.serder if stage == 'query' else grant
        if phase not in self.owner.Terminal:
            phase = 'waiting' if proposal.approved else 'approval_required'
            if deadline is None and not self.partial(grant) or deadline is not None and helping.nowUTC() >= deadline:
                phase = 'expired'
        return dict(aid=hab.pre, grant=grant.said, xid=grant.said, kind='dh', phase=phase,
            deadline=helping.toIso8601(deadline) if deadline else '', active=operation is not None,
            submitted=operation.submitted if operation else False,
            error=operation.error if operation else '',
            actions=('approve_dh',) if phase == 'approval_required' else (),
            credential=grant.sad['a']['o'][0], sender=grant.pre, recipient=grant.sad['ri'],
            group=True, member=hab.mhab.pre, custodian=proposal.custodian,
            coordinator=proposal.coordinator, contributed=proposal.query_signed, stage=stage,
            proposal=selected.said, detail=(selected.sad if stage == 'query' else
                dict(grant=grant.sad, credential=proposal.child.nests[0].serder.sad)))

    def _live(self, proposal):
        status = self.snapshot(proposal, self.owner.operations.get((proposal.hab.pre, proposal.grant.said)))
        if status['phase'] in self.owner.Terminal:
            raise kering.ValidationError('The original group issuance approval has ended')
        coordinator, custodian = election(proposal.hab, proposal.coordinator)
        if custodian != proposal.custodian:
            raise kering.ValidationError('The frozen group custodian is unavailable')

    def _broadcast(self, operation, wire):
        for member in operation.hab.db.signingMembers(pre=operation.hab.pre):
            if member != operation.hab.mhab.pre:
                self.owner.outgoing.append(((operation.hab.pre, operation.grant.said), member, wire, 'multisig'))

    def begin(self, hab, grant, attachment):
        wrapper, atc = multisigExn(hab, grant.raw + attachment, version=V2)
        self.vault.mbx.parser.parse(ims=bytearray(wrapper.raw + atc), local=True)
        proposal = self._read(wrapper, authored=True)
        if not proposal.lead:
            raise kering.ValidationError('Only the elected issuer custodian starts derived issuance')
        proposal.approved = True
        operation = self.owner._group_operation(proposal)
        self._broadcast(operation, bytes(wrapper.raw + atc))
        self.progress(operation)
        return self.snapshot(proposal, operation)

    def approve(self, hab, said, selected):
        self.scan()
        proposal = self.proposals[(hab.pre, said)]
        self._live(proposal)
        operation = self.owner.operations.get((hab.pre, said))
        status = self.snapshot(proposal, operation)
        if status['actions'] != ('approve_dh',) or status['proposal'] != selected:
            raise kering.ValidationError('Review this exact current group proposal before signing')
        signed = hab.endorse(proposal.grant, last=False, framed=False, gvrsn=V2,
            nests=[exchanging.serializeParsedSubstream(node) for node in proposal.child.nests])
        wrapper, atc = multisigExn(hab, signed, version=V2)
        proposal.approved = True
        operation = self.owner._group_operation(proposal)
        self.vault.mbx.parser.parse(ims=bytearray(wrapper.raw + atc), local=True)
        self._broadcast(operation, bytes(wrapper.raw + atc))
        self.progress(operation)
        return self.snapshot(proposal, operation)

    def broadcast_query(self, operation, raw):
        proposal = operation.group
        child = Parser(version=V2).parseOneBare(ims=bytearray(raw), processive=False)
        if proposal.query is not None and proposal.query.serder.raw != child.serder.raw:
            raise kering.ValidationError('DH query differs from the exact approved proposal')
        proposal.query = child
        wrapper = exchange(sender=operation.hab.mhab.pre, route=self.resource,
            attributes=dict(gid=operation.hab.pre, qry=child.serder.said),
            version=V2, gvrsn=V2, kind=kering.Kinds.json)
        wire = operation.hab.mhab.endorse(wrapper, framed=False, gvrsn=V2,
            nests=[exchanging.serializeParsedSubstream(child)])
        self.vault.mbx.parser.parse(ims=bytearray(raw), local=True)
        self._broadcast(operation, bytes(wire))

    def verify(self, serder, attachments=None, nests=None):
        try:
            self.scan()
            child = nests[0]
            if isinstance(child, dict):
                from types import SimpleNamespace
                child = SimpleNamespace(**child)
            body = child.serder
            proposal = self.proposals[(body.pre, body.sad['q']['x'])]
            self._live(proposal)
            return (not attachments and len(nests) == 1 and serder.pvrsn == V2
                and serder.pre in proposal.hab.db.signingMembers(pre=proposal.hab.pre)
                and serder.sad['a'] == dict(gid=body.pre, qry=body.said)
                and body.pvrsn == V2 and body.ilk == 'qry' and body.route == Dhke.Route
                and body.sad.get('rr') == body.route
                and (proposal.query is not None and proposal.query.serder.raw == body.raw
                     or proposal.query is None and serder.pre == proposal.custodian)
                and not any(value for key, value in vars(child).items()
                    if key not in ('serder', 'tsgs', 'lsgs', 'local')))
        except (kering.KeriError, ValueError, KeyError, TypeError, AttributeError, IndexError):
            return False

    def handle(self, serder, attachments=None, nests=None):
        child = exchanging.loadParsedNestedSubstreams(self.vault.hby, serder.said)[0]
        proposal = self.proposals[(child.serder.pre, child.serder.sad['q']['x'])]
        if proposal.query is None:
            proposal.query = child
        if proposal.query_signed:
            self.vault.mbx.parser.parse(ims=exchanging.serializeParsedSubstream(child))

    def progress(self, operation):
        proposal = operation.group
        self._live(proposal)
        if not proposal.started:
            if self.owner._context(operation.hab, operation.grant.said) is None:
                return
            operation.protocol.approve(operation.grant.said,
                coordinator=proposal.coordinator, custodian=proposal.custodian)
            proposal.started = True
            if proposal.lead:
                tsgs, cigars = exchanging.verify(self.vault.hby, operation.grant)
                raw = messagize(operation.grant, tsgs=tsgs or None, cigars=cigars or None,
                    nests=[exchanging.serializeParsedSubstream(node) for node in proposal.child.nests], gvrsn=V2)
                self.owner.outgoing.append(((operation.hab.pre, operation.grant.said),
                    operation.grant.sad['ri'], bytes(raw), 'credential'))
                proposal.query_signed = True
                self.broadcast_query(operation, operation.protocol.start(operation.grant.said))
        if proposal.query is not None and not proposal.query_signed:
            # Setup consent covers this contribution. Dhke checks the frozen scope,
            # original deadline and custodian signature before signing exact bytes.
            raw = exchanging.serializeParsedSubstream(proposal.query)
            contribution = operation.protocol.contribute(operation.xid, raw)
            proposal.query_signed = True
            self.vault.mbx.parser.parse(ims=bytearray(raw))
            self.broadcast_query(operation, contribution)

    def publish(self, operation):
        """Deliver accepted public BUP evidence so the individual holder can finish."""
        proposal = operation.group
        if not proposal.lead or proposal.publication:
            return
        registry = proposal.child.nests[0].serder.regid
        event = self.vault.rgy.store.headEvent(registry)
        sn, said = regeventing.vetAnchor(event, db=operation.hab.db, issuer=operation.hab.pre)
        proposal.publication = bytes(messagize(event,
            bonds=[SealSource(s=f'{sn:x}', d=said)], gvrsn=V2))
        self.owner.outgoing.append(((operation.hab.pre, operation.grant.said),
            operation.grant.sad['ri'], proposal.publication, 'credential'))
