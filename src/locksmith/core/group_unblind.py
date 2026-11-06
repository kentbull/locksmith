"""Member consent and ordinary threshold coordination for v2 Unblind."""
from dataclasses import dataclass, field
from types import SimpleNamespace

from keri import kering
from keri.acdc.unblinding import Unblind
from keri.app.habbing import GroupHab
from keri.app.grouping import multisigRpyExn
from keri.core import BlindState, BoundState, Parser, Prefixer, SealEvent, exchange, messagize
from keri.help import helping
from keri.peer import exchanging

V2 = kering.Vrsn_2_0


@dataclass
class _Opening:
    hab: object
    grant: object
    proposer: str
    deadline: str
    started: bool = True
    frozen: bytes = b''
    contributed: bool = False
    finished: bool = False
    forwarded: set = field(default_factory=set)
    sent: set = field(default_factory=set)
    publication: bytes = b''

    @property
    def requester(self):
        return self.hab.pre == self.grant.sad['ri']

    @property
    def author(self):
        return self.hab.mhab.pre == self.proposer


class _Wrappers:
    """Core Multiplexor delegate for Unblind children of /multisig/qry and /multisig/rpy."""
    def __init__(self, owner):
        self.owner = owner

    def verify(self, serder, attachments=None, nests=None):
        try:
            self.owner.scope(serder, nests)
            return not attachments
        except (kering.KeriError, ValueError, KeyError, TypeError, AttributeError):
            return False

    def handle(self, serder, attachments=None, nests=None):
        hab, grant, child = self.owner.scope(serder, nests)
        # Intake records public member proposals only. No Unblind approval or signature.
        self.owner.pending.setdefault((hab.pre, grant.said), {})[serder.said] = (serder, child)


class GroupOpenings:
    def __init__(self, owner):
        self.owner, self.vault = owner, owner.vault
        self.entries, self.pending = {}, {}
        delegate = _Wrappers(self)
        for route in ('/multisig/qry', '/multisig/rpy'):
            self.vault.mux.addChildHandler(route, Unblind.Route, delegate)

    def scope(self, wrapper, nests):
        if wrapper.pvrsn != V2 or len(nests or []) != 1:
            raise kering.ValidationError('Expected one v2 group opening proposal')
        child = SimpleNamespace(**nests[0]) if isinstance(nests[0], dict) else nests[0]
        body = child.serder
        hab = self.vault.hby.habByPre(body.pre)
        kind = wrapper.route.rsplit('/', 1)[-1]
        data = body.sad.get('q' if kind == 'qry' else 'a', {})
        if (kind not in ('qry', 'rpy') or body.ilk != kind or body.pvrsn != V2
                or body.route != Unblind.Route or not isinstance(hab, GroupHab)
                or not hab.accepted or hab.mhab is None
                or wrapper.pre not in hab.db.signingMembers(pre=hab.pre)
                or wrapper.sad['a'] != dict(gid=hab.pre, **{kind: body.said})):
            raise kering.ValidationError('Opening wrapper does not match its group member and child')
        allowed = ('serder', 'tsgs', 'lsgs', 'nests', 'local') if kind == 'qry' else (
            'serder', 'tsgs', 'bsqs', 'bsss', 'local')
        if any(value for key, value in vars(child).items() if key not in allowed):
            raise kering.ValidationError('Opening proposal carries unexpected attachments')
        grants = {}
        for store in (hab.db.exns, hab.db.epse):
            for _, grant in store.getTopItemIter():
                xid = grant.said if grant.ilk == 'xip' else grant.sad.get('x')
                if (grant.route == '/ipex/grant' and xid == data.get('x')
                        and hab.pre == (grant.sad['ri'] if kind == 'qry' else grant.pre)
                        and self.owner._presentation(hab, grant.said)):
                    grants[grant.said] = grant
        if len(grants) != 1:
            raise kering.ValidationError('Opening proposal has no exact live group presentation')
        grant = next(iter(grants.values()))
        deadline = self.vault.exc.exchangeDeadline(grant)
        if deadline is None or helping.nowUTC() >= deadline:
            raise kering.ValidationError('The original Grant deadline has elapsed')
        return hab, grant, child

    def check(self, entry):
        deadline = self.vault.exc.exchangeDeadline(entry.grant)
        if (deadline is None or helping.toIso8601(deadline) != entry.deadline or helping.nowUTC() >= deadline
                or entry.proposer not in entry.hab.db.signingMembers(pre=entry.hab.pre)):
            raise kering.ValidationError('The original group opening scope has ended')
        operation = self.owner.operations[(entry.hab.pre, entry.grant.said)]
        if operation.phase in self.owner.Terminal:
            raise kering.ValidationError('This group opening consent has ended')
        operation.protocol.complete(operation.xid)

    def snapshot(self, entry, operation):
        status = self.owner._snapshot(entry.hab, entry.grant, operation.xid, operation, group=False)
        status.update(group=True, member=entry.hab.mhab.pre, proposer=entry.proposer,
                      contributed=entry.contributed, detail=entry.grant.sad)
        return status

    def approve(self, hab, grant, *, proposer, requester):
        from locksmith.core.auxiliary import _Operation
        if (not hab.accepted or hab.mhab is None
                or hab.mhab.pre not in hab.db.signingMembers(pre=hab.pre)
                or proposer not in hab.db.signingMembers(pre=hab.pre)):
            raise kering.ValidationError('Select an accepted group signing member as proposer')
        key = (hab.pre, grant.said)
        existing = self.owner.operations.get(key)
        if existing is not None and (existing.group is not None or existing.phase in self.owner.Terminal):
            raise kering.ValidationError('This group opening consent has already started or ended')
        if hab.pre != (grant.sad['ri'] if requester else grant.pre):
            raise kering.ValidationError('Wrong group role for this opening consent')
        deadline = self.vault.exc.exchangeDeadline(grant)
        if deadline is None or helping.nowUTC() >= deadline:
            raise kering.ValidationError('The original Grant deadline has elapsed')
        protocol = self.owner._owner(hab, 'unblind')
        xid = protocol.approve(grant.said)
        entry = _Opening(hab, grant, proposer, helping.toIso8601(deadline))
        operation = existing or _Operation(hab, grant, xid, protocol, kind='unblind')
        operation.group, operation.release_approved = entry, True
        self.entries[key] = entry
        self.owner.operations[key] = operation
        self.owner._changed(operation, 'waiting')
        if entry.author:
            tsgs, cigars = exchanging.verify(self.vault.hby, grant)
            seals = [SealEvent(i=Prefixer(qb64=keys[1]), s=number, d=diger)
                     for keys, (number, diger) in hab.db.ests.getTopItemIter(keys=(grant.said, ''))]
            raw = messagize(grant, tsgs=tsgs or None, cigars=cigars or None,
                bonds=seals or None, nests=[exchanging.serializeParsedSubstream(node)
                    for node in exchanging.loadParsedNestedSubstreams(self.vault.hby, grant.said)], gvrsn=V2)
            self.broadcast(operation, raw, 'credential')
            if requester:
                protocol.start(grant.said)
        self.owner._retry_queries(operation)
        try:
            self.progress(operation)
            self.owner._drain(operation)
        except (kering.MissingOpeningError, kering.MissingChainError,
                kering.MissingAnchorError, kering.MissingSchemaError) as error:
            self.owner._changed(operation, 'waiting', str(error))
        return self.snapshot(entry, operation)

    def broadcast(self, operation, wire, topic='multisig'):
        for member in operation.hab.db.signingMembers(pre=operation.hab.pre):
            if member != operation.hab.mhab.pre:
                self.owner.outgoing.append(((operation.hab.pre, operation.grant.said), member, bytes(wire), topic))

    def peer_query(self, operation, query):
        entry = operation.group
        if query.serder.said not in entry.forwarded:
            entry.forwarded.add(query.serder.said)
            self.broadcast(operation, exchanging.serializeParsedSubstream(
                dict(serder=query.serder, **query.attachments)), 'reply')

    def signing(self, operation, raw):
        entry = operation.group
        child = Parser(version=V2).parseOneBare(ims=bytearray(raw), processive=False)
        entry.frozen, entry.contributed = child.serder.raw, True
        if child.serder.ilk == 'qry':
            wrapper = exchange(sender=entry.hab.mhab.pre, route='/multisig/qry',
                attributes=dict(gid=entry.hab.pre, qry=child.serder.said),
                version=V2, gvrsn=V2, kind=kering.Kinds.json)
            wire = entry.hab.mhab.endorse(wrapper, framed=False, gvrsn=V2,
                nests=[exchanging.serializeParsedSubstream(child)])
        else:
            raw = messagize(child.serder, tsgs=child.tsgs,
                bonds=[*(BlindState(*value) for value in child.bsqs),
                       *(BoundState(*value) for value in child.bsss)], gvrsn=V2)
            wrapper, atc = multisigRpyExn(entry.hab, raw, version=V2)
            wire = wrapper.raw + atc
        self.vault.mbx.parser.parse(ims=bytearray(raw), local=True)
        self.broadcast(operation, wire)

    def progress(self, operation):
        entry, protocol = operation.group, operation.protocol
        self.check(entry)
        requested = protocol._operations[operation.xid]['requestedByPeer']
        if not entry.requester and entry.author and requested and not entry.contributed:
            protocol.respond(operation.xid)
            self.owner._drain(operation)
        pending = self.pending.get((entry.hab.pre, entry.grant.said), {})
        for said, (wrapper, child) in list(pending.items()):
            if not entry.frozen and wrapper.pre != entry.proposer:
                continue
            if not entry.requester and not requested:
                continue
            self.scope(wrapper, [child])
            if entry.frozen and entry.frozen != child.serder.raw:
                del pending[said]
                continue
            raw = exchanging.serializeParsedSubstream(child)
            contribution = protocol.contribute(operation.xid, raw)
            self.vault.mbx.parser.parse(ims=bytearray(raw))
            if not entry.contributed:
                self.signing(operation, contribution)
            del pending[said]
        self.owner._drain(operation)
        if not entry.requester and protocol.complete(operation.xid) and not entry.finished:
            protocol.finish(operation.xid)
            entry.finished = True
            self.owner._changed(operation, 'answered')
