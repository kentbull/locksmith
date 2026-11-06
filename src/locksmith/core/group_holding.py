"""Group-holder setup consent, rootless verification and exact Admit contribution."""
from dataclasses import dataclass, field
from types import SimpleNamespace

from keri import kering
from keri.acdc import regeventing, ipexing as core_ipex
from keri.acdc.dhking import Dhke
from keri.app.grouping import multisigExn, multisigRpyExn
from keri.app.habbing import GroupHab
from keri.core import BlindState, Blinder, Parser, Prefixer, SealEvent, exchange, messagize
from keri.help import helping
from keri.peer import exchanging

from locksmith.core.group_dh import election

V2 = kering.Vrsn_2_0
ProofRoute = '/multisig/ipex-proof'


@dataclass
class _Holder:
    hab: object
    grant: object
    original: list
    coordinator: tuple
    custodian: str
    started: bool = False
    reply: object = None
    reply_signed: bool = False
    pending: list = field(default_factory=list)
    seen: set = field(default_factory=set)
    proof: str = ''
    publication: bytes = b''
    interrupted: bool = False

    @property
    def lead(self):
        return self.hab.mhab.pre == self.custodian

    @property
    def xid(self):
        return self.grant.said if self.grant.ilk == 'xip' else self.grant.sad['x']


class _Replies:
    """Core Multiplexor delegate for DH children of /multisig/rpy; it uses the live owner."""

    def __init__(self, holders):
        self.holders = holders

    def verify(self, serder, attachments=None, nests=None):
        try:
            self.holders.reply_scope(serder, nests)
            return not attachments
        except (kering.KeriError, ValueError, KeyError, TypeError, AttributeError):
            return False

    def handle(self, serder, attachments=None, nests=None):
        entry, child = self.holders.reply_scope(serder, nests)
        if entry.reply is None:
            entry.reply = child
        if serder.said not in entry.seen:
            entry.pending.append(serder.said)


class GroupHolders:
    """One vault dispatcher, borrowing core DH and verification authority."""
    resource = ProofRoute

    def __init__(self, owner):
        self.owner, self.vault = owner, owner.vault
        self.entries = {}
        self.noticed = set()
        # Core registers both wrapper routes; delegate only the children this owner verifies.
        self.vault.mux.addChildHandler('/multisig/rpy', Dhke.Route, _Replies(self))
        self.vault.mux.addChildHandler(ProofRoute, '/ipex/grant', self)

    def candidate(self, hab, grant):
        key = (hab.pre, grant.said)
        if key in self.entries:
            return self.entries[key]
        if (not isinstance(hab, GroupHab) or grant.sad['ri'] != hab.pre
                or self.owner._context(hab, grant.said) is None):
            raise kering.ValidationError('Select this group holder\'s authenticated fresh Grant')
        coordinator, custodian = election(hab)
        entry = _Holder(hab, grant, exchanging.loadParsedNestedSubstreams(self.vault.hby, grant.said),
                        coordinator, custodian)
        # A retained local reply records prior use of ephemeral setup authority.
        for _, wrapper in self.vault.hby.db.exns.getTopItemIter():
            if wrapper.pre != hab.mhab.pre or wrapper.route != '/multisig/rpy':
                continue
            nests = exchanging.loadParsedNestedSubstreams(self.vault.hby, wrapper.said)
            if nests and nests[0].serder.route == Dhke.Route and nests[0].serder.sad['a'].get('x') == entry.xid:
                entry.interrupted = True
                break
        self.entries[key] = entry
        return entry

    def snapshot(self, entry, operation=None):
        grant, hab = entry.grant, entry.hab
        deadline = self.vault.exc.exchangeDeadline(grant)
        phase = operation.phase if operation else ('interrupted' if entry.interrupted else 'approval_required')
        if phase not in self.owner.Terminal and (deadline is None or helping.nowUTC() >= deadline):
            phase = 'expired'
        return dict(aid=hab.pre, grant=grant.said, xid=entry.xid, kind='dh', phase=phase,
            deadline=helping.toIso8601(deadline) if deadline else '', active=operation is not None,
            submitted=operation.submitted if operation else False, error=operation.error if operation else '',
            actions=('approve_dh',) if phase == 'approval_required' else (),
            credential=grant.sad['a']['o'][0], sender=grant.pre, recipient=hab.pre,
            group=True, role='holder', member=hab.mhab.pre, custodian=entry.custodian,
            coordinator=entry.coordinator, contributed=entry.reply_signed,
            stage='reply' if entry.reply is not None else 'grant', proposal=grant.said,
            detail=dict(grant=grant.sad, credential=entry.original[0].serder.sad))

    def check(self, entry):
        operation = self.owner.operations.get((entry.hab.pre, entry.grant.said))
        if self.snapshot(entry, operation)['phase'] in self.owner.Terminal:
            raise kering.ValidationError('The original group setup approval has ended')
        _, custodian = election(entry.hab, entry.coordinator)
        if custodian != entry.custodian:
            raise kering.ValidationError('Frozen group custodian is unavailable')

    def broadcast(self, operation, wire, topic='multisig'):
        for member in operation.hab.db.signingMembers(pre=operation.hab.pre):
            if member != operation.hab.mhab.pre:
                self.owner.outgoing.append(((operation.hab.pre, operation.grant.said), member, bytes(wire), topic))

    def approve(self, hab, said, selected):
        grant = self.vault.exc.pending(said)
        if grant is None or selected != said:
            raise kering.ValidationError('Review the exact pending group-holder Grant')
        entry = self.candidate(hab, grant)
        self.check(entry)
        if entry.started:
            raise kering.ValidationError('This setup already has local consent')
        operation = self.owner._group_operation(entry)
        operation.protocol.approve(said, coordinator=entry.coordinator, custodian=entry.custodian)
        entry.started = True
        if entry.lead:
            tsgs, cigars = exchanging.verify(self.vault.hby, grant)
            raw = messagize(grant, tsgs=tsgs or None, cigars=cigars or None,
                nests=[exchanging.serializeParsedSubstream(node) for node in entry.original], gvrsn=V2)
            self.broadcast(operation, raw, 'credential')
        self.owner._retry_queries(operation)
        self.progress(operation)
        return self.snapshot(entry, operation)

    def peer_query(self, operation, query):
        """Every member authenticates the issuer's unchanged query before replying."""
        if operation.group.lead:
            raw = exchanging.serializeParsedSubstream(dict(serder=query.serder, **query.attachments))
            self.broadcast(operation, raw, 'reply')

    def reply_scope(self, wrapper, nests):
        child = SimpleNamespace(**nests[0]) if isinstance(nests[0], dict) else nests[0]
        body = child.serder
        grant = next((message for message in self.vault.exc.pendingIter()
                      if message.sad.get('ri') == body.pre and
                      (message.said if message.ilk == 'xip' else message.sad.get('x')) == body.sad['a'].get('x')), None)
        hab = self.vault.hby.habByPre(body.pre)
        if grant is None or hab is None:
            raise kering.ValidationError('DH reply has no pending local group Grant')
        entry = self.candidate(hab, grant)
        self.check(entry)
        self.vault.mux.validate(wrapper, nests=nests)
        if (wrapper.pvrsn != V2 or len(nests) != 1 or body.pvrsn != V2 or body.ilk != 'rpy'
                or body.route != Dhke.Route or wrapper.sad['a'] != dict(gid=hab.pre, rpy=body.said)
                or wrapper.pre not in hab.db.signingMembers(pre=hab.pre)
                or any(value for name, value in vars(child).items() if name not in ('serder', 'tsgs', 'local'))
                or entry.reply is None and wrapper.pre != entry.custodian
                or entry.reply is not None and entry.reply.serder.raw != body.raw):
            raise kering.ValidationError('DH reply differs from the frozen holder proposal')
        return entry, child

    def signing(self, operation, raw):
        entry = operation.group
        entry.reply = Parser(version=V2).parseOneBare(ims=bytearray(raw), processive=False)
        entry.reply_signed = True
        self.vault.mbx.parser.parse(ims=bytearray(raw), local=True)
        wrapper, atc = multisigRpyExn(operation.hab, rpy=raw, version=V2)
        self.vault.mbx.parser.parse(ims=bytearray(wrapper.raw + atc), local=True)
        self.broadcast(operation, wrapper.raw + atc)

    def progress(self, operation):
        entry = operation.group
        self.check(entry)
        if not entry.started:
            return
        for said in list(entry.pending):
            if said in entry.seen:
                entry.pending.remove(said)
                continue
            wrapper = self.vault.hby.db.exns.get((said,))
            child = exchanging.loadParsedNestedSubstreams(self.vault.hby, said)[0]
            self.reply_scope(wrapper, [child])
            # The core owner requires the authenticated peer query before contribution.
            if operation.protocol._operations[operation.xid]['peer'] is None:
                continue
            raw = exchanging.serializeParsedSubstream(child)
            if not entry.reply_signed:
                contribution = operation.protocol.contribute(operation.xid, raw)
                self.vault.mbx.parser.parse(ims=bytearray(raw))
                self.signing(operation, contribution)
            else:
                self.vault.mbx.parser.parse(ims=bytearray(raw))
            entry.seen.add(said)
            entry.pending.remove(said)
        if entry.proof:
            self.retry_proof(operation)

    def verify(self, serder, attachments=None, nests=None):
        try:
            entry = self.entries[(serder.sad['a']['gid'], serder.sad['a']['grant'])]
            self.check(entry)
            if (attachments or entry.lead or not entry.started or serder.pvrsn != V2
                    or serder.pre != entry.custodian or len(nests) != 1
                    or serder.sad['a'] != dict(gid=entry.hab.pre, grant=entry.grant.said)):
                return False
            child = SimpleNamespace(**nests[0]) if isinstance(nests[0], dict) else nests[0]
            if child.serder.raw != entry.grant.raw or len(child.nests) != len(entry.original):
                return False
            tsgs, cigars = exchanging.verify(self.vault.hby, entry.grant)
            seals = [SealEvent(i=Prefixer(qb64=keys[1]), s=number, d=diger)
                     for keys, (number, diger) in entry.hab.db.ests.getTopItemIter(keys=(entry.grant.said, ''))]
            original = Parser(version=V2).parseOneBare(ims=messagize(entry.grant,
                tsgs=tsgs or None, cigars=cigars or None, bonds=seals or None, gvrsn=V2), processive=False)
            if exchanging.serializeParsedSubstream(dict(vars(child), nests=[])) != exchanging.serializeParsedSubstream(original):
                return False
            for old, item in zip(entry.original, child.nests):
                node = SimpleNamespace(**item) if isinstance(item, dict) else item
                if (exchanging.serializeParsedSubstream(dict(vars(node), bsqs=old.bsqs, bsss=old.bsss)) !=
                        exchanging.serializeParsedSubstream(old) or node.bsss != old.bsss
                        or len(node.bsqs) != len(old.bsqs) + 1 or node.bsqs[:-1] != old.bsqs):
                    return False
                opening = Blinder(data=BlindState(*node.bsqs[-1]), verify=False)
                if opening.acdc != node.serder.said or opening.state != 'issued':
                    return False
            return True
        except (kering.KeriError, ValueError, KeyError, TypeError, AttributeError):
            return False

    def handle(self, serder, attachments=None, nests=None):
        self.entries[(serder.sad['a']['gid'], serder.sad['a']['grant'])].proof = serder.said

    def retry_proof(self, operation):
        entry = operation.group
        wrapper = self.vault.hby.db.exns.get((entry.proof,))
        child = exchanging.loadParsedNestedSubstreams(self.vault.hby, entry.proof)[0]
        if not self.verify(wrapper, nests=[child]):
            raise kering.ValidationError('Holder proof changed the approved issuer disclosure')
        for node in child.nests:
            regid = node.serder.regid
            head = self.vault.rgy.store.headEvent(regid)
            opening = Blinder(data=BlindState(*node.bsqs[-1]), verify=False)
            if head is None or head.ilk != 'bup' or head.sad['b'] != opening.said:
                return
            state = regeventing.vetBinds(self.vault.rgy.store.seqEvent(regid, 0),
                [self.vault.rgy.store.seqEvent(regid, sn) for sn in range(1, head.sn + 1)],
                db=entry.hab.db, blinders=[Blinder(data=BlindState(*data), verify=False) for data in node.bsqs],
                target=node.serder.said, acdc=node.serder)
            regeventing.vetAnchor(head, db=entry.hab.db, issuer=entry.grant.pre)
            if state.said != head.said or state.state != 'issued':
                raise kering.ValidationError('Holder proof does not verify the current issued head')
        deadline = self.vault.exc.exchangeDeadline(entry.grant)
        if deadline is None or helping.nowUTC() >= deadline:
            raise kering.ValidationError('The original group Grant deadline has ended')
        protected = Parser(version=V2, kvy=self.vault.hby.kvy, exc=self.vault.exc,
                           rvy=self.vault.hby.rvy, rgy=self.vault.rgy, local=True)
        protected.parse(ims=exchanging.serializeParsedSubstream(child), local=True)
        if self.vault.exc.exchangeDeadline(entry.grant) != deadline:
            raise kering.ValidationError('Holder proof changed the original Grant deadline')
        from locksmith.core import ipexing
        ipexing._validate_grant_graph(self.vault, entry.grant.said)
        entry.proof = ''

    def publish(self, operation):
        entry = operation.group
        if not entry.lead or entry.publication:
            return
        child = Parser(version=V2).parseOneBare(
            ims=exchanging.serializeMessage(self.vault.hby, entry.grant.said), processive=False)
        wrapper = exchange(sender=entry.hab.mhab.pre, route=ProofRoute,
            attributes=dict(gid=entry.hab.pre, grant=entry.grant.said),
            version=V2, gvrsn=V2, kind=kering.Kinds.json)
        entry.publication = bytes(entry.hab.mhab.endorse(wrapper, framed=False, gvrsn=V2,
            nests=[exchanging.serializeParsedSubstream(child)]))
        self.broadcast(operation, entry.publication)

    def reconcile(self):
        """Observe retained exact Admit proposals and finish previously recorded consent."""
        from locksmith.core import ipexing
        for _, wrapper in self.vault.hby.db.exns.getTopItemIter():
            if wrapper.route != '/multisig/exn' or wrapper.said in self.noticed:
                continue
            hab = self.vault.hby.habByPre(wrapper.sad['a'].get('gid'))
            if not isinstance(hab, GroupHab):
                continue
            children = exchanging.loadParsedNestedSubstreams(self.vault.hby, wrapper.said)
            if not children or children[0].serder.route != '/ipex/admit':
                continue
            grant = children[0].serder.sad.get('p')
            try:
                selected = admit_proposal(self.vault, hab, grant)
                if selected is None or selected.said != children[0].serder.said:
                    continue
            except (ValueError, kering.KeriError):
                continue
            self.noticed.add(wrapper.said)
            self.vault.signals.emit_doer_event('Ipex', 'group_admit_proposed',
                dict(grant=grant, aid=hab.pre, said=selected.said))
        for keys, receipt in list(self.vault.db.receipts.getTopItemIter()):
            if receipt.status != 'preparing' or not isinstance(self.vault.hby.habByPre(keys[0]), GroupHab):
                continue
            try:
                ipexing._finish_receipt(self.vault, *keys, receipt)
            except (ValueError, kering.KeriError) as error:
                receipt.status, receipt.error = 'interrupted', str(error)
                self.vault.db.receipts.pin(keys, receipt)
            else:
                if receipt.status == 'accepted':
                    self.vault.signals.emit_doer_event('Ipex', 'accepted', {'said': receipt.admit})


def admit_proposal(vault, hab, grant_said):
    """Read one retained group Admit body; this never creates or signs an acknowledgment."""
    grant = vault.hby.db.exns.get((grant_said,))
    if not isinstance(hab, GroupHab) or grant is None or grant.sad['ri'] != hab.pre:
        return None
    receipt = vault.db.receipts.get((hab.pre, grant_said))
    selected = receipt.admit if receipt else ''
    completed = vault.exc.response(grant_said)
    if completed is not None and completed.route == '/ipex/admit':
        if selected and selected != completed.said:
            raise kering.ValidationError('The terminal Admit differs from local acceptance consent')
        return completed
    entry = vault.auxiliary.holders.entries.get((hab.pre, grant_said))
    opening = vault.auxiliary.openings.entries.get((hab.pre, grant_said))
    proposer = opening.proposer if opening else entry.custodian if entry else None
    proposals = {}
    for _, wrapper in vault.hby.db.exns.getTopItemIter():
        if (wrapper.route != '/multisig/exn' or wrapper.pvrsn != V2
                or wrapper.sad['a'].get('gid') != hab.pre
                or wrapper.pre not in hab.db.signingMembers(pre=hab.pre)
                or (not selected and proposer is not None and wrapper.pre != proposer)):
            continue
        children = exchanging.loadParsedNestedSubstreams(vault.hby, wrapper.said)
        if len(children) != 1:
            continue
        child = children[0]
        body = child.serder
        if (body.route != '/ipex/admit' or body.pre != hab.pre or body.sad.get('p') != grant_said
                or body.sad.get('x') != (grant.said if grant.ilk == 'xip' else grant.sad['x'])
                or body.sad['ri'] != grant.pre or selected and selected != body.said):
            continue
        vault.mux.validate(wrapper, nests=children)
        if any(value for name, value in vars(child).items() if name not in ('serder', 'tsgs', 'local')):
            raise kering.ValidationError('Group Admit proposal carries unexpected attachments')
        proposals[body.said] = body
    if len(proposals) > 1:
        raise kering.ValidationError('Conflicting group Admit proposals require review')
    return next(iter(proposals.values()), None)


def pending_admit(vault, hab, grant_said, receipt):
    """Return an exact retained partial acknowledgment without claiming acceptance."""
    body = admit_proposal(vault, hab, grant_said)
    if body is None or body.said != receipt.admit:
        raise kering.ValidationError('The consented group Admit proposal is unavailable')
    for diger in vault.hby.db.meids.get((body.said,)):
        child = exchanging.loadParsedNestedSubstreams(vault.hby, diger.qb64)[0]
        # Return the ordinary top-level form used by the existing UI API.
        raw = messagize(body, tsgs=child.tsgs, gvrsn=V2)
        return body, raw[body.size:]
    raise kering.ValidationError('The consented group Admit has no retained member contribution')


def contribute_admit(vault, hab, grant, message, send, selected):
    """One acceptance click creates or endorses exactly one ordinary group Admit."""
    from locksmith.core import ipexing
    from locksmith.db.basing import GrantReceipt
    response = vault.exc.response(grant.said)
    if response is not None:
        if response.route != '/ipex/admit':
            raise kering.ValidationError('This Grant already has a terminal reply and cannot be accepted')
    receipt = vault.db.receipts.get((hab.pre, grant.said))
    if receipt is not None:
        if selected is not None and receipt.admit != selected:
            raise kering.ValidationError('This acceptance already selected another exact Admit')
        if send and not receipt.send:
            receipt.send = True
            vault.db.receipts.pin((hab.pre, grant.said), receipt)
        return ipexing._finish_receipt(vault, hab.pre, grant.said, receipt)
    credential = ipexing.grant_credential(vault, grant.said)
    ipexing._validate_credential(vault, credential, grant.said)
    if error := ipexing.expiry_error(vault, grant):
        raise kering.ValidationError(error)
    body = admit_proposal(vault, hab, grant.said)
    if body is None:
        entry = vault.auxiliary.holders.entries.get((hab.pre, grant.said))
        opening = vault.auxiliary.openings.entries.get((hab.pre, grant.said))
        proposer = opening.proposer if opening else entry.custodian if entry else None
        if (selected is not None or hab.mhab.pre not in hab.db.signingMembers(pre=hab.pre)
                or proposer is not None and hab.mhab.pre != proposer):
            raise kering.ValidationError('Wait for and review the selected member\'s exact Admit proposal')
        body, atc = core_ipex.admit(hab, message, grant, kind=kering.Kinds.json, gvrsn=V2)
        raw = body.raw + atc
    else:
        if selected != body.said:
            raise kering.ValidationError('Review this exact Admit proposal before contributing')
        raw = hab.endorse(body, last=False, framed=False, gvrsn=V2)
    receipt = GrantReceipt(credential=credential.said,
                           admit=body.said, send=send)
    vault.db.receipts.put((hab.pre, grant.said), receipt)
    wrapper, atc = multisigExn(hab, raw, version=V2)
    vault.mbx.parser.parse(ims=bytearray(wrapper.raw + atc), local=True)
    for member in vault.hby.db.signingMembers(pre=hab.pre):
        if member != hab.mhab.pre:
            vault.postman.send(src=hab.mhab.pre, dest=member, topic='multisig',
                               serder=wrapper, attachment=atc, stream=True)
    vault.signals.emit_doer_event('Ipex', 'group_admit_proposed',
                                 dict(grant=grant.said, aid=hab.pre, said=body.said))
    result = ipexing._finish_receipt(vault, hab.pre, grant.said, receipt)
    if receipt.status != 'accepted':
        vault.signals.emit_doer_event('Ipex', 'awaiting_group', {'said': body.said})
    return result
