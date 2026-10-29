"""Explicit registry creation and encrypted salt sharing using existing vault owners.

Local R&D application policy composes KERIpy's normal registry approval, reply
signature verification, ESSR encryption, and finite StreamPoster transport.
There is no assignment protocol or retained delivery/receipt machinery.
"""
from hio.base import doing
from keri import kering
from keri.acdc import Registrar
from keri.app.acdc_v2_grouping import RegistryApproval
from keri.app.essring import envelope
from keri.app.forwarding import StreamPoster
from keri.app.habbing import GroupHab
from keri.app.grouping import replyProposal, endorseReply, multisigRpyExn
from keri.app.registry_salt_service import ROUTE
from keri.core import Diger, Number, Parser, Salter, SerderKERI, messagize
from keri.db import fetchTsgs
from keri.peer.exchanging import loadParsedNestedSubstreams, serializeMessage
from locksmith.core.credentialing import CredentialUpdateDoer
from locksmith.core.receipting import LocksmithReceiptor
from locksmith.core import evidence


class SaltActions:
    """Validate operator choices and inspect exact retained group proposals."""

    def __init__(self, vault):
        """Borrow the open vault's existing reply and registry owners."""
        self.vault, self.service = vault, vault.salts.service

    def local(self, party):
        """Return a currently accepted local habitat or reject the selection."""
        hab = self.vault.hby.habByPre(party)
        if hab is None or not hab.accepted:
            raise kering.ConfigurationError('Choose an accepted local identifier')
        return hab

    def member(self, party):
        """Return the existing local signer for an individual or group."""
        hab = self.local(party)
        return hab.mhab if isinstance(hab, GroupHab) else hab

    def prepare(self, party, registry, recipient, target=None):
        """Prepare one recipient-encrypted reply for preview, without signing it."""
        return self.service.makeReply(self.local(party), registry, recipient, target=target)

    def registryApproval(self, party):
        """Borrow normal KERIpy group registry approval without another processor."""
        return RegistryApproval(self.vault.hby, self.vault.rgy, self.local(party),
            self.vault.exc, self.vault.mux, self.vault.mbx.parser, self.vault.counselor)

    def acceptedRegistry(self, registry, issuer):
        """Return the exact accepted issuer rip for optional public evidence sharing.

        registry/issuer are explicit public AIDs. This supplies public verification dependencies, not salt authority.
        """
        rip = self.vault.rgy.store.seqEvent(registry, 0)
        if rip is None or rip.said != registry or rip.israid != issuer:
            raise kering.ValidationError('Choose an accepted registry belonging to the selected issuer')
        return rip

    def publicEvidence(self, registry, issuer):
        """Return accepted controller KEL plus only the exact requested rip frame.

        registry/issuer select public dependencies, checked before export. Existing
        EvidenceProcessor.clone supplies verified framing; the borrowed parser is
        used only for frame boundaries. Other TEL updates, inventory and event
        openings are excluded. No custody operation or new parser is involved.
        """
        self.acceptedRegistry(registry, issuer)
        remaining = bytearray(evidence.processor(self.vault).clone([registry]))
        parser, frames = self.vault.mbx.parser, []
        version = parser.version
        try:
            while remaining:
                original = bytes(remaining)
                parsed = parser.parseOne(ims=remaining, processive=False, local=False)
                if parsed is None or len(remaining) >= len(original):
                    raise kering.ValidationError('Public registry evidence has incomplete framing')
                body = parsed.serder
                if isinstance(body, SerderKERI):
                    if body.ilk not in ('icp', 'dip', 'rot', 'drt', 'ixn'):
                        raise kering.ValidationError('Public registry dependency is not controller KEL evidence')
                    frames.append((body, original[body.size:len(original) - len(remaining)]))
                elif body.ilk == 'rip' and body.said == registry:
                    frames.append((body, original[body.size:len(original) - len(remaining)]))
        finally:
            parser.version = version
        return frames

    def inspect(self, said):
        """Verify a retained proposal and return its exact body, anchor and opening."""
        wrapper = self.vault.hby.db.exns.get((said,))
        if wrapper is None:
            raise kering.MissingEntryError('The retained proposal is unavailable')
        party = wrapper.sad['a']['gid']
        if wrapper.route == '/multisig/rpy':
            child = replyProposal(self.vault.hby, self.vault.exc, self.vault.mux, said,
                ghab=self.local(party), validate=self.service.validate)
            return child.serder, None, None
        if wrapper.route not in ('/multisig/rip', '/multisig/bup'):
            raise kering.ValidationError('This is not a registry or salt proposal')
        return self.registryApproval(party).proposal(serializeMessage(self.vault.hby, said))

    def snapshot(self):
        """Read public registry choices and ordinary group notifications, never salts."""
        rows = []
        registries = set(self.vault.rgy.regs)
        registries.update(regk for (regk,), _ in self.vault.rgy.baser.heads.getTopItemIter())
        for regk in sorted(registries):
            rip = self.vault.rgy.store.seqEvent(regk, 0)
            candidate = rip or self.vault.rgy.store.event(regk)
            if candidate is not None:
                rows.append(dict(kind='registry', said=regk, party=candidate.israid,
                    registry=regk, route='', accepted=rip is not None,
                    **self.vault.salts.status(regk)))
        for _, note in self.vault.notifier.noter.notes.getTopItemIter():
            said = note.attrs.get('d')
            wrapper = self.vault.hby.db.exns.get((said,)) if said else None
            if wrapper is None or wrapper.route not in ('/multisig/rpy', '/multisig/rip', '/multisig/bup'):
                continue
            if wrapper.route == '/multisig/rpy':
                children = loadParsedNestedSubstreams(self.vault.hby, said)
                if len(children) != 1 or children[0].serder.route != ROUTE:
                    continue
            rows.append(dict(kind='proposal', said=said, party=wrapper.sad['a']['gid'],
                             registry='', route=wrapper.route))
        return rows


class SaltActionDoer(CredentialUpdateDoer):
    """Own one explicitly approved operation and its finite transport children."""
    Timeout = 30.0

    def __init__(self, vault, body=None, *, proposal=None, create=None, auths=None, **kwa):
        """Retain exact approved inputs; begin work only when the vault schedules it."""
        if (body is None) == (create is None):
            raise ValueError('Choose one exact reply/proposal or registry creation')
        self.vault, self.body, self.proposal, self.create = vault, body, proposal, create
        self.auths, self.actions = dict(auths or {}), SaltActions(vault)
        self.result, self.error, self.children = None, '', []
        super().__init__(doers=[doing.doify(self.run)], **kwa)

    def _emit(self):
        """Publish action progress through the existing UI signal bridge."""
        self.vault.signals.emit_doer_event('RegistryAccess', 'registry_access_changed',
            dict(success=not bool(self.error), error=self.error, result=self.result))

    def _send(self, sender, target, body, attachments, topic, dependencies=()):
        """Schedule ordinary StreamPoster children, with no persistent delivery state."""
        poster = StreamPoster(hby=self.vault.hby, hab=sender, recp=target, topic=topic,
                              version=kering.Vrsn_2_0, essr=False)
        for supporting, proof in dependencies:
            poster.send(supporting, attachment=proof, gvrsn=kering.Vrsn_2_0)
        poster.send(body, attachment=attachments, gvrsn=kering.Vrsn_2_0)
        children = poster.deliver() or []
        self.children.extend(children)
        self.extend(children)
        return children

    def _fanout(self, hab, wrapper, attachments):
        """Share a member signature without imposing an all-member signing threshold."""
        deliveries = {}
        for member in hab.smids:
            if member != hab.mhab.pre:
                try:
                    deliveries[member] = self._send(hab.mhab, member, wrapper, attachments, 'multisig')
                except kering.KeriError:
                    continue  # Ordinary unavailable routes do not change group quorum.
        return deliveries

    def run(self, tymth, tock=0.0, **kwa):
        """Sign reviewed inputs, await normal verification, and submit exact bytes."""
        self.wind(tymth)
        yield tock
        receiptor, copies, group, registry = None, None, None, None
        try:
            if self.vault.closed:
                raise kering.ConfigurationError('The vault is closed')
            deadline = self.tyme + self.Timeout
            custody = self.vault.salts.custody
            if self.create:
                party, name = self.create
                hab = self.actions.local(party)
                custody._manager()  # This control explicitly creates blinded-state custody.
                registry = self.vault.rgy.registryByName(name)
                if registry is not None and registry.hab.pre != party:
                    raise kering.ValidationError('That registry name belongs to another issuer')
                registry = registry or Registrar(rgy=self.vault.rgy).makeRegistry(name=name, prefix=party)
                self.body = self.vault.rgy.store.event(registry.regk)
                if isinstance(hab, GroupHab):
                    group = hab
                    pending = self.vault.hby.db.pses.getLast(keys=party, on=hab.kever.sn + 1)
                    anchor = self.vault.hby.db.evts.get((party, pending)) if pending else None
                    accepted = registry.store.anchor(self.body.said)
                    if anchor is None and accepted is not None:
                        anchor = self.vault.hby.db.evts.get((party, accepted[1].qb64))
                    if anchor is not None:
                        for said in self.vault.hby.db.meids.get((anchor.said,)):
                            previous = self.vault.hby.db.exns.get((said.qb64,))
                            if previous and previous.pre == hab.mhab.pre and previous.sad['a'].get('tel') == self.body.said:
                                copies = previous.sad['a'].get('salts')
                                if copies:
                                    break
                    if copies is None:
                        root = (Salter(qb64=custody._load(registry.regk).salt)
                                if self.vault.hby.ks.custody.get((registry.regk,)) else Salter())
                        copies = custody.sealMembers(hab, root)
                    if registry.store.seqEvent(registry.regk, 0) is None:
                        wrapper, attachments = self.actions.registryApproval(party).approve(self.body, salts=copies)
                        member_deliveries = self._fanout(hab, wrapper, attachments)
                else:
                    receiptor = LocksmithReceiptor(hby=self.vault.hby)
                    self.extend([receiptor])
                    yield from self.anchor(registry, self.body, receiptor, self.auths)
            elif self.body.ilk in ('rip', 'bup'):
                body, anchor, opening = self.actions.inspect(self.proposal)
                if body.raw != self.body.raw:
                    raise kering.ValidationError('The displayed registry proposal changed')
                wrapper = self.vault.hby.db.exns.get((self.proposal,))
                group = self.actions.local(wrapper.sad['a']['gid'])
                copies = wrapper.sad['a'].get('salts')
                if copies and group.mhab.pre in copies:
                    custody.openRoot(copies[group.mhab.pre], group.mhab.kever.verfers[0])
                outgoing, attachments = self.actions.registryApproval(group.pre).approve(
                    body, anchor, opening=opening, salts=copies)
                self._fanout(group, outgoing, attachments)
            else:
                body = self.body
                self.actions.service.validate(body)
                hab = self.actions.local(body.pre)
                if isinstance(hab, GroupHab):
                    if self.proposal:
                        child = replyProposal(self.vault.hby, self.vault.exc, self.vault.mux,
                            self.proposal, ghab=hab, validate=self.actions.service.validate)
                        if child.serder.raw != body.raw:
                            raise kering.ValidationError('The displayed reply changed')
                        signed, wrapper, attachments = endorseReply(self.vault.hby, hab, child,
                            validate=self.actions.service.validate)
                    else:
                        signed = hab.endorse(body, gvrsn=kering.Vrsn_2_0)
                        wrapper, attachments = multisigRpyExn(hab, signed,
                            version=kering.Vrsn_2_0, gvrsn=kering.Vrsn_2_0)
                    self.vault.mbx.parser.parse(ims=bytearray(signed), local=True)
                    self.vault.mbx.parser.parse(ims=bytearray(wrapper.raw + attachments), local=True)
                    member_deliveries = self._fanout(hab, wrapper, attachments)
                else:
                    self.vault.mbx.parser.parse(ims=bytearray(hab.endorse(body, gvrsn=kering.Vrsn_2_0)), local=True)
                while True:
                    diger = Diger(qb64=body.said)
                    tsgs = list(fetchTsgs(db=self.vault.hby.db.tsgs, diger=diger))
                    cigars = []
                    for verfer, cigar in self.vault.hby.db.scgs.get((body.said,)):
                        cigar.verfer = verfer
                        cigars.append(cigar)
                    if self.vault.rvy.acceptReply(serder=body, saider=diger, route=body.route,
                            aid=body.pre, tsgs=tsgs, cigars=cigars):
                        break
                    if self.tyme >= deadline:
                        self.result = dict(state='Awaiting group signatures', said=body.said)
                        return
                    yield self.tock
                if self.proposal is not None:
                    proposer = self.vault.hby.db.exns.get((self.proposal,)).pre
                    deliveries = member_deliveries.get(proposer, [])
                    if not deliveries:
                        raise kering.ConfigurationError('No route to the proposing member is available')
                    while not all(child.done for child in deliveries):
                        if self.tyme >= deadline:
                            raise kering.ConfigurationError('Member signature submission timed out')
                        yield self.tock
                    self.result = dict(said=body.said, state='Group reply approved; initiator submits to recipient')
                    return
                signed = messagize(body, tsgs=tsgs or None, cigars=cigars or None, gvrsn=kering.Vrsn_2_0)
                target = body.sad['a']['target']
                if self.vault.hby.habByPre(target) is None:
                    sender = self.actions.member(body.pre)
                    key = self.vault.hby.kevers[target].verfers[0]
                    sealed = envelope(sender, signed, target, key, version=kering.Vrsn_2_0)
                    outer = SerderKERI(raw=sealed)
                    rip = self.vault.rgy.store.seqEvent(body.sad['a']['registry'], 0)
                    deliveries = self._send(sender, target, outer, sealed[outer.size:], 'credential',
                        self.actions.publicEvidence(rip.said, rip.israid))
                    if not deliveries:
                        raise kering.ConfigurationError('No recipient delivery route is available')
                    while not all(child.done for child in deliveries):
                        if self.tyme >= deadline:
                            raise kering.ConfigurationError('Salt reply transmission timed out')
                        yield self.tock
                self.result = dict(said=body.said, state='Reply submitted; recipient acceptance is separate')
                return
            regid = self.body.said if self.body.ilk == 'rip' else self.body.sad['rd']
            while True:
                accepted = self.vault.rgy.store.seqEvent(regid, Number(numh=self.body.sad['n']).num)
                if accepted is not None and accepted.said == self.body.said:
                    break
                if self.tyme >= deadline:
                    self.result = dict(said=self.body.said, state='Awaiting registry anchor acceptance')
                    return
                yield self.tock
            if copies and group.mhab.pre in copies:
                custody.retainMemberCopy(regid, group, copies)
            elif self.create and group is None:
                custody.createCustody(regid, self.body.israid)
            self.result = dict(said=self.body.said, registry=regid, state='Registry event accepted')
        except Exception as ex:
            self.error = str(ex) if isinstance(ex, kering.KeriError) else 'Registry access operation failed'
        finally:
            self.remove(self.children)
            if receiptor is not None:
                self.remove([receiptor])
            self._emit()
