"""Explicit operator actions over the vault's borrowed registry/salt owners.

RegistrySaltService owns the provisional reply profile. RegistryApproval owns
native group TEL consent; CredentialUpdateDoer owns individual anchor receipts.
This module opens no store or processor and keeps no separate approval journal.
"""

from hio.base import doing
from keri import kering
from keri.acdc import Registrar
from keri.app.acdc_v2_grouping import RegistryApproval
from keri.app.essring import envelope
from keri.app.forwarding import StreamPoster
from keri.app.habbing import GroupHab
from keri.app import registry_salt_replies as replies
from keri.app.replying import parseReply
from keri.app.group_members import acceptedRoster, currentRecipientKey
from keri.app.registry_salt_delivery import SaltTransportAttempt
from keri.app.registry_salt_proofs import verifyArchivedReply
from keri.core import Number, SerderKERI
from keri.peer.exchanging import loadParsedNestedSubstreams, serializeMessage

from locksmith.core.credentialing import CredentialUpdateDoer
from locksmith.core.receipting import LocksmithReceiptor
from locksmith.core import evidence


class SaltActions:
    """Prepare explicit actions and read public choices without granting consent."""

    def __init__(self, vault):
        """Borrow the open vault and its already-composed optional salt service."""
        self.vault, self.service = vault, vault.salts.service

    def local(self, party):
        """Return the local logical habitat selected by party, or reject it."""
        hab = self.vault.hby.habByPre(party)
        if hab is None or not hab.accepted:
            raise kering.ConfigurationError('Choose an accepted local identifier')
        return hab

    def member(self, party):
        """Return the existing local individual signer for the selected party."""
        hab = self.local(party)
        return hab.mhab if isinstance(hab, GroupHab) else hab

    def trust(self, party, members):
        """Validate an operator-confirmed ordered member map against accepted KEL."""
        return self.service.trustRoster(party, list(members))

    def roster(self, party):
        """Return a previously trusted map, or an accepted local group's map.

        party selects public identity state. Remote group member mappings are
        never inferred from contacts or incoming proposals. No state is written.
        """
        roster = self.service.state.roster(party)
        if roster is not None:
            return [member.aid for member in self.service.roster(party).members]
        hab = self.vault.hby.habByPre(party)
        if isinstance(hab, GroupHab) and hab.accepted:
            members = self.vault.hby.db.signingMembers(pre=party)
            try:
                return [member.aid for member in acceptedRoster(self.vault.hby, party, members).members]
            except kering.ValidationError:
                return []  # Persisted proposed lists are not an accepted map.
        kever = self.vault.hby.kevers.get(party)
        return [party] if kever is not None and len(kever.verfers) == 1 else []

    def prepare(self, action, party, **values):
        """Return one exact unsigned reply for explicit preview and later approval.

        action is start, bind, confirm, assign or recover. party is the selected
        local logical signer; values supplies the named service arguments. Start
        and bind protect pending DH state before returning; neither signs yet.
        """
        member = self.member(party)
        if action == 'start':
            body = self.service.prepareInit(issuer=values['issuer'], discloser=values['discloser'],
                                            party=party, representative=member.pre)
        elif action == 'bind':
            body = self.service.prepareBind(values['init'], values['registry'], member.pre)
        elif action == 'confirm':
            body = self.service.prepareConfirm(values['init'], values['bind'])
        elif action == 'assign':
            body = self.service.prepareAssign(values['origin'], values['recipient'])
        elif action == 'recover':
            saved = self.service.state.proof(values['statement']) if values.get('statement') else None
            if saved is not None:
                parsed = parseReply(self.vault.mbx.parser, saved,
                    {replies.INIT_ROUTE, replies.BIND_ROUTE, replies.CONFIRM_ROUTE, replies.ASSIGN_ROUTE})
                body = verifyArchivedReply(self.vault.hby, self.vault.mbx.parser,
                                           saved, parsed.serder.route, party)
                self.service.checkLive(body)
            else:
                body = self.service.resume(values['init'], member.pre)
        else:
            raise ValueError('Unsupported registry access action')
        if body.pre != party:
            raise kering.ValidationError('This statement belongs to another local party')
        return body

    def registryApproval(self, party):
        """Borrow the core passive native approval collaborator for a local group."""
        return RegistryApproval(self.vault.hby, self.vault.rgy, self.local(party),
            self.vault.exc, self.vault.mux, self.vault.mbx.parser, self.vault.counselor)

    def acceptedRegistry(self, registry, issuer):
        """Return the exact accepted issuer rip for optional public evidence sharing.

        registry/issuer are explicit public AIDs. This does not bind a DH request
        or grant custody; the other party must separately select and sign Bind.
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
        """Return a retained exact salt or native TEL proposal without signing.

        said identifies an authenticated member wrapper. Return (body, anchor,
        opening); salt replies have None anchor/opening. Missing dependencies
        remain pending and cannot be approved through a display-only fallback.
        """
        wrapper = self.vault.hby.db.exns.get((said,))
        if wrapper is None:
            raise kering.MissingEntryError('The retained proposal is unavailable')
        if wrapper.route == '/multisig/rpy':
            return self.service.inspectProposal(said), None, None
        if wrapper.route not in ('/multisig/rip', '/multisig/bup'):
            raise kering.ValidationError('This proposal is not a registry access action')
        approval = self.registryApproval(wrapper.sad['a']['gid'])
        return approval.proposal(serializeMessage(self.vault.hby, said))

    def summary(self, body):
        """Describe the displayed exact body using public parties and capability.

        body was prepared or inspected by the domain owners. Return a small
        presentation snapshot; this reads no private state and grants nothing.
        """
        data = body.sad
        if body.ilk in ('rip', 'bup'):
            registry = body.said if body.ilk == 'rip' else data['rd']
            issuer = data['i'] if body.ilk == 'rip' else self.vault.rgy.store.seqEvent(registry, 0).israid
            return dict(title='Registry inception' if body.ilk == 'rip' else 'Registry state update',
                parties=[('Controller', issuer)], registry=registry,
                capability='Approves this exact registry event and group anchor. This does not establish or share root custody.')
        fields = data['a']
        if body.route == replies.ASSIGN_ROUTE:
            return dict(title='Additional state discloser', registry=fields['registry'],
                parties=[('Issuer', body.pre), ('Additional party', fields['party'])],
                capability='Grants the same root’s future state-opening derivation to the additional party and its accepted signing members. Group signing authority is unchanged.')
        init = body if body.route == replies.INIT_ROUTE else parseReply(self.vault.mbx.parser,
            self.service.state.proof(fields['init']), {replies.INIT_ROUTE}).serder
        titles = {replies.INIT_ROUTE: 'Registry access request', replies.BIND_ROUTE: 'Bind agreement to registry',
                  replies.CONFIRM_ROUTE: 'Issuer confirms registry access'}
        capabilities = {
            replies.INIT_ROUTE: 'Proposes shared derivation of future registry state openings. This request establishes no root.',
            replies.BIND_ROUTE: 'Binds this exact agreement to the accepted registry. Issuer confirmation is still required.',
            replies.CONFIRM_ROUTE: 'Establishes future state-opening derivation for these parties and their accepted signing members. Group signing authority is unchanged.'}
        return dict(title=titles[body.route], registry=fields.get('registry'),
            parties=[('Issuer', init.sad['a']['issuer']), ('Initial discloser', init.sad['a']['discloser'])],
            capability=capabilities[body.route])

    def snapshot(self):
        """Return public registries, retained statements and reviewable proposals.

        No private state is opened. Snapshot rows are display choices only;
        prepare/inspect/approve repeat normal authority checks before signing.
        """
        rows = []
        registries = set(self.vault.rgy.regs)
        registries.update(regk for (regk,), _ in self.vault.rgy.baser.heads.getTopItemIter())
        for regk in sorted(registries):
            rip = self.vault.rgy.store.seqEvent(regk, 0)
            candidate = rip or self.vault.rgy.store.event(regk)
            if candidate is None:
                continue
            status = self.vault.salts.status(regk)
            rows.append(dict(kind='registry', said=regk, party=candidate.israid,
                registry=regk, route='', accepted=rip is not None, **status))
        for (said,), _ in self.vault.db.saltProofs.getTopItemIter():
            body = parseReply(self.vault.mbx.parser, self.service.state.proof(said),
                              {replies.INIT_ROUTE, replies.BIND_ROUTE,
                               replies.CONFIRM_ROUTE, replies.ASSIGN_ROUTE}).serder
            rows.append(dict(kind='statement', said=said, party=body.pre, route=body.route,
                             registry=body.sad['a'].get('registry', ''), body=body))
        for (init, representative), _ in self.vault.db.saltPending.getTopItemIter():
            rows.append(dict(kind='draft', said=init, party=representative, registry='', route=''))
        for _, note in self.vault.notifier.noter.notes.getTopItemIter():
            said = note.attrs.get('d')
            wrapper = self.vault.hby.db.exns.get((said,)) if said else None
            if wrapper is None or wrapper.route not in ('/multisig/rpy', '/multisig/rip', '/multisig/bup'):
                continue
            if wrapper.route == '/multisig/rpy':
                # Other ordinary reply domains retain their existing UI owners.
                children = loadParsedNestedSubstreams(self.vault.hby, said)
                if (len(children) != 1 or children[0].serder.route not in
                        (replies.INIT_ROUTE, replies.BIND_ROUTE, replies.CONFIRM_ROUTE, replies.ASSIGN_ROUTE)):
                    continue
            rows.append(dict(kind='proposal', said=said, party=wrapper.sad['a']['gid'],
                             registry='', route=wrapper.route))
        return rows


class SaltActionDoer(CredentialUpdateDoer):
    """Approve one displayed action and own only its finite transport children."""

    Timeout = 30.0

    def __init__(self, vault, body=None, *, proposal=None, create=None, auths=None,
                 registryEvidence=None, **kwa):
        """Schedule a selected exact body/proposal or explicit (party,name) registry.

        vault supplies every runtime owner. auths contains transient witness
        authorization for individual registry creation. No operation starts in
        construction. result/error describe protocol progress, never remote custody.
        registryEvidence optionally shares a separately accepted issuer rip with
        an init; it never changes the signed init or grants a binding.
        """
        if (body is None) == (create is None):
            raise ValueError('Choose one exact statement or explicit registry creation')
        if registryEvidence is not None and (body is None or body.route != replies.INIT_ROUTE):
            raise ValueError('An optional registry evidence choice belongs only to an initial request')
        self.vault, self.body, self.proposal = vault, body, proposal
        self.create, self.auths = create, dict(auths or {})
        self.registryEvidence = registryEvidence
        self.actions = SaltActions(vault)
        self.result, self.error, self.children = None, '', []
        super().__init__(doers=[doing.doify(self.run)], **kwa)

    def _emit(self):
        """Report this finite action through the vault's existing UI signal bridge."""
        self.vault.signals.emit_doer_event('RegistryAccess', 'registry_access_changed',
            dict(success=not bool(self.error), error=self.error, result=self.result))

    def recur(self, tyme, deeds=None):
        """Contain transport child errors within this action's existing HIO owner."""
        try:
            return super().recur(tyme, deeds)
        except Exception:
            self.error = 'Registry access delivery failed; retained approval is unchanged'
            self._emit()
            return True

    def _send(self, sender, target, body, attachments, topic, dependencies=()):
        """Return one supervised submission, or None for an unavailable route.

        sender/target/body/attachments/topic select exact ordinary forwarding
        input. The existing salt transport owner isolates HTTP/TCP failures;
        forwarding never reseals an ultimate-member envelope to its mailbox.
        """
        poster = StreamPoster(hby=self.vault.hby, hab=sender, recp=target, topic=topic,
                              version=kering.Vrsn_2_0, essr=False)
        try:
            for supporting, proof in dependencies:
                poster.send(supporting, attachment=proof, gvrsn=kering.Vrsn_2_0)
            poster.send(body, attachment=attachments, gvrsn=kering.Vrsn_2_0)
            children = poster.deliver()
        except kering.KeriError:
            return None  # One unavailable member route cannot abort other peers.
        if not children:
            return None
        attempt = SaltTransportAttempt(children, timeout=5.0, tock=self.tock)
        self.children.append(attempt)
        self.extend([attempt])
        return attempt

    def _fanout(self, party, wrapper, attachments, dependencies=()):
        """Submit the existing member proposal without adding an all-members quorum."""
        sender = self.actions.member(party)
        members = self.actions.roster(party)
        for member in members:
            if member != sender.pre:
                self._send(sender, member, wrapper, attachments, 'multisig', dependencies)

    def _replyTargets(self, body):
        """Resolve explicit current rosters for public statement delivery."""
        data = body.sad['a']
        if body.route == replies.INIT_ROUTE:
            parties = (data['issuer'], data['discloser'])
        elif body.route in (replies.BIND_ROUTE, replies.CONFIRM_ROUTE):
            init = parseReply(self.vault.mbx.parser, self.actions.service.state.proof(data['init']),
                              {replies.INIT_ROUTE}).serder
            parties = (init.sad['a']['issuer'], init.sad['a']['discloser'])
        else:
            confirm = parseReply(self.vault.mbx.parser,
                self.actions.service.state.proof(data['origin']), {replies.CONFIRM_ROUTE}).serder
            parties = tuple(confirm.sad['a']['entitled'])
        targets = {}
        for party in parties:
            roster = self.actions.service.roster(party)
            targets[party] = []
            for member in roster.members:
                event, _key = currentRecipientKey(self.vault.hby, roster, member)
                targets[party].append((member.aid, event))
        return targets

    def run(self, tymth, tock=0.0, **kwa):
        """Approve explicitly, wait boundedly for exact acceptance, then submit bytes.

        HIO supplies tymth/tock/kwa. The vault's existing escrow/counselor cadence
        advances dependencies. An offline nonapprover is never required for
        threshold acceptance; incomplete transports are reported separately.
        Exact archived resends retain the receiver's live domain checks: an
        independently rotated representative can invalidate an unfinished
        agreement even within its KRAM time window. No body/key is refreshed.
        """
        self.wind(tymth)
        yield self.tock
        receiptor = None
        try:
            if self.vault.closed:
                raise kering.ConfigurationError('The vault is closed')
            deadline = self.tyme + self.Timeout
            if self.create is not None:
                party, name = self.create
                hab = self.actions.local(party)
                registry = self.vault.rgy.names.get(name)
                if registry is not None and registry.hab.pre != party:
                    raise kering.ValidationError('That registry name belongs to another issuer')
                registry = registry or Registrar(rgy=self.vault.rgy).makeRegistry(name=name, prefix=party)
                body = self.vault.rgy.store.event(registry.regk)
                if self.vault.rgy.store.seqEvent(registry.regk, 0) is not None:
                    pass  # An accepted existing inception needs no new seal.
                elif isinstance(hab, GroupHab):
                    wrapper, attachments = self.actions.registryApproval(party).approve(body)
                    self._fanout(party, wrapper, attachments)
                else:
                    receiptor = LocksmithReceiptor(hby=self.vault.hby)
                    self.extend([receiptor])
                    yield from self.anchor(registry, body, receiptor, self.auths)
                self.body = body
            elif self.body.ilk in ('rip', 'bup'):
                body, anchor, opening = self.actions.inspect(self.proposal)
                if body.raw != self.body.raw:
                    raise kering.ValidationError('The displayed registry proposal changed')
                wrapper = self.vault.hby.db.exns.get((self.proposal,))
                party = wrapper.sad['a']['gid']
                outgoing, attachments = self.actions.registryApproval(party).approve(body, anchor, opening=opening)
                dependencies = (self.actions.publicEvidence(body.sad['rd'], party)
                                if body.ilk == 'bup' else ())
                self._fanout(party, outgoing, attachments, dependencies)
            else:
                data = self.body.sad['a']
                registry = self.registryEvidence if self.body.route == replies.INIT_ROUTE else data.get('registry')
                if registry:
                    issuer = data['issuer'] if self.body.route == replies.INIT_ROUTE else (
                        self.vault.rgy.store.seqEvent(registry, 0).israid)
                    dependencies = self.actions.publicEvidence(registry, issuer)
                else:
                    dependencies = ()
                saved = self.actions.service.state.proof(self.body.said)
                if saved is not None and self.proposal is None:
                    archived = verifyArchivedReply(self.vault.hby, self.vault.mbx.parser,
                                                   saved, self.body.route, self.body.pre)
                    if archived.raw != self.body.raw:
                        raise kering.ValidationError('The displayed statement differs from its saved frame')
                    self.actions.service.checkLive(self.body)
                else:
                    outbound = self.actions.service.approveReply(self.body, proposal=self.proposal)
                    if outbound.proposal is not None:
                        self._fanout(self.body.pre, outbound.proposal, outbound.attachments, dependencies)
                while self.actions.service.state.proof(self.body.said) is None:
                    if self.tyme >= deadline:
                        self.result = dict(said=self.body.said, state='Awaiting exact group approval')
                        return
                    yield self.tock
                self.actions.service.checkLive(self.body)
                sender = self.actions.member(self.body.pre)
                stream = self.actions.service.state.proof(self.body.said)
                peers, local = {}, set()
                for party, members in self._replyTargets(self.body).items():
                    peers[party] = []
                    for target, event in members:
                        if self.vault.hby.habByPre(target) is not None:
                            local.add(party)
                            continue  # This parser already authenticated the local statement.
                        sealed = envelope(sender, stream, target, event.verfers[0],
                            version=kering.Vrsn_2_0, establishment=(event.sn, event.said))
                        outer = SerderKERI(raw=sealed)
                        attempt = self._send(sender, target, outer, sealed[outer.size:], 'credential', dependencies)
                        if attempt is not None:
                            peers[party].append(attempt)
                required = set(peers) - {self.body.pre} - local
                while any(not any(attempt.done and not attempt.error for attempt in peers[party])
                          and any(not attempt.done for attempt in peers[party]) for party in required):
                    if self.tyme >= deadline:
                        break
                    yield self.tock
                missing = [party for party in required
                           if not any(attempt.done and not attempt.error for attempt in peers[party])]
                self.result = dict(said=self.body.said, state='Statement authenticated',
                    unavailable=missing, transport='Peer submission remains pending' if missing else
                    ('Submitted to peer transport; remote acceptance unconfirmed' if required else
                     'No remote submission required'))
            if self.body.ilk in ('rip', 'bup'):
                registry = self.body.said if self.body.ilk == 'rip' else self.body.sad['rd']
                while True:
                    accepted = self.vault.rgy.store.seqEvent(registry, Number(numh=self.body.sad['n']).num)
                    if accepted is not None and accepted.said == self.body.said:
                        self.result = dict(said=self.body.said, state='Registry event accepted', registry=registry)
                        break
                    if self.tyme >= deadline:
                        self.result = dict(said=self.body.said, state='Awaiting exact group approval')
                        return
                    yield self.tock
                self.result['transport'] = 'Local acceptance verified; member dissemination is separate'
        except Exception as ex:
            self.error = str(ex) if isinstance(ex, kering.KeriError) else 'Registry access operation failed'
        finally:
            self.remove(self.children)
            if receiptor is not None:
                self.remove([receiptor])
            self._emit()
