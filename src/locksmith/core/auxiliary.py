"""Vault-owned live auxiliary exchanges; protocol owners retain their authority.

Signed pending Grants and ephemeral DH state belong only to this process. They
never enter the ordinary accepted-message outbox or confer admission consent.
"""
from collections import deque
from copy import deepcopy
from dataclasses import dataclass
from datetime import timedelta

from hio.base import doing
from keri import kering
from keri.acdc.dhking import Dhke
from keri.app import agenting, forwarding
from keri.core import Parser, SerderACDC, SerderKERI
from keri.help import helping
from keri.peer import exchanging

from locksmith.core import ipexing


@dataclass
class _Operation:
    """One local approval bound to the original signed Grant."""
    hab: object
    grant: object
    xid: str
    protocol: object
    wire: bytes = b''
    phase: str = 'waiting'
    error: str = ''
    kind: str = 'dh'


@dataclass
class _Query:
    """A fully authenticated first arrival waiting for local consent."""
    serder: object
    attachments: dict
    expires: object


class Auxiliary(doing.DoDoer):
    """Compose individual live operations over one vault's normal protocol intake."""

    Terminal = ('cancelled', 'interrupted', 'expired', 'refused', 'verified')

    def __init__(self, vault):
        self.vault = vault
        self.operations = {}
        self._dh = {}
        self._queries = {}
        self._query_deadlines = {}
        self.outgoing = deque()
        self._delivery = None
        self._observed = {}
        vault.hby.rtr.addRoute(Dhke.Route, self)
        super().__init__(doers=[doing.doify(self.run)])

    def _context(self, hab, said):
        """Authenticate a live pending issuance without accepting its credential."""
        message = self.vault.hby.db.epse.get((said,))
        if message is None or hab.pre not in (message.pre, message.sad.get('ri')):
            return None
        xid = message.said if message.ilk == 'xip' else message.sad.get('x')
        context = self.vault.exc.pendingGrant(said, xid=xid, sender=message.pre,
                                              recipient=message.sad.get('ri'))
        nests = exchanging.loadParsedNestedSubstreams(self.vault.hby, said) if context else []
        return (message, xid) if context and len(context[1]) == 1 and len(nests) == 1 else None

    def _owner(self, hab):
        """Keep the native DH owner and its ephemeral keys within this vault."""
        from keri.app.habbing import GroupHab
        if hab is not self.vault.hby.habByPre(hab.pre) or isinstance(hab, GroupHab):
            raise ValueError('Live agreement requires an individual local identifier')
        if hab.pre not in self._dh:
            self._dh[hab.pre] = Dhke(hab, self.vault.exc)
        return self._dh[hab.pre]

    def _snapshot(self, hab, message, xid, operation=None):
        """Expose identifiers and readiness, never private keys or registry roots."""
        phase = operation.phase if operation else ('approval_required'
                 if hab.pre == message.sad['ri'] else 'interrupted')
        cutoff = self._query_deadlines.get((Dhke.Route, message.pre, xid))
        if operation is None and cutoff is not None and helping.nowUTC() >= cutoff:
            phase = 'expired'
        actions = ('approve_dh',) if phase == 'approval_required' else ()
        return dict(aid=hab.pre, grant=message.said, xid=xid, kind='dh', phase=phase,
                    error=operation.error if operation else '', actions=actions,
                    credential=message.sad['a']['o'][0], sender=message.pre,
                    recipient=message.sad['ri'])

    def pending(self, hab=None):
        """Return authenticated pending requests, separately from accepted inventory."""
        result = {}
        for _, message in self.vault.hby.db.epse.getTopItemIter():
            for pre in (message.pre, message.sad.get('ri')):
                local = self.vault.hby.habByPre(pre)
                if local is None or hab is not None and local is not hab:
                    continue
                if context := self._context(local, message.said):
                    result[(pre, message.said)] = self._snapshot(local, *context)
        for key, operation in self.operations.items():
            if hab is None or operation.hab is hab:
                result[key] = self._snapshot(operation.hab, operation.grant,
                                              operation.xid, operation)
        return list(result.values())

    def observe_pending(self):
        """Notify views after authenticated intake or a live context changes."""
        current = {(row['aid'], row['grant']): row['phase'] for row in self.pending()}
        for key in self._observed.keys() | current.keys():
            if self._observed.get(key) != current.get(key):
                self.vault.signals.emit_doer_event('Auxiliary', 'changed', dict(aid=key[0], grant=key[1]))
        self._observed = current

    def status(self, aid, grant_said):
        """Read either a live operation or an authenticated pre-approval request."""
        if operation := self.operations.get((aid, grant_said)):
            return self._snapshot(operation.hab, operation.grant, operation.xid, operation)
        hab = self.vault.hby.habByPre(aid)
        if hab is not None and (context := self._context(hab, grant_said)):
            return self._snapshot(hab, *context)
        return None

    def _changed(self, operation, phase, error=''):
        if (operation.phase, operation.error) != (phase, error):
            operation.phase, operation.error = phase, error
            self.vault.signals.emit_doer_event('Auxiliary', 'changed',
                dict(aid=operation.hab.pre, grant=operation.grant.said))

    def begin_dh(self, hab, grant, attachment):
        """Explicitly approve and send one issuer's fresh, signed proofless Grant."""
        ipexing._require_vault(self.vault, hab)
        if grant.pre != hab.pre or grant.route != '/ipex/grant':
            raise ValueError('Select this issuer\'s exact Grant')
        wire = bytes(grant.raw + attachment)
        key = (hab.pre, grant.said)
        if key in self.operations:
            operation = self.operations[key]
            if operation.wire != wire or operation.phase in self.Terminal:
                raise ValueError('This live issuance cannot be replaced or resumed')
            return self.status(*key)
        self.vault.mbx.parser.parse(ims=bytearray(wire), local=True,
                                   version=kering.Vrsn_2_0)
        context = self._context(hab, grant.said)
        if context is None:
            raise kering.ValidationError('Grant is not an authenticated fresh issuance')
        owner = self._owner(hab)
        xid = owner.approve(grant.said)
        operation = _Operation(hab, grant, xid, owner, wire)
        self.operations[key] = operation
        self.outgoing.append((key, grant.sad['ri'], wire, 'credential'))
        self.outgoing.append((key, grant.sad['ri'], owner.start(grant.said), 'reply'))
        self.vault.signals.emit_doer_event('Auxiliary', 'changed', dict(aid=hab.pre, grant=grant.said))
        return self.status(*key)

    def approve_dh(self, hab, grant_said):
        """Approve the issuee's exact authenticated pending Grant; never Admit it."""
        ipexing._require_vault(self.vault, hab)
        existing = self.operations.get((hab.pre, grant_said))
        if existing is not None and existing.phase in self.Terminal:
            raise kering.ValidationError('This live agreement has ended; start a new exchange')
        current = self.status(hab.pre, grant_said)
        if current is not None and current['phase'] in self.Terminal:
            raise kering.ValidationError('The original auxiliary request deadline has elapsed')
        context = self._context(hab, grant_said)
        if context is None or context[0].sad['ri'] != hab.pre:
            raise kering.ValidationError('Select a live issuance addressed to this identifier')
        owner = self._owner(hab)
        xid = owner.approve(grant_said)
        key = (hab.pre, grant_said)
        if key not in self.operations:
            self.operations[key] = _Operation(hab, context[0], xid, owner)
        self._retry_queries(self.operations[key])
        return self.status(*key)

    def agreement_ready(self, aid, grant_said):
        """Let issuance read readiness while roots remain exclusively in Keeper."""
        operation = self.operations[(aid, grant_said)]
        return operation.protocol.complete(operation.xid)

    def _query_attachments(self, serder, attachments):
        allowed = ('sigers', 'cigars', 'lsgs', 'tsgs')
        if any(value for name, value in attachments.items()
               if name not in (*allowed, 'local', 'source')):
            raise kering.ValidationError('DH query carries unsupported attachments')
        data = serder.sad.get('q')
        if (serder.route != Dhke.Route or serder.sad.get('rr') != Dhke.Route
                or not isinstance(data, dict) or set(data) != {'x', 'pk'}
                or not isinstance(data['x'], str) or not isinstance(data['pk'], dict)):
            raise kering.ValidationError('Invalid DH query')
        selected = {name: attachments[name] for name in allowed if attachments.get(name)}
        if not exchanging.verifyQueryAttachments(self.vault.hby, serder, **selected):
            raise kering.MissingSignatureError('Auxiliary query needs its complete sender threshold')
        return selected

    def processQuery(self, serder, **attachments):
        """Retain a post-parser authenticated first arrival without granting consent."""
        selected = self._query_attachments(serder, attachments)
        key = (serder.route, serder.pre, serder.sad['q']['x'])
        if any(op.xid == key[2] and op.grant.pre == serder.pre and op.phase in self.Terminal
               for op in self.operations.values()):
            raise kering.ValidationError('This live agreement has ended')
        previous = self._queries.get(key)
        if previous is not None:
            if previous.serder.raw != serder.raw:
                raise kering.ValidationError('Conflicting query for this live transaction')
            return
        if len(self._queries) >= 32 or len(serder.raw) > 16384:
            raise kering.ValidationError('Too many waiting auxiliary requests')
        expires = self._query_deadlines.get(key)
        if expires is None:
            expires = helping.nowUTC() + timedelta(minutes=5)  # Explicit KRAM-off consent wait.
        kramer = self.vault.kramer
        if kramer.enabled and not any(kramer.denial(serder).startswith(value) for value in kramer.denials):
            cache = self.vault.hby.db.kramMSGC.get((serder.pre, serder.said))
            if cache is None:
                raise kering.ValidationError('Auxiliary query has no accepted receipt time')
            expires = helping.fromIso8601(cache.mdt) + timedelta(milliseconds=cache.d + cache.ml)
        expires = self._query_deadlines.setdefault(key, expires)
        if helping.nowUTC() >= expires:
            raise kering.ValidationError('The original auxiliary request deadline has elapsed')
        self._queries[key] = _Query(serder, deepcopy(selected), expires)
        for operation in self.operations.values():
            self._retry_queries(operation)
        self.observe_pending()

    def _retry_queries(self, operation):
        key = (Dhke.Route, operation.grant.pre, operation.xid)
        query = self._queries.get(key)
        if (query is None or operation.hab.pre != operation.grant.sad['ri']
                or operation.phase in self.Terminal):
            return
        deadline = self.vault.hby.db.epsd.get((operation.grant.said,))
        if deadline is None or helping.nowUTC() >= min(deadline.datetime, query.expires):
            self._queries.pop(key, None)
            self._terminate(operation, 'expired', 'The original request deadline has elapsed')
            return
        try:
            operation.protocol.processQuery(query.serder, **deepcopy(query.attachments))
        except kering.ValidationError as error:
            self._queries.pop(key, None)
            self._terminate(operation, 'refused', str(error))
            raise
        self._queries.pop(key, None)
        self._drain(operation)

    def processReply(self, *, serder, diger, route, cigars=None, tsgs=None):
        """Dispatch only to an explicitly approved exact Grant and opposite party."""
        data = serder.sad.get('a') or {}
        candidates = [op for op in self.operations.values()
                      if op.xid == data.get('x') and op.hab.pre == op.grant.pre
                      and serder.pre == op.grant.sad['ri']]
        if (route != Dhke.Route or len(candidates) != 1
                or candidates[0].phase in self.Terminal):
            raise kering.ValidationError('Reply has no matching local approval')
        operation = candidates[0]
        operation.protocol.processReply(serder=serder, diger=diger, route=route,
                                          cigars=cigars, tsgs=tsgs)

    def _drain(self, operation):
        while operation.protocol.cues:
            cue = operation.protocol.cues.popleft()
            self.outgoing.append(((operation.hab.pre, operation.grant.said),
                                  cue['dest'], cue['msg'], 'reply'))

    def process(self):
        """Retry approved operations from existing evidence, without another intake."""
        for key, query in list(self._queries.items()):
            if helping.nowUTC() >= query.expires:
                self._queries.pop(key)
                for operation in self.operations.values():
                    if (operation.xid == key[2] and operation.grant.pre == key[1]
                            and operation.hab.pre == operation.grant.sad['ri']
                            and operation.phase not in self.Terminal):
                        self._terminate(operation, 'expired', 'The original request deadline has elapsed')
        for operation in self.operations.values():
            if operation.phase in self.Terminal:
                continue
            deadline = self.vault.hby.db.epsd.get((operation.grant.said,))
            if deadline is None or helping.nowUTC() >= deadline.datetime:
                self._terminate(operation, 'expired', 'The original Grant deadline has elapsed')
                continue
            if self.vault.exc.complete(operation.grant.said):
                try:
                    ipexing._validate_grant_graph(self.vault, operation.grant.said)
                    self._changed(operation, 'verified')
                except kering.KeriError as error:
                    self._terminate(operation, 'refused', str(error))
                continue
            try:
                self._retry_queries(operation)
                if operation.phase in self.Terminal or not operation.protocol.complete(operation.xid):
                    continue
                nest = exchanging.loadParsedNestedSubstreams(self.vault.hby, operation.grant.said)[0]
                head = self.vault.rgy.store.headEvent(nest.serder.sad['rd'])
                if head is None or head.ilk == 'rip':
                    self._changed(operation, 'waiting', 'Waiting for the accepted issuance update')
                    continue
                operation.protocol.finish(operation.xid)
                if self.vault.exc.complete(operation.grant.said):
                    ipexing._validate_grant_graph(self.vault, operation.grant.said)
                    self._changed(operation, 'verified')
            except (kering.MissingChainError, kering.MissingAnchorError, kering.MissingSchemaError) as error:
                self._changed(operation, 'waiting', str(error))
            except kering.ValidationError as error:
                self._terminate(operation, 'refused', str(error))
            self._drain(operation)
        self.observe_pending()

    def _terminate(self, operation, phase, error=''):
        """Drop ephemeral authority and queued work while retaining encrypted roots/history."""
        operation.protocol.abandon(operation.xid)
        self._changed(operation, phase, error)
        key = (operation.hab.pre, operation.grant.said)
        self.outgoing = deque(item for item in self.outgoing if item[0] != key)
        self._queries = {item: value for item, value in self._queries.items() if item[2] != operation.xid}
        if self._delivery is not None and self._delivery.key == key:
            self.remove([self._delivery])
            self._delivery = None

    def abandon(self, aid, grant_said):
        operation = self.operations[(aid, grant_said)]
        if operation.phase in self.Terminal:
            raise kering.ValidationError('This live agreement has already ended')
        self._terminate(operation, 'cancelled')

    def close(self):
        """Abandon ephemeral state before the vault's stores close."""
        for operation in self.operations.values():
            if operation.phase not in self.Terminal:
                self._terminate(operation, 'interrupted')
        self._queries.clear()
        self._query_deadlines.clear()
        self.outgoing.clear()
        if self._delivery is not None:
            self.remove([self._delivery])
            self._delivery = None

    def exit(self, **kwa):
        self.close()
        super().exit(**kwa)

    def run(self, tymth=None, tock=0.0, **kwa):
        self.wind(tymth)
        yield self.tock
        while not self.vault.closed:
            self.process()
            if self._delivery is not None and self._delivery.done:
                self._delivery = None
            if self._delivery is None and self.outgoing:
                key, destination, wire, topic = self.outgoing.popleft()
                self._delivery = _Delivery(self, key, destination, wire, topic)
                self.extend([self._delivery])
            yield .1


class _Delivery(doing.DoDoer):
    """Send one exact live auxiliary message with ordinary public support and cleanup."""
    def __init__(self, owner, key, destination, wire, topic):
        self.owner, self.key = owner, key
        self.destination, self.wire, self.topic = destination, wire, topic
        super().__init__(doers=[doing.doify(self.send)])

    def send(self, tymth=None, tock=0.0, **kwa):
        self.wind(tymth)
        yield self.tock
        delivery = None
        operation = self.owner.operations[self.key]
        vault, hab = self.owner.vault, operation.hab
        try:
            ipexing._require_route(hab, self.destination)
            message = Parser(version=kering.Vrsn_2_0).parseOne(
                ims=bytearray(self.wire), processive=False).serder
            if not self.wire.startswith(message.raw):
                raise kering.ValidationError('Expected a complete signed auxiliary message')
            poster = forwarding.StreamPoster(hby=vault.hby, hab=hab,
                                               recp=self.destination, topic=self.topic)
            for raw in vault.hby.db.clonePreIter(hab.pre, gvrsn=kering.Vrsn_2_0):
                event = SerderKERI(raw=raw)
                poster.send(serder=event, attachment=raw[event.size:])
            # Fresh issuance support is public; the secret root never enters transport.
            registries = {nest.serder.sad.get('rd') for nest in
                          exchanging.loadParsedNestedSubstreams(vault.hby, operation.grant.said)}
            for regid in registries - {None}:
                for raw in vault.rgy.store.cloneTelIter(regid):
                    event = SerderACDC(raw=raw)
                    poster.send(serder=event, attachment=raw[event.size:])
            poster.send(serder=message, attachment=self.wire[message.size:])
            doers = poster.deliver()
            if not doers:
                raise kering.ConfigurationError('No transport could submit this auxiliary message')
            delivery = doing.DoDoer(doers=doers, tymth=self.tymth)
            delivery.enter()
            deadline = self.tyme + 30
            while not delivery.recur(tyme=self.tyme):
                if self.tyme >= deadline:
                    raise TimeoutError('Auxiliary delivery timed out')
                yield self.tock
            for messenger in poster.messagers:
                if isinstance(messenger, agenting.HTTPStreamMessenger):
                    if messenger.rep is None or not 200 <= messenger.rep.status < 300:
                        raise kering.ValidationError('Auxiliary transport request failed')
        except (OSError, ValueError, kering.KeriError) as error:
            if operation.phase not in self.owner.Terminal:
                self.owner._changed(operation, 'waiting', str(error))
        finally:
            if delivery is not None:
                delivery.exit()


def install(vault):
    """Wire live operations into the existing vault's single parser/reply owners.

    The same function supports construction and scheduler-safe test composition;
    its caller adds the returned child through the HIO scheduler API.
    """
    vault.rvy = vault.hby.rvy
    vault.rvy.cues = vault.cues
    vault.kvy.rvy = vault.rvy
    vault.auxiliary = Auxiliary(vault)
    vault.kvy.qvy = vault.auxiliary
    return vault.auxiliary
