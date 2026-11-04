# -*- encoding: utf-8 -*-
"""Native credential exchanges through the vault's parser and transport."""
from hio.base import doing
from keri import help, kering
from keri.acdc import ipexing
from keri.app import agenting, forwarding
from keri.core import Blinder, BlindState, BoundState, SerderKERI
from keri.peer import exchanging

from locksmith.db.basing import AcceptedCredential

logger = help.ogler.getLogger(__name__)


class IpexHandler(ipexing.IpexHandler):
    """Apply the wallet's endpoint and incoming-notification policy."""

    def verify(self, serder, attachments=None, nests=None, sscs=None):
        if serder.pvrsn.major != 2 or not ({serder.pre, serder.ked.get('ri')} & self.hby.prefixes):
            return False
        return super().verify(serder, attachments=attachments, nests=nests, sscs=sscs)

    def handle(self, serder, attachments=None, nests=None, sscs=None):
        if serder.pre not in self.hby.prefixes:
            super().handle(serder, attachments=attachments, nests=nests, sscs=sscs)


def prepare(vault, hab, serder, attachment):
    """Verify and retain the local signed copy before export or submission."""
    if hab is not vault.hby.habByPre(serder.pre) or serder.pvrsn.major != 2:
        raise ValueError('IPEX must be signed by this vault')
    if not serder.route.startswith('/ipex/'):
        raise ValueError('Expected an IPEX message')
    vault.mbx.parser.parse(ims=bytearray(serder.raw + attachment), local=True,
                           version=kering.Vrsn_2_0)
    if not vault.exc.complete(serder.said):
        raise kering.ValidationError('Outgoing IPEX has not passed protocol verification')
    return exchanging.serializeMessage(vault.hby, serder.said)


def grant_credential(vault, grant_said):
    """Load the origin credential from a retained, verified grant."""
    exn = vault.hby.db.exns.get(keys=(grant_said,))
    if exn is None or exn.route != '/ipex/grant' or exn.pvrsn.major != 2:
        raise kering.ValidationError('Verified native grant not found')
    exchanging.verify(vault.hby, exn)
    origin = exn.sad['a']['o'][0]
    for nest in exchanging.loadParsedNestedSubstreams(vault.hby, grant_said):
        if nest.serder.said == origin:
            return nest.serder
    raise kering.ValidationError('Grant origin evidence is missing')


def grant(vault, hab, credential_said, recipient, message=''):
    """Build a grant from the wallet's retained issuance or received evidence."""
    from locksmith.core import credentialing

    view = credentialing.credential(vault, credential_said)
    if view['status']['et'] != 'issued':
        raise kering.ValidationError('Credential does not have a verified issued state')
    artifacts = dict(view['artifacts'])
    pending = [view]
    while pending:
        current = pending.pop()
        for edge in current['sad'].get('e', {}).values():
            if not isinstance(edge, dict) or not isinstance(edge.get('n'), str):
                continue
            said = edge['n']
            if said == credential_said or said in artifacts:
                continue
            source = credentialing.credential(vault, said)
            if source['status']['et'] != 'issued':
                raise kering.ValidationError(f'Source credential {said} is not issued')
            artifacts[said] = source['proof']
            artifacts.update(source['artifacts'])
            pending.append(source)
    return ipexing.grant(hab, recipient, message, origin=view['proof'],
                        artifacts=list(artifacts.values()))


def admit(vault, hab, grant_said, message=''):
    """Record explicit wallet acceptance and retain its signed admit."""
    from locksmith.core import credentialing

    grant = vault.hby.db.exns.get(keys=(grant_said,))
    if grant is None or grant.route != '/ipex/grant' or grant.sad['ri'] != hab.pre:
        raise kering.ValidationError('Grant is not addressed to the selected identifier')
    credential = grant_credential(vault, grant_said)
    record = vault.db.accepted.get(keys=(credential.said,))
    if record is not None:
        if record.grant != grant_said:
            raise kering.ValidationError('Credential was already accepted from another grant')
        exn = vault.hby.db.exns.get(keys=(record.admit,))
        stream = exchanging.serializeMessage(vault.hby, record.admit)
        return exn, stream[exn.size:]
    credentialing.validate_schema(vault, credential)
    nest = next(nest for nest in exchanging.loadParsedNestedSubstreams(vault.hby, grant_said)
                if nest.serder.said == credential.said)
    proofs = [Blinder(clan=BlindState, qb64=b''.join(part.qb64b for part in proof))
              for proof in nest.bsqs]
    proofs.extend(Blinder(clan=BoundState, qb64=b''.join(part.qb64b for part in proof))
                  for proof in nest.bsss)
    if len(proofs) != 1:
        raise kering.ValidationError('Credential must disclose one registry state proof')
    state = credentialing.credential_state(vault, credential, proofs[0])
    if state.state != 'issued':
        raise kering.ValidationError(f'Credential state is {state.state}, not issued')
    if reply := vault.hby.db.erpy.get(keys=(grant_said,)):
        exn = vault.hby.db.exns.get(keys=(reply.qb64,))
        if (exn is None or exn.route != '/ipex/admit' or exn.pre != hab.pre
                or exn.sad['p'] != grant_said):
            raise kering.ValidationError('Grant already has a different response')
        stream = exchanging.serializeMessage(vault.hby, exn.said)
        atc = stream[exn.size:]
    else:
        exn, atc = ipexing.admit(hab, message, grant)
        prepare(vault, hab, exn, atc)
    vault.db.accepted.pin(keys=(credential.said,), val=AcceptedCredential(grant_said, exn.said))
    return exn, atc


class SendIpexDoer(doing.DoDoer):
    """Submit a retained native exchange and report the transport result."""

    Timeout = 30.0

    def __init__(self, vault, hab, serder, attachment, **kwa):
        self.vault, self.hab = vault, hab
        self.serder, self.attachment = serder, attachment
        super().__init__(doers=[doing.doify(self.sendDo)], **kwa)

    def sendDo(self, tymth=None, tock=0.0, **kwa):
        self.wind(tymth)
        yield self.tock
        delivery = None
        try:
            stream = prepare(self.vault, self.hab, self.serder, self.attachment)
            poster = forwarding.StreamPoster(hby=self.vault.hby, hab=self.hab,
                                              recp=self.serder.sad['ri'], topic='credential')
            prefixes = [self.hab.pre]
            if self.serder.route == '/ipex/grant':
                for nest in exchanging.loadParsedNestedSubstreams(self.vault.hby, self.serder.said):
                    prefixes.append(nest.serder.israid)
                    issuee = nest.serder.iseaid
                    if issuee is not None and issuee != self.serder.sad['ri']:
                        prefixes.append(issuee)
            for pre in dict.fromkeys(prefixes):
                kever = self.vault.hby.kevers[pre]
                for msg in self.vault.hby.db.cloneDelegation(kever, gvrsn=kering.Vrsn_2_0):
                    event = SerderKERI(raw=msg)
                    poster.send(serder=event, attachment=msg[event.size:])
                for msg in self.vault.hby.db.clonePreIter(pre=pre, gvrsn=kering.Vrsn_2_0):
                    event = SerderKERI(raw=msg)
                    poster.send(serder=event, attachment=msg[event.size:])
            poster.send(serder=self.serder, attachment=stream[self.serder.size:])
            doers = poster.deliver()
            if not doers:
                raise kering.ConfigurationError('No transport could submit this IPEX message')
            delivery = doing.DoDoer(doers=doers)
            self.extend([delivery])
            deadline = self.tyme + self.Timeout
            while not delivery.done:
                if self.tyme >= deadline:
                    raise TimeoutError('IPEX transport did not finish before its deadline')
                yield self.tock
            for messenger in poster.messagers:
                if isinstance(messenger, agenting.HTTPStreamMessenger):
                    if messenger.rep is None or not 200 <= messenger.rep.status < 300:
                        raise kering.ValidationError('IPEX transport request failed')
            self.vault.signals.emit_doer_event('Ipex', 'transport_submitted', {'said': self.serder.said})
        except Exception as ex:
            self.vault.signals.emit_doer_event('Ipex', 'send_failed',
                                               {'said': self.serder.said, 'error': str(ex)})
            logger.exception('IPEX submission failed')
        finally:
            if delivery is not None:
                self.remove([delivery])
