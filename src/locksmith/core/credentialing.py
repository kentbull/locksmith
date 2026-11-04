# -*- encoding: utf-8 -*-
"""Schema selection, native credential issuance, and the wallet's inventory."""
from collections.abc import Mapping
import json
from time import monotonic
import uuid

from PySide6.QtCore import QUrl
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest
from hio.base import doing
from keri import help, kering
from keri.acdc import Registrar, acdcmap, regeventing
from keri.app.habbing import GroupHab
from keri.core import (Blinder, BlindState, BoundState, Noncer, Number, SerderACDC,
                       SerderKERI, messagize, scheming)
from keri.help import helping
from keri.peer import exchanging

from locksmith.core.receipting import LocksmithReceiptor
from locksmith.db.basing import IssuedCredential

logger = help.ogler.getLogger(__name__)


def validate_schema(vault, acdc):
    schema = acdc.schema
    schemer = (scheming.Schemer(sed=schema) if isinstance(schema, Mapping)
               else vault.hby.db.schema.get(keys=(schema,)))
    if schemer is None:
        raise kering.ValidationError(f'Load credential schema {schema} before accepting it')
    # Validate fields without changing the credential's signed wire format.
    schemer.verify(raw=json.dumps(acdc.sad).encode())
    return schemer


def credential_state(vault, acdc, blinder):
    """Verify a disclosed credential against the locally known registry head."""
    regk = acdc.sad.get('rd')
    store = vault.rgy.store
    rip, head = store.seqEvent(regk, 0), store.headEvent(regk)
    if rip is None or head is None:
        raise kering.MissingChainError(f'Missing registry evidence for {regk}')
    updates = []
    for sn in range(1, Number(numh=head.sad['n']).num + 1):
        update = store.seqEvent(regk, sn)
        if update is None:
            raise kering.MissingChainError(f'Missing registry update {sn} for {regk}')
        updates.append(update)
    return regeventing.vet(rip=rip, updates=updates, db=vault.hby.db,
                          acdc=acdc, blinder=blinder)


def credential(vault, said, received=False):
    """Build a wallet view from local issuance or retained grant evidence."""
    artifacts = {}
    pending = False
    if not received and (record := vault.db.issued.get(keys=(said,))):
        acdc = SerderACDC(raw=record.raw.encode())
        recipient = acdc.iseaid
        blinder = Blinder(clan=BlindState, qb64=record.blinder)
        update = vault.rgy.store.event(record.update)
        pending = vault.rgy.store.seqEvent(
            acdc.sad['rd'], Number(numh=update.sad['n']).num) is None
        proof = messagize(serder=acdc, bonds=[blinder.data], framed=False)
    elif record := vault.db.accepted.get(keys=(said,)):
        recipient = vault.hby.db.exns.get(keys=(record.grant,)).sad['ri']
        nests = exchanging.loadParsedNestedSubstreams(vault.hby, record.grant)
        nest = next(nest for nest in nests if nest.serder.said == said)
        acdc = nest.serder
        proof = exchanging.serializeParsedSubstream(nest)
        artifacts = {other.serder.said: exchanging.serializeParsedSubstream(other)
                     for other in nests if other.serder.said != said}
        proofs = [Blinder(clan=BlindState, qb64=b''.join(part.qb64b for part in proof))
                  for proof in nest.bsqs]
        proofs.extend(Blinder(clan=BoundState, qb64=b''.join(part.qb64b for part in proof))
                      for proof in nest.bsss)
        if len(proofs) != 1:
            raise kering.ValidationError('Credential must disclose one registry state proof')
        blinder = proofs[0]
    else:
        raise kering.ValidationError(f'Credential {said} is not in this wallet')
    try:
        if pending:
            raise kering.MissingChainError('Credential registry update is still pending')
        state = credential_state(vault, acdc, blinder)
        status = {'et': state.state, 'dt': state.stamp}
    except kering.MissingChainError:
        status = {'et': 'pending', 'dt': acdc.sad.get('a', {}).get('dt', '')}
    except kering.ValidationError:
        status = {'et': 'unknown', 'dt': acdc.sad.get('a', {}).get('dt', '')}
    schema = acdc.schema
    schemer = (scheming.Schemer(sed=schema) if isinstance(schema, Mapping)
               else vault.hby.db.schema.get(keys=(schema,)))
    return {'sad': acdc.sad, 'schema': schemer.sed if schemer else {}, 'recipient': recipient,
            'status': status, 'proof': proof, 'artifacts': artifacts}


def credentials(vault, received=None):
    stores = ([vault.db.accepted] if received is True else
              [vault.db.issued] if received is False else [vault.db.issued, vault.db.accepted])
    saids = dict.fromkeys(said for store in stores for (said,), _ in store.getTopItemIter())
    return [credential(vault, said, received=received is True) for said in saids]


def delete_credential(vault, said, received=False):
    """Remove one wallet entry while retaining signed protocol history."""
    store = vault.db.accepted if received else vault.db.issued
    return store.rem(keys=(said,))


class LoadSchemaDoer(doing.DoDoer):
    """Load a schema and optionally select its local issuer."""

    Timeout = 15.0

    def __init__(self, app, oobi=None, file_content=None,
                 enable_issuance=False, issuer_aid=None, signal_bridge=None):
        self.vault = app.vault
        self.oobi, self.file_content = oobi, file_content
        self.enable_issuance, self.issuer_aid = enable_issuance, issuer_aid
        self.signals = signal_bridge if signal_bridge is not None else self.vault.signals
        if bool(oobi) == bool(file_content):
            raise ValueError('Provide a schema URL or file content')
        super().__init__(doers=[doing.doify(self.load_schema_do)])

    def load_schema_do(self, tymth, tock=0.0, **opts):
        self.wind(tymth)
        yield self.tock
        manager = reply = None
        try:
            raw = self.file_content
            if self.oobi:
                url = QUrl(self.oobi)
                if url.scheme() not in ('http', 'https'):
                    raise ValueError('Schema URL must use HTTP or HTTPS')
                manager = QNetworkAccessManager()
                reply = manager.get(QNetworkRequest(url))
                deadline = monotonic() + self.Timeout
                while not reply.isFinished():
                    if monotonic() >= deadline:
                        raise TimeoutError('Schema download timed out')
                    yield self.tock
                if reply.error() != QNetworkReply.NetworkError.NoError:
                    raise ValueError(reply.errorString())
                raw = bytes(reply.readAll())
            schemer = scheming.Schemer(raw=raw)
            if self.enable_issuance:
                hab = self.vault.hby.habByPre(self.issuer_aid)
                if hab is None or isinstance(hab, GroupHab):
                    raise ValueError('Select an individual local identifier for issuance')
            self.vault.hby.db.schema.pin(keys=(schemer.said,), val=schemer)
            if self.enable_issuance:
                self.vault.db.issuers.pin(keys=(schemer.said,), val=hab.pre)
            self.signals.emit_doer_event('LoadSchemaDoer', 'schema_loaded', {
                'title': schemer.sed.get('title', 'Untitled'), 'said': schemer.said,
                'enable_issuance': self.enable_issuance, 'success': True})
        except Exception as ex:
            logger.exception('Schema loading failed')
            self.signals.emit_doer_event('LoadSchemaDoer', 'schema_load_failed',
                                        {'error': str(ex), 'success': False})
        finally:
            if reply is not None and not reply.isFinished():
                reply.abort()
            if manager is not None:
                manager.deleteLater()


class IssueCredentialDoer(doing.DoDoer):
    """Issue a native credential with its own blindable state registry."""

    def __init__(self, app, schema_said, recipient_pre, attributes, edges=None, rules=None,
                 codes=None, signal_bridge=None):
        self.vault = app.vault
        self.schema_said, self.recipient_pre = schema_said, recipient_pre
        self.attributes, self.edges, self.rules = attributes, edges or {}, rules
        self.codes = codes or []
        self.signals = signal_bridge if signal_bridge is not None else self.vault.signals
        super().__init__(doers=[doing.doify(self.issue_credential_do)])

    def issue_credential_do(self, tymth, tock=0.0, **opts):
        self.wind(tymth)
        yield self.tock
        receiptor = None
        try:
            issuer = self.vault.db.issuers.get(keys=(self.schema_said,))
            hab = self.vault.hby.habByPre(issuer)
            if hab is None or isinstance(hab, GroupHab):
                raise ValueError('Select an individual local identifier for this schema')
            schemer = self.vault.hby.db.schema.get(keys=(self.schema_said,))
            if schemer is None:
                raise kering.ValidationError(f'Load credential schema {self.schema_said} before issuing it')
            properties = schemer.sed.get('properties', {})
            attribute_schema = properties.get('a', {})
            candidates = attribute_schema.get('oneOf', [attribute_schema])
            attribute_schema = next((item for item in candidates
                                     if isinstance(item, Mapping) and item.get('type') == 'object'), {})
            attributes = {'d': '', 'dt': helping.nowIso8601(), **self.attributes}
            if 'u' in attribute_schema.get('properties', {}):
                attributes['u'] = Noncer().qb64
            nonce = Noncer().qb64 if 'u' in properties else None
            registrar = Registrar(rgy=self.vault.rgy)
            registry = registrar.makeRegistry(name=uuid.uuid4().hex, prefix=hab.pre)
            edges = {'d': '', **{name: {'n': edge['cred_said'], 's': edge['schema_said']}
                                for name, edge in self.edges.items()}} if self.edges else None
            acdc = acdcmap(israid=hab.pre, uuid=nonce, regid=registry.regk, schema=self.schema_said,
                           attribute=attributes,
                           iseaid=self.recipient_pre, edge=edges, rule=self.rules)
            schemer = validate_schema(self.vault, acdc)
            rip = self.vault.rgy.store.event(registry.regk)
            auths = {}
            for entry in self.codes:
                wit, code = entry.split(':', 1)
                auths[wit] = f'{code}#{helping.nowIso8601()}'
            receiptor = LocksmithReceiptor(hby=self.vault.hby)
            self.extend([receiptor])
            yield from self.anchor(registry, rip, receiptor, auths)
            blinder, update = registrar.issue(registry, acdc=acdc, state='issued')
            self.vault.db.issued.pin(keys=(acdc.said,),
                                     val=IssuedCredential(acdc.raw.decode(), blinder.qb64, update.said))
            yield from self.anchor(registry, update, receiptor, auths)
            self.signals.emit_doer_event('IssueCredentialDoer', 'credential_issued', {
                'schema_title': schemer.sed.get('title', 'Untitled'),
                'schema_said': self.schema_said, 'credential_said': acdc.said,
                'recipient_pre': self.recipient_pre, 'success': True})
        except Exception as ex:
            logger.exception('Credential issuance failed')
            self.signals.emit_doer_event('IssueCredentialDoer', 'credential_issuance_failed',
                                        {'error': str(ex), 'schema_said': self.schema_said, 'success': False})
        finally:
            if receiptor is not None:
                self.remove([receiptor])

    def anchor(self, registry, event, receiptor, auths):
        hab = registry.hab
        seal = dict(i=registry.regk, s=event.sad['n'], d=event.said)
        raw = (hab.rotate(data=[seal]) if hab.kever.estOnly else hab.interact(data=[seal]))
        anchor = SerderKERI(raw=raw)
        receipt = receiptor.receipt(hab.pre, sn=anchor.sn, auths=auths)
        deadline = self.tyme + 30.0
        try:
            for _ in receipt:
                if self.tyme >= deadline:
                    raise TimeoutError('Witness receipts are still pending for credential issuance')
                yield self.tock
        finally:
            receipt.close()
        if not registry.anchorMsg(event.said):
            raise kering.ValidationError('Registry anchor is still pending')
