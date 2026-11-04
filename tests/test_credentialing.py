"""Native wallet issuance and explicit acceptance with independent stores."""
from time import monotonic, sleep

import pytest
from PySide6.QtNetwork import QAbstractSocket, QHostAddress, QTcpServer
from hio.base import doing
from keri import kering
from keri.acdc.messaging import acmSchemaDefault
from keri.core import scheming, SerderKERI

from locksmith.core import credentialing, ipexing
from test_keri_v2_compat import _deliver_ipex, _retry_ipex
from test_keri_v2_compat import ipex_vaults as ipex_vaults


@pytest.fixture
def schema_server(qapp):
    _, schema = acmSchemaDefault()
    schemer = scheming.Schemer(sed=schema)
    server = QTcpServer()
    assert server.listen(QHostAddress.SpecialAddress.LocalHost, 0)
    requests, connections, buffers = [], [], {}

    def respond(connection):
        buffers[connection].extend(bytes(connection.readAll()))
        if b'\r\n\r\n' not in buffers[connection]:
            return
        path = bytes(buffers[connection]).split(b' ')[1].decode()
        buffers[connection].clear()
        requests.append(path)
        if path.startswith('/stall'):
            return
        status, headers, body = b'200 OK', b'', schemer.raw
        if path in ('/redirect', '/redirect308'):
            status = b'302 Found' if path == '/redirect' else b'308 Permanent Redirect'
            headers, body = b'Location: /schema\r\n', b''
        elif path == '/failure':
            status, body = b'503 Service Unavailable', b''
        elif path == '/invalid':
            body = b'not a schema'
        connection.write(b'HTTP/1.1 ' + status + b'\r\n' + headers +
                         f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode() + body)
        connection.disconnectFromHost()

    def accept():
        while server.hasPendingConnections():
            connection = server.nextPendingConnection()
            connections.append(connection)
            buffers[connection] = bytearray()
            connection.readyRead.connect(lambda connection=connection: respond(connection))

    server.newConnection.connect(accept)
    yield f'http://127.0.0.1:{server.serverPort()}', schemer, requests, connections
    for connection in connections:
        connection.abort()
    server.close()
    server.deleteLater()
    qapp.processEvents()


@pytest.mark.parametrize('path', ['/schema', '/redirect', '/redirect308', '/failure',
                                  '/invalid', '/stall-timeout', '/stall-close'])
def test_schema_url_loading_and_cleanup(ipex_vaults, schema_server, qapp, monkeypatch, path):
    url, schemer, requests, connections = schema_server
    app = ipex_vaults('schema-download')
    events, clock = [], [0.0]
    monkeypatch.setattr(credentialing, 'monotonic', lambda: clock[0])
    app.vault.signals.doer_event.connect(lambda name, event, data: events.append((event, data)))
    doer = credentialing.LoadSchemaDoer(app, oobi=url + path)
    app.qtask.extend([doer])
    deadline = monotonic() + 3.0
    while path not in requests and monotonic() < deadline:
        qapp.processEvents()
        app.qtask.run()
        sleep(0.001)
    assert path in requests
    if path.startswith('/stall'):
        assert not doer.done
        assert not events
        assert app.hby.db.schema.get((schemer.said,)) is None
    if path == '/stall-close':
        app.close_vault()
    else:
        if path == '/stall-timeout':
            clock[0] = doer.Timeout + 1
        while not doer.done and monotonic() < deadline:
            qapp.processEvents()
            app.qtask.run()
            sleep(0.001)
        assert doer.done
        if path in ('/schema', '/redirect', '/redirect308'):
            assert events[-1][0] == 'schema_loaded'
            assert app.hby.db.schema.get((schemer.said,)).raw == schemer.raw
        else:
            assert events[-1][0] == 'schema_load_failed'
            assert app.hby.db.schema.get((schemer.said,)) is None
        if path == '/stall-timeout':
            assert 'timed out' in events[-1][1]['error']
    while any(connection.state() != QAbstractSocket.SocketState.UnconnectedState
              for connection in connections) and monotonic() < deadline:
        qapp.processEvents()
        sleep(0.001)
    assert all(connection.state() == QAbstractSocket.SocketState.UnconnectedState
               for connection in connections)
    if path == '/stall-close':
        assert not events


def _load_schema(app, issuer):
    _, schema = acmSchemaDefault()
    schemer = scheming.Schemer(sed=schema)
    doer = credentialing.LoadSchemaDoer(
        app, file_content=schemer.raw, enable_issuance=True, issuer_aid=issuer.pre)
    doing.Doist(doers=[doer], tock=0.03125, limit=1.0).do()
    assert app.vault.db.issuers.get((schemer.said,)) == issuer.pre
    assert app.vault.rgy.regs == {}
    return schemer


def _issue(app, schema, recipient, attributes=None, edges=None):
    events = []
    callback = lambda name, event, data: events.append((name, event, data))
    app.vault.signals.doer_event.connect(callback)
    doer = credentialing.IssueCredentialDoer(
        app, schema.said, recipient.pre, attributes or {'LEI': '254900OPPU84GM83MG36'},
        edges=edges)
    doing.Doist(doers=[doer], tock=0.03125, limit=1.0).do()
    app.vault.signals.doer_event.disconnect(callback)
    assert doer.done
    assert events[-1][1] == 'credential_issued', events
    return events[-1][2]['credential_said']


def test_native_issuance_keeps_independent_credentials_valid_after_reopen(ipex_vaults):
    app = ipex_vaults('native-issuer')
    issuer = app.hby.makeHab(name='issuer')
    holder = app.hby.makeHab(name='holder')
    schema = _load_schema(app, issuer)
    first = _issue(app, schema, holder)
    second = _issue(app, schema, holder)
    assert first != second
    views = credentialing.credentials(app.vault, received=False)
    assert len(views) == 2
    assert {view['status']['et'] for view in views} == {'issued'}
    assert len({view['sad']['rd'] for view in views}) == 2
    assert all(view['sad']['a']['i'] == holder.pre for view in views)
    assert not credentialing.credentials(app.vault, received=True)
    app.close_vault()
    app = ipex_vaults('native-issuer')
    assert {view['sad']['d'] for view in credentialing.credentials(app.vault)} == {first, second}
    assert credentialing.credential(app.vault, first)['status']['et'] == 'issued'
    assert credentialing.delete_credential(app.vault, first)
    assert [view['sad']['d'] for view in credentialing.credentials(app.vault)] == [second]
    assert len(app.vault.rgy.regs) == 2


def test_grant_collects_shared_sources_without_hiding_inventory_after_deletion(ipex_vaults):
    from keri.peer import exchanging

    app = ipex_vaults('shared-source')
    hab = app.hby.makeHab(name='issuer')
    schema = _load_schema(app, hab)
    source = _issue(app, schema, hab)
    child = _issue(app, schema, hab, edges={
        'source_a': {'cred_said': source, 'schema_said': schema.said},
        'source_b': {'cred_said': source, 'schema_said': schema.said},
    })
    grant, atc = ipexing.grant(app.vault, hab, child, hab.pre)
    ipexing.prepare(app.vault, hab, grant, atc)
    assert app.vault.exc.complete(grant.said)
    nested = exchanging.loadParsedNestedSubstreams(app.hby, grant.said)
    assert [nest.serder.said for nest in nested] == [child, source]

    assert credentialing.delete_credential(app.vault, source)
    assert [view['sad']['d'] for view in credentialing.credentials(app.vault)] == [child]
    assert credentialing.credential(app.vault, child)['status']['et'] == 'issued'
    with pytest.raises(kering.ValidationError, match='not in this wallet'):
        ipexing.grant(app.vault, hab, child, hab.pre)


def test_native_grant_requires_evidence_schema_and_consent_before_inventory(ipex_vaults):
    from keri.peer import exchanging

    sender, receiver = ipex_vaults('issue-sender'), ipex_vaults('issue-receiver')
    issuer, holder = sender.hby.makeHab(name='issuer'), receiver.hby.makeHab(name='holder')
    schema = _load_schema(sender, issuer)
    said = _issue(sender, schema, holder)
    _deliver_ipex(receiver.vault, issuer.replay(gvrsn=kering.Vrsn_2_0))
    _deliver_ipex(sender.vault, holder.replay(gvrsn=kering.Vrsn_2_0))
    grant, attachment = ipexing.grant(sender.vault, issuer, said, holder.pre)
    stream = ipexing.prepare(sender.vault, issuer, grant, attachment)
    _deliver_ipex(receiver.vault, stream)
    assert not receiver.vault.exc.complete(grant.said)
    with pytest.raises(kering.ValidationError):
        ipexing.admit(receiver.vault, holder, grant.said)
    assert not credentialing.credentials(receiver.vault)
    # Prepared TEL is fixture input; observer ingestion is a separate service boundary.
    regk = credentialing.credential(sender.vault, said)['sad']['rd']
    for sn in (0, 1):
        receiver.vault.rgy.store.accept(regk, sn, sender.vault.rgy.store.seqEvent(regk, sn))
    _retry_ipex(receiver.vault)
    assert receiver.vault.exc.complete(grant.said)
    assert not credentialing.credentials(receiver.vault)
    with pytest.raises(kering.ValidationError, match='Load credential schema'):
        ipexing.admit(receiver.vault, holder, grant.said)
    receiver.hby.db.schema.pin((schema.said,), schema)
    admit, atc = ipexing.admit(receiver.vault, holder, grant.said)
    assert receiver.vault.exc.complete(admit.said)
    _deliver_ipex(sender.vault, admit.raw + atc)
    assert sender.vault.exc.complete(admit.said)
    assert ipexing.admit(receiver.vault, holder, grant.said)[0].said == admit.said
    assert [view['sad']['d'] for view in credentialing.credentials(receiver.vault, received=True)] == [said]
    assert not credentialing.credentials(receiver.vault, received=False)
    receiver.close_vault()
    receiver = ipex_vaults('issue-receiver')
    view = credentialing.credential(receiver.vault, said)
    assert view['status']['et'] == 'issued'
    assert view['proof']
    assert receiver.vault.db.accepted.get((said,)).admit == admit.said

    retained = exchanging.serializeMessage(receiver.hby, admit.said)
    assert credentialing.delete_credential(receiver.vault, said, received=True)
    receiver.close_vault()
    receiver = ipex_vaults('issue-receiver')
    holder = receiver.hby.habByName('holder')
    assert not credentialing.credentials(receiver.vault, received=True)
    _deliver_ipex(receiver.vault, stream)
    restored, restored_atc = ipexing.admit(receiver.vault, holder, grant.said,
                                          message='Restore this credential')
    assert restored.raw == admit.raw
    assert restored.raw + restored_atc == retained
    assert receiver.vault.db.accepted.get((said,)).admit == admit.said
    assert receiver.hby.db.erpy.get((grant.said,)).qb64 == admit.said
    assert [view['sad']['d'] for view in credentialing.credentials(receiver.vault, received=True)] == [said]


def test_issuance_rejects_schema_mismatch(ipex_vaults):
    app = ipex_vaults('schema-mismatch')
    hab = app.hby.makeHab(name='issuer')
    _, schema = acmSchemaDefault()
    schema['properties']['a'] = {
        'type': 'object', 'required': ['LEI'],
        'properties': {'LEI': {'type': 'string'}}}
    schema['$id'] = ''
    schemer = scheming.Schemer(sed=schema)
    app.hby.db.schema.pin((schemer.said,), schemer)
    app.vault.db.issuers.pin((schemer.said,), hab.pre)
    events = []
    app.vault.signals.doer_event.connect(lambda name, event, data: events.append((event, data)))
    doer = credentialing.IssueCredentialDoer(app, schemer.said, hab.pre, {'LEI': 123})
    doing.Doist(doers=[doer], tock=0.03125, limit=1.0).do()
    assert events[-1][0] == 'credential_issuance_failed'
    assert 'credential_issued' not in [event for event, _ in events]
    assert not credentialing.credentials(app.vault)
    assert hab.kever.sn == 0


def test_witness_timeout_preserves_pending_issuance_and_closes_receiptor(ipex_vaults, monkeypatch):
    app = ipex_vaults('issuance-timeout')
    witness = app.hby.makeHab(name='witness', transferable=False)
    hab = app.hby.makeHab(name='issuer', wits=[witness.pre], toad=1)
    schema = _load_schema(app, hab)
    receipts = []
    def receipt(self, pre, sn=None, auths=None):
        receipts.append(sn)
        if sn == 1:
            _deliver_ipex(app.vault, witness.witness(SerderKERI(raw=hab.msgOwnEvent(sn=sn))))
            return
        try:
            while True:
                yield self.tock
        finally:
            receipts.append('closed')
    monkeypatch.setattr(credentialing.LocksmithReceiptor, 'receipt', receipt)
    events = []
    app.vault.signals.doer_event.connect(lambda name, event, data: events.append((event, data)))
    doer = credentialing.IssueCredentialDoer(app, schema.said, hab.pre, {'LEI': 'test'})
    doing.Doist(doers=[doer], tock=0.03125, limit=31.0).do()
    assert doer.done
    assert not doer.deeds
    assert receipts == [1, 2, 'closed'], (receipts, events)
    assert events[-1][0] == 'credential_issuance_failed'
    ((said,), _), = app.vault.db.issued.getTopItemIter()
    app.vault.rgy.processEscrows()
    assert credentialing.credential(app.vault, said)['status']['et'] == 'pending'
    with pytest.raises(kering.ValidationError, match='verified issued state'):
        ipexing.grant(app.vault, hab, said, hab.pre)
    app.close_vault()
    reopened = ipex_vaults('issuance-timeout')
    assert len(list(reopened.vault.db.issued.getTopItemIter())) == 1
    reopened.vault.rgy.processEscrows()
    assert credentialing.credential(reopened.vault, said)['status']['et'] == 'pending'
    hab = reopened.hby.habByName('issuer')
    witness = reopened.hby.habByName('witness')
    _deliver_ipex(reopened.vault, witness.witness(SerderKERI(raw=hab.msgOwnEvent(sn=2))))
    reopened.vault.rgy.processEscrows()
    assert credentialing.credential(reopened.vault, said)['status']['et'] == 'issued'


@pytest.mark.parametrize('kind', [kering.Kinds.json, kering.Kinds.cbor, kering.Kinds.mgpk])
@pytest.mark.parametrize('state', ['issued', 'revoked'])
def test_native_credential_content_kind_and_acceptance_state(ipex_vaults, kind, state):
    from keri.acdc import Registrar, acdcmap
    from keri.acdc import ipexing as native_ipexing
    from keri.core import messagize
    from keri.peer import exchanging

    sender, receiver = ipex_vaults('content-sender'), ipex_vaults('content-receiver')
    issuer, holder = sender.hby.makeHab(name='issuer'), receiver.hby.makeHab(name='holder')
    schema = _load_schema(sender, issuer)
    registrar = Registrar(rgy=sender.vault.rgy)
    reg = registrar.makeRegistry(name='content', prefix=issuer.pre)
    rip = sender.vault.rgy.store.event(reg.regk)
    issuer.interact(data=[dict(i=reg.regk, s=rip.sad['n'], d=rip.said)])
    assert reg.anchorMsg(rip.said)
    acdc = acdcmap(israid=issuer.pre, regid=reg.regk, iseaid=holder.pre,
                   schema=schema.said, attribute={'d': '', 'LEI': 'test'}, kind=kind)
    blinder, update = registrar.issue(reg, acdc=acdc, state=state)
    issuer.interact(data=[dict(i=reg.regk, s=update.sad['n'], d=update.said)])
    assert reg.anchorMsg(update.said)
    _deliver_ipex(receiver.vault, issuer.replay(gvrsn=kering.Vrsn_2_0))
    # Registry data is prepared fixture evidence, not observer delivery.
    for sn in range(2):
        receiver.vault.rgy.store.accept(reg.regk, sn, sender.vault.rgy.store.seqEvent(reg.regk, sn))
    receiver.hby.db.schema.pin((schema.said,), schema)
    proof = messagize(serder=acdc, bonds=[blinder.data], framed=False)
    grant, attachment = native_ipexing.grant(issuer, holder.pre, 'Credential', origin=proof)
    _deliver_ipex(receiver.vault, grant.raw + attachment)
    assert receiver.vault.exc.complete(grant.said)
    if state == 'issued':
        admit, _ = ipexing.admit(receiver.vault, holder, grant.said)
        assert receiver.vault.exc.complete(admit.said)
        assert credentialing.credential(receiver.vault, acdc.said)['status']['et'] == 'issued'
        nested, = exchanging.loadParsedNestedSubstreams(receiver.hby, grant.said)
        assert nested.serder.kind == kind
        assert nested.serder.raw == acdc.raw
    else:
        with pytest.raises(kering.ValidationError, match='revoked'):
            ipexing.admit(receiver.vault, holder, grant.said)
        assert not credentialing.credentials(receiver.vault)
        assert not receiver.hby.db.erpy.get((grant.said,))
