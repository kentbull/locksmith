"""Registry transport must retain only complete, anchored, current evidence."""
from collections import deque
from contextlib import ExitStack
import json
from time import monotonic, sleep
from types import SimpleNamespace

import pytest
from hio.base import doing
from PySide6.QtNetwork import QHostAddress, QTcpServer
from keri import kering
from keri.acdc import Registrar, Regery, acdcmap
from keri.app import habbing
from keri.core import Diger, Kevery, Parser

from locksmith.core import registries


@pytest.fixture
def wallets():
    from locksmith.db.basing import LocksmithBaser
    with ExitStack() as stack:
        def make(name):
            hby = stack.enter_context(habbing.openHby(name=name, temp=True, version=kering.Vrsn_2_0))
            rgy = Regery(hby=hby, name=name, temp=True)
            db = LocksmithBaser(name=name, temp=True)
            stack.callback(rgy.close)
            stack.callback(db.close)
            return SimpleNamespace(hby=hby, rgy=rgy, db=db,
                                   exc=SimpleNamespace(cues=deque()))
        yield make('registry-sender'), make('registry-receiver')


def _anchor(hab, registry, event):
    hab.interact(data=[dict(i=registry.regk, s=event.sad['n'], d=event.said)], gvrsn=kering.Vrsn_2_0)
    assert registry.anchorMsg(event.said)


def _issue(vault):
    hab = vault.hby.makeHab(name='issuer')
    registrar = Registrar(rgy=vault.rgy)
    registry = registrar.makeRegistry(name='registry', prefix=hab.pre)
    rip = vault.rgy.store.event(registry.regk)
    _anchor(hab, registry, rip)
    acdc = acdcmap(israid=hab.pre, regid=registry.regk, attribute={'d': '', 'value': 'example'})
    _, update = registrar.issue(registry, acdc=acdc, state='issued')
    _anchor(hab, registry, update)
    return hab, registrar, registry, acdc


def _copy_kel(source, receiver):
    raw = b''.join(source.db.clonePreIter(pre=source.pre, gvrsn=kering.Vrsn_2_0))
    Parser(version=kering.Vrsn_2_0).parse(
        ims=bytearray(raw), kvy=Kevery(db=receiver.hby.db, local=False, lax=False))


def test_full_evidence_accepts_updates_and_rejects_rollback(wallets):
    from locksmith.core import evidence

    sender, receiver = wallets
    issuer, registrar, registry, acdc = _issue(sender)
    initial, headers = _full_reply(sender, registry)
    first = evidence.receive(receiver, registry.regk, initial, headers)
    assert first.sn == 1
    assert evidence.receive(receiver, registry.regk, initial, headers).said == first.said

    _, update = registrar.issue(registry, acdc=acdc, state='revoked')
    _anchor(issuer, registry, update)
    full, current_headers = _full_reply(sender, registry)
    assert evidence.receive(receiver, registry.regk, full, current_headers).said == update.said
    with pytest.raises(kering.ValidationError):
        evidence.receive(receiver, registry.regk, initial, headers)
    assert receiver.rgy.store.headEvent(registry.regk).said == update.said
    receiver.rgy.baser.close(clear=False)
    receiver.rgy.baser.reopen(reuse=True)
    assert receiver.rgy.store.headEvent(registry.regk).said == update.said


@pytest.fixture
def service(qapp):
    """Yield a loopback Qt HTTP fixture with configurable replies; this is not a KF service."""
    server = QTcpServer()
    assert server.listen(QHostAddress.SpecialAddress.LocalHost, 0)
    connections, buffers, requests = [], {}, []
    state = {'respond': lambda method, path, body: (200, b'{}')}
    def read(connection):
        """Buffer complete Content-Length requests and reply through the configured fixture callback."""
        buffers[connection].extend(bytes(connection.readAll()))
        raw = buffers[connection]
        while b'\r\n\r\n' in raw:
            header, body = bytes(raw).split(b'\r\n\r\n', 1)
            headers = dict(line.split(b':', 1) for line in header.split(b'\r\n')[1:])
            length = int(next(value for key, value in headers.items() if key.lower() == b'content-length'))
            if len(body) < length:
                return
            del raw[:len(header) + 4 + length]
            method, path = [part.decode() for part in header.split(b' ')[:2]]
            requests.append((method, path, body[:length]))
            result = state['respond'](method, path, body[:length])
            if result is None:
                return
            status, response = result[:2]
            extra = result[2] if len(result) == 3 else {}
            extra = ''.join(f'{key}: {value}\r\n' for key, value in extra.items())
            connection_mode = 'keep-alive' if state.get('keepalive') else 'close'
            connection.write(f'HTTP/1.1 {status} Reply\r\nContent-Length: {len(response)}\r\nConnection: {connection_mode}\r\n{extra}\r\n'.encode() + response)
            if not state.get('keepalive'):
                connection.disconnectFromHost()
                return
    def accept():
        while server.hasPendingConnections():
            connection = server.nextPendingConnection()
            connections.append(connection)
            buffers[connection] = bytearray()
            connection.readyRead.connect(lambda connection=connection: read(connection))
    server.newConnection.connect(accept)
    yield f'http://127.0.0.1:{server.serverPort()}', state, requests
    for connection in connections:
        connection.abort()
    server.close()
    server.deleteLater()
    qapp.processEvents()


def _advance(runner, qapp):
    qapp.processEvents()
    runner.tyme = monotonic()
    runner.recur()
    sleep(0.001)


def _run(doer, qapp):
    runner = doing.Doist(doers=[doer], tyme=monotonic(), tock=0.0)
    runner.enter()
    try:
        deadline = monotonic() + 4
        while not doer.done and monotonic() < deadline:
            _advance(runner, qapp)
        assert doer.done
    finally:
        runner.exit()


@pytest.mark.parametrize('accepted', [True, False])
def test_publish_requires_registrar_exact_head(wallets, service, qapp, accepted):
    sender, _ = wallets
    hab, _, registry, _ = _issue(sender)
    url, state, requests = service
    head = sender.rgy.store.headEvent(registry.regk).said
    summary = {'heads': {registry.regk: head if accepted else Diger(ser=b'other').qb64},
               'pending': {}, 'rejected': {}}
    state['respond'] = lambda method, path, body: (200, json.dumps(summary).encode())
    doer = registries.RegistrySyncDoer(sender, hab, registry.regk, registrar_url=url)
    _run(doer, qapp)
    assert (doer.result == summary) is accepted
    assert bool(doer.error) is not accepted
    assert [(method, path) for method, path, _ in requests] == [('POST', '/ingest')]
    parsed = Parser(version=kering.Vrsn_2_0).parseOne(
        ims=bytearray(requests[0][2]), processive=False)
    assert parsed.serder.route == 'tels/publish'
    assert parsed.serder.pre == hab.pre and parsed.sigers is not None
    assert doer.manager is None


@pytest.mark.parametrize('status', [404, 405])
def test_observer_rejects_signed_query(wallets, service, qapp, status):
    sender, receiver = wallets
    _, _, registry, _ = _issue(sender)
    holder = receiver.hby.makeHab(name='holder')
    url, state, requests = service
    state['respond'] = lambda method, path, body: (status, b'{}')
    doer = registries.RegistrySyncDoer(receiver, holder, registry.regk, observer_url=url)
    _run(doer, qapp)
    assert f'HTTP {status}' in doer.error
    assert [(method, path) for method, path, _ in requests] == [('POST', '/')]
    assert doer.result is None and doer.manager is None
    assert receiver.rgy.store.head(registry.regk) is None


@pytest.mark.parametrize('rotations', [0, 4])
def test_wallet_queries_real_full_evidence_observer(wallets, service, qapp, tmp_path, rotations):
    from falcon import testing
    from keri.app.httping import CESR_CONTENT_TYPE
    from locksmith.core import evidence

    Context = pytest.importorskip('kfobserver.core.evidence').Context
    sender, receiver = wallets
    _, _, registry, _ = _issue(sender)
    holder = receiver.hby.makeHab(name='holder')
    for _ in range(rotations):
        holder.rotate(gvrsn=kering.Vrsn_2_0)
    ca = tmp_path / 'unused-ca.pem'
    ca.write_text('No network source pull in this test.')
    source_url = 'https://registrar.example/'
    with habbing.openHby(name='independent-observer', temp=True,
                         version=kering.Vrsn_2_0) as hby:
        observer = Context(hby, readers=[holder.pre], sources=[
            {'url': source_url, 'cafilepath': str(ca)}])
        try:
            assert not observer.ingest(holder.replay(gvrsn=kering.Vrsn_2_0))['rejected']
            stream = evidence.processor(sender).clone([registry.regk])
            assert not observer.observe(source_url, stream)['rejected']
            client = testing.TestClient(observer.app)
            url, state, requests = service
            def respond(method, path, body):
                reply = client.simulate_post(path, body=body,
                                             headers={'Content-Type': CESR_CONTENT_TYPE})
                return reply.status_code, reply.content, {
                    key: value for key, value in reply.headers.items()
                    if key.lower().startswith('observer-') or key.lower() == 'content-type'}
            state['respond'] = respond
            worker = registries.RegistrySyncDoer(receiver, holder, registry.regk,
                                                  observer_url=url)
            _run(worker, qapp)
            assert worker.error == ''
            assert worker.result.said == sender.rgy.store.headEvent(registry.regk).said
            assert [(method, path) for method, path, _ in requests] == [('POST', '/')]
            assert receiver.rgy.store.headEvent(registry.regk).said == worker.result.said
        finally:
            observer.close()


def test_registry_timeout_aborts_request(wallets, service, qapp, monkeypatch):
    sender, _ = wallets
    hab, _, registry, _ = _issue(sender)
    url, state, requests = service
    doer = registries.RegistrySyncDoer(sender, hab, registry.regk, registrar_url=url)
    clock = [monotonic()]
    monkeypatch.setattr(registries, 'monotonic', lambda: clock[0])
    def stall(method, path, body):
        clock[0] += doer.Timeout + 1
    state['respond'] = stall
    _run(doer, qapp)
    assert requests
    assert 'timed out' in doer.error
    assert doer.result is None and doer.manager is None


def test_registry_worker_rebuilds_requests_and_refreshes_revocation(wallets, service, qapp, request):
    from keri.peer import exchanging
    from locksmith.core import evidence
    from locksmith.db.basing import LocksmithBaser

    sender, receiver = wallets
    issuer, registrar, registry, acdc = _issue(sender)
    _copy_kel(issuer, receiver)
    holder = receiver.hby.makeHab(name='holder')
    # Existing accepted state must trigger a refresh after the worker restarts.
    initial, headers = _full_reply(sender, registry)
    evidence.receive(receiver, registry.regk, initial, headers)
    receiver.db = LocksmithBaser(name='registry-worker', temp=True)
    request.addfinalizer(receiver.db.close)
    receiver.exc = exchanging.Exchanger(hby=receiver.hby, handlers=[])
    url, state, requests = service
    receiver.hby.cf.put({'registries': {'observer': url}})
    def respond(method, path, body):
        stream, headers = _full_reply(sender, registry)
        return 200, stream, headers
    state['respond'] = respond
    worker = registries.RegistryEvidenceDoer(receiver)
    checks = []
    receiver.signals = SimpleNamespace(emit_doer_event=lambda name, event, data: checks.append(
        (name, event, data, worker.ensure(registry.regk, holder))))
    assert not worker.ensure(registry.regk, holder)
    assert not worker.ensure(registry.regk, holder)  # Repeated UI reads coalesce.
    runner = doing.Doist(doers=[worker], tyme=monotonic(), tock=0.0)
    runner.enter()
    def until(predicate):
        deadline = monotonic() + 5
        while not predicate() and monotonic() < deadline:
            _advance(runner, qapp)
        assert predicate()
    try:
        until(lambda: worker.ensure(registry.regk, holder))
        assert [path for method, path, _ in requests if method == 'POST'].count('/') == 1
        _, update = registrar.issue(registry, acdc=acdc, state='revoked')
        _anchor(issuer, registry, update)
        worker._fetched[registry.regk] = (worker._fetched[registry.regk][0], monotonic() - 1)
        until(lambda: receiver.rgy.store.headEvent(registry.regk).said == update.said)
        until(lambda: worker.ensure(registry.regk, holder))
        assert [path for method, path, _ in requests if method == 'POST'].count('/') == 2
        assert any(name == 'RegistryEvidence' and event == 'status_checked' and data['success'] and fresh
                   for name, event, data, fresh in checks)
        state['respond'] = lambda method, path, body: (503, b'')
        worker._fetched[registry.regk] = (worker._fetched[registry.regk][0], monotonic() - 1)
        until(lambda: registry.regk in worker.errors)
        assert any(name == 'RegistryEvidence' and event == 'status_checked' and not data['success'] and not fresh
                   for name, event, data, fresh in checks)
        receiver.hby.cf.put({'registries': {'observer': url + '/changed'}})
        assert not worker.ensure(registry.regk, holder)
        state['respond'] = respond
        until(lambda: worker.ensure(registry.regk, holder))
        assert [path for method, path, _ in requests if method == 'POST'].count('/changed/') == 1
        assert receiver.rgy.store.headEvent(registry.regk).said == update.said
    finally:
        runner.exit()
    assert not worker._active
    # A replacement worker must discover accepted heads and fetch them again.
    worker = registries.RegistryEvidenceDoer(receiver)
    runner = doing.Doist(doers=[worker], tyme=monotonic(), tock=0.0)
    runner.enter()
    try:
        until(lambda: [path for method, path, _ in requests if method == 'POST'].count('/changed/') == 2)
        until(lambda: worker.ensure(registry.regk, holder))
        assert receiver.rgy.store.headEvent(registry.regk).said == update.said
    finally:
        runner.exit()
    assert not worker._active


def test_registry_worker_without_services_stays_idle(wallets, qapp):
    sender, _ = wallets
    issuer, _, registry, _ = _issue(sender)
    sender.hby.cf.put({})
    sender.exc.cues.extend([{'kin': 'saved', 'said': 'saved'},
                           {'kin': 'proof', 'said': 'pending'}, {'kin': 'other'}])
    worker = registries.RegistryEvidenceDoer(sender)
    assert not worker.ensure(registry.regk, issuer)
    assert 'observer' in worker.errors[registry.regk]
    runner = doing.Doist(doers=[worker], tyme=monotonic(), tock=0.0)
    runner.enter()
    try:
        for _ in range(5):
            runner.recur()
        assert not worker._active
        assert not worker.published(registry.regk)
        assert list(sender.exc.cues) == [{'kin': 'other'}]
    finally:
        runner.exit()


def test_registry_worker_publishes_owned_history_without_registry_cache(wallets, service, qapp):
    sender, _ = wallets
    issuer, _, registry, _ = _issue(sender)
    url, state, requests = service
    sender.hby.cf.put({'registries': {'registrar': url}})
    sender.rgy.regs.clear()
    head = sender.rgy.store.headEvent(registry.regk).said
    state['respond'] = lambda method, path, body: (200, json.dumps({
        'heads': {registry.regk: head}, 'pending': {}, 'rejected': {}}).encode())
    worker = registries.RegistryEvidenceDoer(sender)
    runner = doing.Doist(doers=[worker], tyme=monotonic(), tock=0.0)
    runner.enter()
    try:
        deadline = monotonic() + 4
        while not worker.published(registry.regk) and monotonic() < deadline:
            _advance(runner, qapp)
        assert worker.published(registry.regk)
        assert [path for method, path, _ in requests if method == 'POST'] == ['/ingest']
        sender.hby.cf.put({'registries': {'registrar': url + '/changed'}})
        assert not worker.published(registry.regk)
        deadline = monotonic() + 4
        while not worker.published(registry.regk) and monotonic() < deadline:
            _advance(runner, qapp)
        assert worker.published(registry.regk)
        assert [path for method, path, _ in requests if method == 'POST'] == ['/ingest', '/changed/ingest']
    finally:
        runner.exit()
    assert not worker._active


def _full_reply(sender, registry):
    """Export real accepted evidence and receiver-observation headers for the fixture."""
    from locksmith.core import evidence
    from keri.help import helping
    stream = evidence.processor(sender).clone([registry.regk])
    return stream, {
        'content-type': 'application/cesr',
        'observer-evidence-state': 'fresh',
        'observer-observed-at': helping.nowIso8601(),
        'observer-registry-head': sender.rgy.store.headEvent(registry.regk).said,
    }


@pytest.mark.parametrize('public', [False, True])
def test_full_observer_fetch_verifies_kels_without_signer_put(wallets, service, qapp, public):
    """Authenticate an unknown issuer and retain an explicit public opening for standing."""
    sender, receiver = wallets
    issuer, registrar, registry, acdc = _issue(sender)
    opening = event = None
    if public:
        opening, event = registrar.issue(registry, acdc, state='revoked')
        sender.rgy.store.retainOpening(event, opening)
        _anchor(issuer, registry, event)
    holder = receiver.hby.makeHab(name='holder')
    url, state, requests = service
    stream, headers = _full_reply(sender, registry)
    state['respond'] = lambda method, path, body: (200, stream, headers)
    doer = registries.RegistrySyncDoer(receiver, holder, registry.regk, observer_url=url)
    _run(doer, qapp)
    assert doer.error == ''
    assert doer.result.said == headers['observer-registry-head']
    assert [(method, path) for method, path, _ in requests] == [('POST', '/')]
    assert issuer.pre in receiver.hby.kevers
    assert receiver.evidence.reger is receiver.rgy.baser
    if public:
        from locksmith.core import credentialing
        assert receiver.rgy.store.opening(event.said) == opening.qb64
        assert credentialing.credential_state(receiver, acdc).state == 'revoked'
        assert not list(receiver.db.custody.getTopItemIter())


@pytest.mark.parametrize('failure', ['head', 'stale', 'future', 'missing', 'pending'])
def test_full_reply_cannot_claim_freshness_without_matching_proof(wallets, failure):
    """Neither a fresh header nor authentic older bytes alone imply a current head."""
    from datetime import timedelta
    from locksmith.core import evidence
    from keri.help import helping
    sender, receiver = wallets
    _, _, registry, _ = _issue(sender)
    stream, headers = _full_reply(sender, registry)
    if failure == 'head':
        headers['observer-registry-head'] = Diger(ser=b'unrelated head').qb64
    elif failure in ('stale', 'future'):
        offset = -60 if failure == 'stale' else 60
        headers['observer-observed-at'] = helping.toIso8601(helping.nowUTC() + timedelta(seconds=offset))
    elif failure == 'missing':
        del headers['observer-observed-at']
    else:
        from keri.core import Counter, Codens
        # Authentic TEL bodies without their issuer KEL remain durable dependencies.
        stream = b''.join(raw + Counter(Codens.AttachmentGroup, count=0,
                         version=kering.Vrsn_2_0).qb64b
                         for raw in sender.rgy.store.cloneTelIter(registry.regk))
    with pytest.raises(kering.ValidationError):
        evidence.receive(receiver, registry.regk, stream, headers)
    if failure == 'pending':
        assert receiver.rgy.store.head(registry.regk) is None
        assert list(receiver.rgy.baser.maes.getTopItemIter())


def test_default_service_publishes_signed_complete_evidence(wallets, service, qapp):
    """Sign the exact KEL/TEL bytes including an independently verifiable public opening."""
    sender, receiver = wallets
    from locksmith.core import evidence
    from keri.acdc import regeventing
    hab, registrar, registry, acdc = _issue(sender)
    opening, event = registrar.issue(registry, acdc, state='revoked')
    sender.rgy.store.retainOpening(event, opening)
    _anchor(hab, registry, event)
    expected = evidence.processor(sender).clone([registry.regk])
    url, state, requests = service
    def accept(method, path, raw):
        """Verify the signed publication envelope and pass its stream through real shared intake."""
        parsed = Parser(version=kering.Vrsn_2_0).parseOne(ims=bytearray(raw), processive=False)
        assert parsed.serder.route == 'tels/publish'
        assert parsed.serder.pre == hab.pre and parsed.sigers is not None
        stream = parsed.serder.sad['q']['stream'].encode()
        assert stream == expected
        assert opening.qb64 == sender.rgy.store.opening(event.said)
        state = regeventing.vet(sender.rgy.store.seqEvent(registry.regk, 0),
                                [sender.rgy.store.seqEvent(registry.regk, sn)
                                 for sn in range(1, event.sn + 1)],
                                db=sender.hby.db, acdc=acdc, blinder=opening)
        assert state.state == 'revoked'
        result = evidence.processor(receiver).ingest(stream)
        return 200, json.dumps(result).encode()
    state['respond'] = accept
    doer = registries.RegistrySyncDoer(sender, hab, registry.regk, registrar_url=url)
    _run(doer, qapp)
    assert doer.error == ''
    assert receiver.rgy.store.head(registry.regk).qb64 == sender.rgy.store.head(registry.regk).qb64
    assert [(method, path) for method, path, _ in requests] == [('POST', '/ingest')]


def test_full_observation_cache_does_not_restart_age(wallets, service, qapp, monkeypatch):
    """A nearly expired observation gets only its remaining lifetime locally."""
    from datetime import timedelta
    from keri.help import helping
    sender, receiver = wallets
    _, _, registry, _ = _issue(sender)
    holder = receiver.hby.makeHab(name='holder')
    url, state, requests = service
    receiver.hby.cf.put({'registries': {'observer': url}})
    stream, headers = _full_reply(sender, registry)
    headers['observer-observed-at'] = helping.toIso8601(helping.nowUTC() - timedelta(seconds=14))
    state['respond'] = lambda method, path, body: (200, stream, headers)
    worker = registries.RegistrySyncDoer(receiver, holder, registry.regk, observer_url=url)
    _run(worker, qapp)
    assert not worker.error
    assert 0 < worker.fresh_until - monotonic() < 1
    cache = registries.RegistryEvidenceDoer(receiver)
    cache._fetched[registry.regk] = (worker.result.said, worker.fresh_until)
    assert cache.ensure(registry.regk, holder)
    monkeypatch.setattr(registries, 'monotonic', lambda: worker.fresh_until + .01)
    assert not cache.ensure(registry.regk, holder)
