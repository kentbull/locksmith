"""Private driver lifecycle and mailbox intake use the actual application owner."""
import json
from time import monotonic, sleep

import pytest
from falcon import testing
from PySide6.QtNetwork import QLocalSocket
from keri.app import habbing
from locksmith.driver.runtime import LocalControl, Intake, open_runtime
from test_keri_v2_compat import ipex_vaults as ipex_vaults


def call(qapp, path, request):
    """Exchange one local command while pumping the real Qt event loop."""
    client = QLocalSocket()
    client.connectToServer(str(path))
    assert client.waitForConnected(1000)
    client.write(json.dumps(request).encode() + b'\n')
    deadline = monotonic() + 5
    while not client.canReadLine() and monotonic() < deadline:
        qapp.processEvents()
        sleep(.01)
    assert client.canReadLine(), client.errorString()
    result = json.loads(bytes(client.readLine()))
    client.abort()
    return result


def test_private_control_uses_open_application_and_rejects_unknown(qapp, ipex_vaults, tmp_path):
    """No new vault is opened per command; malformed commands fail explicitly."""
    app = ipex_vaults('driver-control')
    tmp_path.chmod(0o700)
    path = tmp_path / 'operator.sock'
    control = LocalControl(app, path)
    try:
        assert call(qapp, path, {'op': 'status'})['result']['name'] == app.name
        hab = app.hby.makeHab(name='holder')
        failure = call(qapp, path, {'op': 'unknown', 'alias': 'holder'})
        assert not failure['ok'] and 'Unknown operator action' in failure['error']
        assert hab.pre in app.hby.kevers
    finally:
        control.close()
    assert not path.exists()
    tmp_path.chmod(0o755)
    with pytest.raises(ValueError, match='owner-only'):
        LocalControl(app, path)


def test_cesr_http_enters_mailbox_without_admission(ipex_vaults):
    """Both public methods queue exact bytes and report transport acceptance only."""
    import falcon
    app = ipex_vaults('driver-intake')
    api = falcon.App()
    api.add_route('/', Intake(app.vault))
    client = testing.TestClient(api)
    for method in ('POST', 'PUT'):
        result = client.simulate_request(path='/', method=method, body=b'not-yet-verified',
                                         headers={'content-type': 'application/cesr'})
        assert result.status_code == 202 and result.json == {'queued': True}
        assert app.vault.mbx.messages.popleft() == (b'not-yet-verified', None)
    assert client.simulate_post('/', body=b'{}', content_type='application/json').status_code == 415
    assert not list(app.vault.db.accepted.getTopItemIter())


def test_real_runtime_owns_and_closes_one_vault(qapp, tmp_path, monkeypatch):
    """Open initialized stores, run actual QtTask, then deterministically close."""
    monkeypatch.delenv('KLI_KEYSTORE_PASSCODE', raising=False)
    name, base = 'driver-runtime', tmp_path.name
    with habbing.openHby(name=name, base=base, temp=False) as hby:
        hby.makeHab(name='holder')
    tmp_path.chmod(0o700)
    path = tmp_path / 'runtime.sock'
    app, control = open_runtime(name, base, 'holder', path, 0)
    vault = app.vault
    try:
        result = call(qapp, path, {'op': 'status'})
        assert result['ok'] and result['result']['open']
        assert app.qtask.doist.deeds
    finally:
        control.close()
        app.close_vault()
    assert vault.closed and not vault.db.opened and not vault.hby.db.opened
