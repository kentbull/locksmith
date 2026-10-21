"""One Qt/HIO vault owner with private local control and ordinary CESR intake.

The scheduling and cleanup sequence follows Locksmith's vault-open dialog and
QtTask. The local socket is an R&D operator adapter, not an interoperable wallet
or provisioning protocol. Qt's UserAccessOption and an owner-only parent protect
local commands independently of the public protocol listener.
"""
import json
import os
from pathlib import Path

import falcon
from hio.core import http
from PySide6.QtCore import QObject, QTimer
from PySide6.QtNetwork import QLocalServer
from keri.acdc import Regery
from keri.app import habbing
from keri.app.httping import CESR_CONTENT_TYPE
from locksmith.core.apping import LocksmithApplication
from locksmith.core.tasking import run_qt_task
from locksmith.core.vaulting import Vault
from locksmith.driver.operations import execute

MAX_REQUEST = 8 * 1024 * 1024


class Intake:
    """Queue public CESR through the vault's actual durable mailbox intake."""

    def __init__(self, vault):
        """Borrow the one vault; do not create a parser or evidence store."""
        self.vault = vault

    def on_post(self, req, rep):
        """Accept a finite CESR frame for processing, without implying admission."""
        if (req.content_type or '').split(';')[0] != CESR_CONTENT_TYPE:
            raise falcon.HTTPUnsupportedMediaType()
        raw = req.bounded_stream.read(MAX_REQUEST + 1)
        if not raw or len(raw) > MAX_REQUEST:
            raise falcon.HTTPBadRequest(description='Expected a bounded CESR message')
        self.vault.mbx.messages.append((raw, None))
        rep.status = falcon.HTTP_202
        rep.media = {'queued': True}

    on_put = on_post


class LocalControl(QObject):
    """Execute one local operator request cooperatively; reject concurrent work."""

    def __init__(self, app, path):
        """Listen at an unused socket path inside an existing private directory."""
        super().__init__()
        parent = Path(path).absolute().parent
        info = parent.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('Control socket requires an owner-only parent directory')
        self.app, self.active = app, None
        self.clients = set()
        self.server = QLocalServer(self)
        self.server.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
        if not self.server.listen(str(Path(path).absolute())):
            raise RuntimeError(self.server.errorString())
        self.server.newConnection.connect(self._connect)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._advance)
        self.timer.start(20)

    def _connect(self):
        """Retain bounded clients until one request completes or disconnects."""
        while self.server.hasPendingConnections():
            client = self.server.nextPendingConnection()
            client.setReadBufferSize(MAX_REQUEST + 1)
            self.clients.add(client)
            client.readyRead.connect(lambda client=client: self._read(client))
            client.disconnected.connect(lambda client=client: self._disconnect(client))
            # Data may have arrived before readyRead was connected.
            self._read(client)

    def _read(self, client):
        """Decode one JSON line; never accept a second concurrent mutation."""
        if client.bytesAvailable() > MAX_REQUEST:
            self._reply(client, error='Operator request exceeds size limit')
        elif client.canReadLine():
            if self.active:
                self._reply(client, error='Another operator command is running')
                return
            try:
                request = json.loads(bytes(client.readLine()))
                if not isinstance(request, dict):
                    raise ValueError('Expected a JSON object')
                self.active = (client, execute(self.app, request))
            except Exception as ex:
                self._reply(client, error=str(ex))

    def _advance(self):
        """Advance one generator step while Qt and protocol processing stay live."""
        if not self.active:
            return
        client, action = self.active
        try:
            next(action)
        except StopIteration as result:
            self.active = None
            self._reply(client, result=result.value)
        except Exception as ex:
            self.active = None
            self._reply(client, error=str(ex))

    def _reply(self, client, *, result=None, error=None):
        """Send exactly one JSON outcome and close this local connection."""
        payload = {'ok': error is None, 'result': result, 'error': error}
        client.write(json.dumps(payload).encode() + b'\n')
        client.disconnectFromServer()

    def _disconnect(self, client):
        """Cancel this caller's wait, retaining already authorized outbox work."""
        if self.active and self.active[0] is client:
            self.active[1].close()
            self.active = None
        self.clients.discard(client)
        client.deleteLater()

    def close(self):
        """Stop operator work before the owning application closes its vault."""
        self.timer.stop()
        if self.active:
            self.active[1].close()
            self.active = None
        for client in tuple(self.clients):
            client.abort()
        self.server.close()


def open_runtime(name, base, alias, socket_path, port):
    """Open an existing vault and its real application scheduler.

    name/base locate initialized stores; alias selects a local signer; socket_path
    is private operator IPC; port exposes public CESR. Passcode comes only from
    KLI_KEYSTORE_PASSCODE. Return app/control; caller closes control then app.
    """
    app = LocksmithApplication()
    hby = habbing.Habery(name=name, base=base, bran=os.environ.get('KLI_KEYSTORE_PASSCODE'))
    rgy = Regery(hby=hby, name=name, base=base)
    try:
        if hby.habByName(alias) is None:
            raise ValueError('Selected local identifier does not exist')
        vault = Vault(app, hby, rgy)
        api = falcon.App()
        intake = Intake(vault)
        api.add_route('/', intake)
        api.add_route('/ingest', intake)
        server = http.Server(port=port, app=api)
        qtask = run_qt_task([vault, http.ServerDoer(server=server)])
        app.open_vault(name, vault, qtask)
        app.hab = hby.habByName(alias)
        control = LocalControl(app, socket_path)
        return app, control
    except Exception:
        if app.is_vault_open:
            app.close_vault()
        else:
            rgy.close()
            hby.close()
        raise
