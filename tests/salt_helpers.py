"""Explicit real local DH setup for optional registry-root adapter tests."""

from keri.acdc import Registrar
from keri import kering
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread


def establish(vault, issuer, discloser):
    """Create/accept a registry and explicitly approve both parties' exact replies."""
    registry = Registrar(rgy=vault.rgy).makeRegistry(name='established', prefix=issuer.pre)
    rip = vault.rgy.store.event(registry.regk)
    issuer.interact(data=[dict(i=registry.regk, s=rip.sad['n'], d=rip.said)])
    assert registry.anchorMsg(rip.said)
    service = vault.salts.service
    for hab in (issuer, discloser):
        service.trustRoster(hab.pre, [hab.pre])
    init = service.prepareInit(issuer=issuer.pre, discloser=discloser.pre,
                              party=issuer.pre, representative=issuer.pre)
    service.approveReply(init)
    bind = service.prepareBind(init.said, registry.regk, discloser.pre)
    service.approveReply(bind)
    confirm = service.prepareConfirm(init.said, bind.said)
    service.approveReply(confirm)
    assert vault.salts.state.origin(registry.regk).confirm == confirm.said
    return registry


@contextmanager
def capture_http():
    """Capture actual finite HTTP submissions without processing on its thread."""
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_PUT(self):
            received.append(self.rfile.read(int(self.headers['Content-Length'])))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            """Keep test transport logs free of payload bytes."""

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, received
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def group_vaults(open_vault):
    """Build three actual members of one accepted 2-of-3 group, without sockets."""
    apps = [open_vault(f'access-group-{index}', bran='0123456789abcdefghijk') for index in range(3)]
    people = [app.hby.makeHab(name='member', algo='randy') for app in apps]
    for app in apps:
        for person in people:
            app.vault.mbx.parser.parse(ims=person.replay(gvrsn=kering.Vrsn_2_0), local=False)
    groups = [app.hby.makeGroupHab(group='issuer group', mhab=person,
        smids=[member.pre for member in people], isith='2', nsith='2', version=kering.Vrsn_2_0)
        for app, person in zip(apps, people)]
    for app in apps:
        for group in groups:
            app.vault.mbx.parser.parse(ims=group.msgOwnInception(allowPartiallySigned=True,
                gvrsn=kering.Vrsn_2_0), local=False)
        app.hby.kvy.processEscrows()
    assert all(group.accepted for group in groups)
    return apps, people, groups
