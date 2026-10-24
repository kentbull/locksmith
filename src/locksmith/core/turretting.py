# -*- encoding: utf-8 -*-
"""
locksmith.core.challenging module


This module contains the peer-to-peer challenge response protocol

"""
import os
import tempfile

from hio.base import doing
from hio.help import decking
from keri import help
from keri.peer import exchanging
from locksmith.turret import directing
from locksmith.turret.handling import IdentifiersHandler, CredentialsHandler, IPEXGrantRequestHandler
from locksmith.turret.uxd import Server, ServerDoer

logger = help.ogler.getLogger(__name__)

UXD_MAX_CONNECTIONS = 8
UXD_ACCEPTS_PER_TURN = 4
UXD_RX_BUFFER_LIMIT = 8 * 1024 * 1024
UXD_RX_BYTES_PER_TURN = 64 * 1024
UXD_IDLE_TIMEOUT = 30.0


def load_handlers(hby, rgy, exc, cues):

    ids = IdentifiersHandler(hby=hby, cues=cues)
    exc.addHandler(ids)

    chs = CredentialsHandler(hby=hby, rgy=rgy, cues=cues)
    exc.addHandler(chs)

    igr = IPEXGrantRequestHandler(hby=hby, rgy=rgy, cues=cues)
    exc.addHandler(igr)


FORMAT = '%(asctime)s [turret] %(levelname)-8s %(message)s'

class TurretDoer(doing.DoDoer):
    """ Doer for turret"""
    def __init__(self, hby, rgy, locksmith_alias, plugin_identifier, **kwa):
        """  Initialize the TurretDoer

        Args:
            hby: Habitat database instance used for retrieving settings and configurations.
            locksmith_alias: Alias of the locksmith, used to retrieve the habitat settings.
            plugin_identifier: Identifier for the plugin that this doer will utilize.
            **kwa: Additional keyword arguments passed to the base class constructor.
        """
        hab = hby.habByName(locksmith_alias, ns="settings")
        cues = decking.Deck()

        _socket_path = os.path.join(tempfile.gettempdir(), "keripy_kli.s")
        if os.path.exists(_socket_path):
            os.remove(_socket_path)

        server = Server(path=_socket_path, bufsize=8069,
                        maxConnections=UXD_MAX_CONNECTIONS,
                        acceptsPerTurn=UXD_ACCEPTS_PER_TURN,
                        rxbsLimit=UXD_RX_BUFFER_LIMIT,
                        rxbsPerTurn=UXD_RX_BYTES_PER_TURN,
                        tymeout=UXD_IDLE_TIMEOUT)
        server_doer = ServerDoer(server=server)

        exc = exchanging.Exchanger(hby, handlers=[])
        load_handlers(hby, rgy, exc, cues)

        self.shim = ExchangerShim(aid=plugin_identifier, exc=exc)
        directant = directing.Directant(hab=hab, server=server, exchanger=self.shim, cues=cues)

        doers =  [directant, server_doer]

        super(TurretDoer, self).__init__(doers=doers, **kwa)

    def set_plugin_identifier(self, plugin_identifier):
        self.shim.aid = plugin_identifier


class ExchangerShim:

    def __init__(self, aid, exc):
        logger.debug(f"creating with {aid}")
        self.aid = aid
        self.exchanger = exc

    def processEvent(self, serder, tsgs=None, cigars=None, **kwargs):
        print(serder.pretty())
        sender = serder.ked["i"]
        if sender == self.aid:
            self.exchanger.processEvent(serder, tsgs, cigars, **kwargs)
        else:
            logger.info(f"Received an exn message from invalid signer={sender}")

