"""Prepare explicit public introductions and isolated local service identities."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import string
import sys

from keri import Vrsn_2_0
from keri.app import Habery, openHby
from keri.core import Parser, SerderKERI
from keri.peer.exchanging import serializeParsedSubstream
from kfregistrar.core.serving import makeContext


def introductions(config_path):
    """Verify each selected Share file, copying only its public KEL support."""
    config_path = Path(config_path).resolve()
    config = json.loads(config_path.read_text())
    if not isinstance(config, dict) or set(config) != {'publishers', 'readers'}:
        raise ValueError('Config must contain only publishers and readers arrays')
    for role, paths in config.items():
        if not isinstance(paths, list) or not paths or any(not isinstance(p, str) or not p for p in paths):
            raise ValueError(f'{role} must be a nonempty array of public introduction paths')
    roles, streams = {}, {}
    with openHby(name='local-registry-introductions', temp=True, version=Vrsn_2_0) as hby:
        context = makeContext(hby)
        try:
            for role, paths in config.items():
                roles[role] = []
                for value in paths:
                    path = (config_path.parent / value).resolve()
                    if path not in streams:
                        with path.open('rb') as source:
                            raw = source.read(8 * 1024 * 1024 + 1)
                        if not raw or len(raw) > 8 * 1024 * 1024:
                            raise ValueError(f'Empty or oversized public introduction: {path}')
                        ims = bytearray(raw)
                        parser, frames = Parser(version=Vrsn_2_0), []
                        while ims:
                            frames.append(parser.parseOneBare(ims=ims, processive=False))
                        if (ims or not frames or frames[0].serder.ilk not in ('icp', 'dip')
                                or any(not isinstance(frame.serder, SerderKERI)
                                       or frame.serder.ilk not in ('icp', 'dip', 'rot', 'drt', 'ixn', 'rct', 'rpy')
                                       for frame in frames)):
                            raise ValueError(f'Expected one complete public Share introduction: {path}')
                        aid = frames[0].serder.pre
                        kel = b''.join(serializeParsedSubstream(frame) for frame in frames
                                       if frame.serder.ilk != 'rpy')
                        result = context.ingest(kel)
                        if result['pending'] or result['rejected'] or aid not in hby.kevers:
                            raise ValueError(f'Public KEL did not verify completely: {path}')
                        streams[path] = aid, kel
                    aid, _ = streams[path]
                    if aid not in roles[role]:
                        roles[role].append(aid)
        finally:
            context.close()
    return roles, b''.join(kel for _, kel in streams.values())


def bootstrap(state, config):
    """Retain encrypted service identities; write only public bootstrap outputs."""
    roles, public = introductions(config)
    state = Path(state).resolve()
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    base = 'locksmith-local-registries/' + hashlib.sha256(str(state).encode()).hexdigest()[:16]
    secret = state / 'service-passcode'
    if not secret.exists():
        with os.fdopen(os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as target:
            # The ordinary KERI CLI strips hyphens as passcode separators.
            target.write(''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(21)))
    secret.chmod(0o600)
    passcode = secret.read_text().strip()
    if len(passcode) != 21 or '-' in passcode:
        raise ValueError('Invalid retained local service passcode; preserve existing identities')
    for service in ('registrar', 'observer'):
        hby = Habery(name=f'localdev-{service}', base=f'{base}/{service}',
                     bran=passcode, version=Vrsn_2_0)
        try:
            hab = hby.habByName(service) or hby.makeHab(service)
            public += bytes(hab.replay(gvrsn=Vrsn_2_0))
            (state / f'{service}.aid').write_text(hab.pre + '\n')
            print(f'{service}: {hab.pre}')
        finally:
            hby.close()
    for role, aids in roles.items():
        (state / f'{role}.aids').write_text('\n'.join(aids) + '\n')
    (state / 'public-bootstrap.cesr').write_bytes(public)
    (state / 'keri-base').write_text(base + '\n')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('Usage: local_registry_bootstrap.py STATE_DIR CONFIG_JSON')
    os.umask(0o077)
    try:
        bootstrap(*sys.argv[1:])
    except Exception as error:
        raise SystemExit(f'Local registry bootstrap refused: {error}') from None
