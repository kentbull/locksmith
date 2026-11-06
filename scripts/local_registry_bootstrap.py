"""Prepare explicit public introductions and isolated local service identities."""
import argparse
import hashlib
import json
import os
import secrets
import signal
import string
import subprocess
from pathlib import Path

from keri import Vrsn_2_0
from keri.app import Habery, openHby
from keri.core import Parser, SerderKERI
from keri.kering import KeriError
from keri.peer.exchanging import serializeParsedSubstream
from kfregistrar.core.serving import makeContext


def introductions(config_path):
    """Verify each selected Share file, copying only its public KEL support."""
    if config_path is None:
        return {"publishers": [], "readers": []}, b""
    config_path = Path(config_path).resolve()
    config = json.loads(config_path.read_text())
    if not isinstance(config, dict) or set(config) != {'publishers', 'readers'}:
        raise ValueError('Config must contain only publishers and readers arrays')
    for role, paths in config.items():
        if not isinstance(paths, list) or any(not isinstance(p, str) or not p for p in paths):
            raise ValueError(f'{role} must be an array of public introduction paths')
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


def tufa_identity(state, service, passcode, ts_repo):
    """Create/reopen one service only through normal Tufa commands, preserving its retained AID."""
    store = ['--name', f'localdev-{service}', '--head-dir', str(state / 'tufa'), '--passcode', passcode]

    def command(*arguments):
        child = subprocess.Popen(['deno', 'run', '--allow-all', '--unstable-ffi', 'packages/tufa/mod.ts',
                                  *arguments, *store], cwd=ts_repo, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = child.communicate(timeout=120)
            if child.returncode:
                raise ValueError(f'Tufa {arguments[0]} failed: {stderr.strip()}')
            return stdout.strip()
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()

    retained = state / f'{service}.aid'
    if not retained.exists():
        command('init')
        command('incept', '--alias', service, '--transferable')
    aid = command('aid', '--alias', service)
    if retained.exists() and retained.read_text().strip() != aid:
        raise ValueError(f'Retained {service} AID differs from its actual Tufa store')
    return aid, command('export', '--alias', service).encode()


def bootstrap(state, config=None, *, registrar_backend='python', observer_backend='python', ts_repo=None):
    """Retain encrypted service identities; write only public bootstrap outputs."""
    backends = {'registrar': registrar_backend, 'observer': observer_backend}
    roles, public = introductions(config)
    if registrar_backend == 'typescript' and roles['publishers']:
        raise ValueError('TypeScript publishers require provider enrollment; configure only static readers here')
    if 'typescript' in backends.values() and ts_repo is None:
        raise ValueError('TypeScript services require their explicit repository path')
    state = Path(state).resolve()
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Service state is bound to one registry topology; older state is never migrated.
    topology = ' '.join(f'{service}={backend}' for service, backend in backends.items())
    marker = state / 'topology'
    if marker.exists():
        if marker.read_text().strip() != topology:
            raise ValueError('Topology differs from retained service state; use a separate state directory')
    elif (state / 'backend').exists() or (state / 'service-passcode').exists():
        raise ValueError('Retained service state has no topology marker; use a separate state directory')
    marker.write_text(topology + '\n')
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
        if backends[service] == 'typescript':
            aid, kel = tufa_identity(state, service, passcode, ts_repo)
        else:
            hby = Habery(name=f'localdev-{service}', base=f'{base}/{service}',
                         bran=passcode, version=Vrsn_2_0)
            try:
                hab = hby.habByName(service) or hby.makeHab(service)
                aid, kel = hab.pre, bytes(hab.replay(gvrsn=Vrsn_2_0))
            finally:
                hby.close()
        public += kel
        (state / f'{service}.aid').write_text(aid + '\n')
        print(f'{service}: {aid}')
    for role, aids in roles.items():
        (state / f'{role}.aids').write_text('\n'.join(aids) + ('\n' if aids else ''))
    (state / 'public-bootstrap.cesr').write_bytes(public)
    (state / 'keri-base').write_text(base + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('state')
    parser.add_argument('config', nargs='?')
    parser.add_argument('--registrar-backend', choices=('python', 'typescript'), default='python')
    parser.add_argument('--observer-backend', choices=('python', 'typescript'), default='python')
    parser.add_argument('--ts-repo', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    def stop(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        bootstrap(args.state, args.config, registrar_backend=args.registrar_backend,
                  observer_backend=args.observer_backend, ts_repo=args.ts_repo)
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except (OSError, ValueError, KeriError, subprocess.SubprocessError) as error:
        raise SystemExit(f'Local registry bootstrap refused: {error}') from None
