"""Translate the existing six Bash stories into private Locksmith commands.

Only test orchestration lives here. Identity/witness bootstrap stays in KLI;
holder and designated-presenter commands call the persistent application. This
adapter writes public proof artifacts, never accepted database rows.
"""
import argparse
import json
from pathlib import Path
import socket
import sys


def request(root, role, body):
    """Call the running vault and return its explicit JSON outcome or fail."""
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(90)
        client.connect(str(root / 'private' / role / 'operator.sock'))
        client.sendall(json.dumps(body).encode() + b'\n')
        with client.makefile('rb') as stream:
            response = json.loads(stream.readline(8 * 1024 * 1024 + 1))
    if not response['ok']:
        raise ValueError(response['error'])
    return response['result']


def main():
    """Translate only explicitly supported scenario arguments; reject others."""
    root, role, *tokens = sys.argv[1:]
    root = Path(root)
    if tokens[0] == 'setup':
        parser = argparse.ArgumentParser()
        parser.add_argument('--observer', required=True)
        args = parser.parse_args(tokens[1:])
        request(root, role, {'op': 'configure', 'registries': {
            'profile': 'full-evidence', 'observer': args.observer}})
        credential = json.loads((root / 'credential.json').read_text())
        request(root, role, {'op': 'schema', 'schema': credential['s']})
        if (root / 'presenter.aid').exists():
            request(root, role, {'op': 'policy', 'credential': credential['d'],
                'presenter': (root / 'presenter.aid').read_text().strip()})
        print(json.dumps({'ready': True, 'application': 'locksmith'}))
        return
    family, verb, *tokens = tokens
    if family == 'vc' and verb == 'registry':
        verb, *tokens = tokens
    parser = argparse.ArgumentParser()
    for flag in ('v2', 'refresh', 'derive', 'custody'):
        parser.add_argument('--' + flag, action='store_true')
    for short, long in (('-a', '--alias'), ('-r', '--recipient'), ('-s', '--said')):
        parser.add_argument(short, long)
    for flag in ('prior', 'from-grant', 'endpoint', 'output', 'plan', 'registry',
                 'controller', 'discloser', 'file', 'ordinal', 'bound-event'):
        parser.add_argument('--' + flag)
    parser.add_argument('--disclose', action='append', default=[])
    parser.add_argument('--opening', action='append', default=[])
    args = parser.parse_args(tokens)
    body = {'op': verb, 'alias': args.alias or role}
    if family == 'ipex':
        body.update(recipient=args.recipient, credential=args.said,
                    from_grant=args.from_grant, disclose=args.disclose,
                    refresh=args.refresh, derive=args.derive,
                    openings=[Path(path).read_text() for path in args.opening])
        if verb in ('inspect',):
            body['said'] = args.said
        elif verb in ('agree', 'admit', 'spurn'):
            body['prior'] = args.said
        elif args.prior:
            body['prior'] = args.prior
        if args.plan:
            plan = json.loads(Path(args.plan.removeprefix('@')).read_text())
            # Scenario files use the native disclosure plan, not a new syntax.
            body['schema'], _, body['disclose'] = plan[0][0]
    elif verb == 'query':
        body.update(registry=args.registry, observer=args.endpoint)
    elif verb == 'list':
        body['op'] = 'inventory'
    elif verb == 'import' and args.custody:
        body.update(op='custody-import', path=args.file, registry=args.registry,
                    controller=args.controller, discloser=args.discloser)
    elif verb == 'opening':
        body.update(registry=args.registry, credential=args.said,
                    from_grant=args.from_grant, ordinal=int(args.ordinal), state='issued')
    else:
        raise ValueError('Unsupported Locksmith scenario operation')
    if args.bound_event:
        body['bound_event'] = args.bound_event
    result = request(root, role, body)
    if args.output:
        material = result.pop('stream', None) or result.get('opening')
        if material is None:
            raise ValueError('Operation did not return a public proof artifact')
        Path(args.output).write_text(material)
    else:
        result.pop('stream', None)
    if family == 'ipex' and verb != 'inspect':
        result['exchange'] = result['said']
        if verb == 'admit':
            result['admitted'] = result.pop('accepted')
    if verb == 'list':
        for item in result['credentials']:
            print(json.dumps(item))
    else:
        print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'ERR: {error}', file=sys.stderr)
        raise SystemExit(1)
