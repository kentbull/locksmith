"""Run a persistent Locksmith vault or submit one private local JSON command."""
import argparse
import json
import signal
import socket
import sys


def main():
    """Expose explicit run/call modes without putting passcodes on command lines."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('run')
    for key in ('name', 'base', 'alias', 'socket'):
        run.add_argument('--' + key, required=True)
    run.add_argument('--port', type=int, required=True)
    call = commands.add_parser('call')
    call.add_argument('--socket', required=True)
    call.add_argument('--timeout', type=float, default=90)
    args = parser.parse_args()
    if args.command == 'call':
        # This client is a separate process; blocking here cannot stall the vault.
        request = json.load(sys.stdin)
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(args.timeout)
            client.connect(args.socket)
            client.sendall(json.dumps(request).encode() + b'\n')
            with client.makefile('rb') as response:
                raw = response.readline(8 * 1024 * 1024 + 1)
        result = json.loads(raw)
        print(json.dumps(result))
        return 0 if result['ok'] else 1
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication
    from locksmith.driver.runtime import open_runtime
    qt = QApplication.instance() or QApplication([])
    app, control = open_runtime(args.name, args.base, args.alias, args.socket, args.port)
    # A periodic Qt callback lets Python handle SIGTERM during the event loop.
    heartbeat = QTimer()
    heartbeat.timeout.connect(lambda: None)
    heartbeat.start(100)
    signal.signal(signal.SIGTERM, lambda *_: qt.quit())
    signal.signal(signal.SIGINT, lambda *_: qt.quit())
    try:
        return qt.exec()
    finally:
        control.close()
        app.close_vault()


if __name__ == '__main__':
    raise SystemExit(main())
