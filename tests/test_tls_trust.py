"""Explicit local CA trust keeps Qt's real TLS peer checks enabled."""

import ssl
import sys
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from PySide6.QtCore import QEventLoop, QTimer, QUrl
from PySide6.QtNetwork import (
    QNetworkAccessManager, QNetworkReply, QNetworkRequest, QSslConfiguration, QSslError,
)

from locksmith.main import configure_tls_trust

# The hosted macos-15 runner's Secure Transport backend refuses these handshakes
# without reporting per-certificate sslErrors (kentbull/locksmith Actions run
# 42259014800, job test (macos-15)); a local macOS 27 host reports them. The
# refusal itself stays mandatory everywhere; only the error detail is optional
# on macOS.
SSL_ERRORS_OPTIONAL = sys.platform == 'darwin'


def assert_refused(error, errors, expected=None):
    assert error == QNetworkReply.NetworkError.SslHandshakeFailedError
    if SSL_ERRORS_OPTIONAL and not errors:
        return
    assert errors
    if expected is not None:
        assert expected in errors


def test_explicit_tls_ca_keeps_peer_and_hostname_checks(qapp, tmp_path):
    # Generate an isolated synthetic localhost certificate, never an OS trust entry.
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Locksmith test CA')])
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=1))
          .not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    cafile, certfile, keyfile = (tmp_path / name for name in ('ca.pem', 'server.pem', 'server-key.pem'))
    cafile.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'trusted localhost')

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
    thread.start()
    original = QSslConfiguration.defaultConfiguration()

    def get(host):
        manager = QNetworkAccessManager()
        reply = manager.get(QNetworkRequest(QUrl(f'https://{host}:{server.server_port}/')))
        errors = []
        reply.sslErrors.connect(lambda values: errors.extend(value.error() for value in values))
        loop, timer = QEventLoop(), QTimer()
        timer.setSingleShot(True)
        timer.timeout.connect(loop.quit)
        reply.finished.connect(loop.quit)
        timer.start(5000)
        loop.exec()
        timer.stop()
        if not reply.isFinished():
            reply.abort()
            pytest.fail('Local Qt TLS request did not finish')
        result = reply.error(), bytes(reply.readAll()), errors
        reply.deleteLater()
        return result

    try:
        # The same live endpoint refuses its untrusted certificate before configuration.
        assert_refused(*get('localhost')[::2])

        configure_tls_trust(cafile)
        configured = QSslConfiguration.defaultConfiguration()
        assert configured.caCertificates()[:-1] == original.caCertificates()
        assert configured.peerVerifyMode() == original.peerVerifyMode()
        assert get('localhost') == (QNetworkReply.NetworkError.NoError, b'trusted localhost', [])

        # Trusting the signer must not authenticate an unlisted host name.
        assert_refused(*get('127.0.0.1')[::2], QSslError.SslError.HostNameMismatch)
    finally:
        QSslConfiguration.setDefaultConfiguration(original)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_explicit_tls_ca_rejects_unusable_bundles(tmp_path):
    original = QSslConfiguration.defaultConfiguration()
    configure_tls_trust(None)
    with pytest.raises(ValueError, match='Cannot read SSL_CERT_FILE'):
        configure_tls_trust(tmp_path / 'missing.pem')
    empty = tmp_path / 'empty.pem'
    empty.write_bytes(b'')
    with pytest.raises(ValueError, match='no valid PEM certificates'):
        configure_tls_trust(empty)
    invalid = tmp_path / 'invalid.pem'
    invalid.write_bytes(b'-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n')
    with pytest.raises(ValueError, match='no valid PEM certificates'):
        configure_tls_trust(invalid)
    assert QSslConfiguration.defaultConfiguration().caCertificates() == original.caCertificates()
