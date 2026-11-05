#!/usr/bin/env bash
# Start only the local registry services, after normal wallet onboarding.
set -euo pipefail
umask 077
if [ "$#" -ne 2 ]; then
    echo 'Usage: bash scripts/local-registries.sh STATE_DIR CONFIG_JSON' >&2
    exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
keri_workspace=${KERI_WORKSPACE:-$(cd "$script_dir/../../../.." && pwd)}
state_dir=$1
config_path=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' "$2")
mkdir -p "$state_dir"
chmod 700 "$state_dir"
state_dir=$(cd "$state_dir" && pwd)
registrar_repo="$keri_workspace/core/python/kf-registrar"
observer_repo="$keri_workspace/core/python/kf-observer"

# Fail before provisioning identities or installing anything if another stack owns a port.
python3 - <<'PY'
import socket
for port in (19931, 19932, 19942):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', port))
PY
for repo in "$registrar_repo" "$observer_repo"; do
    uv sync --project "$repo" --locked --extra dev --python 3.14
done
service_python="$registrar_repo/.venv/bin/python"
"$service_python" "$script_dir/local_registry_bootstrap.py" "$state_dir" "$config_path"
registry_base=$(cat "$state_dir/keri-base")
observer_aid=$(cat "$state_dir/observer.aid")
publishers=()
readers=()
while IFS= read -r aid; do publishers+=(--publisher "$aid"); done < "$state_dir/publishers.aids"
while IFS= read -r aid; do readers+=(--reader "$aid"); done < "$state_dir/readers.aids"

key="$state_dir/server-key.pem"
certificate="$state_dir/server-cert.pem"
ca="$state_dir/ca.pem"
ca_key="$state_dir/ca-key.pem"
tls_files=("$ca" "$ca_key" "$certificate" "$key")
existing=0
for file in "${tls_files[@]}"; do
    if [ -e "$file" ]; then existing=$((existing + 1)); fi
done
if [ "$existing" -eq 0 ]; then
    (
        tls_work=$(mktemp -d "$state_dir/.tls.XXXXXX")
        trap 'rm -rf "$tls_work"' EXIT
        openssl req -x509 -newkey rsa:2048 -noenc -sha256 -days 3650 \
            -config /dev/null -subj '/CN=Locksmith local registry CA' \
            -addext 'basicConstraints=critical,CA:TRUE' \
            -addext 'keyUsage=critical,keyCertSign,cRLSign' \
            -addext 'subjectKeyIdentifier=hash' \
            -keyout "$tls_work/ca-key.pem" -out "$tls_work/ca.pem" >/dev/null 2>&1
        openssl req -new -newkey rsa:2048 -noenc -sha256 -config /dev/null \
            -subj '/CN=localhost' -keyout "$tls_work/server-key.pem" \
            -out "$tls_work/server.csr" >/dev/null 2>&1
        cat > "$tls_work/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
        # macOS TLS policy limits server certificate lifetimes independently of CA trust.
        openssl x509 -req -sha256 -days 365 -in "$tls_work/server.csr" \
            -CA "$tls_work/ca.pem" -CAkey "$tls_work/ca-key.pem" -CAcreateserial \
            -extfile "$tls_work/server.ext" -out "$tls_work/server-cert.pem" >/dev/null 2>&1
        for name in ca.pem ca-key.pem server-cert.pem server-key.pem; do
            cp "$tls_work/$name" "$state_dir/$name"
        done
    )
fi
for file in "${tls_files[@]}"; do
    if [ ! -f "$file" ]; then
        echo 'Incomplete retained TLS files; restore all four files or use a new state directory.' >&2
        exit 1
    fi
done
chmod 600 "${tls_files[@]}"
openssl x509 -in "$ca" -checkend 86400 -noout >/dev/null
openssl x509 -in "$certificate" -checkend 86400 -noout >/dev/null
openssl x509 -in "$certificate" -noout -ext subjectAltName | grep -Eq 'DNS:localhost(,|[[:space:]]|$)'
openssl verify -CAfile "$ca" -purpose sslserver -verify_hostname localhost "$certificate" >/dev/null
"$service_python" - "$certificate" "$key" "$ca" "$ca_key" <<'PY'
import ssl, sys
for certificate, key in (sys.argv[1:3], sys.argv[3:5]):
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(certificate, key)
PY

pids=()
cleanup() {
    trap - EXIT INT TERM
    for pid in "${pids[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
    for _ in {1..100}; do
        active=0
        for pid in "${pids[@]}"; do kill -0 "$pid" 2>/dev/null && active=1; done
        [ "$active" -eq 0 ] && break
        sleep .1
    done
    for pid in "${pids[@]}"; do kill -KILL "$pid" 2>/dev/null || true; done
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

(cd "$registrar_repo" && KLI_KEYSTORE_PASSCODE=$(cat "$state_dir/service-passcode") \
    exec .venv/bin/kf-registrar start --name localdev-registrar --alias registrar \
    --base "$registry_base/registrar" --host 127.0.0.1 --http 19932 \
    --boothost 127.0.0.1 --bootport 19931 --observer "$observer_aid" \
    "${publishers[@]}" --full-evidence --kel "$state_dir/public-bootstrap.cesr" \
    --keypath "$key" --certpath "$certificate" --cafilepath "$ca" --no-prompt) \
    > "$state_dir/registrar.log" 2>&1 &
pids+=("$!")
(cd "$observer_repo" && KLI_KEYSTORE_PASSCODE=$(cat "$state_dir/service-passcode") \
    exec .venv/bin/kf-observer start --name localdev-observer --alias observer \
    --base "$registry_base/observer" --host 127.0.0.1 --http 19942 \
    --registrar https://localhost:19932/ --registrar-ca "$ca" \
    "${readers[@]}" --kel "$state_dir/public-bootstrap.cesr" --poll 1 --timeout 5 --no-prompt) \
    > "$state_dir/observer.log" 2>&1 &
pids+=("$!")

"$service_python" - "$ca" "${pids[@]}" <<'PY'
import os, ssl, sys, time
from urllib.request import urlopen
context = ssl.create_default_context(cafile=sys.argv[1])
deadline = time.monotonic() + 15
pending = {'https://localhost:19931/health', 'https://localhost:19932/health',
           'http://127.0.0.1:19942/health'}
while pending:
    for pid in map(int, sys.argv[2:]):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            raise SystemExit('Registry service exited during startup; inspect registrar.log and observer.log') from None
    for url in list(pending):
        try:
            with urlopen(url, context=context, timeout=.3) as response:
                if response.status == 200:
                    pending.remove(url)
        except OSError:
            pass
    if time.monotonic() >= deadline:
        raise SystemExit('Registry service startup timed out; inspect owned service logs')
    time.sleep(.1)
PY
printf 'Local registry services ready. Logs/state: %s\n' "$state_dir"
printf 'KERI service state namespace: %s\n' "$registry_base"
printf 'Registrar: https://localhost:19932; Observer: http://127.0.0.1:19942\n'
printf 'Explicit wallet CA: %s\n' "$ca"
printf 'Wallet: SSL_CERT_FILE="%s" uv run --locked python -m locksmith.main\n' "$ca"
printf 'Ctrl-C stops only these services and preserves their state.\n'
while true; do
    for pid in "${pids[@]}"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo 'A registry service exited; inspect registrar.log and observer.log.' >&2
            exit 1
        fi
    done
    sleep 1
done
