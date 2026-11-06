#!/usr/bin/env bash
# Start the selected normal registry services; wallet roles are enrolled by kf-boot.
set -euo pipefail
umask 077
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo 'Usage: bash scripts/local-registries.sh STATE_DIR [CONFIG_JSON]' >&2
    exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
keri_workspace=${KERI_WORKSPACE:-$(cd "$script_dir/../../../.." && pwd)}
default_backend=${LOCAL_PROVIDER_BACKEND:-python}
registrar_backend=${LOCAL_PROVIDER_REGISTRAR_BACKEND:-$default_backend}
observer_backend=${LOCAL_PROVIDER_OBSERVER_BACKEND:-$default_backend}
for knob in LOCAL_PROVIDER_BACKEND:"$default_backend" LOCAL_PROVIDER_REGISTRAR_BACKEND:"$registrar_backend" \
    LOCAL_PROVIDER_OBSERVER_BACKEND:"$observer_backend"; do
    case "${knob#*:}" in python|typescript) ;; *) echo "${knob%%:*} must be python or typescript" >&2; exit 2 ;; esac
done
offset=$(python3 - "${LOCAL_PROVIDER_PORT_OFFSET:-0}" <<'PYOFFSET'
import sys
value = sys.argv[1]
if not value.isdecimal() or not 0 <= int(value) <= 45593:
    raise SystemExit('LOCAL_PROVIDER_PORT_OFFSET must be an integer between 0 and 45593')
print(int(value))
PYOFFSET
)
state_dir=$1
mkdir -p "$state_dir"
chmod 700 "$state_dir"
state_dir=$(cd "$state_dir" && pwd)
registrar_repo="$keri_workspace/core/python/kf-registrar"
observer_repo="$keri_workspace/core/python/kf-observer"
ts_repo="$keri_workspace/core/typescript/keri-ts"
registrar_boot=$((19931 + offset)); registrar_public=$((19932 + offset))
observer_boot=$((19941 + offset)); observer_public=$((19942 + offset))
python3 - "$registrar_boot" "$registrar_public" "$observer_boot" "$observer_public" <<'PYPORTS'
import socket, sys
for port in map(int, sys.argv[1:]):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', port))
PYPORTS
# The bootstrap helper still imports kf-registrar, so its install is always required.
uv sync --project "$registrar_repo" --locked --extra dev --python 3.14
if [ "$observer_backend" = python ]; then
    uv sync --project "$observer_repo" --locked --extra dev --python 3.14
fi
service_python="$registrar_repo/.venv/bin/python"
pids=()
cleanup() {
    trap - EXIT INT TERM
    for pid in ${pids[@]+"${pids[@]}"}; do kill -TERM "$pid" 2>/dev/null || true; done
    for _ in {1..100}; do
        active=0
        for pid in ${pids[@]+"${pids[@]}"}; do kill -0 "$pid" 2>/dev/null && active=1; done
        [ "$active" -eq 0 ] && break
        sleep .1
    done
    for pid in ${pids[@]+"${pids[@]}"}; do kill -KILL "$pid" 2>/dev/null || true; done
    for pid in ${pids[@]+"${pids[@]}"}; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
rm -f "$state_dir/registry-services.env"
bootstrap_args=("$state_dir")
if [ "$#" -eq 2 ]; then bootstrap_args+=("$2"); fi
"$service_python" "$script_dir/local_registry_bootstrap.py" "${bootstrap_args[@]}" \
    --registrar-backend "$registrar_backend" --observer-backend "$observer_backend" --ts-repo "$ts_repo" > "$state_dir/bootstrap.log" 2>&1 &
pids+=("$!")
wait "${pids[0]}"
pids=()
registry_base=$(cat "$state_dir/keri-base")
registrar_aid=$(cat "$state_dir/registrar.aid")
observer_aid=$(cat "$state_dir/observer.aid")
publishers=()
readers=()
while IFS= read -r aid; do [ -z "$aid" ] || publishers+=(--publisher "$aid"); done < "$state_dir/publishers.aids"
while IFS= read -r aid; do [ -z "$aid" ] || readers+=(--reader "$aid"); done < "$state_dir/readers.aids"

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


tufa=(deno run --allow-all --unstable-ffi packages/tufa/mod.ts)
passcode=$(cat "$state_dir/service-passcode")
if [ "$registrar_backend" = python ]; then
    (cd "$registrar_repo" && KLI_KEYSTORE_PASSCODE="$passcode" \
        exec .venv/bin/kf-registrar start --name localdev-registrar --alias registrar \
        --base "$registry_base/registrar" --host 127.0.0.1 --http "$registrar_public" \
        --boothost 127.0.0.1 --bootport "$registrar_boot" --observer "$observer_aid" \
        ${publishers[@]+"${publishers[@]}"} --kel "$state_dir/public-bootstrap.cesr" \
        --keypath "$key" --certpath "$certificate" --cafilepath "$ca" --no-prompt) \
        > "$state_dir/registrar.log" 2>&1 &
else
    (cd "$ts_repo" && exec "${tufa[@]}" registrar start --name localdev-registrar --alias registrar \
        --head-dir "$state_dir/tufa" --passcode "$passcode" --url "https://localhost:$registrar_public" \
        --http "$registrar_public" --boot-port "$registrar_boot" --observer "$observer_aid" \
        --kel "$state_dir/public-bootstrap.cesr" --tls-key "$key" --tls-cert "$certificate") \
        > "$state_dir/registrar.log" 2>&1 &
fi
pids+=("$!")
if [ "$observer_backend" = python ]; then
    (cd "$observer_repo" && KLI_KEYSTORE_PASSCODE="$passcode" \
        exec .venv/bin/kf-observer start --name localdev-observer --alias observer \
        --base "$registry_base/observer" --host 127.0.0.1 --http "$observer_public" --bootport "$observer_boot" \
        --registrar "https://localhost:$registrar_public/" --registrar-ca "$ca" \
        --keypath "$key" --certpath "$certificate" --cafilepath "$ca" \
        ${readers[@]+"${readers[@]}"} --kel "$state_dir/public-bootstrap.cesr" --poll 1 --timeout 5 --no-prompt) \
        > "$state_dir/observer.log" 2>&1 &
else
    (cd "$ts_repo" && exec "${tufa[@]}" observer start --name localdev-observer --alias observer \
        --head-dir "$state_dir/tufa" --passcode "$passcode" --url "https://localhost:$observer_public" \
        --http "$observer_public" --boot-port "$observer_boot" --registrar "https://localhost:$registrar_public" \
        --registrar-ca "$ca" --kel "$state_dir/public-bootstrap.cesr" --poll-interval 1 \
        ${readers[@]+"${readers[@]}"} --tls-key "$key" --tls-cert "$certificate") > "$state_dir/observer.log" 2>&1 &
fi
pids+=("$!")

"$service_python" - "$ca" "$registrar_boot" "$registrar_public" "$observer_boot" "$observer_public" ${pids[@]+"${pids[@]}"} <<'PYREADY'
import os, ssl, sys, time
from urllib.request import urlopen
context = ssl.create_default_context(cafile=sys.argv[1])
rb, rp, ob, op = map(int, sys.argv[2:6])
deadline = time.monotonic() + 30
pending = {f'http://127.0.0.1:{rb}/health', f'https://localhost:{rp}/health',
           f'http://127.0.0.1:{ob}/health', f'https://localhost:{op}/health'}
while pending:
    for pid in map(int, sys.argv[6:]):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            raise SystemExit('Registry service exited during startup; inspect owned service logs') from None
    for url in list(pending):
        try:
            with urlopen(url, context=context if url.startswith('https://') else None, timeout=.3) as response:
                if response.status == 200:
                    pending.remove(url)
        except OSError:
            pass
    if time.monotonic() >= deadline:
        raise SystemExit('Registry startup timed out; inspect registrar.log and observer.log')
    time.sleep(.1)
PYREADY
{
    printf 'export KF_BOOT_REGISTRAR_BOOT_URL=%q\n' "http://127.0.0.1:$registrar_boot"
    printf 'export KF_BOOT_REGISTRAR_PUBLIC_URL=%q\n' "https://localhost:$registrar_public"
    printf 'export KF_BOOT_REGISTRAR_SERVICE_AID=%q\n' "$registrar_aid"
    printf 'export KF_BOOT_REGISTRAR_CA_FILE=%q\n' "$ca"
    printf 'export KF_BOOT_OBSERVER_BOOT_URL=%q\n' "http://127.0.0.1:$observer_boot"
    printf 'export KF_BOOT_OBSERVER_PUBLIC_URL=%q\n' "https://localhost:$observer_public"
    printf 'export KF_BOOT_OBSERVER_SERVICE_AID=%q\n' "$observer_aid"
    printf 'export KF_BOOT_OBSERVER_CA_FILE=%q\n' "$ca"
} > "$state_dir/registry-services.env.tmp"
mv "$state_dir/registry-services.env.tmp" "$state_dir/registry-services.env"
printf 'Local registry services ready (registrar=%s observer=%s). Logs/state: %s\n' \
    "$registrar_backend" "$observer_backend" "$state_dir"
printf 'Registrar: https://localhost:%s; Observer: https://localhost:%s\n' "$registrar_public" "$observer_public"
printf 'Explicit public service CA: %s\n' "$ca"
printf 'Ctrl-C stops only these services and preserves their state.\n'
while true; do
    for pid in ${pids[@]+"${pids[@]}"}; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo 'A registry service exited; inspect registrar.log and observer.log.' >&2
            exit 1
        fi
    done
    sleep 1
done
