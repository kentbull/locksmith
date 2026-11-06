#!/usr/bin/env bash
# Run the normal Foundation provider locally; wallet access is enrolled by kf-boot.
set -euo pipefail
umask 077
if [ "$#" -gt 2 ]; then
    echo 'Usage: bash scripts/local-provider.sh [STATE_DIR [PARTICIPANTS_JSON]]' >&2
    exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
keri_workspace=${KERI_WORKSPACE:-$(cd "$script_dir/../../../.." && pwd)}
state_dir=${1:-${XDG_DATA_HOME:-$HOME/.local/share}/locksmith-local-provider}
default_backend=${LOCAL_PROVIDER_BACKEND:-python}
boot_backend=${LOCAL_PROVIDER_BOOT:-python}
witness_backend=${LOCAL_PROVIDER_WITNESS_BACKEND:-$default_backend}
watcher_backend=${LOCAL_PROVIDER_WATCHER_BACKEND:-$default_backend}
registrar_backend=${LOCAL_PROVIDER_REGISTRAR_BACKEND:-$default_backend}
observer_backend=${LOCAL_PROVIDER_OBSERVER_BACKEND:-$default_backend}
for knob in LOCAL_PROVIDER_BACKEND:"$default_backend" LOCAL_PROVIDER_BOOT:"$boot_backend" \
    LOCAL_PROVIDER_WITNESS_BACKEND:"$witness_backend" LOCAL_PROVIDER_WATCHER_BACKEND:"$watcher_backend" \
    LOCAL_PROVIDER_REGISTRAR_BACKEND:"$registrar_backend" LOCAL_PROVIDER_OBSERVER_BACKEND:"$observer_backend"; do
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
export LOCAL_PROVIDER_BACKEND="$default_backend" LOCAL_PROVIDER_BOOT="$boot_backend" \
    LOCAL_PROVIDER_WITNESS_BACKEND="$witness_backend" LOCAL_PROVIDER_WATCHER_BACKEND="$watcher_backend" \
    LOCAL_PROVIDER_REGISTRAR_BACKEND="$registrar_backend" LOCAL_PROVIDER_OBSERVER_BACKEND="$observer_backend" \
    LOCAL_PROVIDER_PORT_OFFSET="$offset"
topology="boot=$boot_backend witness=$witness_backend watcher=$watcher_backend"
topology+=" registrar=$registrar_backend observer=$observer_backend"
mkdir -p "$state_dir"
chmod 700 "$state_dir"
state_dir=$(cd "$state_dir" && pwd)
# A state directory is bound to one role topology; older state is never migrated.
if [ -f "$state_dir/topology" ]; then
    if [ "$(cat "$state_dir/topology")" != "$topology" ]; then
        echo 'Topology differs from retained provider state; use a separate state directory.' >&2
        exit 1
    fi
elif [ -e "$state_dir/backend" ] || [ -d "$state_dir/boot-db" ] || [ -d "$state_dir/witness-0" ] \
    || [ -d "$state_dir/watcher" ] || [ -d "$state_dir/tufa" ] || [ -d "$state_dir/registries" ]; then
    echo 'Retained provider state has no topology marker; use a separate state directory.' >&2
    exit 1
fi
printf '%s\n' "$topology" > "$state_dir/topology"
config_dt=$(date -u +'%Y-%m-%dT%H:%M:%S.000000+00:00')
state_key=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest()[:16])' "$state_dir")
provider_base="locksmith-local-provider/$state_key"
provider_port=$((19723 + offset))
watcher_boot=$((19831 + offset)); watcher_public=$((19832 + offset))
registry_state="$state_dir/registries"
export LOCAL_PROVIDER_URL="http://127.0.0.1:$provider_port"
# Probe the entire topology before starting anything; never stop another stack.
python3 - "$offset" <<'PYPORTS'
import socket, sys
offset = int(sys.argv[1])
ports = [19723, 19831, 19832, 19931, 19932, 19941, 19942]
ports += [19631 + 10*i + j for i in range(4) for j in (0, 1)]
for port in ports:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', port + offset))
PYPORTS
witness_repo="$keri_workspace/core/python/witness-hk"
watcher_repo="$keri_workspace/core/python/watcher-hk"
boot_repo="$keri_workspace/infra/kf-boot"
ts_repo="$keri_workspace/core/typescript/keri-ts"
# Install only the Python repositories whose role is selected.
if [ "$boot_backend" = python ]; then uv sync --project "$boot_repo" --locked --extra dev --python 3.14; fi
if [ "$witness_backend" = python ]; then uv sync --project "$witness_repo" --locked --extra dev --python 3.14; fi
if [ "$watcher_backend" = python ]; then uv sync --project "$watcher_repo" --locked --extra dev --python 3.14; fi
pids=()
cleanup() {
    trap - EXIT INT TERM
    for pid in ${pids[@]+"${pids[@]}"}; do kill -TERM "$pid" 2>/dev/null || true; done
    # The registry child joins its own services within ten seconds.
    for _ in {1..150}; do
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
# Registry capabilities must exist in provider configuration before an account activates.
mkdir -p "$registry_state"
rm -f "$registry_state/registry-services.env"
registry_args=("$registry_state")
if [ "$#" -eq 2 ]; then registry_args+=("$2"); fi
bash "$script_dir/local-registries.sh" "${registry_args[@]}" > "$state_dir/registries.log" 2>&1 &
pids+=("$!")
registry_pid=$!
deadline=$((SECONDS + 180))
while [ ! -f "$registry_state/registry-services.env" ]; do
    if ! kill -0 "$registry_pid" 2>/dev/null; then
        echo 'Registry startup failed; inspect registries.log and registries/bootstrap.log.' >&2
        exit 1
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then echo 'Registry startup timed out; inspect owned logs.' >&2; exit 1; fi
    sleep .2
done
# This file is generated by our registry child only after both listeners are ready.
source "$registry_state/registry-services.env"
backends=""
tufa=(deno run --allow-all --unstable-ffi packages/tufa/mod.ts)
case "$boot_backend $witness_backend $watcher_backend" in
    *typescript*) passcode=$(cat "$registry_state/service-passcode") ;;
esac
for i in 0 1 2 3; do
    boot_port=$((19631 + 10*i + offset)); public_port=$((boot_port + 1))
    if [ "$witness_backend" = python ]; then
        config_dir="$state_dir/witness-$i"
        mkdir -p "$config_dir/keri/cf/main"
        cat > "$config_dir/keri/cf/main/witopnet.json" <<JSON
{"dt":"$config_dt","witopnet":{"dt":"$config_dt","curls":["http://127.0.0.1:$public_port/"]}}
JSON
        (cd "$witness_repo" && exec .venv/bin/witopnet marshal start \
            --base "$provider_base/witness-$i" --config-dir "$config_dir" \
            --host 127.0.0.1 --http "$public_port" --boothost 127.0.0.1 --bootport "$boot_port") \
            > "$state_dir/witness-$i.log" 2>&1 &
    else
        (cd "$ts_repo" && exec "${tufa[@]}" witness backend --name "localdev-witness-$i" \
            --head-dir "$state_dir/tufa" --passcode "$passcode" --url "http://127.0.0.1:$public_port" \
            --http "$public_port" --boot-port "$boot_port") > "$state_dir/witness-$i.log" 2>&1 &
    fi
    pids+=("$!")
    backends+="${backends:+,}w$i|http://127.0.0.1:$boot_port|http://127.0.0.1:$public_port"
done
if [ "$watcher_backend" = python ]; then
    mkdir -p "$state_dir/watcher/keri/cf/main"
    cat > "$state_dir/watcher/keri/cf/main/watopnet.json" <<JSON
{"dt":"$config_dt","watopnet":{"dt":"$config_dt","curls":["http://127.0.0.1:$watcher_public/"]}}
JSON
    (cd "$watcher_repo" && exec .venv/bin/watopnet start \
        --base "$provider_base/watcher" --config-dir "$state_dir/watcher" \
        --host 127.0.0.1 --http "$watcher_public" --boothost 127.0.0.1 --bootport "$watcher_boot") \
        > "$state_dir/watcher.log" 2>&1 &
else
    (cd "$ts_repo" && exec "${tufa[@]}" watcher backend --name localdev-watcher \
        --head-dir "$state_dir/tufa" --passcode "$passcode" --url "http://127.0.0.1:$watcher_public" \
        --http "$watcher_public" --boot-port "$watcher_boot" --poll-interval 1) > "$state_dir/watcher.log" 2>&1 &
fi
pids+=("$!")
python3 - "$offset" ${pids[@]+"${pids[@]}"} <<'PYREADY'
import os, socket, sys, time
offset = int(sys.argv[1])
ports = [19831, 19832] + [19631 + 10*i + j for i in range(4) for j in (0, 1)]
pending = {port + offset for port in ports}
deadline = time.monotonic() + 60
while pending:
    for pid in map(int, sys.argv[2:]):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            raise SystemExit('A backend exited during startup; inspect owned logs') from None
    for port in list(pending):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.3):
                pending.remove(port)
        except OSError:
            pass
    if time.monotonic() >= deadline:
        raise SystemExit('Backend listener startup timed out; inspect owned logs')
    time.sleep(.1)
PYREADY
# Both kf-boot implementations read the same KF_BOOT_* settings; only the executable differs.
export KF_BOOT_HOST=127.0.0.1 KF_BOOT_PORT="$provider_port" \
    KF_BOOT_DB_PATH="$state_dir/boot-db" KF_BOOT_KERI_DIR="$state_dir/boot-keri" \
    KF_BOOT_KERI_NAME=locksmith-local-provider KF_BOOT_WITNESS_BACKENDS="$backends" \
    KF_BOOT_WAT_BOOT_URL="http://127.0.0.1:$watcher_boot" KF_BOOT_WAT_PUBLIC_URL="http://127.0.0.1:$watcher_public" \
    KF_BOOT_ONBOARDING_PUBLIC_URL="$LOCAL_PROVIDER_URL/onboarding" \
    KF_BOOT_ACCOUNT_PUBLIC_URL="$LOCAL_PROVIDER_URL/account"
if [ "$boot_backend" = python ]; then
    (cd "$boot_repo" && exec .venv/bin/kf-boot) > "$state_dir/boot.log" 2>&1 &
else
    (cd "$ts_repo" && exec "${tufa[@]}" boot backend --name localdev-boot \
        --head-dir "$state_dir/tufa" --passcode "$passcode") > "$state_dir/boot.log" 2>&1 &
fi
pids+=("$!")
python3 - "$LOCAL_PROVIDER_URL/health" "$!" <<'PYBOOT'
import os, sys, time
from urllib.request import urlopen
deadline = time.monotonic() + 120
while True:
    try:
        os.kill(int(sys.argv[2]), 0)
    except ProcessLookupError:
        raise SystemExit('kf-boot exited during startup; inspect boot.log') from None
    try:
        with urlopen(sys.argv[1], timeout=.5) as response:
            if 200 <= response.status < 300:
                break
    except OSError:
        pass
    if time.monotonic() >= deadline:
        raise SystemExit('kf-boot health check timed out; inspect boot.log')
    time.sleep(.2)
PYBOOT
printf 'Local provider processes started (%s). Logs/state: %s\n' "$topology" "$state_dir"
printf 'Discovery: %s/bootstrap/config\n' "$LOCAL_PROVIDER_URL"
printf 'Wallet: LOCAL_PROVIDER_URL=%q uv run --locked python -m locksmith.main\n' "$LOCAL_PROVIDER_URL"
printf 'Keep this terminal open. Ctrl-C stops only owned services and preserves their state.\n'
while true; do
    for pid in ${pids[@]+"${pids[@]}"}; do
        if ! kill -0 "$pid" 2>/dev/null; then echo 'A provider service exited; inspect owned logs.' >&2; exit 1; fi
    done
    sleep 1
done
