#!/usr/bin/env bash
# Run the real Foundation provisioning services on this host. No wallet state
# is created here: create and onboard vaults through the normal Locksmith UI.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
keri_workspace=${KERI_WORKSPACE:-$(cd "$script_dir/../../../.." && pwd)}
state_dir=${1:-${XDG_DATA_HOME:-$HOME/.local/share}/locksmith-local-provider}
mkdir -p "$state_dir"
state_dir=$(cd "$state_dir" && pwd)
config_dt=$(date -u +'%Y-%m-%dT%H:%M:%S.000000+00:00')
# Service index databases use the normal KERI root rather than --config-dir.
# Give each state directory a stable, distinct base in that root as well.
state_key=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest()[:16])' "$state_dir")
provider_base="locksmith-local-provider/$state_key"

witness_repo="$keri_workspace/core/python/witness-hk"
watcher_repo="$keri_workspace/core/python/watcher-hk"
boot_repo="$keri_workspace/infra/kf-boot"
for repo in "$witness_repo" "$watcher_repo" "$boot_repo"; do
    uv sync --project "$repo" --locked --extra dev
done

# Refuse occupied ports before starting anything; never stop another stack.
python3 - <<'PY'
import socket
ports = [19723, 19831, 19832] + [19631 + 10*i + j for i in range(4) for j in (0, 1)]
for port in ports:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', port))
PY

pids=()
cleanup() {
    trap - EXIT INT TERM
    for pid in "${pids[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

backends=""
for i in 0 1 2 3; do
    boot_port=$((19631 + 10*i))
    public_port=$((boot_port + 1))
    config_dir="$state_dir/witness-$i"
    mkdir -p "$config_dir/keri/cf/main"
    cat > "$config_dir/keri/cf/main/witopnet.json" <<EOF
{"dt":"$config_dt","witopnet":{"dt":"$config_dt","curls":["http://127.0.0.1:$public_port/"]}}
EOF
    (cd "$witness_repo" && exec .venv/bin/witopnet marshal start \
        --base "$provider_base/witness-$i" --config-dir "$config_dir" \
        --host 127.0.0.1 --http "$public_port" --boothost 127.0.0.1 --bootport "$boot_port") \
        > "$state_dir/witness-$i.log" 2>&1 &
    pids+=("$!")
    backends+="${backends:+,}w$i|http://127.0.0.1:$boot_port|http://127.0.0.1:$public_port"
done

mkdir -p "$state_dir/watcher/keri/cf/main"
cat > "$state_dir/watcher/keri/cf/main/watopnet.json" <<EOF
{"dt":"$config_dt","watopnet":{"dt":"$config_dt","curls":["http://127.0.0.1:19832/"]}}
EOF
(cd "$watcher_repo" && exec .venv/bin/watopnet start \
    --base "$provider_base/watcher" --config-dir "$state_dir/watcher" \
    --host 127.0.0.1 --http 19832 --boothost 127.0.0.1 --bootport 19831) \
    > "$state_dir/watcher.log" 2>&1 &
pids+=("$!")

(cd "$boot_repo" && \
    KF_BOOT_HOST=127.0.0.1 KF_BOOT_PORT=19723 \
    KF_BOOT_DB_PATH="$state_dir/boot-db" KF_BOOT_KERI_DIR="$state_dir/boot-keri" \
    KF_BOOT_KERI_NAME=locksmith-local-provider KF_BOOT_WITNESS_BACKENDS="$backends" \
    KF_BOOT_WAT_BOOT_URL=http://127.0.0.1:19831 KF_BOOT_WAT_PUBLIC_URL=http://127.0.0.1:19832 \
    KF_BOOT_ONBOARDING_PUBLIC_URL=http://127.0.0.1:19723/onboarding \
    KF_BOOT_ACCOUNT_PUBLIC_URL=http://127.0.0.1:19723/account \
    exec .venv/bin/kf-boot) > "$state_dir/boot.log" 2>&1 &
pids+=("$!")

printf 'Local provider processes started. Logs: %s\n' "$state_dir"
printf 'Service index database base: %s\n' "$provider_base"
printf 'Check http://127.0.0.1:19723/bootstrap/config, then launch Locksmith normally.\n'
printf 'Keep this terminal open. Ctrl-C stops these services and preserves their state.\n'
wait
