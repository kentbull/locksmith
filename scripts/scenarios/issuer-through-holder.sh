#!/usr/bin/env bash
# Additional issuer gate: real Locksmith issues, grants and stops; holder presents.
set -Eeuo pipefail
source /workspace/scripts/v2-e2e/scenarios/common.sh
export SCENARIO_WALLET_PROFILE=locksmith SCENARIO_SERVICE_PROFILE=kf SCENARIO_WITNESS_PROFILE=hk
export SCENARIO_ISSUER_PROFILE=locksmith SCENARIO_DOLLY_SCHEMA=acm-default-v2
prepare locksmith-issuer-through-holder

start_issuer() {
    mkdir -p "$RUN_DIR/private/issuer"
    spawn issuer-app python -m locksmith.driver run --name "${NAMES[issuer]}" --base "$STORE_BASE" \
        --alias issuer --socket "$RUN_DIR/private/issuer/operator.sock" --port "${PORTS[issuer]}"
    python "$JSON" tcp-ready 127.0.0.1 "${PORTS[issuer]}" 15
}
issuer_ipex() {
    printf 'locksmith issuer ' >> "$RUN_DIR/commands.log"
    printf '%q ' "$@" >> "$RUN_DIR/commands.log"
    printf '\n' >> "$RUN_DIR/commands.log"
    python -m locksmith.driver.scenario "$RUN_DIR" issuer ipex "$@" | tee "$RUN_DIR/latest-issuer.jsonl"
}

python "$JSON" attributes "$RUN_DIR/attributes.json" "$(kli nonce)" "$(kli nonce)" "$(kli nonce)" "$(kli nonce)"
python "$HERE/hosted.py" auth "$RUN_DIR" issuer
start_issuer
python /component/scripts/scenarios/issuer-material.py "$RUN_DIR" "${SCENARIO_REGISTRY_MODE:-public}" | tee "$RUN_DIR/issued.json"
REGISTRY=$(value "$RUN_DIR/issued.json" registry)
CREDENTIAL=$(value "$RUN_DIR/issued.json" credential)
SCHEMA=$(value "$RUN_DIR/credential.json" 's.$id')
stop issuer-app
# Service bootstrapping and initial signed publication retain the KLI adapter.
# Actual issuance and IPEX grant are exclusively the Locksmith application.
services
stop issuer-intake
start_issuer
python -m locksmith.driver.scenario "$RUN_DIR" issuer setup --observer "$OBSERVER_URL"
python - "$RUN_DIR" "http://127.0.0.1:${PORTS[registrar]}/" "$OBSERVER_URL" <<'PY'
import sys
from pathlib import Path
from locksmith.driver.scenario import request
request(Path(sys.argv[1]), 'issuer', {'op':'configure', 'registries': {
    'profile':'full-evidence', 'registrar':sys.argv[2], 'observer':sys.argv[3]}})
PY
issuer_ipex grant --v2 -a issuer -r "${AIDS[holder]}" -s "$CREDENTIAL" --output "$RUN_DIR/issuer-full.cesr"
HELD=$(value "$RUN_DIR/latest-issuer.jsonl" exchange)
poll accepted_exchange holder "$HELD"
k holder ipex admit --v2 -a holder -s "$HELD"
assert_json "$RUN_DIR/latest-holder.jsonl" admitted true
printf '%s\n' "$HELD" > "$RUN_DIR/held-grant.ref"
stop issuer-app

for disclosure in partial full; do
    python "$JSON" plan "$RUN_DIR/$disclosure-plan.json" "$SCHEMA" "$disclosure"
    k dolly ipex apply --v2 -a dolly -r "${AIDS[holder]}" --plan "@$RUN_DIR/$disclosure-plan.json" --endpoint "$HOLDER_ENDPOINT"
    APPLY=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
    k holder ipex offer --v2 -a holder -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$HELD" --prior "$APPLY"
    OFFER=$(value "$RUN_DIR/latest-holder.jsonl" exchange)
    poll accepted_exchange dolly "$OFFER"
    k dolly ipex agree --v2 -a dolly -s "$OFFER" --endpoint "$HOLDER_ENDPOINT"
    AGREE=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
    k holder ipex grant --v2 -a holder -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$HELD" --prior "$AGREE" --output "$RUN_DIR/holder-$disclosure.cesr"
    GRANT=$(value "$RUN_DIR/latest-holder.jsonl" exchange)
    printf '%s\n' "$GRANT" > "$RUN_DIR/$disclosure-grant.ref"
    poll delivered "$GRANT"
    if [[ $disclosure == partial ]]; then
        k dolly ipex inspect -s "$GRANT" > "$RUN_DIR/partial-retained-before.json"
        python "$JSON" first-hook "$RUN_DIR/hooks.jsonl" "$RUN_DIR/first-hook.json"
    fi
    k dolly ipex admit --v2 -a dolly -s "$GRANT" --endpoint "$HOLDER_ENDPOINT"
done
k dolly ipex inspect -s "$(cat "$RUN_DIR/partial-grant.ref")" > "$RUN_DIR/partial-retained-after.json"
[[ $(python "$JSON" hash "$RUN_DIR/partial-retained-before.json") == $(python "$JSON" hash "$RUN_DIR/partial-retained-after.json") ]]
python "$JSON" first-hook "$RUN_DIR/hooks.jsonl" "$RUN_DIR/first-hook-after.json"
[[ $(python "$JSON" hash "$RUN_DIR/first-hook.json") == $(python "$JSON" hash "$RUN_DIR/first-hook-after.json") ]]
python "$JSON" assert-hooks "$RUN_DIR/hooks.jsonl" 2 "$CREDENTIAL" "${AIDS[holder]}"
result
