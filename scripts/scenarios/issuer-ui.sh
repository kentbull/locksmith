#!/usr/bin/env bash
# UI issuer gate: real issuance form and authentication; one onward Dolly hook.
set -Eeuo pipefail
source /workspace/scripts/v2-e2e/scenarios/common.sh
export SCENARIO_WALLET_PROFILE=locksmith SCENARIO_SERVICE_PROFILE=kf SCENARIO_WITNESS_PROFILE=hk
export SCENARIO_ISSUER_PROFILE=locksmith SCENARIO_DOLLY_SCHEMA=entitlement-v2
export SCENARIO_LOCKSMITH_UI=1
prepare locksmith-ui-issuer

start_issuer() {
    mkdir -p "$RUN_DIR/private/issuer"
    spawn issuer-app python /component/scripts/scenarios/ui_runtime.py run --name "${NAMES[issuer]}" --base "$STORE_BASE" \
        --alias issuer --socket "$RUN_DIR/private/issuer/operator.sock" --port "${PORTS[issuer]}"
    python "$JSON" tcp-ready 127.0.0.1 "${PORTS[issuer]}" 15
}
issuer_ipex() {
    printf 'locksmith issuer ' >> "$RUN_DIR/commands.log"
    printf '%q ' "$@" >> "$RUN_DIR/commands.log"
    printf '\n' >> "$RUN_DIR/commands.log"
    python -m locksmith.driver.scenario "$RUN_DIR" issuer ipex "$@" | tee "$RUN_DIR/latest-issuer.jsonl"
}

printf '{"entitlement":"authorized"}\n' > "$RUN_DIR/attributes.json"
python "$HERE/hosted.py" auth "$RUN_DIR" issuer
start_issuer
SCENARIO_ISSUER_SCHEMA=entitlement-v2 python /component/scripts/scenarios/issuer-material.py "$RUN_DIR" "${SCENARIO_REGISTRY_MODE:-public}" | tee "$RUN_DIR/issued.json"
REGISTRY=$(value "$RUN_DIR/issued.json" registry)
CREDENTIAL=$(value "$RUN_DIR/issued.json" credential)
SCHEMA=$(value "$RUN_DIR/credential.json" 's.$id')
stop issuer-app
# Service bootstrapping and initial signed publication retain the KLI adapter.
# Actual issuance and IPEX grant are exclusively the Locksmith application.
services
# This fixture has a scalar entitlement, unlike the six compacted-field stories.
# Select its reporting policy before any grant arrives; keep Dolly's normal
# configured projection and required-field enforcement as the only owner.
stop dolly
python - "$RUN_DIR/dolly-policy.json" <<'PY_POLICY'
import json
from pathlib import Path
import sys
path = Path(sys.argv[1])
policy = json.loads(path.read_text())
policy['fields'] = {'entitlement': 'a/entitlement'}
policy['required'] = ['entitlement']
path.write_text(json.dumps(policy))
PY_POLICY
spawn dolly dolly server start --direct --name "${NAMES[dolly]}" --base "$STORE_BASE" -a dolly \
    --config "$RUN_DIR/dolly-policy.json" --kel "$RUN_DIR/bootstrap.cesr" \
    --packaged-schema entitlement-v2 --http "${PORTS[dolly]}" --tcp "${PORTS[dollytcp]}" --no-prompt
python "$JSON" ready "http://127.0.0.1:${PORTS[dolly]}/health" 15
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

# The issuer's real UI produced the credential. Forward the admitted proof through
# the ordinary holder operation; negotiated UI disclosure has six separate stories.
k holder ipex grant --v2 -a holder -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$HELD"
GRANT=$(value "$RUN_DIR/latest-holder.jsonl" exchange)
poll delivered "$GRANT"
python - "$RUN_DIR" "$CREDENTIAL" "$GRANT" <<'PY_CHECK'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
hooks = [json.loads(line) for line in (root / 'hooks.jsonl').read_text().splitlines()]
assert len(hooks) == 1 and hooks[0]['credential'] == sys.argv[2]
assert hooks[0]['grant'] == sys.argv[3] and hooks[0]['decision'] == 'accepted'
assert hooks[0]['protocol'] == 2
assert hooks[0]['business'] == {'entitlement': 'authorized'}
assert hooks[0]['disclosure'] == {'entitlement': 'disclosed'}
(root / 'ui-issuer-result.json').write_text(json.dumps({
    'result': 'passed', 'issuer': 'Locksmith IssueCredentialDialog',
    'holderAdmission': 'Locksmith AcceptGrantDialog', 'hook': hooks[0]}, indent=2))
print((root / 'ui-issuer-result.json').read_text())
PY_CHECK
