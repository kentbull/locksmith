#!/usr/bin/env bash
# Reproduce baseline plus actual community applications from six clean inputs.
set -Eeuo pipefail
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LOCKSMITH_SOURCE=$(CDPATH= cd -- "$HERE/../.." && pwd)
: "${KERI_SOURCE:?Set the clean pinned KERIpy checkout}"
: "${DOLLY_SOURCE:?Set the clean pinned Dolly checkout}"
: "${REGISTRAR_SOURCE:?Set the clean pinned registrar checkout}"
: "${OBSERVER_SOURCE:?Set the clean pinned observer checkout}"
: "${WITNESS_SOURCE:?Set the clean pinned hosted-witness checkout}"
RUN=${QUALIFICATION_RUN:-community-qualified-$(date +%Y%m%d-%H%M%S)}
OUTPUT=${QUALIFICATION_OUTPUT:-$(mktemp -d /tmp/community-qualification.XXXXXXXX)}
mkdir -p "$OUTPUT"
SOURCES=("$KERI_SOURCE" "$DOLLY_SOURCE" "$REGISTRAR_SOURCE" "$OBSERVER_SOURCE" "$WITNESS_SOURCE" "$LOCKSMITH_SOURCE")
NAMES=(KERIPY DOLLY REGISTRAR OBSERVER WITNESS LOCKSMITH)

# The checker also refuses mismatched dependency pins and unpublished inputs.
python3 "$HERE/check-sources.py" "${SOURCES[@]}" > "$OUTPUT/sources.json"
ARGS=(--build-arg QUALIFIED_CLEAN=1)
for index in "${!SOURCES[@]}"; do
    revision=$(git -C "${SOURCES[$index]}" rev-parse HEAD)
    ARGS+=(--build-arg "${NAMES[$index]}_REVISION=$revision")
done
CORE_IMAGE="$RUN-core"
WALLET_IMAGE="$RUN-wallet"
IMAGE="$RUN-scenarios"
docker build -t "$CORE_IMAGE" -f "$KERI_SOURCE/scripts/v2-e2e/Dockerfile" "$KERI_SOURCE" > "$OUTPUT/build-core.log" 2>&1
docker build -t "$WALLET_IMAGE" --build-arg "CORE_IMAGE=$CORE_IMAGE" \
    -f "$LOCKSMITH_SOURCE/scripts/Dockerfile.test" "$LOCKSMITH_SOURCE" > "$OUTPUT/build-wallet.log" 2>&1
docker build -t "$IMAGE" --build-arg "LOCKSMITH_IMAGE=$WALLET_IMAGE" "${ARGS[@]}" \
    --build-context "core-src=$KERI_SOURCE" --build-context "dolly-src=$DOLLY_SOURCE" \
    --build-context "registrar-src=$REGISTRAR_SOURCE" --build-context "observer-src=$OBSERVER_SOURCE" \
    --build-context "witness-src=$WITNESS_SOURCE" -f "$HERE/Dockerfile" "$LOCKSMITH_SOURCE" > "$OUTPUT/build-scenarios.log" 2>&1
python3 "$HERE/check-sources.py" "${SOURCES[@]}" > "$OUTPUT/sources-after-build.json"
cmp "$OUTPUT/sources.json" "$OUTPUT/sources-after-build.json"
docker image inspect "$CORE_IMAGE" "$WALLET_IMAGE" "$IMAGE" > "$OUTPUT/images.json"
docker run --rm "$IMAGE" -c 'cat /artifacts/manifest.json' > "$OUTPUT/artifacts.json"

# Separate processes keep each application's conftest and package ownership clear.
for component in kf-registrar kf-observer witness-hk; do
    docker run --rm --name "$RUN-$component-tests" -w "/opt/$component" \
        -v "$RUN-$component-tests:/tmp" -v "$RUN-$component-state:/usr/local/var" \
        "$IMAGE" -c 'python -m pytest -q -o pythonpath= tests' > "$OUTPUT/$component-tests.log" 2>&1
done
# The composed image includes the observer: optional wallet ingress tests must run.
docker run --rm --name "$RUN-wallet-tests" -w /component -v "$RUN-wallet-tests:/tmp" \
    -v "$RUN-wallet-tests-state:/usr/local/var" "$IMAGE" \
    -c 'python -m pytest -q -o pythonpath= tests' > "$OUTPUT/wallet-tests.log" 2>&1

# Cover shared-core integration changes not selected by the older baseline list.
docker run --rm --name "$RUN-core-integration-tests" --entrypoint python -w /workspace \
    -v "$RUN-core-integration-tests:/tmp" -v "$RUN-core-integration-state:/usr/local/var" \
    "$CORE_IMAGE" -m pytest -q -o pythonpath= \
    tests/app/test_evidence_processor.py tests/app/test_httping.py \
    tests/app/test_agenting.py::test_receiptor_v2_propagates_witness_receipts \
    tests/app/test_agenting.py::test_receiptor_propagates_only_verified_receipts \
    tests/app/test_agenting.py::test_receiptor_collects_past_offline_first_witness \
    > "$OUTPUT/core-integration-tests.log" 2>&1

# Preserve the original KLI/v1 oracle in addition to the new application profile.
DOLLY_SOURCE="$DOLLY_SOURCE" SCENARIO_VOLUME="$RUN-baseline" \
    "$KERI_SOURCE/scripts/v2-e2e/qualify.sh" > "$OUTPUT/baseline.log" 2>&1
HOSTED_MATRIX_IMAGE="$IMAGE" "$WITNESS_SOURCE/scripts/legacy-peers/check.sh" > "$OUTPUT/hosted-released-peers.log" 2>&1

STORIES=(holder-full-then-graduated holder-partial-then-onward holder-supplied-state-opening
    holder-provisioned-state-derivation holder-selected-discloser-openings holder-selected-discloser-derivation)
for profile in headless ui; do
    for index in "${!STORIES[@]}"; do
        transport=http
        if (( index % 2 )); then transport=tcp; fi
        name="$RUN-$profile-s$((index + 1))"
        ui=0; if [[ $profile == ui ]]; then ui=1; fi
        docker run --rm --name "$name" -e "SCENARIO_LOCKSMITH_UI=$ui" \
            -e "SCENARIO_TRANSPORT=$transport" -v "$name:/tmp" -v "$name-state:/usr/local/var" \
            "$IMAGE" "/workspace/scripts/v2-e2e/scenarios/${STORIES[$index]}.sh" > "$OUTPUT/$profile-s$((index + 1)).log" 2>&1
    done
done
for profile in issuer-through-holder issuer-ui; do
    for mode in public blinded derived; do
        name="$RUN-$profile-$mode"
        docker run --rm --name "$name" -e "SCENARIO_REGISTRY_MODE=$mode" \
            -v "$name:/tmp" -v "$name-state:/usr/local/var" "$IMAGE" \
            "/component/scripts/scenarios/$profile.sh" > "$OUTPUT/$profile-$mode.log" 2>&1
    done
done
name="$RUN-hosted-quorum"
docker run --rm --name "$name" -v "$name:/tmp" -v "$name-state:/usr/local/var" \
    "$IMAGE" /workspace/scripts/v2-e2e/scenarios/hosted-quorum-restart.sh > "$OUTPUT/hosted-quorum.log" 2>&1
printf 'All qualification commands passed. Public reports: %s; named-volume prefix: %s\n' "$OUTPUT" "$RUN"
