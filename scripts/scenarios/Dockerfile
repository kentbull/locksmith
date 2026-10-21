# syntax=docker/dockerfile:1
# Community composition; the host qualifier verifies clean immutable inputs.
ARG LOCKSMITH_IMAGE=locksmith:parity
FROM ${LOCKSMITH_IMAGE}
COPY pyproject.toml uv.lock README.md LICENSE /component/
COPY src /component/src
COPY scripts/scenarios /component/scripts/scenarios
RUN mkdir -p /artifacts && rm -f /artifacts/*.whl && python -m pip wheel --no-deps --no-build-isolation /component -w /artifacts && python -m pip install --force-reinstall --no-deps /artifacts/locksmith*.whl
COPY --from=core-src scripts/v2-e2e/scenarios /workspace/scripts/v2-e2e/scenarios
COPY --from=dolly-src pyproject.toml README.md LICENSE NOTICE /opt/dolly/
COPY --from=dolly-src src /opt/dolly/src
COPY --from=dolly-src tests /opt/dolly/tests
COPY --from=registrar-src pyproject.toml README.md LICENSE /opt/kf-registrar/
COPY --from=registrar-src src /opt/kf-registrar/src
COPY --from=registrar-src tests /opt/kf-registrar/tests
COPY --from=observer-src pyproject.toml README.md LICENSE /opt/kf-observer/
COPY --from=observer-src src /opt/kf-observer/src
COPY --from=observer-src tests /opt/kf-observer/tests
COPY --from=witness-src pyproject.toml README.md LICENSE /opt/witness-hk/
COPY --from=witness-src src /opt/witness-hk/src
COPY --from=witness-src tests /opt/witness-hk/tests
RUN python -m pip wheel --no-deps --no-build-isolation /workspace /opt/dolly /opt/kf-registrar /opt/kf-observer /opt/witness-hk -w /artifacts && python -m pip install --force-reinstall --no-deps /artifacts/*.whl
ARG KERIPY_REVISION=development
ARG DOLLY_REVISION=development
ARG REGISTRAR_REVISION=development
ARG OBSERVER_REVISION=development
ARG WITNESS_REVISION=development
ARG LOCKSMITH_REVISION=development
ENV SCENARIO_KERIPY_REVISION=${KERIPY_REVISION} SCENARIO_DOLLY_REVISION=${DOLLY_REVISION} SCENARIO_REGISTRAR_REVISION=${REGISTRAR_REVISION} SCENARIO_OBSERVER_REVISION=${OBSERVER_REVISION} SCENARIO_WITNESS_REVISION=${WITNESS_REVISION} SCENARIO_LOCKSMITH_REVISION=${LOCKSMITH_REVISION}
ARG QUALIFIED_CLEAN=0
ENV QUALIFIED_CLEAN=${QUALIFIED_CLEAN}
RUN python /component/scripts/scenarios/artifacts.py
ENV SCENARIO_SERVICE_PROFILE=kf SCENARIO_WITNESS_PROFILE=hk SCENARIO_WALLET_PROFILE=locksmith
WORKDIR /workspace
ENTRYPOINT ["bash"]
