# syntax=docker/dockerfile:1
# Development composition; final qualification supplies clean revision arguments.
ARG LOCKSMITH_IMAGE=locksmith:parity
FROM ${LOCKSMITH_IMAGE}
COPY src /component/src
RUN mkdir -p /artifacts && python -m pip wheel --no-deps --no-build-isolation /component -w /artifacts && python -m pip install --force-reinstall --no-deps /artifacts/locksmith*.whl
COPY --from=core-src scripts/v2-e2e/scenarios /workspace/scripts/v2-e2e/scenarios
COPY --from=dolly-src pyproject.toml README.md LICENSE NOTICE /opt/dolly/
COPY --from=dolly-src src /opt/dolly/src
COPY --from=registrar-src pyproject.toml README.md LICENSE /opt/kf-registrar/
COPY --from=registrar-src src /opt/kf-registrar/src
COPY --from=observer-src pyproject.toml README.md LICENSE /opt/kf-observer/
COPY --from=observer-src src /opt/kf-observer/src
COPY --from=witness-src pyproject.toml README.md LICENSE /opt/witness-hk/
COPY --from=witness-src src /opt/witness-hk/src
RUN python -m pip wheel --no-deps --no-build-isolation /workspace /opt/dolly /opt/kf-registrar /opt/kf-observer /opt/witness-hk -w /artifacts && python -m pip install --no-deps /artifacts/dolly*.whl /artifacts/kf_*.whl /artifacts/witopnet*.whl
ARG KERIPY_REVISION=development
ARG DOLLY_REVISION=development
ARG REGISTRAR_REVISION=development
ARG OBSERVER_REVISION=development
ARG WITNESS_REVISION=development
ARG LOCKSMITH_REVISION=development
ENV SCENARIO_KERIPY_REVISION=${KERIPY_REVISION} SCENARIO_DOLLY_REVISION=${DOLLY_REVISION} SCENARIO_REGISTRAR_REVISION=${REGISTRAR_REVISION} SCENARIO_OBSERVER_REVISION=${OBSERVER_REVISION} SCENARIO_WITNESS_REVISION=${WITNESS_REVISION} SCENARIO_LOCKSMITH_REVISION=${LOCKSMITH_REVISION}
# Development defaults are explicitly dirty; clean qualification must replace this manifest.
RUN python -c 'import os,json,hashlib,pathlib; p=pathlib.Path("/artifacts"); value={k.lower()+"_revision":os.environ["SCENARIO_"+k+"_REVISION"] for k in ("KERIPY","DOLLY","REGISTRAR","OBSERVER","WITNESS","LOCKSMITH")}; value.update(keripy_worktree_dirty=True,dolly_worktree_dirty=False,registrar_worktree_dirty=False,observer_worktree_dirty=False,witness_worktree_dirty=False,locksmith_worktree_dirty=True,wheels={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in p.glob("*.whl")}); (p/"manifest.json").write_text(json.dumps(value,indent=2))'
ENV SCENARIO_SERVICE_PROFILE=kf SCENARIO_WITNESS_PROFILE=hk SCENARIO_WALLET_PROFILE=locksmith
WORKDIR /workspace
ENTRYPOINT ["bash"]
