"""Submission readiness must not strand accepted replies or consume retries.

Regression for the HTTP UI S1 failure reproduced on 2026-10-24: the Grant
was accepted locally, but an observer check interrupted outbox authorization.
"""
from datetime import timedelta

import pytest
from hio.base import doing
from keri import kering
from keri.acdc import ipexing as acdc_v2_ipexing
from keri.help import helping
from keri.peer import exchanging

from locksmith.core import credentialing, ipexing
from test_keri_v2_compat import (IPEX_PLAN, ipex_vaults, ipex_mailbox,
                                 _ipex_fixture, _deliver_ipex)


def _run_sender(vault):
    """Run one real sender attempt with its own finite HIO lifetime."""
    runner = doing.Doist(doers=[ipexing.SendIpexDoer(vault, next(
        said for (said,), _ in vault.db.outbox.getTopItemIter()))], limit=2.0, tock=0.03125)
    runner.do()


def test_readiness_after_acceptance_preserves_authorization(ipex_vaults, ipex_mailbox, monkeypatch):
    issuer, holder = ipex_vaults('readiness-issuer'), ipex_vaults('readiness-holder')
    ih, hh, _, _, _, acdc, proof = _ipex_fixture(issuer, holder)
    request, request_atc = acdc_v2_ipexing.apply(hh, ih.pre, 'Request disclosure',
        modifiers={'dp': [[acdc.sad['s']['$id'], '/', []]]})
    _deliver_ipex(issuer.vault, ipexing.prepare(holder.vault, hh, request, request_atc))
    grant, atc = acdc_v2_ipexing.grant(ih, hh.pre, 'Approved disclosure', proof, apply=request)
    checks = []

    def pending(*args):
        checks.append(True)
        raise credentialing.RegistryEvidencePending('Waiting for a current observer status check')

    with monkeypatch.context() as patch:
        patch.setattr(credentialing, 'require_registry_evidence', pending)
        assert ipexing.submit(issuer.vault, ih, grant, atc) == grant.said
        assert issuer.vault.exc.complete(grant.said)
        assert issuer.hby.db.erpy.get((request.said,)).qb64 == grant.said
        _run_sender(issuer.vault)
        record = issuer.vault.db.outbox.get((grant.said,))
        assert record.status == 'waiting_evidence'
        assert record.attempts == 0 and record.retry_at == 0
        assert checks
    issuer.close_vault()
    issuer = ipex_vaults('readiness-issuer')
    ih = issuer.hby.habByName('issuer')
    assert issuer.vault.db.outbox.get((grant.said,)).status == 'waiting_evidence'
    stream = exchanging.serializeMessage(issuer.hby, grant.said)
    ipex_mailbox(issuer, holder, ih, grant, stream, queued=True)
    assert issuer.vault.db.outbox.get((grant.said,)).status == 'submitted'
    assert len(list(issuer.vault.db.outbox.getTopItemIter())) == 1
    assert exchanging.serializeMessage(issuer.hby, grant.said) == stream


def test_saved_message_recovery_is_explicit_and_idempotent(ipex_vaults):
    issuer, holder = ipex_vaults('saved-issuer'), ipex_vaults('saved-holder')
    ih, hh, _, _, _, _, proof = _ipex_fixture(issuer, holder)
    grant, atc = acdc_v2_ipexing.grant(ih, hh.pre, 'Approved disclosure', proof)
    ipexing.prepare(issuer.vault, ih, grant, atc)
    assert issuer.vault.db.outbox.get((grant.said,)) is None
    issuer.close_vault()
    issuer = ipex_vaults('saved-issuer')
    ih = issuer.hby.habByName('issuer')
    assert issuer.vault.db.outbox.get((grant.said,)) is None
    for _ in range(2):
        assert ipexing.submit(issuer.vault, ih, grant, atc) == grant.said
    assert len(list(issuer.vault.db.outbox.getTopItemIter())) == 1


def test_saved_grant_expiry_blocks_without_resigning(ipex_vaults, monkeypatch):
    issuer, holder = ipex_vaults('expired-issuer'), ipex_vaults('expired-holder')
    ih, hh, _, _, _, _, proof = _ipex_fixture(issuer, holder)
    grant, atc = acdc_v2_ipexing.grant(ih, hh.pre, 'Approved disclosure', proof)
    ipexing.submit(issuer.vault, ih, grant, atc)
    original = exchanging.serializeMessage(issuer.hby, grant.said)
    policy = issuer.hby.db.kramCTYP.get('~')
    future = helping.fromIso8601(grant.stamp) + timedelta(milliseconds=policy.d + policy.sl + 1)
    monkeypatch.setattr(helping, 'nowUTC', lambda: future)
    _run_sender(issuer.vault)
    record = issuer.vault.db.outbox.get((grant.said,))
    assert record.status == 'blocked' and record.attempts == 0
    assert exchanging.serializeMessage(issuer.hby, grant.said) == original


@pytest.mark.parametrize('failure', ['waiting', 'invalid'])
def test_final_readiness_gate_prevents_transport(ipex_vaults, monkeypatch, failure):
    """Readiness changing after the initial check cannot start a network attempt."""
    issuer, holder = ipex_vaults('final-issuer'), ipex_vaults('final-holder')
    ih, hh, _, _, _, _, proof = _ipex_fixture(issuer, holder)
    grant, atc = acdc_v2_ipexing.grant(ih, hh.pre, 'Approved disclosure', proof)
    ipexing.submit(issuer.vault, ih, grant, atc)
    checks = 0
    def check(*args):
        nonlocal checks
        checks += 1
        if checks == 2:
            error = credentialing.RegistryEvidencePending if failure == 'waiting' else kering.ValidationError
            raise error('Readiness changed before transport')
    monkeypatch.setattr(credentialing, 'require_registry_evidence', check)
    _run_sender(issuer.vault)
    record = issuer.vault.db.outbox.get((grant.said,))
    assert checks == 2
    assert record.status == ('waiting_evidence' if failure == 'waiting' else 'blocked')
    assert record.attempts == 0


@pytest.mark.parametrize('key_count', [1, 3])
def test_delivery_age_uses_authentication_specific_kram_lag(ipex_vaults, monkeypatch, key_count):
    """Single-key and multi-key messages retain the existing distinct lag windows."""
    sender = ipex_vaults('timing-sender')
    hab = sender.hby.makeHab(name='sender', icount=key_count, isith=1)
    recipient = sender.hby.makeHab(name='recipient')
    exn, atc = acdc_v2_ipexing.apply(
        hab, recipient.pre, 'Timing boundary', modifiers={'dp': IPEX_PLAN})
    ipexing.prepare(sender.vault, hab, exn, atc)
    policy = sender.hby.db.kramCTYP.get('~')
    assert policy.ll > policy.sl
    now = helping.fromIso8601(exn.stamp) + timedelta(milliseconds=policy.d + policy.sl + 1)
    monkeypatch.setattr(helping, 'nowUTC', lambda: now)
    if key_count == 1:
        with pytest.raises(kering.ValidationError, match='timing window'):
            ipexing._require_delivery_time(sender.vault, exn)
    else:
        ipexing._require_delivery_time(sender.vault, exn)


def test_final_graph_gate_rechecks_semantic_evidence_before_transport(ipex_vaults, monkeypatch):
    """Losing an edge pin after initial readiness preserves the queued bytes."""
    from keri.core import scheming
    from test_credentialing import _issue, _load_schema
    from test_ipex_policy import _introduce

    issuer, holder = ipex_vaults('final-graph-issuer'), ipex_vaults('final-graph-holder')
    ih, hh = issuer.hby.makeHab(name='issuer'), holder.hby.makeHab(name='holder')
    schema = _load_schema(issuer, ih)
    pin = scheming.Schemer(sed={'$id': '', 'version': '1.0.0', 'title': 'current edge constraint', 'type': 'object'})
    issuer.hby.db.schema.pin((pin.said,), pin)
    leaf = _issue(issuer, schema, hh, authentication='signature')
    root = _issue(issuer, schema, hh, authentication='signature', edges={
        'source': {'n': leaf, 's': pin.said, 'o': 'NI2I'}})
    _introduce(issuer, holder)
    _introduce(holder, issuer)
    grant, atc = ipexing.grant(issuer.vault, ih, root, hh.pre)
    ipexing.submit(issuer.vault, ih, grant, atc)
    exact = exchanging.serializeMessage(issuer.hby, grant.said)
    checks = []

    def evidence_changes(*args):
        checks.append(True)
        if len(checks) == 2:
            issuer.hby.db.schema.rem((pin.said,))

    def forbidden_transport(**kwa):
        pytest.fail('An unresolved graph reached network delivery')

    monkeypatch.setattr(credentialing, 'require_registry_evidence', evidence_changes)
    monkeypatch.setattr(ipexing.forwarding, 'StreamPoster', forbidden_transport)
    _run_sender(issuer.vault)
    record = issuer.vault.db.outbox.get((grant.said,))
    assert len(checks) == 2
    assert record.status == 'waiting_evidence' and record.attempts == 0
    assert exchanging.serializeMessage(issuer.hby, grant.said) == exact
    assert issuer.vault.exc.routes['/ipex/grant'].verifyAccepted(grant.said, historical=True)
