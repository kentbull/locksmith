"""Local delegation anchors through the delegator's witnessed KEL."""
from hio.base import doing
from keri.core.serdering import SerderKERI

from locksmith.core import credentialing, habbing
from locksmith.core.receipting import LocksmithReceiptor
from test_keri_v2_compat import _deliver_ipex, ipex_vaults  # noqa: F401
from test_credentialing import _load_schema


def _witnessed_delegator(app):
    witness = app.hby.makeHab(name='witness', transferable=False)
    state = app.hby.makeHab(name='state', wits=[witness.pre], toad=1)
    _deliver_ipex(app.vault, witness.witness(SerderKERI(raw=state.msgOwnEvent(sn=0))))
    return witness, state


def _run(app, monkeypatch, alias='program', delpre=None, deliver=True, limit=2.0):
    witness = app.hby.habByName('witness')
    calls = []

    def receipt(self, pre, sn=None, auths=None):
        calls.append((pre, sn, dict(auths or {})))
        if deliver:
            hab = app.hby.habByPre(pre)
            _deliver_ipex(app.vault, witness.witness(SerderKERI(raw=hab.msgOwnEvent(sn=sn))))
        while True:
            yield self.tock
    monkeypatch.setattr(LocksmithReceiptor, 'receipt', receipt)
    monkeypatch.setattr(habbing.LocalDelegateInceptDoer, 'Timeout', 0.5)
    events = []
    app.vault.signals.doer_event.connect(lambda name, event, data: events.append((name, event, data)))
    scheduled = []
    monkeypatch.setattr(app.vault, 'extend', scheduled.extend)
    result = habbing.create_identifier(app, alias, key_type='randy', delegation_type='local',
                                       delpre=delpre, codes=[f'{witness.pre}:123456'])
    assert result['success'] and result['async'], result
    doing.Doist(doers=scheduled, tock=0.03125, limit=limit).do()
    return events, calls


def test_local_delegate_waits_for_witnessed_anchor_that_remote_verifiers_accept(ipex_vaults, monkeypatch):
    app, verifier = ipex_vaults('delegating-wallet'), ipex_vaults('delegation-verifier')
    witness, state = _witnessed_delegator(app)
    events, calls = _run(app, monkeypatch, delpre=state.pre)

    assert events[-1][:2] == ('InceptDoer', 'identifier_created'), events
    program = app.hby.habByName('program')
    assert program.kever.delpre == state.pre and state.kever.sn == 1
    assert calls == [(state.pre, 1, {witness.pre: calls[0][2][witness.pre]})]
    assert calls[0][2][witness.pre].startswith('123456#')
    assert len(app.hby.db.wigs.get((state.pre, state.kever.serder.said))) == 1
    status = habbing.delegation_status(app, program)
    assert status['sn'] == 1 and (status['receipts'], status['threshold']) == (1, 1)
    assert status['text'] == f'Delegated by state ({state.pre[:12]}…) · anchored at sn 1'

    # A remote verifier first-sees the receipted anchor and so accepts the delegate.
    _deliver_ipex(verifier.vault, bytearray(witness.replay()) + state.replay() + program.replay())
    assert verifier.hby.kevers[state.pre].sn == 1
    assert program.pre in verifier.hby.kevers


def test_unreceipted_delegation_fails_readably_and_retry_reuses_the_anchor(ipex_vaults, monkeypatch):
    app = ipex_vaults('delegation-retry')
    _, state = _witnessed_delegator(app)
    events, _ = _run(app, monkeypatch, delpre=state.pre, deliver=False)

    assert events[-1][1] == 'identifier_creation_failed'
    assert 'returned 0 of 1 receipts' in events[-1][2]['error']
    program = app.hby.habByName('program')
    assert habbing.delegation_status(app, program)['text'].endswith(
        'anchored at sn 1 · waiting for delegator witness receipts (0 of 1)')

    events, calls = _run(app, monkeypatch, delpre=state.pre)
    assert events[-1][1] == 'identifier_created'
    assert [sn for _, sn, _ in calls] == [1]
    assert state.kever.sn == 1 and app.hby.habByName('program').pre == program.pre


def test_unwitnessed_delegator_and_both_issuers_share_one_schema(ipex_vaults, monkeypatch):
    app = ipex_vaults('delegation-issuers')
    app.hby.makeHab(name='witness', transferable=False)
    state = app.hby.makeHab(name='state')
    events, calls = _run(app, monkeypatch, delpre=state.pre)
    assert events[-1][1] == 'identifier_created' and calls == []
    program = app.hby.habByName('program')

    schema = _load_schema(app, state)
    assert credentialing.issuer_choices(app.vault, schema.said)[:1] == [state.pre]
    assert program.pre in credentialing.issuer_choices(app.vault, schema.said)
    issued = []
    app.vault.signals.doer_event.connect(lambda name, event, data: issued.append((event, data)))
    for issuer in (state, program):
        doer = credentialing.IssueCredentialDoer(app, schema.said, program.pre, {'LEI': 'test'},
                                                 authentication='signature', issuer=issuer.pre)
        doing.Doist(doers=[doer], tock=0.03125, limit=1.0).do()
    made = [data for event, data in issued if event == 'credential_issued']
    assert len(made) == 2
    issuers = {credentialing.credential(app.vault, data['credential_said'])['sad']['i'] for data in made}
    assert issuers == {state.pre, program.pre}


def test_identifier_view_shows_delegation_status(ipex_vaults, monkeypatch, qapp):
    from locksmith.ui.vault.identifiers.view import ViewIdentifierDialog

    app = ipex_vaults('delegation-view')
    _, state = _witnessed_delegator(app)
    _run(app, monkeypatch, delpre=state.pre)
    dialog = ViewIdentifierDialog(':/assets/custom/identifiers.png', app, 'program')
    assert not dialog.delegation_status.isHidden()
    assert dialog.delegation_status.text().startswith('Delegated by state (')
    assert dialog.delegation_status.text().endswith('anchored at sn 1')
    plain = ViewIdentifierDialog(':/assets/custom/identifiers.png', app, 'state')
    assert plain.delegation_status.isHidden()


def test_create_dialog_collects_delegator_witness_codes_before_anchoring(ipex_vaults, monkeypatch, qapp):
    from locksmith.ui.vault.identifiers.create import CreateIdentifierDialog

    app = ipex_vaults('delegation-create-ui')
    witness, state = _witnessed_delegator(app)
    launched = []
    monkeypatch.setattr(habbing, 'create_identifier',
                        lambda app, **params: launched.append(params) or {'success': True, 'async': True})
    dialog = CreateIdentifierDialog(':/assets/custom/identifiers.png', app)
    dialog.name_field.setText('program')
    dialog.local_delegation_radio.setChecked(True)
    dialog.delegator_dropdown.setCurrentIndex(dialog.delegator_dropdown.combo_box.findData(state.pre))
    assert dialog.delegator_dropdown.currentText() == 'state'
    assert 'collects receipts from its 1 witness' in dialog.delegation_help.text()
    dialog.create_button.click()
    assert dialog._auth_panel is not None and not launched
    assert dialog.create_button.text() == 'Authenticate'
    next(iter(dialog._auth_panel.passcode_fields.values())).setText('123456')
    dialog.create_button.click()
    (params,) = launched
    assert params['delpre'] == state.pre and params['delegation_type'] == 'local'
    assert params['codes'] == [f'{witness.pre}:123456']
    dialog.cancel_button.click()
    assert dialog._auth_panel is None and dialog.create_button.text() == 'Create'
