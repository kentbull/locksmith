from contextlib import ExitStack
from types import SimpleNamespace
import pytest
from PySide6.QtWidgets import QWidget
from hio.base import doing
from keri import kering
from keri.acdc import Registrar, Regery, acdcmap, ipexing as native_ipexing
from keri.app import habbing, notifying, organizing
from keri.core import Noncer, messagize, parsing, scheming, SerderACDC, SerderKERI
from keri.peer import exchanging

from locksmith.core import ipexing
from locksmith.core.signals import DoerSignalBridge
from locksmith.db.basing import IssuedCredential, LocksmithBaser
from locksmith.ui.vault.credentials.issued.grant import GrantCredentialDialog
from locksmith.ui.vault.credentials.issued.issue import IssueCredentialDialog
from locksmith.ui.vault.credentials.issued.list import IssuedCredentialsListPage
from locksmith.ui.vault.credentials.issued.view import ViewIssuedCredentialDialog
from locksmith.ui.vault.credentials.received.accept import AcceptCredentialDialog
from locksmith.ui.vault.credentials.received.accept_grant import AcceptGrantDialog
from locksmith.ui.vault.credentials.received.delete import DeleteReceivedCredentialDialog
from locksmith.ui.vault.credentials.received.list import ReceivedCredentialsListPage
from locksmith.ui.vault.credentials.schema.add import AddSchemaDialog
from locksmith.ui.vault.notifications.list import NotificationsListPage


@pytest.fixture
def wallet(qapp):
    with ExitStack() as contexts:
        def create(name):
            hby = contexts.enter_context(habbing.openHby(name=name, temp=True, version=kering.Vrsn_2_0))
            rgy = Regery(hby=hby, name=name, temp=True)
            contexts.callback(rgy.close)
            db = LocksmithBaser(name=name, temp=True)
            contexts.callback(db.close)
            notifier = notifying.Notifier(hby=hby, noter=notifying.Noter(name=name, temp=True))
            contexts.callback(notifier.noter.close)
            signals = DoerSignalBridge()
            exc = exchanging.Exchanger(hby=hby, handlers=[])
            for verb in ('apply', 'offer', 'agree', 'grant', 'admit', 'spurn'):
                exc.addHandler(ipexing.IpexHandler(f'/ipex/{verb}', hby, notifier, rgy))
            queued = []
            vault = SimpleNamespace(hby=hby, rgy=rgy, db=db, org=organizing.Organizer(hby=hby),
                                    exc=exc, signals=signals, extend=queued.extend)
            vault.mbx = SimpleNamespace(parser=parsing.Parser(kvy=hby.kvy, exc=exc, version=kering.Vrsn_2_0))
            app = SimpleNamespace(hby=hby, vault=vault, queued=queued)
            return app
        yield create
        for widget in list(qapp.topLevelWidgets()):
            widget.close()
            widget.deleteLater()
        qapp.processEvents()


def schema(require_issuee=True):
    fields = {key: {'type': 'string'} for key in ('v', 't', 'd', 'i', 'rd', 's')}
    fields['a'] = {'type': 'object', 'properties': {
        'd': {'type': 'string'}, 'i': {'type': 'string'}, 'dt': {'type': 'string'},
        'nickname': {'type': 'string', 'description': 'Nickname'},
    }, 'required': ['d', 'i', 'dt', 'nickname'], 'additionalProperties': False}
    if not require_issuee:
        fields['a']['required'].remove('i')
    return scheming.Schemer(sed={
        '$id': '', '$schema': 'http://json-schema.org/draft-07/schema#',
        'title': 'Native Credential', 'type': 'object', 'properties': fields,
        'required': list(fields), 'additionalProperties': False,
    })


def issue(app, hab, recipient):
    schemer = schema(require_issuee=recipient is not None)
    app.hby.db.schema.pin(keys=(schemer.said,), val=schemer)
    app.vault.db.issuers.pin(keys=(schemer.said,), val=hab.pre)
    registrar = Registrar(rgy=app.vault.rgy)
    reg = registrar.makeRegistry(name=f'credential-{len(app.vault.rgy.regs)}', prefix=hab.pre)
    def anchor(event):
        hab.interact(data=[{'i': reg.regk, 's': event.sad['n'], 'd': event.said}], gvrsn=kering.Vrsn_2_0)
        assert reg.anchorMsg(event.said)
    anchor(app.vault.rgy.store.event(reg.regk))
    acdc = acdcmap(israid=hab.pre, regid=reg.regk, schema=schemer.said,
                   attribute={'d': '', 'dt': '2026-09-09T00:00:00Z', 'nickname': 'Alice'}, iseaid=recipient)
    schemer.verify(raw=acdc.raw)
    blinder, update = registrar.issue(reg, acdc)
    anchor(update)
    app.vault.db.issued.pin(keys=(acdc.said,), val=IssuedCredential(acdc.raw.decode(), blinder.qb64, update.said))
    proof = messagize(serder=acdc, bonds=[blinder.data], framed=False, gvrsn=kering.Vrsn_2_0)
    return acdc, proof, schemer


def test_schema_selection_does_not_create_registry_or_request_witness_auth(wallet, tmp_path):
    app = wallet('schema-ui')
    hab = app.hby.makeHab(name='issuer')
    schemer = schema()
    source = tmp_path / 'native.json'
    source.write_bytes(schemer.raw)
    dialog = AddSchemaDialog(app=app)
    dialog.file_radio.setChecked(True)
    dialog.file_path_field.setText(str(source))
    dialog.said_field.setText(schemer.said)
    dialog.enable_issuance_checkbox.setChecked(True)
    dialog.issuer_dropdown.setCurrentIndex(1)
    dialog._on_load()
    assert len(app.queued) == 1
    assert dialog.load_button.text() == 'Loading...'
    doing.Doist(doers=app.queued, limit=1.0, tock=0.03125).do()
    assert app.vault.db.issuers.get(keys=(schemer.said,)) == hab.pre
    assert app.vault.rgy.regs == {}
    assert app.hby.db.schema.get(keys=(schemer.said,)).said == schemer.said


@pytest.mark.parametrize('nonces', [False, True])
@pytest.mark.parametrize('attribute_union', [False, True])
def test_issue_form_uses_selected_issuer_and_attribute_schema(wallet, nonces, attribute_union):
    app = wallet('issue-ui')
    issuer = app.hby.makeHab(name='issuer')
    recipient = app.hby.makeHab(name='recipient')
    sad = schema().sed
    sad['$id'] = ''
    if nonces:
        sad['properties']['u'] = {'type': 'string'}
        sad['required'].append('u')
        sad['properties']['a']['properties']['u'] = {'type': 'string'}
        sad['properties']['a']['required'].append('u')
    if attribute_union:
        sad['properties']['a'] = {'oneOf': [{'type': 'string'}, sad['properties']['a']]}
    schemer = scheming.Schemer(sed=sad)
    app.hby.db.schema.pin(keys=(schemer.said,), val=schemer)
    app.vault.db.issuers.pin(keys=(schemer.said,), val=issuer.pre)
    dialog = IssueCredentialDialog(app=app)
    assert dialog.schema_dropdown.count() == 2
    dialog.schema_dropdown.setCurrentIndex(1)
    assert set(dialog._dynamic_field_widgets) == {'nickname'}
    assert dialog._dynamic_field_widgets['nickname']['field_def']['required'] is True
    assert app.queued == []
    assert app.vault.rgy.regs == {}
    dialog.local_radio.setChecked(True)
    recipient_index = next(index for index in range(dialog.recipient_dropdown.count())
                           if dialog.recipient_dropdown.itemData(index) == recipient.pre)
    dialog.recipient_dropdown.setCurrentIndex(recipient_index)
    dialog._dynamic_field_widgets['nickname']['widget'].setText('Alice')
    events = []
    app.vault.signals.doer_event.connect(lambda name, event, data: events.append((event, data)))
    dialog._on_issue()
    assert len(app.queued) == 1
    doing.Doist(doers=app.queued, limit=1.0, tock=0.03125).do()
    assert events[-1][0] == 'credential_issued', events
    ((_,), record), = app.vault.db.issued.getTopItemIter()
    acdc = SerderACDC(raw=record.raw.encode())
    assert acdc.pvrsn == kering.Vrsn_2_0
    assert acdc.sad['i'] == issuer.pre
    assert acdc.iseaid == recipient.pre
    assert schemer.verify(raw=acdc.raw)
    if nonces:
        assert Noncer(qb64=acdc.sad['u']).qb64 == acdc.sad['u']
        assert Noncer(qb64=acdc.sad['a']['u']).qb64 == acdc.sad['a']['u']
        assert acdc.sad['u'] != acdc.sad['a']['u']
    else:
        assert 'u' not in acdc.sad
        assert 'u' not in acdc.sad['a']


def test_grant_transport_events_do_not_imply_remote_receipt(wallet, monkeypatch):
    app = wallet('grant-ui')
    issuer = app.hby.makeHab(name='issuer')
    recipient = app.hby.makeHab(name='recipient')
    acdc, _, schemer = issue(app, issuer, recipient.pre)
    app.vault.org.update(recipient.pre, {'alias': 'Recipient'})
    parent = QWidget()
    dialog = GrantCredentialDialog(app=app, parent=parent, credential_said=acdc.said,
                                   credential_schema=schemer.sed['title'], credential_issuer=issuer.pre)
    success, errors = [], []
    monkeypatch.setattr(dialog, 'show_success', success.append)
    monkeypatch.setattr(dialog, 'show_error', errors.append)
    dialog._on_grant()
    assert len(app.queued) == 1
    assert isinstance(app.queued[0], ipexing.SendIpexDoer)
    said = app.queued[0].serder.said
    app.vault.signals.emit_doer_event('Ipex', 'transport_submitted', {'said': 'unrelated'})
    assert not success and not errors
    assert dialog.action_button.text() == 'Sending...'
    app.vault.signals.emit_doer_event('Ipex', 'send_failed', {'said': said, 'error': 'No endpoint'})
    assert errors == ['Failed to send: No endpoint']
    assert dialog.action_button.isEnabled()


def test_pending_import_does_not_open_acceptance_or_add_wallet_credential(wallet, tmp_path, monkeypatch):
    sender, receiver = wallet('import-source'), wallet('import-target')
    issuer = sender.hby.makeHab(name='issuer')
    holder = receiver.hby.makeHab(name='holder')
    acdc, proof, _ = issue(sender, issuer, holder.pre)
    receiver.vault.mbx.parser.parse(ims=bytearray(issuer.replay(gvrsn=kering.Vrsn_2_0)), local=False)
    exn, atc = native_ipexing.grant(issuer, holder.pre, 'Grant', proof)
    source = tmp_path / 'grant.cesr'
    source.write_bytes(exn.raw + atc)
    dialog = AcceptCredentialDialog(app=receiver, parent=QWidget())
    errors = []
    monkeypatch.setattr(dialog, 'show_error', errors.append)
    monkeypatch.setattr(AcceptGrantDialog, 'open', lambda self: pytest.fail('Pending grant opened acceptance'))
    dialog.file_path_field.setText(str(source))
    dialog._on_load()
    assert not receiver.vault.exc.complete(exn.said)
    assert receiver.vault.db.accepted.get(keys=(acdc.said,)) is None
    assert errors and 'pending' in errors[0].lower()
    assert dialog.load_button.isEnabled()


def test_grant_notification_and_file_acceptance_use_verified_native_evidence(wallet, tmp_path, monkeypatch):
    app = wallet('accept-ui')
    issuer, holder = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='holder')
    acdc, _, schemer = issue(app, issuer, holder.pre)
    grant, atc = ipexing.grant(app.vault, issuer, acdc.said, holder.pre, 'Native grant')
    ipexing.prepare(app.vault, issuer, grant, atc)
    parent = QWidget()
    parent.app = app
    notifications = NotificationsListPage(parent=parent)
    kind, message = notifications._format_ipex_message(grant, grant.route, 'Native grant')
    assert kind == 'GRANT'
    assert schemer.sed['title'] in message
    assert 'Admit' in notifications._get_row_actions({'Type': kind})[0]
    received = ReceivedCredentialsListPage(parent=parent)
    received.set_vault_name(app.hby.name)
    dialog = AcceptGrantDialog(app=app, parent=parent, grant_said=grant.said, save=True)
    assert dialog.credential_said == acdc.said
    assert dialog.recipient == holder.pre
    assert dialog._get_schema_display() == schemer.sed['title']
    assert app.vault.db.accepted.get(keys=(acdc.said,)) is None
    target = tmp_path / 'admit.cesr'
    monkeypatch.setattr('locksmith.ui.vault.credentials.received.accept_grant.QFileDialog.getSaveFileName', lambda *a, **k: (str(target), 'CESR'))
    dialog._on_admit()
    record = app.vault.db.accepted.get(keys=(acdc.said,))
    assert record.grant == grant.said
    assert SerderKERI(raw=target.read_bytes()).route == '/ipex/admit'
    assert [row['SAID'] for row in received.table._static_data] == [acdc.said]
    assert app.queued == []


def test_missing_schema_grant_can_be_reviewed_but_cannot_be_accepted(wallet, monkeypatch):
    app = wallet('schema-missing-ui')
    issuer, holder = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='holder')
    acdc, _, schemer = issue(app, issuer, holder.pre)
    grant, atc = ipexing.grant(app.vault, issuer, acdc.said, holder.pre)
    ipexing.prepare(app.vault, issuer, grant, atc)
    app.hby.db.schema.rem(keys=(schemer.said,))
    dialog = AcceptGrantDialog(app=app, parent=QWidget(), grant_said=grant.said, save=True)
    assert dialog.credential_said == acdc.said
    errors = []
    monkeypatch.setattr(dialog, 'show_error', errors.append)
    dialog._on_admit()
    assert app.vault.db.accepted.get(keys=(acdc.said,)) is None
    assert errors and 'schema' in errors[0].lower()
    assert dialog.admit_button.isEnabled()


def test_wallet_tables_distinguish_issuee_and_grant_recipient(wallet):
    app = wallet('optional-issuee-ui')
    issuer, holder = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='holder')
    subject = app.hby.makeHab(name='subject')
    credentials = []
    for issuee in (holder.pre, None, subject.pre):
        acdc, _, _ = issue(app, issuer, issuee)
        grant, atc = ipexing.grant(app.vault, issuer, acdc.said, holder.pre)
        ipexing.prepare(app.vault, issuer, grant, atc)
        ipexing.admit(app.vault, holder, grant.said)
        credentials.append(acdc)
    addressed, unaddressed, transferred = credentials
    assert 'i' not in unaddressed.sad['a']
    assert transferred.sad['a']['i'] == subject.pre
    assert len(list(app.vault.db.accepted.getTopItemIter())) == 3
    parent = QWidget()
    parent.app = app
    received = ReceivedCredentialsListPage(parent=parent)
    received.set_vault_name(app.hby.name)
    issued = IssuedCredentialsListPage(parent=parent)
    issued.set_vault_name(app.hby.name)
    received_rows = {row['SAID']: row for row in received.table._static_data}
    issued_rows = {row['SAID']: row for row in issued.table._static_data}
    expected = {acdc.said for acdc in credentials}
    assert set(received_rows) == set(issued_rows) == expected
    assert all(row['Recipient'] == f'{holder.name} ({holder.pre})'
               for row in received_rows.values())
    assert issued_rows[addressed.said]['Recipient'] == f'{holder.name} ({holder.pre})'
    assert issued_rows[unaddressed.said]['Recipient'] == 'Not specified'
    assert issued_rows[transferred.said]['Recipient'] == f'{subject.name} ({subject.pre})'
    details = ViewIssuedCredentialDialog(icon_path='', app=app,
                                         credential_said=unaddressed.said, parent=parent)
    assert details.recipient_field.text() == 'Not specified'
    accepted = app.vault.db.accepted.get(keys=(unaddressed.said,))
    deletion = DeleteReceivedCredentialDialog(schema_name='Native Credential', said=unaddressed.said,
                                             icon_path='', app=app, parent=parent)
    deletion._delete_credential()
    assert app.vault.db.accepted.get(keys=(unaddressed.said,)) is None
    assert app.vault.db.issued.get(keys=(unaddressed.said,)) is not None
    assert app.vault.exc.complete(accepted.grant)
    assert app.vault.exc.complete(accepted.admit)
    assert {row['SAID'] for row in received.table._static_data} == expected - {unaddressed.said}
    issued._load_issued_credentials_data()
    assert {row['SAID'] for row in issued.table._static_data} == expected
