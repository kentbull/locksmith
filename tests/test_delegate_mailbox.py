"""A local delegate gets its own provider-hosted mailbox, never its delegator's routes."""
import asyncio
from contextlib import ExitStack
from importlib.metadata import entry_points
from types import SimpleNamespace

import pytest
from hio.base import doing
from keri import kering
from keri.acdc import registraring
from keri.app import forwarding, habbing
from keri.core import Diger, Number, coring
from keri.core.eventing import SealEvent
from keri.core.serdering import SerderKERI

from locksmith.core import ipexing, remoting
from locksmith.core.apping import LocksmithApplication
from locksmith.core.indirecting import receiving_endpoints
from locksmith.core.vaulting import Vault
from locksmith.plugins.kerifoundation.core import mailboxes
from locksmith.plugins.kerifoundation.db.basing import ACCOUNT_STATUS_ONBOARDED, KFAccountRecord
from locksmith.plugins.kerifoundation.onboarding.service import KFBootError


def delegate(hby, delegator, name='program'):
    """Create ``name`` delegated and anchored by local ``delegator``, as Create Identifier does."""
    hab = hby.makeHab(name=name, delpre=delegator.pre)
    dip = hby.db.evts.get(keys=(hab.pre, hby.db.kels.getLast(keys=hab.pre, on=0)))
    anchor = SerderKERI(raw=delegator.interact(data=[SealEvent(i=hab.pre, s=dip.snh, d=dip.said)._asdict()]))
    hby.db.aess.pin(keys=(hab.pre, dip.said),
                    val=(Number(num=anchor.sn, code=coring.NumDex.Huge), Diger(qb64=anchor.said)))
    hby.kvy.processEscrows()
    return hab


@pytest.fixture
def provider_vault(qapp):
    """A real vault whose Local Development account ``state`` is onboarded."""
    app = LocksmithApplication()
    local = {ep.name: ep for ep in entry_points(group='locksmith.plugins')}['localdev'].load()()
    local.initialize(app)
    with ExitStack() as stack:
        hby = stack.enter_context(habbing.openHby(name='delegate-mailbox', temp=True))
        services = stack.enter_context(habbing.openHby(name='delegate-mailbox-service', temp=True))
        rgy = registraring.Regery(hby=hby, name=hby.name, temp=True)
        stack.callback(rgy.close)
        app.vault = vault = Vault(app, hby, rgy)
        for store in (vault.db, vault.rep.mbx, vault.notifier.noter):
            stack.callback(store.close, clear=True)
        stack.callback(vault.exit)
        local.on_vault_opened(vault)
        stack.callback(local.on_vault_closed, vault, clear=True)
        state = hby.makeHab(name='state')
        local._db.pin_account(KFAccountRecord(account_alias='state', account_aid=state.pre,
                                              status=ACCOUNT_STATUS_ONBOARDED, boot_server_aid='Eboot'))
        app.plugin_manager = SimpleNamespace(mailbox_provider=lambda vault, hab: (
            (local, name) if (name := local.mailbox_provider_name(vault, hab)) else None))
        # The hosted mailbox: a non-transferable service identifier with a public address.
        box = services.makeHab(name='mailbox', transferable=False)
        yield SimpleNamespace(app=app, vault=vault, hby=hby, plugin=local, state=state, box=box,
                              intro=bytes(box.makeEndRole(eid=box.pre, role=kering.Roles.controller)
                                          + box.makeLocScheme(url='http://127.0.0.1:1', scheme='http')))


class FakeBoot:
    """The provider's account surface: records requests and answers one mailbox operation."""

    def __init__(self, account, program, box, fail=None):
        self.calls, self.fail = [], fail
        self.operation = dict(operation_id='op-1', requester=account.pre, kind='delegate_mailbox',
                              subject=f'mailbox:{program.pre}', state='pending')
        self.result = dict(account_aid=account.pre, aid=program.pre,
                           mailbox=dict(eid=box.pre, url='http://127.0.0.1:1',
                                        oobis=[f'http://127.0.0.1:1/oobi/{box.pre}/controller']))

    def request_delegate_mailbox(self, account, delegate):
        self.calls.append(('request', account.pre, delegate.pre))
        return SimpleNamespace(payload=dict(account_aid=account.pre, aid=delegate.pre, operation=dict(self.operation)))

    def send_exn(self, *, surface, hab, route, payload):
        self.calls.append((route, payload['operation_id']))
        if self.fail:
            return SimpleNamespace(payload=dict(operation=dict(self.operation, state='failed', last_error=self.fail)))
        return SimpleNamespace(payload=dict(operation=dict(self.operation, state='succeeded', result=self.result)))


def run_provider(lab, program, boot, monkeypatch):
    """Drive the provider flow with the vault's hio work run in place of its scheduler."""
    mail = []

    def deliver(self):
        mail.extend((self.recp, SerderKERI(raw=bytes(evt['serder'].raw))) for evt in self.evts)
        self.evts.clear()
        return []

    async def resolve(app, pre, oobi, **kwa):
        assert oobi == f'http://127.0.0.1:1/oobi/{pre}/controller'
        lab.hby.psr.parse(ims=bytearray(lab.intro))
        return True

    async def authorize(app, hab, eid, role, timeout=30.0):
        doer = remoting.EndpointRoleDoer(lab.hby, hab, eid, role, timeout=timeout)
        doing.Doist(doers=[doer], tock=0.03125, limit=1.0).do()
        if doer.error:
            raise doer.error

    monkeypatch.setattr(forwarding.StreamPoster, 'deliver', deliver)
    monkeypatch.setattr(mailboxes, 'resolve_oobi', resolve)
    monkeypatch.setattr(mailboxes, 'authorize_endpoint_async', authorize)
    monkeypatch.setattr(lab.plugin, '_boot_client', SimpleNamespace(
        clone=lambda: boot, set_boot_server_aid=lambda aid: None))
    eid = asyncio.run(lab.plugin.provide_mailbox(lab.vault, program))
    return eid, mail


def test_provider_hosts_the_delegates_own_mailbox(provider_vault, monkeypatch):
    lab = provider_vault
    program = delegate(lab.hby, lab.state)
    rogue = lab.hby.makeHab(name='rogue')
    assert lab.plugin.mailbox_provider_name(lab.vault, program) == 'Local Development'
    assert lab.plugin.mailbox_provider_name(lab.vault, lab.state) is None
    assert lab.plugin.mailbox_provider_name(lab.vault, rogue) is None
    lab.hby.psr.parse(ims=bytearray(lab.intro))  # a reachable peer
    with pytest.raises(kering.ConfigurationError, match='cannot receive replies'):
        ipexing._require_route(program, lab.box.pre)

    boot = FakeBoot(lab.state, program, lab.box)
    eid, mail = run_provider(lab, program, boot, monkeypatch)

    assert eid == lab.box.pre
    assert boot.calls == [('request', lab.state.pre, program.pre), ('/operations/status', 'op-1')]
    # The mailbox got the delegation chain, then the delegate's own inception.
    assert {recp for recp, _ in mail} == {lab.box.pre}
    assert [(e.pre, e.sn) for _, e in mail] == [(lab.state.pre, 0), (lab.state.pre, 1), (program.pre, 0)]
    # The delegate receives through its own mailbox, not through state's routes.
    assert receiving_endpoints(program) == {lab.box.pre}
    assert lab.box.pre not in receiving_endpoints(lab.state)
    assert program.loadEndRole(cid=program.pre, role=kering.Roles.mailbox, eid=lab.box.pre)
    ipexing._require_route(program, lab.box.pre)  # the unchanged guard is now satisfied


def test_provider_refusal_is_reported_and_leaves_no_route(provider_vault, monkeypatch):
    lab = provider_vault
    program = delegate(lab.hby, lab.state)
    boot = FakeBoot(lab.state, program, lab.box, fail='Capacity exceeded')
    with pytest.raises(KFBootError, match='could not finish: Capacity exceeded'):
        run_provider(lab, program, boot, monkeypatch)
    assert not receiving_endpoints(program)


def test_mailbox_allocation_must_belong_to_the_requested_delegate(provider_vault):
    lab = provider_vault
    good = dict(account_aid='Eacct', aid='Edel', mailbox=dict(
        eid=lab.box.pre, oobis=[f'http://h/oobi/{lab.box.pre}/controller']))
    assert mailboxes.mailbox_allocation(good, account='Eacct', delegate='Edel')[0] == lab.box.pre
    with pytest.raises(KFBootError, match='another identifier'):
        mailboxes.mailbox_allocation(good, account='Eacct', delegate='Eother')
    with pytest.raises(KFBootError, match='no address'):
        mailboxes.mailbox_allocation(dict(good, mailbox=dict(eid=lab.box.pre, oobis=['http://h/oobi/Ex/controller'])),
                                     account='Eacct', delegate='Edel')


def test_create_dialog_sets_up_the_mailbox_before_closing(provider_vault, monkeypatch, qapp):
    from locksmith.ui.vault.identifiers import create as create_module
    from locksmith.ui.vault.identifiers.create import CreateIdentifierDialog

    lab = provider_vault
    program = delegate(lab.hby, lab.state)
    attempts, tasks, created = [], [], []

    async def provide(vault, hab):
        attempts.append(hab.pre)
        if len(attempts) == 1:
            raise KFBootError('The provider could not finish: Capacity exceeded')
        return lab.box.pre
    monkeypatch.setattr(lab.plugin, 'provide_mailbox', provide)
    monkeypatch.setattr(create_module.asyncio, 'ensure_future', tasks.append)

    dialog = CreateIdentifierDialog(':/assets/custom/identifiers.png', lab.app)
    dialog.name_field.setText('program')
    dialog.local_delegation_radio.setChecked(True)
    dialog.delegator_dropdown.setCurrentIndex(dialog.delegator_dropdown.combo_box.findData(lab.state.pre))
    assert 'Local Development then hosts this identifier\'s own mailbox' in dialog.delegation_help.text()
    dialog.identifier_created.connect(lambda alias, pre: created.append(pre))

    dialog._on_doer_event('InceptDoer', 'identifier_created', {'alias': 'program', 'pre': program.pre})
    qapp.processEvents()
    assert created == [] and not dialog.create_button.isEnabled()
    assert dialog.mailbox_status.text().startswith("Setting up program's mailbox with Local Development")
    asyncio.run(tasks.pop())
    assert dialog.create_button.text() == 'Try again'
    assert 'Capacity exceeded' in dialog.mailbox_status.text() and created == []

    dialog.create_button.click()
    asyncio.run(tasks.pop())
    assert created == [program.pre] and attempts == [program.pre, program.pre]


def test_without_a_provider_the_person_is_told_what_to_do(provider_vault, monkeypatch, qapp):
    from locksmith.ui.vault.identifiers.create import CreateIdentifierDialog
    from locksmith.ui.vault.identifiers.view import ViewIdentifierDialog

    lab = provider_vault
    other = lab.hby.makeHab(name='other')
    program = delegate(lab.hby, other, name='helper')
    dialog = CreateIdentifierDialog(':/assets/custom/identifiers.png', lab.app)
    dialog.name_field.setText('helper')
    dialog.local_delegation_radio.setChecked(True)
    dialog.delegator_dropdown.setCurrentIndex(dialog.delegator_dropdown.combo_box.findData(other.pre))
    assert "No provider hosts a mailbox for other's delegates" in dialog.delegation_help.text()
    dialog._on_doer_event('InceptDoer', 'identifier_created', {'alias': 'helper', 'pre': program.pre})
    qapp.processEvents()
    assert dialog.create_button.text() == 'Done'
    assert 'onboard other with a provider, then open helper and choose Set up mailbox' in dialog.mailbox_status.text()

    view = ViewIdentifierDialog(':/assets/custom/identifiers.png', lab.app, 'helper')
    assert view.mailbox_button.isHidden()
    assert view.receiving_status.text().startswith('helper has no mailbox')
    view.close()
    state_delegate = delegate(lab.hby, lab.state)
    view = ViewIdentifierDialog(':/assets/custom/identifiers.png', lab.app, state_delegate.name)
    assert not view.mailbox_button.isHidden()
    view.close()


def test_delegate_introduction_carries_its_anchor_and_mailbox(provider_vault, monkeypatch, tmp_path):
    lab = provider_vault
    program = delegate(lab.hby, lab.state)
    run_provider(lab, program, FakeBoot(lab.state, program, lab.box), monkeypatch)
    with habbing.openHby(name='delegate-mailbox-holder', temp=True) as holder:
        sue = holder.makeHab(name='sue')
        holder.psr.parse(ims=bytearray(lab.state.msgOwnInception()))  # an introduction from before the delegation
        intro = remoting.identifier_introduction(program)
        assert SerderKERI(raw=intro).pre == program.pre
        path = tmp_path / 'program.cesr'
        path.write_bytes(intro)
        app = SimpleNamespace(vault=SimpleNamespace(org=SimpleNamespace(update=lambda *a: None), hby=holder))
        doing.Doist(doers=[remoting.ImportDoer(app, str(path), 'program')], tock=0.03125, limit=1.0).do()
        assert holder.kevers[program.pre].delpre == lab.state.pre
        assert ipexing._reachable(sue, program.pre)
        assert set(sue.endsFor(program.pre).get(kering.Roles.mailbox, {})) == {lab.box.pre}
