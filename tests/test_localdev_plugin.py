"""The local provider must coexist with Foundation state in a real vault."""

from contextlib import ExitStack
from importlib.metadata import entry_points

from keri.app import habbing
from keri.acdc import registraring

from locksmith.core.apping import LocksmithApplication
from locksmith.core.vaulting import Vault
from locksmith.plugins.kerifoundation.db.basing import KFAccountRecord
from locksmith.plugins.kerifoundation.onboarding.service import KFOnboardingService


def test_local_provider_has_separate_pages_accounts_and_onboarding_keys(qapp):
    app = LocksmithApplication()
    providers = {ep.name: ep.load()() for ep in entry_points(group="locksmith.plugins")}
    foundation, local = providers["kerifoundation"], providers["localdev"]
    foundation.initialize(app)
    local.initialize(app)

    # Normal package discovery must register both providers without page collisions.
    assert foundation.get_pages().keys().isdisjoint(local.get_pages())
    assert "localdev_onboarding" in local.get_pages()
    assert "localdev_provision" not in local.get_pages()
    assert "kf_provision" in foundation.get_pages()
    assert local._boot_client._surfaces.onboarding_url == "http://127.0.0.1:19723/onboarding"

    with ExitStack() as stack:
        hby = stack.enter_context(habbing.openHby(name="local-provider", temp=True))
        rgy = registraring.Regery(hby=hby, name=hby.name, temp=True)
        stack.callback(rgy.close)
        app.vault = vault = Vault(app, hby, rgy)
        for store in (vault.db, vault.rep.mbx, vault.notifier.noter):
            stack.callback(store.close, clear=True)
        stack.callback(vault.exit)
        for plugin in (foundation, local):
            plugin.on_vault_opened(vault)
            stack.callback(plugin.on_vault_closed, vault, clear=True)

        # Empty providers use the real teardown service without remote work.
        foundation.prepare_vault_deletion(vault)
        local.prepare_vault_deletion(vault)

        # An account in the Foundation provider must not configure the local one.
        foundation._db.pin_account(KFAccountRecord(account_alias="foundation-account"))
        assert local._db.get_account() is None
        assert foundation._db.path != local._db.path

        # Each provider creates and later removes only its own hidden auth AID.
        foundation_service = KFOnboardingService(
            app=app, db=foundation._db, boot_client=foundation._boot_client,
        )
        local_service = KFOnboardingService(
            app=app, db=local._db, boot_client=local._boot_client,
            auth_namespace="localdev_onboarding", auth_alias_prefix="localdev-onboarding",
        )
        foundation_hab, _ = foundation_service._load_or_create_onboarding_hab(record=KFAccountRecord())
        local_hab, _ = local_service._load_or_create_onboarding_hab(record=KFAccountRecord())
        assert hby.habByName(local_hab.name, ns="localdev_onboarding") is local_hab
        assert hby.habByName(local_hab.name, ns="kf_onboarding") is None
        local_service._delete_onboarding_hab(local_hab.name)
        assert hby.habByName(local_hab.name, ns="localdev_onboarding") is None
        assert hby.habByName(foundation_hab.name, ns="kf_onboarding") is foundation_hab


def test_provider_capabilities_select_transport_account_without_changing_issuer_evidence(qapp):
    from keri import kering
    from keri.acdc import Registrar, Regery
    from keri.core import Parser
    from locksmith.core import evidence, registries
    from locksmith.plugins.localdev.services import service_settings
    from locksmith.db.basing import LocksmithBaser
    from types import SimpleNamespace

    with ExitStack() as stack:
        hby = stack.enter_context(habbing.openHby(name='provider-capabilities', temp=True,
                                                version=kering.Vrsn_2_0))
        rgy, db = Regery(hby=hby, name=hby.name, temp=True), LocksmithBaser(name=hby.name, temp=True)
        stack.callback(rgy.close)
        stack.callback(db.close)
        vault = SimpleNamespace(hby=hby, rgy=rgy, db=db)
        account, issuer = hby.makeHab(name='account'), hby.makeHab(name='issuer')
        registrar, observer = hby.makeHab(name='registrar'), hby.makeHab(name='observer')
        payload = {'account_aid': account.pre, 'services': {
            kind: {'aid': account.pre, 'roles': [role], 'service': service.pre,
                   'url': url, 'ca_pem': ''}
            for kind, role, service, url in (
                ('registrar', 'publisher', registrar, 'https://registrar.example'),
                ('observer', 'reader', observer, 'https://observer.example'))}}
        settings = service_settings(payload, account=account.pre)
        config = hby.cf.get() or {}
        config['registries'] = settings
        hby.cf.put(config)
        registry = Registrar(rgy=rgy).makeRegistry(name='issuer-registry', prefix=issuer.pre)
        rip = rgy.store.event(registry.regk)
        issuer.interact(data=[dict(i=registry.regk, s=rip.sad['n'], d=rip.said)], gvrsn=kering.Vrsn_2_0)
        assert registry.anchorMsg(rip.said)
        original = evidence.clone(vault, registry.regk)
        worker = registries.RegistrySyncDoer(vault, issuer, registry.regk, registrar_url=settings['registrar'])
        assert worker.hab is issuer and worker.transport_hab is account
        signed = Parser(version=kering.Vrsn_2_0).parseOne(ims=bytearray(evidence.signed_query(
            worker.transport_hab, 'tels/publish', {'stream': original.decode('utf-8')})), processive=False)
        assert signed.serder.pre == account.pre
        assert signed.serder.sad['q']['stream'].encode('utf-8') == original
        assert evidence.clone(vault, registry.regk) == original
        assert registries.RegistrySyncDoer(vault, issuer, registry.regk,
                   observer_url=settings['observer']).transport_hab is account
        # A policy change invalidates readiness even while the endpoint URLs remain unchanged.
        owner = registries.RegistryEvidenceDoer(vault)
        owner._published[registry.regk] = rip.said
        config['registries']['capabilities']['registrar']['ca_pem'] = 'changed'
        hby.cf.put(config)
        owner._configure()
        assert not owner._published
