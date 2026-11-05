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
