# -*- encoding: utf-8 -*-
"""
locksmith.plugins.base module

Abstract base classes defining the plugin contracts for Locksmith extensions.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from hio.base import doing
    from PySide6.QtWidgets import QWidget
    from locksmith.ui.vault.menu import MenuButton


class PluginBase(ABC):
    """Base class that every Locksmith plugin must implement.

    Defines the lifecycle hooks, menu integration, page registration,
    background doer registration, and optional witness hooks.
    """

    @property
    @abstractmethod
    def plugin_id(self) -> str:
        """Unique namespace key for this plugin, e.g. 'your_plugin'."""
        ...

    @abstractmethod
    def initialize(self, app: Any) -> None:
        """Called once at startup after plugin discovery.

        Build pages, wire internal signals, store app reference.
        """
        ...

    @abstractmethod
    def on_vault_opened(self, vault: Any) -> None:
        """Called when a vault is opened.

        Load plugin state, open plugin DB, start doers.
        """
        ...

    def prepare_vault_deletion(self, vault: Any) -> None:
        """Called before a vault is permanently deleted.

        Plugins may use this hook to revoke remote state while the local
        vault and habery are still available. Raising aborts deletion.
        """
        pass

    @abstractmethod
    def on_vault_closed(self, vault: Any, *, clear: bool = False) -> None:
        """Called when a vault is closed.

        Cleanup plugin_state, disconnect signals, close DB.

        When ``clear`` is True, any plugin-local durable state tied to the
        vault should also be deleted from disk.
        """
        ...

    @abstractmethod
    def get_menu_entry(self) -> MenuButton:
        """Return the entry button shown in the main vault sidebar."""
        ...

    @abstractmethod
    def get_menu_section(self) -> list[QWidget]:
        """Return submenu items shown when the plugin menu is pushed."""
        ...

    @abstractmethod
    def get_pages(self) -> dict[str, QWidget]:
        """Return page_key -> widget mappings to register in VaultPage."""
        ...

    def get_doers(self) -> list[doing.Doer]:
        """Return background doers added to vault on open.

        Default returns empty list. Override for plugins that need
        background polling, heartbeats, or scheduled tasks.
        """
        return []

    def get_witness_batches(self, vault: Any, hab_pre: str) -> Any | None:
        """Optional: return batch data for witness authentication grouping.

        Default returns None (no batch data). Override if the plugin
        manages witness provisioning with batch groupings.
        """
        return None

    def get_witness_state(self, vault: Any, wit_eid: str) -> Any | None:
        """Optional: return witness auth/reservation state.

        Default returns None. Override if the plugin manages witness state.
        """
        return None

    def update_witness_state(self, vault: Any, wit_eid: str) -> None:
        """Optional: update witness state after rotation (mark reserved=True).

        Default is a no-op. Override if the plugin manages witness state.
        """
        pass

    def update_witness_state_after_auth(self, vault: Any, wit_eid: str) -> None:
        """Optional: update witness state after authentication (mark reserved=False).

        Default is a no-op. Override if the plugin manages witness state.
        """
        pass

    def mailbox_provider_name(self, vault: Any, hab: Any) -> str | None:
        """Optional: name this provider when it can give ``hab`` a hosted mailbox.

        Every identifier that exchanges credentials needs its own receiving
        route. Return the provider name shown to the person, or None (default)
        when this plugin cannot serve ``hab`` in ``vault``.
        """
        return None

    async def provide_mailbox(self, vault: Any, hab: Any) -> str:
        """Optional: allocate and authorize a hosted mailbox for ``hab``.

        Called only when :meth:`mailbox_provider_name` named this plugin.
        Return the authorized mailbox prefix; raise with a sentence the person
        can act on when it cannot be set up.
        """
        raise NotImplementedError

    async def after_identifier_authenticated(self, vault: Any, hab: Any) -> None:
        """Optional: hook called after an identifier's witnesses are authenticated.

        Default is a no-op. Override to check keystate, spawn update dialogs, etc.
        """
        pass


class AccountProviderPlugin(ABC):
    """Mixin for plugins with a setup/account creation flow."""

    @abstractmethod
    def is_setup_complete(self, vault: Any) -> bool:
        """Return True when all prerequisites are met for full menu navigation."""
        ...

    @abstractmethod
    def get_setup_page(self, vault: Any) -> tuple[str, bool]:
        """Return (page_key, should_push_menu) for the current setup step.

        If no account exists: return (account_creation_page_key, False)
        If account but no team: return (team_start_page_key, True)
        """
        ...

    def on_account_created(self, vault: Any, account: Any) -> None:
        """Hook called after account_created signal fires.

        Default is a no-op.
        """
        pass


class IdentifierUploadProviderPlugin(ABC):
    """Contract for plugins that upload/sync local identifiers to a platform."""
    pass


class WitnessProviderPlugin(ABC):
    """Contract for plugins that provision witness services."""
    pass


class WatcherProviderPlugin(ABC):
    """Contract for plugins that provision watcher services."""
    pass


class CredentialProviderPlugin(ABC):
    """Contract for plugins that manage published credentials."""
    pass
