# -*- encoding: utf-8 -*-
"""
locksmith.plugins.manager module

Plugin discovery, initialization, and lifecycle management.
"""
from __future__ import annotations

import importlib.metadata
from types import SimpleNamespace
from typing import Any, TYPE_CHECKING

from keri import help

from locksmith.plugins.base import (
    PluginBase,
    AccountProviderPlugin,
)

if TYPE_CHECKING:
    from locksmith.ui.vault.menu import VaultNavMenu
    from locksmith.ui.vault.page import VaultPage

logger = help.ogler.getLogger(__name__)

ENTRY_POINT_GROUP = "locksmith.plugins"


class PluginManager:
    """Discovers, initializes, and manages Locksmith plugins."""

    def __init__(self, app: Any):
        self._app = app
        self._plugins: dict[str, PluginBase] = {}

    def discover_and_initialize(self, vault_page: VaultPage, nav_menu: VaultNavMenu) -> None:
        """Discover plugins via entry points, initialize them, and register pages/menus."""
        eps = importlib.metadata.entry_points(group=ENTRY_POINT_GROUP)
        for ep in eps:
            try:
                plugin_cls = ep.load()
                plugin = plugin_cls()
                plugin.initialize(self._app)

                pid = plugin.plugin_id
                self._plugins[pid] = plugin

                # Register pages
                for key, widget in plugin.get_pages().items():
                    vault_page.register_page(key, widget)

                # Register menu section
                nav_menu.register_plugin_section(
                    pid,
                    plugin.get_menu_entry(),
                    plugin.get_menu_section(),
                )

                logger.info(f"Plugin '{pid}' loaded from entry point '{ep.name}'")
            except Exception:
                logger.exception(f"Failed to load plugin from entry point '{ep.name}'")

    def on_vault_opened(self, vault: Any) -> None:
        """Notify all plugins that a vault has been opened."""
        for plugin in self._plugins.values():
            try:
                plugin.on_vault_opened(vault)
                vault.extend(plugin.get_doers())
            except Exception:
                logger.exception(f"Plugin '{plugin.plugin_id}' failed on_vault_opened")

    def prepare_vault_deletion(self, vault: Any) -> None:
        """Let plugins revoke remote state before local vault deletion."""
        for plugin in self._plugins.values():
            try:
                plugin.prepare_vault_deletion(vault)
            except Exception:
                logger.exception(f"Plugin '{plugin.plugin_id}' failed prepare_vault_deletion")
                raise

    def on_vault_closed(self, vault: Any, *, clear: bool = False) -> None:
        """Notify all plugins that a vault is being closed."""
        for plugin in self._plugins.values():
            try:
                plugin.on_vault_closed(vault, clear=clear)
            except Exception:
                logger.exception(f"Plugin '{plugin.plugin_id}' failed on_vault_closed")

    def get_plugin(self, plugin_id: str) -> PluginBase | None:
        """Return a plugin by its ID, or None if not found."""
        return self._plugins.get(plugin_id)

    def is_setup_complete(self, plugin_id: str, vault: Any) -> bool:
        """Check if a plugin's setup is complete. Non-account plugins always return True."""
        plugin = self._plugins.get(plugin_id)
        if plugin and isinstance(plugin, AccountProviderPlugin):
            return plugin.is_setup_complete(vault)
        return True

    async def after_identifier_authenticated(self, vault: Any, hab: Any) -> None:
        """Call after_identifier_authenticated on all plugins."""
        for plugin in self._plugins.values():
            try:
                await plugin.after_identifier_authenticated(vault, hab)
            except Exception:
                logger.exception(
                    f"Plugin '{plugin.plugin_id}' failed after_identifier_authenticated"
                )

    def mailbox_provider(self, vault: Any, hab: Any) -> tuple[PluginBase, str] | None:
        """Return the first plugin, with its display name, that can give ``hab`` a mailbox."""
        for plugin in self._plugins.values():
            try:
                name = plugin.mailbox_provider_name(vault, hab)
            except Exception:
                logger.exception(f"Plugin '{plugin.plugin_id}' failed mailbox_provider_name")
                continue
            if name:
                return plugin, name
        return None

    def get_witness_batches(self, vault: Any, hab_pre: str) -> Any | None:
        """Query all plugins for witness batch data and merge distinct groups."""
        merged = []
        seen = set()

        for plugin in self._plugins.values():
            result = plugin.get_witness_batches(vault, hab_pre)
            if result is None:
                continue

            for batch in getattr(result, "batches", []) or []:
                if not isinstance(batch, (list, tuple)) or not batch:
                    continue

                key = tuple(sorted(str(eid) for eid in batch))
                if key in seen:
                    continue

                seen.add(key)
                merged.append(list(batch))

        if not merged:
            return None

        return SimpleNamespace(batches=merged)

    def update_witness_state_after_rotation(self, vault: Any, wit_eid: str) -> None:
        """Notify all plugins to update witness state after rotation."""
        for plugin in self._plugins.values():
            plugin.update_witness_state(vault, wit_eid)

    def update_witness_state_after_auth(self, vault: Any, wit_eid: str) -> None:
        """Notify all plugins to update witness state after authentication."""
        for plugin in self._plugins.values():
            plugin.update_witness_state_after_auth(vault, wit_eid)
