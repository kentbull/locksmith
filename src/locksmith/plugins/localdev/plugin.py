"""Host development provider; provisioning stays in the local kf-boot service."""

import asyncio
import os
from urllib.parse import urlsplit

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QLabel

from locksmith.ui.vault.menu import MenuButton
from locksmith.plugins.kerifoundation.core.configing import KFSurfaceConfig
from locksmith.plugins.kerifoundation.plugin import KeriFoundationPlugin


class LocalDevelopmentPlugin(KeriFoundationPlugin):
    """Reuse KF onboarding with separate provider pages and per-vault state."""

    page_prefix = "localdev"
    provider_name = "Local Development"
    # All allocations for this provider must go through its own boot service.
    allow_direct_provisioning = False
    boot_surfaces = KFSurfaceConfig(
        onboarding_url="http://127.0.0.1:19723/onboarding",
        account_url="http://127.0.0.1:19723/account",
    )

    @property
    def plugin_id(self) -> str:
        return "localdev"

    def initialize(self, app):
        """Select one explicit local provider origin without changing Foundation defaults."""
        self._refresh_btn = None
        self._refresh_status = None
        origin = os.environ.get('LOCAL_PROVIDER_URL', 'http://127.0.0.1:19723').rstrip('/')
        parsed = urlsplit(origin)
        if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path or not (parsed.scheme == 'https' or parsed.scheme == 'http'
                                      and parsed.hostname in ('localhost', '127.0.0.1', '::1'))):
            raise ValueError('LOCAL_PROVIDER_URL must be an HTTPS or loopback HTTP origin')
        self.boot_surfaces = KFSurfaceConfig(onboarding_url=origin + '/onboarding', account_url=origin + '/account')
        super().initialize(app)

    async def activate_account_services(self, account, client):
        """Keep credential-service activation inside the existing onboarding task."""
        from locksmith.plugins.localdev.services import activate_services
        return await activate_services(self._app.vault, account, client)

    def get_menu_section(self):
        """Expose service renewal beside the existing account navigation."""
        items = super().get_menu_section()
        self._refresh_btn = MenuButton(icon=QIcon(":/assets/material-icons/refresh.svg"),
                                       label="Refresh credential service access")
        self._refresh_btn.clicked.connect(self._refresh_service_access)
        self._refresh_status = QLabel("")
        self._refresh_status.setWordWrap(True)
        self._update_refresh_action()
        return [*items, self._refresh_btn, self._refresh_status]

    def _update_refresh_action(self):
        """Enable refresh only for an open onboarded account with no owned task."""
        if self._refresh_btn is not None:
            active = self._onboarding_task is not None and not self._onboarding_task.done()
            self._refresh_btn.setEnabled(not self._closing_vault and self._has_onboarded_account() and not active)

    def on_vault_opened(self, vault):
        """Restore the action from the persisted account when a vault opens."""
        super().on_vault_opened(vault)
        self._update_refresh_action()

    def on_vault_closed(self, vault, *, clear=False):
        """Join the existing task shutdown and clear the closed vault's status."""
        super().on_vault_closed(vault, clear=clear)
        if self._refresh_status is not None:
            self._refresh_status.clear()
        self._update_refresh_action()

    def _finish_onboarding_run(self):
        """Restore refresh availability after either task using the shared owner."""
        super()._finish_onboarding_run()
        self._update_refresh_action()

    def _refresh_service_access(self, checked=False):
        """Refresh an existing permanent account without another allocation or rotation."""
        if self._closing_vault or self._onboarding_task is not None and not self._onboarding_task.done():
            return
        record = self._get_account_record()
        vault = getattr(self._app, 'vault', None)
        if not self._has_onboarded_account() or vault is None:
            return
        account = vault.hby.habByPre(record.account_aid)
        if account is None or not record.boot_server_aid:
            self._refresh_status.setText('Reopen the onboarded account before refreshing service access.')
            return
        self._sync_boot_client_destination()
        self._refresh_status.setText('Refreshing service access…')
        self._onboarding_task = asyncio.create_task(self._run_service_refresh(
            vault=vault, db=self._db, account=account, client=self._boot_client.clone()))
        self._update_refresh_action()

    async def _run_service_refresh(self, *, vault, db, account, client):
        """Borrow the existing cancellable task owner and its captured vault/account."""
        from locksmith.plugins.localdev.services import activate_services
        task = asyncio.current_task()
        try:
            await activate_services(vault, account, client)
        except asyncio.CancelledError:
            raise
        except Exception as ex:
            if self._is_current_onboarding_task(task, vault=vault, db=db):
                self._refresh_status.setText(f'Service access could not be refreshed: {ex}. Try again.')
        else:
            if self._is_current_onboarding_task(task, vault=vault, db=db):
                # A new authorization must discard old readiness even for identical capabilities.
                vault.registry_evidence.reset()
                self._refresh_status.setText('Service access refreshed')
        finally:
            if task is self._onboarding_task:
                self._finish_onboarding_run()
