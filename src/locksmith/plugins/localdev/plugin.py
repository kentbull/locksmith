"""Host development provider; provisioning stays in the local kf-boot service."""

import os
from urllib.parse import urlsplit

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
