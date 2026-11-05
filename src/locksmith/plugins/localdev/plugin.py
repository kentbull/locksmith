"""Host development provider; provisioning stays in the local kf-boot service."""

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
