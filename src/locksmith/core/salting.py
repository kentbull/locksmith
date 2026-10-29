"""Optional registry-salt composition over one vault's existing KERI owners.

KERIpy owns the provisional profile, custody and reply authentication.
This adapter selects local ESSR recipients and uses the vault mailbox for ordinary reply escrows; incoming statements never grant local approval or consent.
"""

from keri import kering
from keri.app.essring import EssrReplyHandler
from keri.app.registry_custody import RegistryCustody
from keri.app.registry_salt_service import RegistrySaltService, ROUTES


class VaultEssrReplies:
    """Delegate verified outer ESSR to its explicitly addressed local individual."""

    resource = EssrReplyHandler.resource

    def __init__(self, hby, parser):
        """Borrow hby and the vault's live parser; create no processor or store."""
        self.hby, self.parser = hby, parser

    def _handler(self, serder):
        """Select signed outer destination, retaining all core recipient checks."""
        q = serder.sad.get('q')
        dest = q.get('dest') if isinstance(q, dict) else None
        hab = self.hby.habByPre(dest) if isinstance(dest, str) else None
        if hab is None:
            raise kering.ValidationError('ESSR requires an explicitly addressed local recipient')
        return EssrReplyHandler(self.hby, hab, self.parser, ROUTES)

    def verify(self, serder, **kwa):
        """Return core verification for authenticated outer serder and attachments."""
        return self._handler(serder).verify(serder, **kwa)

    def handle(self, serder, **kwa):
        """Delegate decryption and live reply processing; return no custody receipt."""
        return self._handler(serder).handle(serder, **kwa)


class RegistrySalts:
    """Compose optional encrypted salt storage and ordinary reply handling."""

    def __init__(self, vault):
        """Borrow existing owners; the vault mailbox already processes reply escrows."""
        self.vault = vault
        self.custody = RegistryCustody(vault.hby, vault.rgy, db=vault.db)
        self.service = RegistrySaltService(vault.hby, vault.rgy, self.custody, vault.rvy)
        self.service.register()
        vault.exc.addHandler(VaultEssrReplies(vault.hby, vault.mbx.parser))

    def status(self, registry):
        """Report local encrypted-row presence, without implying usable keys or delivery."""
        return dict(root_recorded=self.vault.db.custody.get((registry,)) is not None)

    def issuanceRegistries(self, issuer=None):
        """List accepted local issuer registries with encrypted derivation material.

        This reads no private salt and reports no recipient entitlement. Actual
        authoring authenticates the Keeper and ciphertext through RegistryCustody.
        """
        choices = []
        for regid in self.vault.rgy.regs:
            rip = self.vault.rgy.store.seqEvent(regid, 0)
            if (rip is not None and (issuer is None or rip.israid == issuer)
                    and self.vault.hby.habByPre(rip.israid) is not None
                    and self.vault.db.custody.get((regid,)) is not None):
                choices.append(dict(registry=regid, issuer=rip.israid))
        return sorted(choices, key=lambda choice: choice['registry'])


def require_custody(vault, registry, *, issuer=None):
    """Require accepted issuer evidence and local custody before derived authoring.

    This is a preflight, not a salt agreement or recipient authorization. The
    actual derivation authenticates encrypted storage with the existing Keeper.
    """
    rip = vault.rgy.store.seqEvent(registry, 0)
    if (rip is None or (issuer is not None and rip.israid != issuer)
            or vault.hby.habByPre(rip.israid) is None
            or vault.db.custody.get((registry,)) is None):
        raise kering.ConfigurationError('Choose an accepted issuer registry with local salt custody')
    return rip
