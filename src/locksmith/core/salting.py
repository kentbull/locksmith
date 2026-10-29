"""Optional registry-salt composition over one vault's existing KERI owners.

KERIpy owns the provisional profile, custody, authority and delivery behavior.
This adapter selects local ESSR recipients and ties cooperative work to the
vault lifetime; incoming statements never grant local approval or consent.
"""

from hio.base import doing
from keri import kering
from keri.app.essring import EssrReplyHandler
from keri.app.registry_custody import RegistryCustody
from keri.app.registry_salt_delivery import RegistrySaltDelivery
from keri.app.registry_salt_service import RegistrySaltService, ROUTES
from keri.app.registry_salt_state import RegistrySaltState


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


class RegistrySalts(doing.DoDoer):
    """Resume authorized retained work using the vault's scheduler and cleanup."""

    def __init__(self, vault, **kwa):
        """Borrow vault stores/parser/Revery/KRAM and register the exact six routes.

        Construction opens/decrypts no root and enrolls no party. The existing
        mailbox remains the sole reply-escrow cadence. Worker children exist
        only for locally controlled parties already recorded by retained origins.
        """
        self.vault = vault
        self.custody = RegistryCustody(vault.hby, vault.rgy, db=vault.db)
        self.state = RegistrySaltState(self.custody)
        self.service = RegistrySaltService(vault.hby, vault.rgy, vault, self.custody,
            self.state, vault.mbx.parser, vault.rvy, exc=vault.exc, mux=vault.mux)
        self.service.register()
        vault.exc.addHandler(VaultEssrReplies(vault.hby, vault.mbx.parser))
        self.workers = {}
        self.errors = {}
        self.checkpoints = {}
        self.after = None
        super().__init__(doers=[doing.doify(self.resumeDo, tock=0.5)], **kwa)

    def recur(self, tyme, deeds=None):
        """Isolate optional feature failure from ordinary vault verification/IPEX.

        tyme/deeds are existing HIO inputs. Return completion on failure so HIO
        closes owned children while durable jobs remain recoverable on reopen.
        Like RegistrySyncDoer, this boundary exposes only a static local error.
        """
        try:
            return super().recur(tyme, deeds)
        except Exception:
            self.errors['_runtime'] = 'Optional registry-root processing is unavailable'
            return True

    def _sources(self):
        """Return explicit retained entitled local parties, never arbitrary aliases."""
        origins = self.state.origins()
        candidates = {aid for origin in origins for aid in (origin.issuer, origin.discloser)}
        confirmations = {origin.confirm for origin in origins}
        candidates.update(grant.party for _, grant in self.vault.db.saltAssignments.getTopItemIter()
                          if grant.origin in confirmations)
        return {party for party in candidates if self.vault.hby.habByPre(party) is not None}

    def reconcile(self):
        """Resume same-root work after restart/accepted membership changes.

        Returns: None. KERIpy revalidates trusted accepted rosters and entitlement
        before queueing; pending proposals cannot enroll recipients. Readiness
        errors stay feature-local and do not interrupt ordinary IPEX.
        """
        sources = self._sources()
        for party in set(self.workers) - sources:
            self.remove([self.workers.pop(party)])
            self.errors.pop(party, None)
            self.checkpoints.pop(party, None)
        origins = tuple(origin.confirm for origin in self.state.origins())
        grants = tuple(grant.reply for _, grant in self.vault.db.saltAssignments.getTopItemIter())
        for party in sorted(sources):
            if self.after is not None and party <= self.after:
                continue
            kever = self.vault.hby.kevers.get(party)
            checkpoint = ((kever.lastEst.s, kever.lastEst.d) if kever else None, origins, grants)
            if self.checkpoints.get(party) == checkpoint:
                continue
            self.after = party
            try:
                self.service.reconcileKnown(party)
            except kering.KeriError:
                self.errors[party] = 'Registry custody or accepted evidence is unavailable'
                break
            self.errors.pop(party, None)
            self.checkpoints[party] = checkpoint
            if party not in self.workers:
                worker = RegistrySaltDelivery(self.service, party)
                self.extend([worker])
                self.workers[party] = worker
            break  # Reconcile at most one changed party per cooperative step.
        else:
            self.after = None

    def resumeDo(self, tymth, tock=0.5, **kwa):
        """Yield on the existing HIO clock while reconciling retained optional work.

        tymth/tock/kwa are scheduler inputs. Reply escrow processing remains in
        MailboxDirector; no second Parser, mailbox, environment or timer starts.
        """
        self.wind(tymth)
        yield tock
        while not self.vault.closed:
            self.reconcile()
            yield tock

    def status(self, registry):
        """Return public stored progress without decrypting or promising usable custody.

        registry selects an existing registry. The snapshot reports a recorded
        origin/root cipher, delivery states, and outstanding retention receipts.
        Authentication and decryption happen only in explicit domain operations.
        """
        origin = self.state.origin(registry)
        deliveries = [job for _, job in self.vault.db.saltDeliveries.getTopItemIter(keys=(registry,))]
        counts = {}
        for job in deliveries:
            counts[job.state] = counts.get(job.state, 0) + 1
        receipts = sum(intent.state == 'pending' for _, intent in
                       self.vault.db.saltReceipts.getTopItemIter() if intent.registry == registry)
        return dict(origin=origin.confirm if origin else None,
            root_recorded=self.vault.db.custody.get((registry,)) is not None,
            deliveries=counts, receipt_pending=receipts,
            error=self.errors.get('_runtime', ''))

    def issuanceRegistries(self, issuer=None):
        """Return recorded established registry choices without decrypting custody.

        issuer optionally restricts the locally controlled issuer AID. Each
        snapshot contains registry, issuer, discloser and original confirm SAID
        as origin. Accepted inception, local control and encrypted-row presence
        filter choices; these facts do not promise currently usable custody.
        """
        choices = []
        for origin in self.state.origins():
            if issuer is not None and origin.issuer != issuer:
                continue
            registry = self.vault.rgy.regs.get(origin.registry)
            rip = self.vault.rgy.store.seqEvent(origin.registry, 0)
            if (registry is None or rip is None or rip.israid != origin.issuer
                    or self.vault.hby.habByPre(origin.issuer) is None
                    or self.vault.db.custody.get((origin.registry,)) is None):
                continue
            choices.append(dict(registry=origin.registry, issuer=origin.issuer,
                                discloser=origin.discloser, origin=origin.confirm))
        return sorted(choices, key=lambda choice: choice['registry'])


def require_established(vault, registry, *, issuer=None, discloser=None):
    """Return recorded DH origin before new derived authoring; generate nothing.

    vault owns the optional state; registry is the exact accepted identifier;
    issuer/discloser optionally bind the operator's selected identities. This
    read-only preflight does not decrypt custody or claim its current usability;
    the ensuing core derive operation authenticates Keeper and encrypted root.
    Raises ConfigurationError for missing origin/root or changed role choices.
    """
    salts = vault.salts
    origin = salts.state.origin(registry)
    if origin is None or not salts.status(registry)['root_recorded']:
        raise kering.ConfigurationError('Establish the registry root before derived authoring')
    if (issuer is not None and origin.issuer != issuer or
            discloser is not None and origin.discloser != discloser):
        raise kering.ConfigurationError('Derived authoring must use the original established parties')
    return origin
