# -*- encoding: utf-8 -*-
"""
locksmith.ui.vault.identifiers.mailbox module

Sentences and the provider call for giving a local identifier its own mailbox.

Every identifier that exchanges credentials needs its own receiving route:
witnesses, or a mailbox. A local delegate has no witnesses, so its provider
hosts a mailbox for it. Create Identifier and the identifier view share this.
"""
from locksmith.core.indirecting import receiving_endpoints


def needs_mailbox(hab):
    """True for a local delegate with no witnesses and no authorized mailbox."""
    return bool(hab.kever.delpre) and not receiving_endpoints(hab)


def mailbox_provider(app, hab):
    """Return ``(plugin, provider name)`` able to host ``hab``'s mailbox, or None."""
    find = getattr(getattr(app, 'plugin_manager', None), 'mailbox_provider', None)
    return find(app.vault, hab) if find is not None else None


def no_provider_text(app, hab):
    """Tell the person why ``hab`` cannot exchange credentials yet and what to do."""
    delegator = app.vault.hby.habByPre(hab.kever.delpre)
    who = delegator.name if delegator is not None else 'its delegator'
    return (f"{hab.name} has no mailbox, so it cannot send credentials or receive replies yet. "
            f"Mailboxes come from the provider account that delegated it: onboard {who} with a provider, "
            f"then open {hab.name} and choose Set up mailbox.")


def working_text(hab, provider):
    return f"Setting up {hab.name}'s mailbox with {provider} so it can send credentials and receive replies…"


def failed_text(hab, provider, error):
    return (f"{hab.name}'s mailbox could not be set up with {provider}: {error} "
            "Try again; nothing has to be created twice.")


async def set_up_mailbox(app, hab):
    """Have the provider host and authorize ``hab``'s mailbox; return its prefix."""
    found = mailbox_provider(app, hab)
    if found is None:
        raise ValueError(no_provider_text(app, hab))
    plugin, _ = found
    return await plugin.provide_mailbox(app.vault, hab)
