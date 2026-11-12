# -*- encoding: utf-8 -*-
"""
locksmith.plugins.kerifoundation.core.mailboxes module

Hosted mailboxes for identifiers the provider account delegated.

Every identifier that exchanges credentials needs its own receiving route. A
delegate created in this wallet has no witnesses, so the provider allocates a
mailbox bound to the delegate's AID. The wallet resolves that mailbox, gives it
the delegate's KEL and authorizes it in the delegate's ``mailbox`` end role.
"""
from __future__ import annotations

from keri import kering
from keri.core import Prefixer

from locksmith.core.indirecting import receiving_endpoints
from locksmith.core.remoting import authorize_endpoint_async, resolve_oobi
from locksmith.plugins.kerifoundation.onboarding.service import (
    KFBootError,
    KFOnboardingService,
    await_account_operation,
)


def mailbox_allocation(result, *, account, delegate):
    """Validate the provider's signed operation result and return ``(eid, oobi)``."""
    if (not isinstance(result, dict) or result.get('account_aid') != account
            or result.get('aid') != delegate):
        raise KFBootError('The provider returned a mailbox for another identifier')
    mailbox = result.get('mailbox')
    eid = mailbox.get('eid') if isinstance(mailbox, dict) else None
    oobis = mailbox.get('oobis') if isinstance(mailbox, dict) else None
    try:
        if not isinstance(eid, str) or Prefixer(qb64=eid).qb64 != eid:
            raise ValueError(eid)
    except Exception as ex:
        raise KFBootError('The provider returned an invalid mailbox identifier') from ex
    oobi = next((url for url in oobis or [] if isinstance(url, str) and f'/oobi/{eid}' in url), None)
    if oobi is None:
        raise KFBootError('The provider returned no address for the mailbox')
    return eid, oobi


async def provide_delegate_mailbox(app, vault, account, delegate, client):
    """Allocate, resolve and authorize the hosted mailbox of ``delegate``.

    Args:
        app: Application whose open vault is ``vault``.
        vault: The vault holding both identifiers.
        account: The onboarded provider account; it delegated ``delegate``.
        delegate: Local identifier that needs a receiving route.
        client: A ``KFBootClient`` snapshot for worker-thread requests.

    Returns:
        str: The mailbox identifier now authorized for ``delegate``.
    """
    def opened():
        if (getattr(vault, 'closed', False) or not vault.hby.db.opened or app.vault is not vault
                or vault.hby.habByPre(account.pre) is not account
                or vault.hby.habByPre(delegate.pre) is not delegate):
            raise KFBootError('The vault closed before the mailbox was set up')

    if delegate.kever.delpre != account.pre:
        raise KFBootError(f'{delegate.name} is not delegated by the provider account {account.name}')
    opened()
    reply = await KFOnboardingService._await_blocking_result(
        client.request_delegate_mailbox, account, delegate)
    opened()
    if reply.payload.get('account_aid') != account.pre or reply.payload.get('aid') != delegate.pre:
        raise KFBootError('The provider answered for another identifier')
    result = await await_account_operation(
        client, account, reply.payload.get('operation'), kind='delegate_mailbox',
        subject=f'mailbox:{delegate.pre}', opened=opened,
        pending=f"The provider is still allocating {delegate.name}'s mailbox; try again")
    eid, oobi = mailbox_allocation(result, account=account.pre, delegate=delegate.pre)
    opened()
    if not await resolve_oobi(app, pre=eid, oobi=oobi, force=True,
                              alias=f'{delegate.name} mailbox', cid=delegate.pre, tag='mailbox'):
        raise KFBootError(f"{delegate.name}'s mailbox did not answer at {oobi}")
    opened()
    await authorize_endpoint_async(app, delegate, eid, kering.Roles.mailbox)
    opened()
    if eid not in receiving_endpoints(delegate):
        raise KFBootError(f"{delegate.name}'s mailbox was not authorized")
    return eid
