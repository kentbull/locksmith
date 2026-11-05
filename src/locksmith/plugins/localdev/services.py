"""Activate provider-account service access and retain its authenticated public capabilities."""
import asyncio
from time import monotonic
from urllib.parse import urlsplit

from PySide6.QtNetwork import QSslCertificate
from keri.core import Prefixer

from locksmith.plugins.kerifoundation.onboarding.service import KFBootError, KFOnboardingService


def service_settings(payload, *, account):
    """Validate an authenticated capability result before permitting endpoint-specific CA trust."""
    if not isinstance(payload, dict) or payload.get('account_aid') != account:
        raise KFBootError('Service activation belongs to another account')
    capabilities = payload.get('services')
    if not isinstance(capabilities, dict) or set(capabilities) != {'registrar', 'observer'}:
        raise KFBootError('Local Development requires Registrar and Observer capabilities')
    selected = {}
    for kind, role in (('registrar', 'publisher'), ('observer', 'reader')):
        value = capabilities[kind]
        if (not isinstance(value, dict) or value.get('aid') != account
                or value.get('roles') != [role]):
            raise KFBootError(f'Invalid {kind} account permission')
        service, url, ca = value.get('service'), value.get('url'), value.get('ca_pem')
        if not isinstance(service, str) or Prefixer(qb64=service).qb64 != service:
            raise KFBootError(f'Invalid {kind} service identifier')
        endpoint = urlsplit(url) if isinstance(url, str) else None
        if (endpoint is None or endpoint.scheme != 'https' or not endpoint.hostname
                or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment
                or endpoint.path not in ('', '/')):
            raise KFBootError(f'{kind} must advertise an HTTPS origin')
        if not isinstance(ca, str) or ca and not QSslCertificate.fromData(ca.encode('utf-8')):
            raise KFBootError(f'Invalid {kind} public CA certificate')
        selected[kind] = {'aid': account, 'roles': [role], 'service': service,
                          'url': url.rstrip('/'), 'ca_pem': ca}
    return {'provider': 'localdev', 'account': account, 'capabilities': selected,
            **{kind: value['url'] for kind, value in selected.items()}}


async def activate_services(vault, account, client):
    """Finish one existing boot operation under the onboarding task's cancellation ownership."""
    def opened():
        if (getattr(vault, 'closed', False) or not vault.hby.db.opened
                or vault.hby.habByPre(account.pre) is not account):
            raise KFBootError('The provider account vault is closed')

    opened()
    reply = await KFOnboardingService._await_blocking_result(
        client.send_exn, surface='account', hab=account, route='/account/services',
        payload={'account_aid': account.pre})
    opened()
    if reply.payload.get('account_aid') != account.pre:
        raise KFBootError('Service activation returned another account')
    operation = reply.payload.get('operation')
    if not isinstance(operation, dict) or not isinstance(operation.get('operation_id'), str):
        raise KFBootError('Service activation did not return an operation')
    operation_id = operation['operation_id']
    deadline = monotonic() + 120
    while True:
        if (operation.get('operation_id') != operation_id or operation.get('requester') != account.pre
                or operation.get('kind') != 'account_services' or operation.get('subject') != f'account:{account.pre}'):
            raise KFBootError('Service operation differs from the selected account activation')
        if operation.get('state') == 'succeeded':
            settings = service_settings(operation.get('result'), account=account.pre)
            opened()
            config = vault.hby.cf.get() or {}
            config['registries'] = settings
            vault.hby.cf.put(config)
            return settings
        if operation.get('state') not in ('pending', 'running'):
            raise KFBootError('Credential-service activation failed; retry the existing onboarding session')
        if monotonic() >= deadline:
            raise KFBootError('Credential-service activation is pending; retry the existing onboarding session')
        await asyncio.sleep(0.5)
        opened()
        reply = await KFOnboardingService._await_blocking_result(
            client.send_exn, surface='account', hab=account, route='/operations/status',
            payload={'operation_id': operation_id})
        opened()
        operation = reply.payload.get('operation')
        if not isinstance(operation, dict):
            raise KFBootError('Service operation status is missing')
