"""Cooperative issuer controls over the existing application issuance worker.

Local operator composition of IssueCredentialDoer; no KLI subprocess, alternate
credential constructor, protocol acceptance shortcut or implicit salt sharing.
"""
from time import monotonic

from locksmith.core import credentialing, evidence


def issue(app, request):
    """Run one explicit issuance using the vault's existing schema issuer policy.

    Args:
        app: Open application owning the vault and its running HIO scheduler.
        request: Operator input with alias, schema, recipient, attributes, and
            optional authentication, registry_mode, discloser, nonce, edges,
            rules, witness codes and timeout. Codes are transient input only.

    Yields while the worker runs. Returns public credential/proof metadata after
    the worker reports success. Cancellation removes the worker; already signed
    authoring records remain available for diagnosis and are never rolled back.
    """
    vault = app.vault
    hab = vault.hby.habByName(request['alias'])
    if hab is None or vault.db.issuers.get((request['schema'],)) != hab.pre:
        raise ValueError('Choose the configured local issuer for this schema')
    options = {key: request[key] for key in (
        'edges', 'rules', 'codes', 'authentication', 'nonce', 'registry_mode', 'discloser')
        if key in request}
    worker = credentialing.IssueCredentialDoer(app, request['schema'],
        request['recipient'], request['attributes'], **options)
    outcomes = []

    def completed(name, event, data):
        """Observe only this worker's ordinary application completion signal."""
        if name == 'IssueCredentialDoer' and data.get('issuance_id') == worker.issuance_id:
            outcomes.append(data)

    vault.signals.doer_event.connect(completed)
    vault.extend([worker])
    deadline = monotonic() + request.get('timeout', 60)
    try:
        while not outcomes:
            if monotonic() >= deadline:
                raise TimeoutError('Credential issuance has not completed; inspect retained authoring state')
            yield
        outcome = outcomes[-1]
        if not outcome.get('success'):
            raise ValueError(outcome.get('error', 'Credential issuance failed'))
        said = outcome['credential_said']
        record = vault.db.issued.get((said,))
        view = credentialing.credential(vault, said)
        registry = view['sad'].get('rd')
        return {'credential': said, 'registry': registry, 'update': record.update,
                'sad': view['sad'], 'stream': record.stream,
                'registry_evidence': evidence.processor(vault).clone([registry]).decode()
                    if registry else '', 'accepted': True}
    finally:
        vault.signals.doer_event.disconnect(completed)
        vault.remove([worker])
