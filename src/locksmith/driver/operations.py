"""Cooperative operator actions using the same domain operations as Qt dialogs.

Local R&D adapter authored for community parity. Protocol composition, consent,
validation and delivery remain in credentialing/ipexing and the vault's outbox.
A yielded action keeps the Qt event loop free; it never owns another vault.
"""
from dataclasses import asdict
from time import monotonic

from keri.core import scheming
from keri.peer import exchanging
from locksmith.core import credentialing, disclosing, ipexing, registries


def execute(app, request):
    """Execute one explicit local request, yielding while application work runs.

    Args:
        app: Open LocksmithApplication with its running QtTask.
        request: JSON object naming op, local alias and operation-specific values.

    Returns:
        dict: JSON-safe outcome. submitted means transport completion only;
            callers must independently inspect the receiver's acceptance.

    Exceptions propagate to the local driver response. Already authorized outbox
    work remains durable even if the requesting process disconnects.
    """
    vault = app.vault
    op = request['op']
    if op == 'status':
        return {'name': app.name, 'open': app.is_vault_open}
    if op == 'configure':
        config = vault.hby.cf.get() or {}
        config['registries'] = dict(request['registries'])
        vault.hby.cf.put(config)
        return {'configured': True}
    if op == 'schema':
        schema = scheming.Schemer(sed=request['schema'])
        vault.hby.db.schema.pin((schema.said,), schema)
        return {'schema': schema.said}
    if op == 'policy':
        ipexing.set_presenter_policy(vault, request['credential'], request['presenter'],
                                    enabled=request.get('enabled', True))
        return {'configured': True}
    if op == 'inspect':
        said = request['said']
        if not vault.exc.complete(said):
            raise ValueError('Exchange is not accepted')
        exn = vault.hby.db.exns.get((said,))
        nodes = exchanging.loadParsedNestedSubstreams(vault.hby, said)
        return {'said': said, 'sad': exn.sad,
                'credentials': [node.serder.sad for node in nodes]}
    if op == 'inventory':
        return {'credentials': [dict(said=view['sad']['d'], sad=view['sad'],
                                     status=view['status'], grant=view.get('grant'))
                                for view in credentialing.credentials(vault)]}
    if op == 'custody-import':
        info = disclosing.custody(vault).importCustody(request['path'],
            regid=request['registry'], controller=request['controller'],
            discloser=request['discloser'], rewrap=request.get('rewrap', False))
        return {'custody': asdict(info)}
    if op == 'opening':
        opening = disclosing.custody(vault).derive(request['registry'], request['ordinal'],
                                                  request['credential'], request['state'])
        return {'opening': opening.qb64}
    hab = vault.hby.habByName(request['alias'])
    if hab is None:
        raise ValueError('Choose an identifier in this vault')
    if op == 'query':
        worker = registries.RegistrySyncDoer(vault, hab, request['registry'],
                                             observer_url=request['observer'])
        app.qtask.extend([worker])
        try:
            while not worker.done:
                yield
            if worker.error:
                raise ValueError(worker.error)
            return {'registry': request['registry'], 'head': worker.result.said}
        finally:
            app.qtask.remove([worker])
    selection = {key: request[key] for key in ('from_grant', 'refresh', 'openings', 'derive')
                 if key in request}
    if op in ('apply', 'offer') and not request.get('prior'):
        # Start has no state-refresh capability; Offer preview uses held material.
        said = ipexing.start(vault, hab, request['recipient'], op.title(),
            schema=request.get('schema'), credential_said=request.get('credential'),
            from_grant=request.get('from_grant'), disclose=request.get('disclose', ()))
    elif op == 'grant' and not request.get('prior'):
        exn, atc = ipexing.grant(vault, hab, request['credential'], request['recipient'],
                                disclose=request.get('disclose', ()), **selection)
        said = ipexing.submit(vault, hab, exn, atc)
    elif op in ('offer', 'agree', 'grant', 'admit', 'spurn'):
        said = ipexing.respond(vault, request['prior'], op.title(),
                              credential_said=request.get('credential'), **selection)
    else:
        raise ValueError('Unknown operator action')
    deadline = monotonic() + request.get('timeout', 60)
    while True:
        record = vault.db.outbox.get((said,))
        if record and record.status == 'submitted':
            return {'said': said, 'transport': asdict(record)}
        if record and record.status == 'failed':
            raise ValueError(f'Exchange {said}: {record.error}')
        if monotonic() >= deadline:
            raise TimeoutError(f'Exchange {said} retained; transport not yet submitted')
        yield
