"""Cooperative operator actions using the same domain operations as Qt dialogs.

Local R&D adapter authored for community parity. Protocol composition, consent,
validation and delivery remain in credentialing/ipexing and the vault's outbox.
A yielded action keeps the Qt event loop free; it never owns another vault.
"""
from dataclasses import asdict
from time import monotonic

from keri import kering
from keri.core import scheming, SerderACDC
from keri.peer import exchanging
from locksmith.core import credentialing, disclosing, evidence, ipexing, registries


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
    if op == 'issue':
        from locksmith.driver.authoring import issue
        return (yield from issue(app, request))
    if op == 'schema':
        schema = scheming.Schemer(sed=request['schema'])
        issuer = None
        if request.get('issuer'):
            issuer = vault.hby.habByName(request['issuer'])
            if issuer is None:
                raise ValueError('Choose a local schema issuer')
        vault.hby.db.schema.pin((schema.said,), schema)
        if issuer is not None:
            # Same explicit issuer policy as LoadSchemaDoer; this is not an
            # accepted credential or a delegation of protocol authority.
            vault.db.issuers.pin((schema.said,), issuer.pre)
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
        result = []
        for view in credentialing.credentials(vault):
            said = view['sad']['d']
            admissions = credentialing.admissions(vault, said)
            views = ([credentialing.credential(vault, said, grant=entry.grant)
                      for entry in admissions] if admissions else [view])
            result.extend(dict(said=said, sad=item['sad'], status=item['status'],
                               grant=item.get('grant')) for item in views)
        return {'credentials': result}
    if op == 'custody-import':
        info = disclosing.custody(vault).importCustody(request['path'],
            regid=request['registry'], controller=request['controller'],
            discloser=request['discloser'], rewrap=request.get('rewrap', False))
        return {'custody': asdict(info)}
    if op == 'opening':
        if ipexing.grant_credential(vault, request['from_grant']).said != request['credential']:
            raise ValueError('admitted grant does not bind the requested credential')
        credentialing.credential(vault, request['credential'], grant=request['from_grant'])
        opening = disclosing.custody(vault).derive(request['registry'], request['ordinal'],
                                                  request['credential'], request['state'])
        from keri.acdc.regeventing import vetBlind
        event = vault.rgy.store.seqEvent(request['registry'], request['ordinal'])
        if event is None or vetBlind(opening, blid=event.sad.get('b')) != (request['credential'], request['state']):
            raise ValueError('Opening does not match the selected accepted event')
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
            return {'registry': request['registry'], 'head': worker.result.said,
                    'sn': worker.result.sn, 'stream': evidence.processor(vault).clone(
                        [request['registry']]).decode()}
        finally:
            app.qtask.remove([worker])
    # HTTP intake acknowledges queueing, not parser completion. Wait for the
    # signed prior before asking the same application response operation as UI.
    deadline = monotonic() + request.get('timeout', 60)
    if prior := request.get('prior'):
        while not vault.exc.complete(prior):
            if monotonic() >= deadline:
                raise TimeoutError('Prior exchange has not passed protocol verification')
            yield
    credential = None
    if request.get('credential') and op in ('offer', 'grant'):
        view = credentialing.credential(vault, request['credential'], grant=request.get('from_grant'))
        credential = SerderACDC(sad=view['sad'])
    elif op == 'admit':
        credential = ipexing.grant_credential(vault, request['prior'])
    if credential is not None:
        while True:
            try:
                credentialing.require_registry_evidence(vault, credential, hab)
                break
            except kering.MissingChainError:
                if monotonic() >= deadline:
                    raise
                yield
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
            result = {'said': said, 'transport': asdict(record),
                      'stream': exchanging.serializeMessage(vault.hby, said).decode()}
            if op == 'admit':
                receipt = vault.db.receipts.get((hab.pre, request['prior']))
                result['accepted'] = bool(receipt and receipt.status == 'accepted')
            return result
        # The application owns retries. A transient freshness miss can occur
        # between composition and dispatch; do not report its retained work as
        # terminal while the ordinary outbox still has an authorized retry.
        if record and (record.status == 'blocked' or (record.status == 'failed'
                and record.attempts > len(ipexing.SendIpexDoer.RetryDelays))):
            raise ValueError(f'Exchange {said}: {record.error}')
        if monotonic() >= deadline:
            raise TimeoutError(f'Exchange {said} retained; transport not yet submitted')
        yield
