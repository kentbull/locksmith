# -*- encoding: utf-8 -*-
"""ACDC v2 IPEX exchanges with V2 JSON bodies and V2 CESR attachments."""
from collections import deque
from copy import deepcopy
from collections.abc import Mapping
from contextlib import closing
from itertools import islice

from hio.base import doing
from hio.core.http import httping
from keri import help, kering
from keri.acdc import acdcmap, ipexing
from keri.app import agenting, forwarding
from keri.core.kraming import AuthTypes
from keri.core import Compactor, Prefixer, Saider, SerderACDC, SerderKERI, parsing
from keri.help import helping
from keri.peer import exchanging

from locksmith.core import credentialing, disclosing
from locksmith.core.indirecting import receiving_endpoints
from locksmith.core.receipting import LocksmithReceiptor
from locksmith.db.basing import AcceptedCredential, GrantReceipt, IpexSubmission

logger = help.ogler.getLogger(__name__)


class IpexHandler(ipexing.IpexHandler):
    """Apply the wallet's endpoint and incoming-notification policy."""

    def __init__(self, *args, signals=None, **kwa):
        super().__init__(*args, **kwa)
        self.signals = signals

    def verify(self, serder, attachments=None, nests=None, sscs=None, evidence=None,
               *, historical=False):
        if serder.pvrsn.major != 2 or not ({serder.pre, serder.ked.get('ri')} & self.hby.prefixes):
            return False
        for nest in nests or []:
            credential = nest.get('serder') if isinstance(nest, dict) else nest.serder
            issuer = getattr(credential, 'israid', None)
            if issuer:
                try:
                    # Current-key checks use get(), which does not load disk state.
                    self.hby.db.kevers[issuer]
                except KeyError:
                    pass
        return super().verify(serder, attachments=attachments, nests=nests,
                              sscs=sscs, evidence=evidence, historical=historical)

    def handle(self, serder, attachments=None, nests=None, sscs=None):
        if serder.pre not in self.hby.prefixes:
            super().handle(serder, attachments=attachments, nests=nests, sscs=sscs)
        if self.signals is not None:
            self.signals.emit_doer_event('Ipex', 'saved', {'said': serder.said})


class MissingRouteError(kering.ConfigurationError):
    """The recipient needs an introduction with a usable delivery endpoint."""


class UnsupportedDisclosurePlan(kering.ValidationError):
    """The signed exchange uses a disclosure plan this wallet cannot honor."""


def _validate_plan(plan):
    """Require the maintained flat q.dp profile without rewriting signed history."""
    legacy = (plan == [[]] or isinstance(plan, list) and plan
              and isinstance(plan[0], list) and plan[0]
              and isinstance(plan[0][0], list))
    if legacy:
        raise UnsupportedDisclosurePlan(
            'Historical nested q.dp is unsupported; start a new credential exchange')
    validator = getattr(ipexing, '_disclosurePathError', None)
    if validator is None:
        raise kering.ConfigurationError(
            'Installed KERIpy does not support the maintained flat q.dp profile')
    if error := validator(plan):
        raise UnsupportedDisclosurePlan(f'Unsupported q.dp disclosure plan: {error}')
    return plan


def _message_plan(exn):
    """Read and validate one message's signed flat q.dp value."""
    if exn is None or not isinstance(exn.sad.get('q'), Mapping) or 'dp' not in exn.sad['q']:
        raise UnsupportedDisclosurePlan('The exchange has no explicit q.dp disclosure plan')
    return _validate_plan(exn.sad['q']['dp'])


def _resolved_plan(vault, exn):
    """Resolve empty reply dittos to one earlier non-empty flat plan."""
    seen = set()
    current = exn
    while current is not None and current.said not in seen:
        seen.add(current.said)
        plan = _message_plan(current)
        if plan:
            return plan
        prior = current.sad.get('p', '')
        if not prior:
            raise UnsupportedDisclosurePlan(
                'An opening exchange cannot use an empty q.dp disclosure plan')
        current = vault.hby.db.exns.get((prior,))
        if current is None:
            raise UnsupportedDisclosurePlan('The inherited q.dp disclosure plan is unavailable')
    raise UnsupportedDisclosurePlan('The q.dp disclosure-plan chain is cyclic')


def request_fields(vault, exn):
    """Return the exact origin paths authorized by a supported request chain."""
    return list(_resolved_plan(vault, exn)[0][2])


def presentation_eligible(credential, pre, designated=()):
    """Return whether pre is the disclosed issuee or the original issuer.

    Args:
        credential: Exact disclosed ACDC.
        pre: Candidate presenter identifier.
        designated: Explicit local-policy allowlist; never inferred from receipt
            or custody. Naming an AID here establishes no cryptographic delegation.
    """
    return bool(pre and pre in (credential.israid, credential.iseaid, *designated))


def _require_presenter(credential, sender, recipient, *, vault=None):
    """Enforce the default roles or an explicitly configured per-credential policy."""
    designated = ((vault.hby.cf.get() or {}).get('presentation_policy', {}).get(credential.said, [])
                  if vault is not None else [])
    if not presentation_eligible(credential, sender, designated):
        raise kering.ValidationError('Only the credential issuee or original issuer may present it')
    if (sender == credential.israid and sender != credential.iseaid
            and credential.iseaid and recipient != credential.iseaid):
        raise kering.ValidationError('Original issuer delivery must address the credential issuee')
    if sender in designated:
        return  # Explicit local policy, not an assertion of issuer delegation.
    # An opaque attribute section cannot establish whether delivery is targeted.
    if credential.iseaid is None and (
            isinstance(credential.sad.get('a'), str)
            or isinstance(credential.sad.get('A'), str)
            or isinstance(credential.sad.get('A'), list)
            and (len(credential.sad['A']) < 2 or not isinstance(credential.sad['A'][1], Mapping))):
        raise kering.ValidationError('Disclose the issuee block before presenting this credential')


def set_presenter_policy(vault, credential_said, presenter, *, enabled=True):
    """Record an operator's explicit per-credential presenter allowance.

    Args:
        vault: Open wallet whose local admission/presentation policy changes.
        credential_said: Exact credential commitment, not a schema-wide rule.
        presenter: Known AID selected by the operator.
        enabled: Add the allowance, or remove it when False.

    This is local trust policy only. It grants no issuer keys, does not provision
    a salt, and cannot substitute for possessed credential/opening evidence.
    Each receiving application's policy must separately accept that presenter.
    """
    _require_vault(vault)
    Saider(qb64=credential_said)
    Prefixer(qb64=presenter)
    if presenter not in vault.hby.kevers:
        raise ValueError('Introduce the selected presenter before configuring policy')
    config = vault.hby.cf.get() or {}
    policy = config.setdefault('presentation_policy', {})
    names = set(policy.get(credential_said, []))
    names.add(presenter) if enabled else names.discard(presenter)
    if names:
        policy[credential_said] = sorted(names)
    else:
        policy.pop(credential_said, None)
    vault.hby.cf.put(config)


def _edge_nodes(sad):
    """Yield far node SAIDs and paths, including nested edge groups."""
    edges = sad.get('e')
    blocks = [(edges, 'e/')] if isinstance(edges, Mapping) else (
        [(edge, f'e/{index}/') for index, edge in enumerate(edges)] if isinstance(edges, list) else [])
    for edge, path in blocks:
        groups = deque([(edge, path, False)])
        while groups:
            group, path, nested = groups.popleft()
            if not isinstance(group, Mapping):
                raise kering.ValidationError('Invalid retained credential edges')
            if 'n' in group:
                yield group['n'], path + '_/'
                continue
            labels = ipexing.EdgeGroupLabels if nested else ipexing.EdgeSectionLabels
            groups.extend((node, path + label + '/', True)
                          for label, node in group.items() if label not in labels)


def _reachable(hab, pre):
    """Return whether StreamPoster has a URL for the route it would choose for pre.

    Pinned endsFor also returns revoked roles, and StreamPoster still selects
    them. A revoked role therefore blocks delivery until it is repaired.
    """
    ends = hab.endsFor(pre)
    role = next((role for role in (kering.Roles.controller, kering.Roles.agent, kering.Roles.mailbox)
                 if role in ends), kering.Roles.witness)
    if role != kering.Roles.witness or not (pre in hab.kevers and hab.kevers[pre].wits):
        # StreamPoster reloads this role, so filtering our copy cannot prevent
        # delivery to an inactive endpoint. Block the whole selected route.
        for eid in ends.get(role, {}):
            if (end := hab.db.ends.get((pre, role, eid))) and not (end.allowed or end.enabled):
                return False
    return any(urls.get(scheme) for urls in ends.get(role, {}).values()
               for scheme in (kering.Schemes.http, kering.Schemes.https, kering.Schemes.tcp))


def _require_route(hab, recipient, reply=True):
    """Require routes for network delivery and any required reply."""
    if not _reachable(hab, recipient):
        raise MissingRouteError('There is no known way to reach this identifier. Import its introduction first.')
    if reply and not any(hab.fetchUrls(eid=eid, scheme='http')
                         or hab.fetchUrls(eid=eid, scheme='https') for eid in receiving_endpoints(hab)):
        raise kering.ConfigurationError('This identifier cannot receive replies. Configure a receiving mailbox.')


def _require_vault(vault, hab=None):
    if getattr(vault, 'closed', False) or not vault.db.opened or not vault.hby.db.opened:
        raise ValueError('The vault is closed')
    if hab is not None and hab is not vault.hby.habByPre(hab.pre):
        raise ValueError('The identifier does not belong to this vault')


def _require_graph_result(result):
    """Authorize new use only with an explicit current semantic verdict."""
    if result is None:
        raise credentialing.RegistryEvidencePending('ACDC v2 graph evaluation is unresolved')
    if result is not True:
        raise kering.ValidationError('ACDC v2 graph policy refuses this action')


def _validate_selected(vault, origin, artifacts):
    """Check the exact selected disclosure before the Grant builder signs it."""
    verification = vault.exc.routes['/ipex/grant'].verification
    try:
        result = verification.evaluateSelected(origin, artifacts=artifacts)
    except (kering.MissingChainError, kering.MissingSchemaError) as error:
        raise credentialing.RegistryEvidencePending(str(error)) from error
    _require_graph_result(result)


def _validate_grant_graph(vault, said):
    """Reevaluate retained authenticated evidence before a new wallet action."""
    try:
        result = vault.exc.routes['/ipex/grant'].verification.evaluateGrant(said)
    except (kering.MissingChainError, kering.MissingSchemaError) as error:
        raise credentialing.RegistryEvidencePending(str(error)) from error
    _require_graph_result(result)


def _validate_outgoing_grant(vault, hab, grant):
    """Recheck retained proofs before a new or retried disclosure leaves the wallet."""
    _validate_grant_graph(vault, grant.said)
    for nest in exchanging.loadParsedNestedSubstreams(vault.hby, grant.said):
        credentialing.require_registry_evidence(vault, nest.serder, hab)
        state = credentialing.authentication(vault, nest)
        if state['et'] not in ('issued', 'authenticated'):
            raise kering.ValidationError(f"Credential state is {state['et']}, not issued")
    _require_presenter(grant_credential(vault, grant.said), hab.pre, grant.sad['ri'], vault=vault)


def _require_delivery_time(vault, serder):
    """Reject a retained message already stale under this wallet's KRAM policy.

    This is a conservative local send gate, not a prediction of a remote
    verifier's policy or network arrival time. Reuse KERIpy's authentication
    classification against the exact retained attachments; never re-sign an
    expired reply. Core KRAM remains authoritative at the receiver.
    """
    kramer = vault.kvy.kramer
    if kramer is None or not kramer.enabled:
        return
    if error := expiry_error(vault, serder):
        raise kering.ValidationError(error)
    stream = exchanging.serializeMessage(vault.hby, serder.said)
    parsed = parsing.Parser().parse(ims=bytearray(stream), processive=False,
                                   version=kering.Vrsn_2_0)[0]
    attachments = parsed if isinstance(parsed, dict) else vars(parsed)
    kever = vault.hby.kevers[serder.pre]
    auth, _ = kramer._resolveAuthType(
        serder, attachments, kever, kramer._hasSeals(serder.pre, attachments),
        kramer._hasSigs(serder.pre, attachments), serder.pre)
    if auth is None:
        raise kering.ValidationError('Saved message has no usable authentication')
    policy = vault.hby.db.kramCTYP.get('~')
    lag = policy.ll if auth == AuthTypes.AttachedSignatureMultiKey else policy.sl
    age = (helping.nowUTC() - helping.fromIso8601(serder.stamp)).total_seconds() * 1000
    if age > policy.d + lag or age < -policy.d:
        raise kering.ValidationError(
            'Saved message is outside the local KRAM timing window. Start a new negotiation.')


def _retain(vault, hab, serder, attachment):
    """Retain a new local message, or reuse its previously verified copy.

    This is submission preparation, not intake of additional attachments.
    """
    _require_vault(vault, hab)
    if hab is not vault.hby.habByPre(serder.pre) or serder.pvrsn.major != 2:
        raise ValueError('IPEX must be signed by this vault')
    if not serder.route.startswith('/ipex/'):
        raise ValueError('Expected an IPEX message')
    if not vault.exc.complete(serder.said):
        prior = vault.hby.db.exns.get((serder.sad['p'],)) if serder.sad['p'] else None
        if error := expiry_error(vault, prior):
            raise kering.ValidationError(error)
        vault.mbx.parser.parse(ims=bytearray(serder.raw + attachment), local=True,
                               version=kering.Vrsn_2_0)
    if not vault.exc.complete(serder.said):
        raise kering.ValidationError('Outgoing IPEX has not passed protocol verification')
    return exchanging.serializeMessage(vault.hby, serder.said)


def prepare(vault, hab, serder, attachment):
    """Retain and validate a message without authorizing network delivery.

    Preserve the explicit preparation API for import and admission callers.
    Submission uses _retain directly so mutable readiness cannot strand consent.
    """
    stream = _retain(vault, hab, serder, attachment)
    if serder.route == '/ipex/grant' and serder.sad['a'].get('o'):
        _validate_outgoing_grant(vault, hab, serder)
    return stream


def submit(vault, hab, serder, attachment):
    """Retain a signed message and authorize its delivery by the vault worker."""
    _retain(vault, hab, serder, attachment)
    # Protocol acceptance and delivery consent are separate databases. A crash
    # here is recovered by the existing explicit Send saved message action.
    # The sender checks mutable readiness before any network operation.
    if vault.db.outbox.put((serder.said,), IpexSubmission()):
        vault.signals.emit_doer_event('Ipex', 'queued', {'said': serder.said})
    return serder.said


def retry(vault, said):
    """Retry an existing submission without building or signing another message."""
    _require_vault(vault)
    record = vault.db.outbox.get((said,))
    if record is None:
        raise ValueError('No saved submission to retry')
    if record.status != 'sending':
        record.status, record.error, record.retry_at = 'pending', '', 0.0
        record.missing_route = False
        vault.db.outbox.pin((said,), record)
        vault.signals.emit_doer_event('Ipex', 'queued', {'said': said})


def grant_credential(vault, grant_said):
    """Load the origin credential from a retained, verified grant."""
    exn = vault.hby.db.exns.get(keys=(grant_said,))
    if exn is None or exn.route != '/ipex/grant' or exn.pvrsn.major != 2:
        raise kering.ValidationError('Verified ACDC v2 IPEX grant not found')
    exchanging.verify(vault.hby, exn)
    origin = exn.sad['a']['o'][0]
    for nest in exchanging.loadParsedNestedSubstreams(vault.hby, grant_said):
        if nest.serder.said == origin:
            return nest.serder
    raise kering.ValidationError('Grant origin evidence is missing')


def _disclosure_plan(origin, nodes):
    """Name the retained nodes in disclosure-plan BFS order without expanding their fields."""
    plan, seen = [], set()
    pending = deque([(origin, '/')])
    while pending:
        said, prefix = pending.popleft()
        if said in seen:
            continue
        if said not in nodes:
            raise kering.ValidationError('Linked credential evidence is missing')
        seen.add(said)
        sad = nodes[said]
        schema = sad['s']
        plan.append([schema if isinstance(schema, str) else schema['$id'], prefix, []])
        pending.extend((far, prefix + path) for far, path in _edge_nodes(sad))
    if seen != nodes.keys():
        raise kering.ValidationError('Retained evidence contains unrelated credentials')
    return _validate_plan(plan)


def _credential_evidence(vault, credential_said, hab=None, *, from_grant=None,
                         disclose=(), refresh=False, openings=(), derive=False, bound_event=None, preview=False):
    """Load exact selected material and its ACDC v2 IPEX disclosure plan.

    vault/credential_said identify inventory; hab optionally enforces current
    observer policy. from_grant selects one admission. disclose chooses held
    attribute paths; refresh/openings/derive select explicit Grant proof sources.
    preview selects content only for Offer and refuses state-opening options.
    Return view, serialized artifacts, ACDC v2 IPEX plan and disclosed SADs. Grant
    mode verifies every node's authentication; Offer makes no current-state claim.
    """
    view = credentialing.credential(vault, credential_said, grant=from_grant)
    if preview:
        if refresh or openings or derive or bound_event:
            raise ValueError('State opening selection belongs to Grant, not Offer preview')
        view = dict(view, sad=disclosing.select(SerderACDC(sad=view['sad']), disclose).sad)
    elif disclose or refresh or openings or derive or bound_event:
        view = disclosing.material(vault, view, paths=disclose, refresh=refresh,
                                   openings=openings, derive=derive, bound_event=bound_event)
    if not preview and view['status']['et'] not in ('issued', 'authenticated'):
        raise kering.ValidationError('Credential does not have a verified issued state or issuer authentication')
    if hab is not None:
        credentialing.require_registry_evidence(vault, SerderACDC(sad=view['sad']), hab)
    artifacts = dict(view['artifacts'])
    # Received credentials already retain the ACDC v2 IPEX grant's complete evidence.
    pending = [view] if not from_grant and vault.db.issued.get((credential_said,)) else []
    while pending:
        current = pending.pop()
        for said, _ in _edge_nodes(current['sad']):
            if said == credential_said or said in artifacts:
                continue
            source = credentialing.credential(vault, said)
            if hab is not None:
                credentialing.require_registry_evidence(vault, SerderACDC(sad=source['sad']), hab)
            if not preview and source['status']['et'] not in ('issued', 'authenticated'):
                raise kering.ValidationError(f'Source credential {said} is not issued')
            artifacts[said] = source['proof']
            artifacts.update(source['artifacts'])
            if vault.db.issued.get((said,)):
                pending.append(source)
    nodes = {credential_said: view['sad']}
    for stream in artifacts.values():
        ims = bytearray(stream)
        parsed = parsing.Parser().parse(ims=ims, processive=False, version=kering.Vrsn_2_0)
        if len(parsed) != 1 or ims or not isinstance(parsed[0].serder, SerderACDC):
            raise kering.ValidationError('Invalid retained credential evidence')
        if hab is not None:
            credentialing.require_registry_evidence(vault, parsed[0].serder, hab)
        state = credentialing.authentication(vault, parsed[0]) if not preview else None
        if not preview and state['et'] not in ('issued', 'authenticated'):
            raise kering.ValidationError('Source credential does not have a verified issued state')
        nodes[parsed[0].serder.said] = parsed[0].serder.sad
    plan = _disclosure_plan(credential_said, nodes)
    if disclose:
        plan[0][2] = list(disclose)
        _validate_plan(plan)
    return view, list(artifacts.values()), plan, nodes


def grant(vault, hab, credential_said, recipient, message='', *, from_grant=None,
          disclose=(), refresh=False, openings=(), derive=False, bound_event=None):
    """Build a grant using the selected local disclosure and optional opening.

    Args:
        vault: Open evidence and consent owner.
        hab: Local signing identifier.
        credential_said: Exact credential to present.
        recipient: Counterparty AID.
        message: Human-readable message.
        from_grant: Explicit admitted view; None retains inventory defaults.
        disclose: Attribute paths to reveal from material already possessed.
        refresh: Rebuild only the registry proof against accepted current history.
        openings: Explicit event-specific CESR proof bytes.
        derive: Enable provisioned per-registry derivation for this operation.
        bound_event: Optional exact accepted issuee event for derived bound state.

    Returns:
        tuple: ACDC v2 IPEX signed exchange and attachments, still requiring prepare/submit.
    """
    _require_vault(vault, hab)
    view, artifacts, plan, _ = _credential_evidence(vault, credential_said, hab,
        from_grant=from_grant, disclose=disclose, refresh=refresh, openings=openings, derive=derive, bound_event=bound_event)
    _require_presenter(SerderACDC(sad=view['sad']), hab.pre, recipient, vault=vault)
    _validate_selected(vault, view['proof'], artifacts)
    return ipexing.grant(hab, recipient, message, origin=view['proof'], artifacts=artifacts,
                         modifiers={'dp': plan}, kind=kering.Kinds.json)


def _offer_preview(original):
    """Disclose root metadata without changing any populated commitment."""
    if original.get('e'):
        raise kering.ValidationError(
            'Offers for linked credentials are not supported yet. '
            'This wallet cannot yet offer their terms while keeping credential references private.')

    def public_rules(rules):
        if isinstance(rules, Mapping):
            if rules.get('u'):
                raise kering.ValidationError('Blinded rules require staged terms negotiation, which this wallet does not support')
            for label, value in rules.items():
                if label not in ('d', 'u') and not (label == 'l' and isinstance(value, str)):
                    public_rules(value)
        elif isinstance(rules, list):
            for value in rules:
                public_rules(value)
        elif isinstance(rules, str) and rules:
            try:
                if Saider(qb64=rules).qb64 != rules:
                    return
            except (kering.KeriError, ValueError):
                return
            raise kering.ValidationError('Disclose rule text before offering this credential')

    rules = original.get('r')
    public_rules(rules)
    if isinstance(rules, Mapping):
        compactor = Compactor(mad=rules, makify=True, compactify=True, kind=kering.Kinds.json)
        rules = list(compactor.partials.values())[-1].mad if compactor.partials else compactor.mad
    fields = {'aggregate': ''} if 'A' in original else {'attribute': ''}
    if 'e' in original:
        fields['edge'] = original['e']
    return acdcmap(israid=original['i'], ilk=original.get('t'), uuid='',
                   regid='' if 'rd' in original else None,
                   schema=original['s'], rule=rules, kind=kering.Kinds.json, **fields)


def request_schema(exn, vault=None):
    """Read the origin schema from a supported flat disclosure plan.

    ``vault`` resolves an empty reply ditto through its exact signed priors.
    Historical nested plans raise rather than being silently reinterpreted.
    """
    plan = _resolved_plan(vault, exn) if vault is not None else _message_plan(exn)
    if not plan:
        return None
    schema, prefix, fields = plan[0]
    if prefix not in ('', '/') or any(entry[2] for entry in plan[1:]):
        raise UnsupportedDisclosurePlan(
            'This wallet supports one origin request and node-presence dependencies')
    return schema


def start(vault, hab, recipient, action, message='', *, schema=None, credential_said=None,
          ax=None, from_grant=None, disclose=()):
    """Start an Apply or Offer after explicit local consent.

    vault/hab select the local signer, recipient the counterparty, and message
    the displayed text. schema selects an Apply schema; credential_said and
    from_grant select an Offer's exact evidence. disclose selects attribute
    paths (empty preserves the existing whole-credential form); ax requests
    ACDC v2 IPEX anchor negotiation. Return the queued signed exchange identifier.
    """
    _require_vault(vault, hab)
    if not recipient or recipient == hab.pre:
        raise ValueError('Choose another identifier for this exchange')
    _require_route(hab, recipient)
    if action == 'Apply':
        if not schema or vault.hby.db.schema.get((schema,)) is None:
            raise ValueError('Choose a loaded schema')
        plan = _validate_plan([[schema, '/', list(disclose)]])
        exn, atc = ipexing.apply(hab, recipient, message,
                                 modifiers={'dp': plan}, ax=ax,
                                 kind=kering.Kinds.json)
    elif action == 'Offer':
        view, artifacts, plan, _ = _credential_evidence(vault, credential_said, hab,
            from_grant=from_grant, disclose=disclose, preview=True)
        _require_presenter(SerderACDC(sad=view['sad']), hab.pre, recipient, vault=vault)
        preview = SerderACDC(sad=view['sad']) if disclose else _offer_preview(view['sad'])
        exn, atc = ipexing.offer(hab, message, preview, recp=recipient,
                                 artifacts=[],
                                 modifiers={'dp': plan}, ax=ax,
                                 kind=kering.Kinds.json)
    else:
        raise ValueError('Start with Apply or Offer')
    return submit(vault, hab, exn, atc)


def expiry_error(vault, exn):
    """Explain an expired exchange using the wallet's ACDC v2 IPEX KRAM policy."""
    kramer = vault.kvy.kramer
    if exn is None or kramer is None or not kramer.enabled:
        return None
    seen = set()
    while exn.sad['p']:
        if exn.said in seen:
            return None  # Leave incomplete or damaged chains to protocol validation.
        seen.add(exn.said)
        exn = vault.hby.db.exns.get((exn.sad['p'],))
        if exn is None:
            return None
    # Vault uses one policy for all IPEX routes. The saved opener remains
    # available after KRAM has pruned its transaction cache.
    policy = vault.hby.db.kramCTYP.get('~')
    age = (helping.nowUTC() - helping.fromIso8601(exn.stamp)).total_seconds() * 1000
    if age <= policy.xl:
        return None
    if exn.route == '/ipex/apply':
        if exn.pre in vault.hby.prefixes:
            return 'This application has expired. Send a new application to continue.'
        return ('This application has expired. Ask the holder to send a new application. '
                'You can reuse the existing credential.')
    if exn.pre in vault.hby.prefixes:
        return 'This exchange has expired. Start a new offer using the existing credential.'
    return 'This exchange has expired. Ask the sender to start a new offer.'


def responses(vault, exn):
    """Return decisions available to the local recipient of a saved message."""
    if (exn is None or exn.sad['ri'] not in vault.hby.prefixes
            or vault.hby.db.erpy.get((exn.said,)) is not None
            or expiry_error(vault, exn)):
        return []
    if exn.route in ('/ipex/apply', '/ipex/offer', '/ipex/agree', '/ipex/grant'):
        try:
            _resolved_plan(vault, exn)
        except (UnsupportedDisclosurePlan, kering.ConfigurationError):
            return ['Spurn'] if exn.route != '/ipex/agree' else []
    match exn.route:
        case '/ipex/apply':
            return ['Offer', 'Grant', 'Spurn']
        case '/ipex/offer':
            return ['Agree', 'Spurn']
        case '/ipex/agree':
            return ['Grant', 'Spurn']
        case '/ipex/grant':
            return ['Admit', 'Spurn'] if not exn.sad['p'] else ['Admit']
    return []


def anchor_error(hab):
    """Return why this wallet cannot prepare an IPEX KEL anchor, if any."""
    if not hab.kever.prefixer.transferable:
        return 'This step requires an identifier that supports KEL anchoring.'
    return None


def respond(vault, said, action, message='', credential_said=None, *, from_grant=None,
            refresh=False, openings=(), derive=False, bound_event=None):
    """Validate and queue one response using the prior's agreed disclosure paths.

    vault owns evidence; said names the prior; action and message express the
    operator decision. credential_said/from_grant select exact retained material.
    refresh/openings/derive/bound_event have the same capability meanings as grant.
    Return the signed response identifier. The builder cannot renegotiate fields
    at Grant time or enrich a prior admission from another inventory view.
    """
    _require_vault(vault)
    prior = vault.hby.db.exns.get((said,))
    if error := expiry_error(vault, prior):
        raise kering.ValidationError(error)
    if action not in responses(vault, prior):
        raise ValueError('This exchange has changed. Review its current status.')
    hab = vault.hby.habByPre(prior.sad['ri'])
    if action in ('Agree', 'Grant') and prior.sad['a'].get('ax', [False])[0]:
        if error := anchor_error(hab):
            raise kering.ValidationError(error)
    if action == 'Admit':
        exn, _ = admit(vault, hab, said, message, send=True)
        if vault.db.receipts.get((hab.pre, said)).status == 'accepted':
            vault.signals.emit_doer_event('Ipex', 'accepted', {'said': exn.said})
        return exn.said
    _require_route(hab, prior.pre, reply=action != 'Spurn')
    if action in ('Offer', 'Grant'):
        request = (vault.hby.db.exns.get((prior.sad['p'],))
                   if prior.route == '/ipex/agree' else prior)
        requested = _resolved_plan(vault, request)
        fields = list(requested[0][2])
        view, artifacts, plan, _ = _credential_evidence(vault, credential_said, hab,
            from_grant=from_grant, disclose=fields, refresh=refresh,
            openings=openings, derive=derive, bound_event=bound_event, preview=action == 'Offer')
        _require_presenter(SerderACDC(sad=view['sad']), hab.pre, prior.pre, vault=vault)
        schema = request_schema(request, vault)
        offered = request.sad['a'].get('o', []) if request.route == '/ipex/offer' else []
        if offered:
            previews = exchanging.loadParsedNestedSubstreams(vault.hby, request.said)
            metadata = previews and previews[0].serder.sad.get('u') == ''
            if not metadata and credential_said != offered[0]:
                raise ValueError('Grant must disclose the credential identified by the Offer')
        actual = view['sad']['s']
        actual = actual if isinstance(actual, str) else actual['$id']
        if schema and schema != actual:
            raise ValueError('The credential does not match the requested schema')
        if schema:
            plan[0][2] = list(requested[0][2])
        if action == 'Offer':
            preview = SerderACDC(sad=view['sad']) if fields else _offer_preview(view['sad'])
            exn, atc = ipexing.offer(hab, message, preview, apply=prior,
                                    artifacts=[],
                                    modifiers={'dp': plan}, ax=prior.sad['a'].get('ax'),
                                    kind=kering.Kinds.json)
        else:
            if requested != plan:
                raise ValueError('Credential evidence does not match the agreed disclosure plan')
            _validate_selected(vault, view['proof'], artifacts)
            link = {'apply': prior} if prior.route == '/ipex/apply' else {'agree': prior}
            exn, atc = ipexing.grant(hab, prior.pre, message, view['proof'], artifacts=artifacts,
                                    modifiers={'dp': []}, ax=prior.sad['a'].get('ax'),
                                    kind=kering.Kinds.json, **link)
    elif action == 'Agree':
        exn, atc = ipexing.agree(hab, message, prior, kind=kering.Kinds.json)
    else:
        exn, atc = ipexing.spurn(hab, message, prior, kind=kering.Kinds.json)
    return submit(vault, hab, exn, atc)


class ApprovedResponse(doing.DoDoer):
    """Retry one reviewed response while its vault remains open.

    ``said`` and ``action`` identify the exact predecessor and response;
    ``selection`` is copied so widgets cannot alter consent during a wait.
    The owning outbox scheduler supplies HIO recurrence. No intent is persisted
    until submit authorizes an exact signed message; closing cancels that wait.
    """

    def __init__(self, vault, said, action, **selection):
        """Capture vault, predecessor SAID, action and copied disclosure options."""
        self.vault, self.said, self.action = vault, said, action
        self.selection = deepcopy(selection)
        if credential_said := self.selection.get('credential_said'):
            view = credentialing.credential(vault, credential_said,
                                            grant=self.selection.get('from_grant'))
            if view['grant']:
                self.selection['from_grant'] = view['grant']
        self.result = None
        self.error = ''
        self.waiting = False
        super().__init__(doers=[doing.doify(self.respondDo)])

    def respondDo(self, tymth=None, tock=0.0, **opts):
        """Revalidate the frozen decision each pass; construct at most one reply."""
        self.wind(tymth)
        yield self.tock
        while not getattr(self.vault, 'closed', False):
            try:
                self.result = respond(self.vault, self.said, self.action, **self.selection)
                self.error, self.waiting = '', False
                return
            except credentialing.RegistryEvidencePending as error:
                self.error, self.waiting = str(error), True
            except (OSError, kering.KeriError, ValueError) as error:
                self.error, self.waiting = str(error), False
                return
            finally:
                self.vault.signals.emit_doer_event('Ipex', 'response_preparation',
                                                   {'prior': self.said})
            yield 0.25


def exchanges(vault):
    """Read saved IPEX chains, with transport and acceptance records attached.

    The root fixes credential direction. Reply links fix stage; signed dates
    are display metadata and never select a winner.
    """
    _require_vault(vault)
    messages = {exn.said: exn for _, exn in vault.hby.db.exns.getTopItemIter()
                if exn.pvrsn.major == 2 and exn.route.startswith('/ipex/')
                and {exn.pre, exn.sad['ri']} & vault.hby.prefixes}
    submissions = {said: record for (said,), record in vault.db.outbox.getTopItemIter()}
    receipts = list(vault.db.receipts.getTopItemIter())
    result, visited = [], set()
    for root in messages.values():
        if root.sad['p'] in messages:
            continue
        chain, tip = [], root
        problem = 'Earlier message is missing.' if root.sad['p'] else ''
        while tip.said not in visited:
            visited.add(tip.said)
            chain.append(tip)
            reply = vault.hby.db.erpy.get((tip.said,))
            if reply is None:
                break
            if reply.qb64 not in messages or reply.qb64 in visited:
                problem = 'Saved reply history is incomplete.'
                break
            tip = messages[reply.qb64]
        sender, recipient = root.pre, root.sad['ri']
        if root.route == '/ipex/apply':
            sender, recipient = recipient, sender
        saids = {exn.said for exn in chain}
        expired = (expiry_error(vault, tip)
                   if tip.route not in ('/ipex/admit', '/ipex/spurn') else None)
        problem = problem or expired or ''
        result.append(dict(root=root.said, messages=chain, sender=sender, recipient=recipient,
                           actions=responses(vault, tip) if not problem else [], problem=problem,
                           expired=bool(expired),
                           submissions={said: submissions[said] for said in saids if said in submissions},
                           receipts=[(keys, record) for keys, record in receipts if keys[1] in saids]))
    # Keep damaged saved work reachable without inventing a protocol stage.
    for said, record in submissions.items():
        if said not in messages:
            result.append(dict(root=said, messages=[], sender='', recipient='', actions=[],
                               problem='Saved message is missing.', submissions={said: record}, receipts=[]))
    for keys, record in receipts:
        if keys[1] not in messages and record.status != 'accepted':
            result.append(dict(root=keys[1], messages=[], sender='', recipient=keys[0], actions=[],
                               problem='Original grant is missing.', submissions={}, receipts=[(keys, record)]))
    return result


def _validate_credential(vault, credential, grant_said):
    """Validate a parsed credential against its exact received grant.

    ``vault`` supplies authenticated exchange/KEL/TEL evidence; ``credential``
    is the parsed ACDC and ``grant_said`` names its signed Grant. Require the
    negotiated schema, allowed presenter and valid disclosed nested proofs.
    Raise on missing, stale or invalid evidence; never admit a credential here."""
    grant = vault.hby.db.exns.get((grant_said,))
    _resolved_plan(vault, grant)
    _validate_grant_graph(vault, grant_said)
    prior = vault.hby.db.exns.get((grant.sad['p'],)) if grant.sad['p'] else None
    if prior and prior.route == '/ipex/agree':
        prior = vault.hby.db.exns.get((prior.sad['p'],))
    expected = request_schema(prior, vault) if prior else None
    actual = credential.schema if isinstance(credential.schema, str) else credential.schema['$id']
    if expected and actual != expected:
        raise kering.ValidationError('The disclosed credential does not match the agreed schema')
    _require_presenter(credential, grant.pre, grant.sad['ri'], vault=vault)
    for nest in exchanging.loadParsedNestedSubstreams(vault.hby, grant_said):
        credentialing.validate_schema(vault, nest.serder)
        credentialing.require_registry_evidence(vault, nest.serder, vault.hby.habByPre(grant.sad['ri']))
        state = credentialing.authentication(vault, nest)
        if state['et'] not in ('issued', 'authenticated'):
            raise kering.ValidationError(f"Credential state is {state['et']}, not issued")


def _pending_anchors(vault, exn):
    """Load unreceipted local anchors from the retained ACDC v2 source seals."""
    pending = []
    for (_, pre), (_, diger) in vault.hby.db.ests.getTopItemIter(keys=(exn.said, '')):
        if pre not in vault.hby.prefixes:
            continue
        anchor = vault.hby.db.evts.get((pre, diger.qb64))
        if anchor is None:
            raise kering.ValidationError('Retained IPEX anchor event is missing')
        hab = vault.hby.habByPre(pre)
        threshold = hab.kvy.fetchEstEvent(pre, anchor.sn).bner.num
        if len(vault.hby.db.wigs.get((pre, anchor.said))) < threshold:
            pending.append((hab, anchor))
    return pending


def _finish_receipt(vault, pre, grant_said, receipt, restore=False):
    """Reconcile ACDC v2 IPEX evidence, the send permission and wallet membership."""
    grant = vault.hby.db.exns.get((grant_said,))
    reply = vault.hby.db.erpy.get((grant_said,))
    exn = vault.hby.db.exns.get((reply.qb64,)) if reply else None
    if (grant is None or grant.route != '/ipex/grant' or grant.sad['ri'] != pre
            or exn is None or exn.route != '/ipex/admit' or exn.pre != pre
            or exn.sad['ri'] != grant.pre or exn.sad['p'] != grant_said
            or (receipt.admit and receipt.admit != exn.said)):
        raise kering.ValidationError('Acceptance preparation is incomplete; a new exchange may be required')
    credential = grant_credential(vault, grant_said)
    if credential.said != receipt.credential:
        raise kering.ValidationError('Acceptance does not match the grant credential')
    stream = exchanging.serializeMessage(vault.hby, exn.said)
    if receipt.status != 'accepted':
        accepted = vault.db.accepted.get((credential.said,))
        # Inventory can commit before the final receipt write is interrupted.
        if (accepted is None or accepted.grant != grant_said
                or accepted.admit != exn.said):
            _validate_credential(vault, credential, grant_said)
    receipt.admit = exn.said
    if receipt.send:
        vault.db.outbox.put((exn.said,), IpexSubmission())
    if receipt.status != 'accepted' and _pending_anchors(vault, exn):
        receipt.status, receipt.error = 'preparing', ''
        vault.db.receipts.pin((pre, grant_said), receipt)
        return exn, stream[exn.size:]
    if receipt.status != 'accepted' or restore:
        # Keep the original inventory provenance when another grant contains C.
        vault.db.accepted.put((credential.said,), AcceptedCredential(grant_said, exn.said,
                                                                    helping.nowIso8601()))
    receipt.accepted_at = receipt.accepted_at or helping.nowIso8601()
    receipt.status, receipt.error = 'accepted', ''
    vault.db.receipts.pin((pre, grant_said), receipt)
    return exn, stream[exn.size:]


def admit(vault, hab, grant_said, message='', *, send=False):
    """Record consent, retain one admit and optionally authorize its delivery."""
    _require_vault(vault, hab)
    grant = vault.hby.db.exns.get((grant_said,))
    if grant is None or grant.route != '/ipex/grant' or grant.sad['ri'] != hab.pre:
        raise kering.ValidationError('Grant is not addressed to the selected identifier')
    if send:
        _require_route(hab, grant.pre, reply=False)
    reply = vault.hby.db.erpy.get((grant_said,))
    if reply:
        saved = vault.hby.db.exns.get((reply.qb64,))
        if saved is None or saved.route != '/ipex/admit':
            raise kering.ValidationError('This Grant already has a terminal reply and cannot be accepted')
    receipt = vault.db.receipts.get((hab.pre, grant_said))
    if receipt is None:
        credential = grant_credential(vault, grant_said)
        accepted = vault.db.accepted.get((credential.said,))
        if accepted is not None and accepted.grant == grant_said:
            # Earlier V2 vaults saved acceptance without a separate receipt.
            receipt = GrantReceipt(credential=credential.said, admit=accepted.admit,
                                   send=send, status='accepted')
            return _finish_receipt(vault, hab.pre, grant_said, receipt, restore=True)
        if reply is None and (error := expiry_error(vault, grant)):
            raise kering.ValidationError(error)
        if grant.sad['a'].get('ax', [False])[0] and vault.hby.db.erpy.get((grant_said,)) is None:
            if error := anchor_error(hab):
                raise kering.ValidationError(error)
        _validate_credential(vault, credential, grant_said)
        receipt = GrantReceipt(credential=credential.said, send=send)
        # Save consent before the ACDC v2 IPEX builder can create an AX anchor.
        vault.db.receipts.put((hab.pre, grant_said), receipt)
        if vault.hby.db.erpy.get((grant_said,)) is None:
            exn, atc = ipexing.admit(hab, message, grant, kind=kering.Kinds.json)
            prepare(vault, hab, exn, atc)
    elif send and not receipt.send:
        receipt.send = True
        vault.db.receipts.pin((hab.pre, grant_said), receipt)
    # Never repeat the builder after interrupted preparation.
    return _finish_receipt(vault, hab.pre, grant_said, receipt, restore=True)


class IpexOutboxDoer(doing.DoDoer):
    """Resume saved decisions and submit one pending message at a time."""

    ScanBatch = 256
    ScanDelay = 1.0

    def __init__(self, vault, **kwa):
        self.vault = vault
        for keys, receipt in list(vault.db.receipts.getTopItemIter()):
            try:
                _finish_receipt(vault, *keys, receipt)
            except Exception as ex:
                receipt.error = str(ex)
                if receipt.status != 'accepted':
                    receipt.status = 'interrupted'
                vault.db.receipts.pin(keys, receipt)
        for keys, record in vault.db.outbox.getTopItemIter():
            if record.status == 'sending':
                record.status = 'pending'
                vault.db.outbox.pin(keys, record)
        super().__init__(doers=[doing.doify(self.sendDo)], **kwa)

    def sendDo(self, tymth=None, tock=0.0, **kwa):
        self.wind(tymth)
        yield self.tock
        while not getattr(self.vault, 'closed', False):
            pending = []
            # Yield while scanning history, and close the read transaction
            # before delivery can change records or wait on the network.
            with closing(self.vault.db.outbox.getTopItemIter()) as records:
                while batch := list(islice(records, self.ScanBatch)):
                    now = helping.nowUTC().timestamp()
                    pending.extend(said for (said,), record in batch if _due(record, now))
                    yield self.tock
            with closing(self.vault.db.receipts.getTopItemIter()) as receipts:
                while batch := list(islice(receipts, self.ScanBatch)):
                    pending.extend(receipt.admit for _, receipt in batch
                                   if receipt.status == 'preparing' and receipt.admit)
                    yield self.tock
            for said in dict.fromkeys(pending):
                if getattr(self.vault, 'closed', False):
                    return
                delivery = SendIpexDoer(self.vault, said)
                self.extend([delivery])
                try:
                    while not delivery.done:
                        yield self.tock
                finally:
                    self.remove([delivery])
            yield self.ScanDelay


def _due(record, now):
    """Return whether the outbox should send record now.

    A failed message retries automatically after each delay in RetryDelays,
    then waits for a manual Retry, which sets it back to pending.
    """
    if record.status in ('pending', 'waiting_evidence'):
        return True
    return (record.status == 'failed' and record.attempts <= len(SendIpexDoer.RetryDelays)
            and record.retry_at <= now)


class SendIpexDoer(credentialing.CredentialUpdateDoer):
    """Receipt a retained ACDC v2 IPEX exchange and submit authorized delivery."""

    Timeout = 30.0

    RetryDelays = (30.0, 60.0, 120.0)

    def __init__(self, vault, said, **kwa):
        self.vault, self.said = vault, said
        super().__init__(doers=[doing.doify(self.sendDo)], **kwa)

    def sendDo(self, tymth=None, tock=0.0, **kwa):
        self.wind(tymth)
        yield self.tock
        delivery = None
        receiptor = None
        record = None
        consent = None
        claimed = False
        transport_started = False
        try:
            _require_vault(self.vault)
            record = self.vault.db.outbox.get((self.said,))
            if record is not None and not _due(record, helping.nowUTC().timestamp()):
                return
            self.serder = self.vault.hby.db.exns.get((self.said,))
            if self.serder is None:
                raise kering.ValidationError('Saved submission has no retained message')
            self.hab = self.vault.hby.habByPre(self.serder.pre)
            if self.hab is None:
                raise kering.ValidationError('Saved submission has no local sender')
            _require_delivery_time(self.vault, self.serder)
            if self.serder.route == '/ipex/grant' and self.serder.sad['a'].get('o'):
                _validate_outgoing_grant(self.vault, self.hab, self.serder)
            if self.serder.route == '/ipex/admit':
                consent = self.vault.db.receipts.get((self.hab.pre, self.serder.sad['p']))
            if record is None and (consent is None or consent.status != 'preparing'):
                return
            if record is not None:
                if consent is not None and not consent.send:
                    raise kering.ValidationError('Network delivery was not authorized')
                _require_route(self.hab, self.serder.sad['ri'],
                               reply=self.serder.route not in ('/ipex/admit', '/ipex/spurn'))
                record.status, record.error = 'sending', ''
                record.missing_route = False
                self.vault.db.outbox.pin((self.said,), record)
                claimed = True
            # The EXN and its exact source seals are durable before this wait.
            anchors = _pending_anchors(self.vault, self.serder)
            if anchors:
                receiptor = LocksmithReceiptor(hby=self.vault.hby)
                self.extend([receiptor])
                self.vault.signals.emit_doer_event('Ipex', 'awaiting_witnesses', {'said': self.said})
                for hab, anchor in anchors:
                    yield from self.receipt(hab, anchor, receiptor, {})
            if consent is not None:
                accepted = consent.status == 'accepted'
                _finish_receipt(self.vault, self.hab.pre, self.serder.sad['p'], consent)
                if consent.status != 'accepted':
                    raise kering.MissingChainError('Witness receipts are still pending for the IPEX anchor')
                if not accepted:
                    self.vault.signals.emit_doer_event('Ipex', 'accepted', {'said': self.said})
            if record is None:
                return
            _require_delivery_time(self.vault, self.serder)
            if self.serder.route == '/ipex/grant' and self.serder.sad['a'].get('o'):
                _validate_outgoing_grant(self.vault, self.hab, self.serder)
            transport_started = True
            record.attempts += 1
            record.retry_at = 0.0
            self.vault.db.outbox.pin((self.said,), record)
            stream = exchanging.serializeMessage(self.vault.hby, self.said)
            self.vault.signals.emit_doer_event('Ipex', 'sending', {'said': self.said})
            poster = forwarding.StreamPoster(hby=self.vault.hby, hab=self.hab,
                                              recp=self.serder.sad['ri'], topic='credential')
            prefixes = [self.hab.pre]
            if self.serder.route == '/ipex/grant':
                for nest in exchanging.loadParsedNestedSubstreams(self.vault.hby, self.serder.said):
                    prefixes.append(nest.serder.israid)
                    issuee = nest.serder.iseaid
                    # Issuer authentication does not require the subject's KEL.
                    if (issuee is not None and issuee != self.serder.sad['ri']
                            and issuee in self.vault.hby.kevers):
                        prefixes.append(issuee)
            for pre in dict.fromkeys(prefixes):
                kever = self.vault.hby.kevers[pre]
                for msg in self.vault.hby.db.cloneDelegation(kever, gvrsn=kering.Vrsn_2_0):
                    event = SerderKERI(raw=msg)
                    poster.send(serder=event, attachment=msg[event.size:])
                for msg in self.vault.hby.db.clonePreIter(pre=pre, gvrsn=kering.Vrsn_2_0):
                    event = SerderKERI(raw=msg)
                    poster.send(serder=event, attachment=msg[event.size:])
            poster.send(serder=self.serder, attachment=stream[self.serder.size:])
            doers = poster.deliver()
            if not doers:
                raise kering.ConfigurationError('No transport could submit this IPEX message')
            # Own recurrence here so child transport failures reach this retry
            # boundary rather than escaping through the vault scheduler.
            delivery = doing.DoDoer(doers=doers, tymth=self.tymth)
            delivery.enter()
            deadline = self.tyme + self.Timeout
            while not delivery.recur(tyme=self.tyme):
                if self.tyme >= deadline:
                    raise TimeoutError('IPEX transport did not finish before its deadline')
                yield self.tock
            for messenger in poster.messagers:
                if isinstance(messenger, agenting.HTTPStreamMessenger):
                    if messenger.rep is None or not 200 <= messenger.rep.status < 300:
                        raise kering.ValidationError('IPEX transport request failed')
            record.status = 'submitted'
            self.vault.db.outbox.pin((self.said,), record)
            self.vault.signals.emit_doer_event('Ipex', 'transport_submitted', {'said': self.said})
        except credentialing.RegistryEvidencePending as ex:
            if record is not None and self.vault.db.opened:
                record.status, record.error = 'waiting_evidence', str(ex)
                record.retry_at = 0.0
                self.vault.db.outbox.pin((self.said,), record)
                self.vault.signals.emit_doer_event('Ipex', 'waiting_evidence',
                                                   {'said': self.said, 'error': record.error})
        except (OSError, httping.HTTPException, kering.KeriError, ValueError) as ex:
            if record is not None and self.vault.db.opened:
                failure = ('blocked' if not transport_started and isinstance(ex, (kering.ValidationError, kering.ConfigurationError))
                           else 'failed')
                record.status, record.error = failure, str(ex)
                record.missing_route = isinstance(ex, MissingRouteError)
                delays = self.RetryDelays
                record.retry_at = (helping.nowUTC().timestamp()
                                   + delays[min(max(record.attempts, 1), len(delays)) - 1])
                self.vault.db.outbox.pin((self.said,), record)
                self.vault.signals.emit_doer_event('Ipex', 'send_failed',
                                                   {'said': self.said, 'error': record.error})
            elif consent is not None and self.vault.db.opened:
                consent.status, consent.error = 'interrupted', str(ex)
                self.vault.db.receipts.pin((self.hab.pre, self.serder.sad['p']), consent)
                self.vault.signals.emit_doer_event('Ipex', 'preparation_failed',
                                                   {'said': self.said, 'error': str(ex)})
            logger.exception('IPEX submission failed')
        finally:
            if receiptor is not None:
                self.remove([receiptor])
            if delivery is not None:
                delivery.exit()
            if claimed and record.status == 'sending' and self.vault.db.opened:
                record.status = 'pending'
                self.vault.db.outbox.pin((self.said,), record)
