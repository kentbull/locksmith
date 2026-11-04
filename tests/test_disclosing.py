"""Application negotiation uses exact held material and explicit capabilities."""

import pytest
from keri import kering
from keri.acdc import Registrar
from keri.acdc.messaging import acmSchemaDefault
from keri.core import Blinder, BlindState, Noncer, SerderACDC
from keri.peer import exchanging

from locksmith.core import credentialing, disclosing, evidence, ipexing
from test_credentialing import _issue, _load_schema
from test_ipex_policy import _introduce
from test_keri_v2_compat import _deliver_ipex, ipex_vaults as ipex_vaults


def _send(source, target, said):
    """Deliver the application's prepared message through the receiving mailbox."""
    _deliver_ipex(target.vault, exchanging.serializeMessage(source.hby, said))
    assert target.vault.exc.complete(said)


def _grant(source, target, signer, recipient, said, **kwa):
    """Build and admit a real application grant without writing accepted rows."""
    exn, atc = ipexing.grant(source.vault, signer, said, recipient.pre, **kwa)
    _deliver_ipex(target.vault, ipexing.prepare(source.vault, signer, exn, atc))
    ipexing.admit(target.vault, recipient, exn.said)
    return exn.said


@pytest.mark.parametrize('separate', [False, True])
def test_application_graduates_one_held_view_without_custody(ipex_vaults, separate):
    """Negotiate partial then fuller views, including explicit separate-presenter policy."""
    issuer_app, holder_app, delegate_app, verifier = [ipex_vaults('graduate-' + role)
        for role in ('issuer', 'holder', 'discloser', 'verifier')]
    issuer, holder, discloser, reviewer = [app.hby.makeHab(name=role)
        for app, role in zip((issuer_app, holder_app, delegate_app, verifier),
                             ('issuer', 'holder', 'discloser', 'verifier'), strict=True)]
    _, schema = acmSchemaDefault()
    # A whole-subtree request needs a schema that proves recursive closure.
    # Retain compact-or-expanded blocks so the first admission can hide private.
    block = {'type': 'object', 'properties': {
        key: {'type': 'string'} for key in ('d', 'u', 'value')},
        'additionalProperties': False}
    schema['properties']['a'] = {'type': 'object', 'properties': {
        'd': {'type': 'string'}, 'i': {'type': 'string'},
        'dt': {'type': 'string'},
        'status': {'oneOf': [{'type': 'string'}, block]},
        'private': {'oneOf': [{'type': 'string'}, block]}},
        'additionalProperties': False}
    schema = _load_schema(issuer_app, issuer, schema)
    apps = (issuer_app, holder_app, delegate_app, verifier)
    for app in apps:
        app.hby.db.schema.pin((schema.said,), schema)
        for other in apps:
            if app is not other:
                _introduce(app, other)
    said = _issue(issuer_app, schema, holder, authentication='anchor', attributes={
        'status': {'d': '', 'u': Noncer().qb64, 'value': 'authorized'},
        'private': {'d': '', 'u': Noncer().qb64, 'value': 'private-field'}})
    for app in apps[1:]:
        _introduce(issuer_app, app)
    held = _grant(issuer_app, holder_app, issuer, holder, said)
    presenter_app, presenter = holder_app, holder
    if separate:
        held = _grant(holder_app, delegate_app, holder, discloser, said, from_grant=held)
        presenter_app, presenter = delegate_app, discloser
        with pytest.raises(kering.ValidationError, match='issuee or original issuer'):
            ipexing.grant(delegate_app.vault, discloser, said, reviewer.pre, from_grant=held)
        ipexing.set_presenter_policy(delegate_app.vault, said, discloser.pre)
        ipexing.set_presenter_policy(verifier.vault, said, discloser.pre)
    snapshots = []
    for fields in (['a/status/'], ['a/status/value', 'a/private/value']):
        request = ipexing.start(verifier.vault, reviewer, presenter.pre, 'Apply',
                               schema=schema.said, disclose=fields)
        _send(verifier, presenter_app, request)
        offer = ipexing.respond(presenter_app.vault, request, 'Offer',
                               credential_said=said, from_grant=held)
        _send(presenter_app, verifier, offer)
        agreement = ipexing.respond(verifier.vault, offer, 'Agree')
        _send(verifier, presenter_app, agreement)
        grant = ipexing.respond(presenter_app.vault, agreement, 'Grant',
                               credential_said=said, from_grant=held)
        _send(presenter_app, verifier, grant)
        ipexing.admit(verifier.vault, reviewer, grant)
        snapshots.append(credentialing.credential(verifier.vault, said, grant=grant))
    assert isinstance(snapshots[0]['sad']['a']['private'], str)
    assert snapshots[1]['sad']['a']['private']['value'] == 'private-field'
    assert credentialing.credential(verifier.vault, said, grant=snapshots[0]['grant'])['proof'] == snapshots[0]['proof']
    assert not list(presenter_app.hby.mgr.ks.rroots.getTopItemIter())


@pytest.mark.parametrize('custodyState', ['absent', 'corrupt', 'old-aeid'])
def test_supplied_opening_refresh_is_separate_from_content_and_custody(ipex_vaults, custodyState):
    """Held presentation and supplied openings ignore absent or unusable custody."""

    source = ipex_vaults('opening-issuer')
    target = ipex_vaults('opening-holder',
        bran='0123456789abcdefghijk' if custodyState != 'absent' else None)
    issuer, holder = source.hby.makeHab(name='issuer'), target.hby.makeHab(name='holder')
    schema = _load_schema(source, issuer)
    target.hby.db.schema.pin((schema.said,), schema)
    _introduce(source, target)
    _introduce(target, source)
    said = _issue(source, schema, holder)
    original = credentialing.credential(source.vault, said)
    acdc = SerderACDC(sad=original['sad'])
    registry = source.vault.rgy.regs[acdc.regid]
    evidence.receive(target.vault, acdc.regid, evidence.clone(source.vault, acdc.regid),
                     {'content-type': 'application/cesr'})
    held = _grant(source, target, issuer, holder, said)
    assert not list(target.hby.mgr.ks.rroots.getTopItemIter())
    if custodyState != 'absent':
        from keri.core import Encrypter, Signer, Salter
        signer = Signer()
        cipher = (Encrypter(verkey=signer.verfer.qb64).encrypt(prim=Salter())
            if custodyState == 'old-aeid' else
            Encrypter(verkey=target.hby.mgr.aeid).encrypt(prim=Signer()))
        target.hby.mgr.ks.rroots.pin((holder.pre, acdc.regid), cipher)
    _grant(target, source, holder, issuer, said, from_grant=held)
    old = Blinder(clan=BlindState, qb64=source.vault.db.issued.get((said,)).blinder)
    opening, event = Registrar(rgy=source.vault.rgy).issue(registry, acdc, state='issued')
    issuer.interact(data=[dict(i=registry.regk, s=event.sad['n'], d=event.said)])
    assert registry.anchorMsg(event.said)
    result = evidence.receive(target.vault, acdc.regid, evidence.clone(source.vault, acdc.regid),
                     {'content-type': 'application/cesr'})
    assert result.said == event.said
    view = credentialing.credential(target.vault, said, grant=held)
    offer = ipexing.start(target.vault, holder, issuer.pre, 'Offer',
                         credential_said=said, from_grant=held)
    assert target.vault.exc.complete(offer)
    with pytest.raises(kering.ValidationError, match='verified issued state'):
        ipexing.grant(target.vault, holder, said, issuer.pre, from_grant=held)
    for proofs in ((), [old.qb64b], [Blinder.blind(acdc='').qb64b]):
        with pytest.raises(kering.ValidationError):
            disclosing.material(target.vault, view, refresh=True, openings=proofs)
    if custodyState != 'absent':
        with pytest.raises(kering.KeriError):
            disclosing.material(target.vault, view, refresh=True, derive=True)
    refreshed = disclosing.material(target.vault, view, refresh=True, openings=[opening.qb64b])
    assert refreshed['sad'] == view['sad'] and refreshed['status']['et'] == 'issued'
    assert credentialing.credential(target.vault, said, grant=held)['proof'] == view['proof']
    if custodyState == 'absent':
        assert not list(target.hby.mgr.ks.rroots.getTopItemIter())
    with pytest.raises(ValueError, match='explicit state refresh'):
        disclosing.material(target.vault, view, openings=[opening.qb64b])


# The protected plaintext RegistryCustody export/import scenario is retired.
# RegistrySalt auxiliary transfer and futureDhke consent are a subsequent unit.


def test_graduated_offer_dialog_previews_exact_sent_fields(ipex_vaults, qapp):
    """Click the actual Offer dialog, compare its preview and signed disclosure."""
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QLabel, QWidget
    from locksmith.ui.vault.credentials.activity import CredentialActivityPage
    source, target = ipex_vaults('ui-graduate-source'), ipex_vaults('ui-graduate-target')
    issuer, holder = source.hby.makeHab(name='issuer'), target.hby.makeHab(name='holder')
    schema = _load_schema(source, issuer)
    target.hby.db.schema.pin((schema.said,), schema)
    _introduce(source, target)
    _introduce(target, source)
    said = _issue(source, schema, holder, authentication='anchor', attributes={
        'status': {'d': '', 'u': Noncer().qb64, 'value': 'authorized-visible'},
        'private': {'d': '', 'u': Noncer().qb64, 'value': 'private-not-shared'}})
    _introduce(source, target)
    apply = ipexing.start(target.vault, holder, issuer.pre, 'Apply', schema=schema.said,
                         disclose=['a/status/'])
    _send(target, source, apply)
    parent = QWidget()
    parent.app = source
    page = CredentialActivityPage(parent)
    page.set_vault_name(source.name)
    row = next(row for row in page.tables[0]._static_data if row['root'] == apply)
    page._on_row_action(row, 'Offer')
    dialog = page._response_dialog
    dialog.credential.setCurrentIndex(dialog.credential.findData(said))
    dialog.response.setCurrentIndex(dialog.response.combo_box.findData('Offer'))
    qapp.processEvents()
    labels = [label.text() for label in dialog.preview.findChildren(QLabel)]
    assert any('authorized-visible' in label for label in labels)
    assert not any('private-not-shared' in label for label in labels)
    assert 'before agreement' in dialog.explanation.text()
    assert dialog.send_button.isEnabled()
    QTest.mouseClick(dialog.send_button, Qt.MouseButton.LeftButton)
    offer, = [exn for _, exn in source.hby.db.exns.getTopItemIter()
              if exn.route == '/ipex/offer']
    _send(source, target, offer.said)
    node, = exchanging.loadParsedNestedSubstreams(target.hby, offer.said)
    assert node.serder.sad['a']['status']['value'] == 'authorized-visible'
    assert isinstance(node.serder.sad['a']['private'], str)
    receiver_parent = QWidget()
    receiver_parent.app = target
    receiver_page = CredentialActivityPage(receiver_parent)
    receiver_page.set_vault_name(target.name)
    row = next(row for row in receiver_page.tables[1]._static_data if row['root'] == apply)
    receiver_page._on_row_action(row, 'Agree')
    review = receiver_page._response_dialog
    labels = [label.text() for label in review.offer_review.findChildren(QLabel)]
    assert any('authorized-visible' in label for label in labels)
    assert not any('private-not-shared' in label for label in labels)


def test_offer_start_selects_sections_with_real_controls(ipex_vaults, qapp):
    """Check one section and send; the actual Offer omits the other held value."""
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QWidget
    from locksmith.ui.vault.credentials.start import StartExchangeDialog
    app = ipex_vaults('ui-offer-start')
    issuer, holder = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='holder')
    schema = _load_schema(app, issuer)
    said = _issue(app, schema, holder, authentication='anchor', attributes={
        'status': {'d': '', 'u': Noncer().qb64, 'value': 'selected'},
        'private': {'d': '', 'u': Noncer().qb64, 'value': 'not-selected'}})
    parent = QWidget()
    dialog = StartExchangeDialog(app, parent, 'Offer', credential_said=said)
    dialog.open()
    dialog.recipient.setCurrentIndex(dialog.recipient.combo_box.findData(holder.pre))
    field = next(field for path, field in dialog.fields.fields if path == 'a/status/')
    dialog.scroll_area.ensureWidgetVisible(field)
    field.setFocus()
    qapp.processEvents()
    QTest.keyClick(field, Qt.Key.Key_Space)
    qapp.processEvents()
    assert dialog.fields.paths() == ['a/status/']
    assert 'before agreement' in dialog.explanation.text()
    assert dialog.send_button.isEnabled()
    QTest.mouseClick(dialog.send_button, Qt.MouseButton.LeftButton)
    offer, = [exn for _, exn in app.hby.db.exns.getTopItemIter() if exn.route == '/ipex/offer']
    node, = exchanging.loadParsedNestedSubstreams(app.hby, offer.said)
    assert node.serder.sad['a']['status']['value'] == 'selected'
    assert isinstance(node.serder.sad['a']['private'], str)


@pytest.mark.parametrize('bound', [False, True])
def test_existing_keeper_root_derives_only_explicit_accepted_selection(ipex_vaults, bound):
    """Seed an existing-root fixture; this does not exercise or replace root transfer."""
    from keri.core import Salter
    from keri.acdc import acdcmap
    from locksmith.core import registry_authoring
    from locksmith.db.basing import IssuedCredential

    source = ipex_vaults('existing-root-issuer', bran='0123456789abcdefghijk')
    target = ipex_vaults('existing-root-holder', bran='0123456789abcdefghijk')
    issuer, holder = source.hby.makeHab(name='issuer'), target.hby.makeHab(name='holder')
    schema = _load_schema(source, issuer)
    target.hby.db.schema.pin((schema.said,), schema)
    _introduce(source, target)
    _introduce(target, source)
    registry = Registrar(rgy=source.vault.rgy).makeRegistry('existing', issuer.pre)
    rip = source.vault.rgy.store.event(registry.regk)
    issuer.interact(data=[dict(i=registry.regk, s=rip.sad['n'], d=rip.said)])
    assert registry.anchorMsg(rip.said)
    root = Salter()
    source.hby.mgr.putRegistryRoot(issuer.pre, registry.regk, root)
    acdc = acdcmap(israid=issuer.pre, schema=schema.said, regid=registry.regk,
                   attribute={'d': '', 'i': holder.pre, 'LEI': 'existing-root'})
    selected = holder.kever.serder.said if bound else None
    first, event, proof = registry_authoring.stage(source.vault, registry, acdc,
        'issued', 'derived', bound_event=selected)
    issuer.interact(data=[dict(i=registry.regk, s=event.sad['n'], d=event.said)])
    assert registry.anchorMsg(event.said)
    source.vault.db.issued.pin((acdc.said,), IssuedCredential(acdc.raw.decode(),
        first.qb64, event.said, proof.decode(), registry_mode='derived'))
    evidence.receive(target.vault, registry.regk, evidence.clone(source.vault, registry.regk),
                     {'content-type': 'application/cesr'})
    held = _grant(source, target, issuer, holder, acdc.said)
    target.hby.mgr.putRegistryRoot(holder.pre, registry.regk, root)
    later, update, _ = registry_authoring.stage(source.vault, registry, acdc,
        'issued', 'derived', bound_event=selected)
    issuer.interact(data=[dict(i=registry.regk, s=update.sad['n'], d=update.said)])
    assert registry.anchorMsg(update.said)
    evidence.receive(target.vault, registry.regk, evidence.clone(source.vault, registry.regk),
                     {'content-type': 'application/cesr'})
    view = credentialing.credential(target.vault, acdc.said, grant=held)
    before = view['proof']
    if bound:
        holder.rotate()
        with pytest.raises(kering.ValidationError):
            disclosing.material(target.vault, view, refresh=True, derive=True)
    refreshed = disclosing.material(target.vault, view, refresh=True, derive=True,
                                     bound_event=selected)
    assert later.qb64b in refreshed['proof']
    assert refreshed['sad'] == view['sad']
    assert refreshed['status']['et'] == 'issued'
    assert credentialing.credential(target.vault, acdc.said, grant=held)['proof'] == before
    target.close_vault()
    target = ipex_vaults('existing-root-holder', bran='0123456789abcdefghijk')
    assert disclosing.registry_root(target.vault, holder.pre, registry.regk).qb64 == root.qb64
    # Merely cloning accepted public TEL cannot disclose held proofs or roots.
    assert root.qb64b not in target.vault.rgy.store.cloneTel(registry.regk)
    assert later.qb64b not in target.vault.rgy.store.cloneTel(registry.regk)
