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


def _existing_root_fixture(ipex_vaults, bound=False):
    """Existing encrypted issuer custody and one real exact recipient admission."""
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
    return source, target, issuer, holder, registry, root, acdc, held, selected


@pytest.mark.parametrize('bound', [False, True])
def test_existing_keeper_root_derives_only_explicit_accepted_selection(ipex_vaults, bound):
    """Existing-root derivation remains independent of root-copy UI."""
    from locksmith.core import registry_authoring
    source, target, issuer, holder, registry, root, acdc, held, selected = _existing_root_fixture(ipex_vaults, bound)
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


def test_encrypted_root_file_requires_inspected_consent_and_actual_retention(ipex_vaults, qapp, tmp_path):
    """Real file controls preserve native replay, wrong-root and retention boundaries."""
    from datetime import timedelta
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QWidget
    from keri.core import Encrypter, Salter, SerderKERI, reply
    from keri.help import helping
    from locksmith.core import root_copying
    from locksmith.ui.vault.credentials.root_copy import RootCopyDialog

    source, target, issuer, holder, registry, root, acdc, held, _ = _existing_root_fixture(ipex_vaults)
    parent = QWidget()
    public = target.vault.rgy.store.cloneTel(registry.regk)
    old = credentialing.credential(target.vault, acdc.said, grant=held)['proof']
    export = RootCopyDialog(source, parent, acdc.said)
    export.selection.setCurrentIndex(export.selection.combo_box.findData(holder.pre))
    path = tmp_path / 'encrypted.cesr'
    export.export_file(path)
    assert 'retention unconfirmed' in export.status.text()
    raw = path.read_bytes()
    selected = root_copying.inspect(raw)
    assert root.qb64b not in raw
    assert target.hby.mgr.getRegistryRoot(holder.pre, registry.regk) is None
    for malformed in (raw + b'garbage', raw[:-4]):
        with pytest.raises((kering.KeriError, ValueError)):
            root_copying.inspect(malformed)

    # Inspection and cancellation consume no authenticated replay slot or root.
    cancelled = RootCopyDialog(target, parent, acdc.said, received=True)
    cancelled.open()
    assert not cancelled.action.isEnabled()
    cancelled.inspect_file(path)
    assert 'Unauthenticated file claims' in cancelled.status.text()
    assert target.hby.db.kramMSGC.get((issuer.pre, selected.said)) is None
    cancelled.close()
    assert cancelled.inspected is None and target.vault.root_copies.active is None
    assert target.hby.mgr.getRegistryRoot(holder.pre, registry.regk) is None

    body = SerderKERI(raw=raw)
    expired = reply(pre=issuer.pre, route='/registry/salt', data=body.sad['a'],
        stamp=helping.toIso8601(helping.nowUTC() - timedelta(days=2)), pvrsn=kering.Vrsn_2_0)
    stale = root_copying.inspect(bytes(issuer.endorse(expired, gvrsn=kering.Vrsn_2_0)))
    event, opening = root_copying.held_openings(target.vault, acdc.said, held)[0]
    with pytest.raises(kering.ValidationError, match='not retained'):
        target.vault.root_copies.receive(stale, holder.pre, acdc.said, held, event, opening)
    assert target.hby.mgr.getRegistryRoot(holder.pre, registry.regk) is None
    assert target.vault.root_copies.active is None

    old_dialog = RootCopyDialog(target, parent, acdc.said, received=True)
    old_dialog.open()
    old_dialog.inspect_file(path)
    target.close_vault()
    QTest.mouseClick(old_dialog.action, Qt.MouseButton.LeftButton)
    assert 'vault is closed' in old_dialog.status.text()
    target = ipex_vaults('existing-root-holder', bran='0123456789abcdefghijk')
    dialog = RootCopyDialog(target, parent, acdc.said, received=True)
    dialog.open()
    dialog.inspect_file(path)
    QTest.mouseClick(dialog.action, Qt.MouseButton.LeftButton)
    assert 'retained and verified' in dialog.status.text(), dialog.status.text()
    assert target.vault.root_copies.received == selected.said
    assert target.vault.root_copies.active is None
    assert target.hby.mgr.getRegistryRoot(holder.pre, registry.regk).qb64 == root.qb64

    # A fresh correctly signed wrong root reaches native retention even with a root present.
    cipher = Encrypter(verkey=holder.kever.verfers[0].qb64).encrypt(prim=Salter())
    wrong = reply(pre=issuer.pre, route='/registry/salt', data=dict(body.sad['a'], cipher=cipher.qb64),
                  pvrsn=kering.Vrsn_2_0)
    bad = root_copying.inspect(bytes(issuer.endorse(wrong, gvrsn=kering.Vrsn_2_0)))
    with pytest.raises(kering.ValidationError, match='approved accepted opening'):
        target.vault.root_copies.receive(bad, holder.pre, acdc.said, held, event, opening)
    assert target.hby.db.kramMSGC.get((issuer.pre, wrong.said)) is not None
    assert target.hby.db.rpys.get((wrong.said,)) is not None
    assert target.vault.root_copies.received is None and target.vault.root_copies.active is None
    assert target.vault.rgy.store.cloneTel(registry.regk) == public
    assert credentialing.credential(target.vault, acdc.said, grant=held)['proof'] == old
    assert target.vault.db.accepted.get((acdc.said,)).grant == held
    target.close_vault()
    target = ipex_vaults('existing-root-holder', bran='0123456789abcdefghijk')
    assert target.hby.mgr.getRegistryRoot(holder.pre, registry.regk).qb64 == root.qb64
    assert target.vault.root_copies.active is None


def test_separate_discloser_prepares_issuer_endorses_and_resumes_exact_files(ipex_vaults, qapp, tmp_path):
    """Four independent roles retain one witnessed stale-proof Grant without delivery consent."""
    from time import sleep
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QLabel, QWidget
    from keri.core import SerderKERI, messagize
    from keri.help import helping
    from locksmith.core import grant_files, root_copying
    from locksmith.db.basing import IssuedCredential
    from locksmith.ui.vault.credentials.grant_files import GrantFilesDialog
    from test_auxiliary import pending_issuance
    from test_keri_v2_compat import _deliver_ipex

    issuer, holder, ih, hh, registrar, registry, acdc, issuance, atc, seal = pending_issuance(ipex_vaults)
    io, ho = issuer.vault.auxiliary, holder.vault.auxiliary
    io.begin_dh(ih, issuance, atc)
    _, _, raw, _ = io.outgoing.popleft()
    _deliver_ipex(holder.vault, raw)
    ho.approve_dh(hh, issuance.said)
    _, _, raw, _ = io.outgoing.popleft()
    _deliver_ipex(holder.vault, raw)
    _, _, raw, _ = ho.outgoing.popleft()
    _deliver_ipex(issuer.vault, raw)
    root = issuer.hby.mgr.getRegistryRoot(ih.pre, registry.regk)
    first, event = registrar.issue(registry, acdc, salt=root.qb64)
    seal(event)
    issuer.vault.db.issued.pin((acdc.said,), IssuedCredential(acdc.raw.decode(), first.qb64,
        event.said, messagize(acdc, bonds=[first.data], framed=False).decode(), registry_mode='derived'))
    io.process()
    ho.process()
    ipexing.admit(holder.vault, hh, issuance.said)

    discloser = ipex_vaults('s4-discloser', bran='0123456789abcdefghijk')
    verifier = ipex_vaults('s4-verifier', bran='0123456789abcdefghijk')
    dh, vh = discloser.hby.makeHab('discloser'), verifier.hby.makeHab('verifier')
    for target in (discloser, verifier):
        for wit in ih.kever.wits:
            _deliver_ipex(target.vault, b''.join(issuer.hby.db.clonePreIter(wit, gvrsn=kering.Vrsn_2_0)))
        _deliver_ipex(target.vault, evidence.clone(issuer.vault, registry.regk))
    for source in (issuer, holder, discloser, verifier):
        for target in (issuer, holder, discloser, verifier):
            if source is not target:
                _introduce(source, target)
    held = _grant(holder, discloser, hh, dh, acdc.said, from_grant=issuance.said)
    selected = root_copying.inspect(issuer.vault.root_copies.export(acdc.said, ih.pre, dh.pre))
    held_event, opening = root_copying.held_openings(discloser.vault, acdc.said, held)[0]
    discloser.vault.root_copies.receive(selected, dh.pre, acdc.said, held, held_event, opening)
    assert discloser.hby.mgr.getRegistryRoot(dh.pre, registry.regk).qb64 == root.qb64

    # A genuinely newer witnessed BUP is accepted; the source admission keeps its old proof.
    _, later = registrar.issue(registry, acdc, salt=root.qb64)
    seal(later, recipients=(holder.vault, discloser.vault, verifier.vault))
    before = credentialing.credential(discloser.vault, acdc.said, grant=held)['proof']
    old_holder = credentialing.credential(holder.vault, acdc.said, grant=issuance.said)['proof']
    with pytest.raises(kering.ValidationError):
        ipexing.grant(discloser.vault, dh, acdc.said, vh.pre, from_grant=held)
    assert not (discloser.hby.cf.get() or {}).get('presentation_policy')
    parent = QWidget()
    prepare = GrantFilesDialog(discloser, parent, acdc.said)
    prepare.open()
    prepare.recipient.setCurrentIndex(prepare.recipient.combo_box.findData(vh.pre))
    prepare.message.setText('Exact issuer consent')
    path = tmp_path / 'prepared.cesr'
    prepare.write_file(path)
    original = grant_files.inspect(path.read_bytes())
    grant = original.serder.said
    _, deadline = grant_files.retained(discloser.vault, grant)
    assert 'Original native deadline' in prepare.status.text()
    assert discloser.hby.db.kramTMSC.get((dh.pre, grant, grant)) is None
    assert not discloser.vault.exc.complete(grant)
    prepare.close()
    options = dict(grant=grant, aid=dh.pre, said=acdc.said, source=held,
                   recipient=vh.pre, message='Exact issuer consent')
    with pytest.raises(ValueError, match='issuer endorsement'):
        grant_files.resume(discloser.vault, path.read_bytes(), **options)

    wrong = issuer.hby.makeHab('wrong-issuer')
    with pytest.raises(ValueError, match='local issuer'):
        grant_files.endorse(issuer.vault, path.read_bytes(), issuer=wrong.pre,
                           grant=grant, sender=dh.pre, recipient=vh.pre)
    endorser = GrantFilesDialog(issuer, parent)
    endorser.open()
    endorser.identity.setCurrentIndex(endorser.identity.combo_box.findData(ih.pre))
    endorser.inspect_file(path)
    assert 'Unauthenticated file claims' in endorser.status.text()
    material = ' '.join(label.text() for label in endorser.preview.findChildren(QLabel))
    assert 'role' in material.lower() and 'holder' in material
    assert issuer.hby.db.exns.get((grant,)) is None and issuer.hby.db.epse.get((grant,)) is None
    output = tmp_path / 'endorsed.cesr'
    endorser.write_file(output)
    assert issuer.vault.exc.routes['/ipex/grant'].endorsement is None
    endorsed = grant_files.inspect(output.read_bytes())
    assert endorsed.serder.raw == original.serder.raw and grant_files.nodes(endorsed) == grant_files.nodes(original)
    assert {pre.qb64 for pre, _, _, _ in endorsed.tsgs} == {dh.pre, ih.pre}

    # Refuse edits and removal of original authentication before importing candidate bytes.
    removed = grant_files.inspect(output.read_bytes())
    removed.tsgs = [group for group in removed.tsgs if group[0].qb64 != dh.pre]
    altered = grant_files.inspect(output.read_bytes())
    altered.serder = SerderKERI(sad=dict(altered.serder.sad, a=dict(altered.serder.sad['a'], m='changed')), makify=True)
    changed_nest = grant_files.inspect(output.read_bytes())
    changed_nest.nests[0].bsqs = []
    for raw in (grant_files.wire(removed), grant_files.wire(altered), grant_files.wire(changed_nest)):
        with pytest.raises(ValueError, match='authentication additions'):
            grant_files.resume(discloser.vault, raw, **options)
    resume = GrantFilesDialog(discloser, parent, acdc.said)
    resume.open()
    resume.mode.setCurrentIndex(resume.mode.combo_box.findData('resume'))
    resume.recipient.setCurrentIndex(resume.recipient.combo_box.findData(vh.pre))
    resume.message.setText('Exact issuer consent')
    resume.preparation.setCurrentIndex(resume.preparation.combo_box.findData(grant))
    resume.inspect_file(output)
    QTest.mouseClick(resume.action, Qt.MouseButton.LeftButton)
    assert 'registered locally' in resume.status.text(), resume.status.text()
    final, final_deadline = grant_files.retained(discloser.vault, grant)
    assert final_deadline == deadline and final.serder.raw == original.serder.raw
    assert grant_files.nodes(final) == grant_files.nodes(original)
    cache = discloser.hby.db.kramTMSC.get((dh.pre, grant, grant))
    assert cache.rdt and cache.mdt == cache.xdt == original.serder.stamp
    with pytest.raises(ValueError, match='already registered'):
        grant_files.resume(discloser.vault, output.read_bytes(), **options)
    assert not list(discloser.vault.db.outbox.getTopItemIter())
    assert not discloser.vault.auxiliary.operations
    assert discloser.hby.db.erpy.get((grant,)) is None
    assert not discloser.vault.exc.complete(grant)
    assert verifier.hby.db.exns.get((grant,)) is None and verifier.hby.db.epse.get((grant,)) is None
    assert verifier.hby.mgr.getRegistryRoot(vh.pre, registry.regk) is None
    assert credentialing.credential(discloser.vault, acdc.said, grant=held)['proof'] == before
    assert credentialing.credential(holder.vault, acdc.said, grant=issuance.said)['proof'] == old_holder

    # Existing instance policy is selected BEFORE a new preparation, never applied to an old deadline.
    policy = discloser.vault.exc.TimeoutPSE
    assert policy == 300
    discloser.vault.exc.TimeoutPSE = 1
    expiry_options = dict(options, message='Short-policy refusal')
    expiry_options.pop('grant')
    try:
        expired, expired_raw, cutoff = grant_files.prepare(discloser.vault, **expiry_options)
    finally:
        discloser.vault.exc.TimeoutPSE = policy
    expired_endorsed = grant_files.endorse(issuer.vault, expired_raw, issuer=ih.pre,
        grant=expired, sender=dh.pre, recipient=vh.pre)
    sleep(max(0, (helping.fromIso8601(cutoff) - helping.nowUTC()).total_seconds()) + 0.02)
    with pytest.raises(ValueError, match='original native deadline'):
        grant_files.resume(discloser.vault, expired_endorsed, grant=expired, **expiry_options)
    assert discloser.hby.db.epsd.get((expired,)).dts == cutoff
    assert discloser.hby.db.erpy.get((expired,)) is None

    # A live 300-second preparation does not imply acceptance under a shorter real KRAM lag.
    config = discloser.hby.cf.get()
    config['kram']['caches'] = {'~': (0, 150, 150, 86400000, 300000, 3600000, 86400000)}
    discloser.hby.cf.put(config)
    discloser.vault.kramer.changeConfig(discloser.hby.cf)
    effective = discloser.hby.db.kramCTYP.get('~')
    assert effective.sl == effective.ll == 150
    lag_options = dict(expiry_options, message='Aged KRAM refusal')
    lagged, lag_raw, lag_deadline = grant_files.prepare(discloser.vault, **lag_options)
    lag_endorsed = grant_files.endorse(issuer.vault, lag_raw, issuer=ih.pre,
        grant=lagged, sender=dh.pre, recipient=vh.pre)
    stamp = grant_files.inspect(lag_raw).serder.stamp
    sleep(max(0, (helping.fromIso8601(stamp) - helping.nowUTC()).total_seconds()
              + (effective.d + effective.sl) / 1000) + 0.02)
    assert helping.nowUTC() < helping.fromIso8601(lag_deadline)
    with pytest.raises(ValueError, match='KRAM registration was not accepted'):
        grant_files.resume(discloser.vault, lag_endorsed, grant=lagged, **lag_options)
    assert discloser.hby.db.kramTMSC.get((dh.pre, lagged, lagged)) is None
    assert discloser.hby.db.epsd.get((lagged,)).dts == lag_deadline
    discloser.close_vault()
    QTest.mouseClick(resume.action, Qt.MouseButton.LeftButton)
    assert 'vault is closed' in resume.status.text()
