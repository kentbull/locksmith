"""Real pending registry setup, Qt approval, and separate credential consent."""
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QWidget
from keri import kering

from locksmith.ui.vault.credentials.activity import CredentialActivityPage
from locksmith.ui.vault.credentials.received.accept_grant import AcceptGrantDialog
from test_auxiliary import pending_issuance, ipex_vaults as ipex_vaults
from test_keri_v2_compat import _deliver_ipex


def test_registry_setup_approval_requires_a_separate_admit(qapp, ipex_vaults):
    issuer, holder, ih, hh, registrar, registry, acdc, message, atc, seal = pending_issuance(ipex_vaults)
    io, ho = issuer.vault.auxiliary, holder.vault.auxiliary
    parent = QWidget()
    parent.app = holder
    page = CredentialActivityPage(parent)
    page.set_vault_name(holder.name)
    page.show()
    assert not page.registry_buttons

    # An already open Activity page discovers the real incoming request.
    io.begin_dh(ih, message, atc)
    _, _, wire, _ = io.outgoing.popleft()
    _deliver_ipex(holder.vault, wire)
    _, _, query, _ = io.outgoing.popleft()
    query = query()  # Requests are signed when delivery starts.
    _deliver_ipex(holder.vault, query)
    qapp.processEvents()

    # Activity exposes authenticated pending setup, not an accepted credential.
    QTest.mouseClick(page.registry_buttons[(hh.pre, message.said)], Qt.MouseButton.LeftButton)
    dialog = page._response_dialog
    assert dialog.state.text() == 'Approval needed'
    assert not dialog.cancel.isVisible()
    assert not dialog.review.isVisible()
    assert holder.hby.mgr.getRegistryRoot(hh.pre, registry.regk) is None
    assert holder.vault.db.accepted.get((acdc.said,)) is None

    QTest.mouseClick(dialog.approve, Qt.MouseButton.LeftButton)
    assert dialog.state.text() == 'Waiting for registry evidence'
    assert dialog.cancel.isVisible()
    assert not dialog.approve.isVisible()
    _, _, reply, _ = ho.outgoing.popleft()
    _deliver_ipex(issuer.vault, reply)

    # The original witnessed registry update finishes the same live agreement.
    root = issuer.hby.mgr.getRegistryRoot(ih.pre, registry.regk)
    _, event = registrar.issue(registry, acdc, salt=root.qb64)
    seal(event)
    for _ in range(2):
        io.process()
        ho.process()
    qapp.processEvents()
    assert dialog.state.text() == 'Registry setup verified'
    assert holder.hby.db.exns.get((message.said,)).raw == message.raw
    assert holder.vault.db.accepted.get((acdc.said,)) is None

    # Introduce the issuer's signed reply route; transport delivery is separate.
    location = issuer.hby.db.locs.get((ih.pre, kering.Schemes.http))
    _deliver_ipex(holder.vault, ih.makeLocScheme(url=location.url))
    _deliver_ipex(holder.vault, ih.makeEndRole(eid=ih.pre, role=kering.Roles.mailbox))

    # Verification enables review; only the ordinary Add button records consent.
    QTest.mouseClick(dialog.review, Qt.MouseButton.LeftButton)
    review = page._response_dialog
    qapp.processEvents()
    assert isinstance(review, AcceptGrantDialog)
    assert holder.vault.db.accepted.get((acdc.said,)) is None
    assert review.admit_button.isVisible() and review.admit_button.isEnabled()
    QTest.mouseClick(review.admit_button, Qt.MouseButton.LeftButton)
    accepted = holder.vault.db.accepted.get((acdc.said,))
    assert accepted is not None, review.error_label.text()
    assert accepted.grant == message.said


def test_registry_setup_cancel_stops_the_live_agreement(qapp, ipex_vaults):
    issuer, holder, ih, hh, _, registry, acdc, message, atc, _ = pending_issuance(ipex_vaults)
    io, ho = issuer.vault.auxiliary, holder.vault.auxiliary
    io.begin_dh(ih, message, atc)
    _, _, wire, _ = io.outgoing.popleft()
    _deliver_ipex(holder.vault, wire)

    parent = QWidget()
    parent.app = holder
    page = CredentialActivityPage(parent)
    page.set_vault_name(holder.name)
    page.show()
    QTest.mouseClick(page.registry_buttons[(hh.pre, message.said)], Qt.MouseButton.LeftButton)
    dialog = page._response_dialog
    QTest.mouseClick(dialog.approve, Qt.MouseButton.LeftButton)
    QTest.mouseClick(dialog.cancel, Qt.MouseButton.LeftButton)
    assert ho.status(hh.pre, message.said)['phase'] == 'cancelled'
    assert dialog.state.text() == 'Registry setup cancelled'
    assert not dialog.approve.isVisible() and not dialog.review.isVisible()
    assert holder.hby.mgr.getRegistryRoot(hh.pre, registry.regk) is None
    assert holder.vault.db.accepted.get((acdc.said,)) is None


def test_registry_setup_refuses_a_revoked_opening(qapp, ipex_vaults):
    issuer, holder, ih, hh, registrar, registry, acdc, message, atc, seal = pending_issuance(ipex_vaults)
    io, ho = issuer.vault.auxiliary, holder.vault.auxiliary
    io.begin_dh(ih, message, atc)
    _, _, wire, _ = io.outgoing.popleft()
    _deliver_ipex(holder.vault, wire)
    _, _, query, _ = io.outgoing.popleft()
    query = query()  # Requests are signed when delivery starts.
    _deliver_ipex(holder.vault, query)
    parent = QWidget()
    parent.app = holder
    page = CredentialActivityPage(parent)
    page.set_vault_name(holder.name)
    page.show()
    QTest.mouseClick(page.registry_buttons[(hh.pre, message.said)], Qt.MouseButton.LeftButton)
    dialog = page._response_dialog
    QTest.mouseClick(dialog.approve, Qt.MouseButton.LeftButton)
    _, _, reply, _ = ho.outgoing.popleft()
    _deliver_ipex(issuer.vault, reply)

    # A real witnessed revoked update cannot complete issuance as issued.
    root = issuer.hby.mgr.getRegistryRoot(ih.pre, registry.regk)
    _, event = registrar.issue(registry, acdc, state='revoked', salt=root.qb64)
    seal(event)
    ho.process()
    qapp.processEvents()
    assert dialog.state.text() == 'Registry setup refused'
    assert 'does not open this credential as issued' in dialog.error.text()
    assert not dialog.approve.isVisible() and not dialog.review.isVisible()
    assert not holder.vault.exc.complete(message.said)
    assert holder.vault.db.accepted.get((acdc.said,)) is None
