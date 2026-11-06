"""Explicit Qt consent over v2 event-opening requests and exact held views."""
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QWidget
from keri import kering
from keri.core import Parser
from keri.peer import exchanging

from locksmith.core import credentialing
from locksmith.ui.vault.credentials.activity import CredentialActivityPage
from locksmith.ui.vault.credentials.received.accept_grant import AcceptGrantDialog
from test_keri_v2_compat import ipex_vaults as ipex_vaults, _deliver_ipex
from test_unblind import live_presentation


def test_openings_require_request_approval_and_separate_admit(qapp, ipex_vaults):
    holder, verifier, hh, vh, acdc, registry, issuance, retained, message, _, _ = live_presentation(ipex_vaults)
    ho, vo = holder.vault.auxiliary, verifier.vault.auxiliary
    presenter_window, recipient_window = QWidget(), QWidget()
    presenter_window.app, recipient_window.app = holder, verifier
    presenter = CredentialActivityPage(presenter_window)
    recipient = CredentialActivityPage(recipient_window)
    presenter.set_vault_name(holder.name)
    recipient.set_vault_name(verifier.name)
    presenter.show()
    recipient.show()
    assert not presenter.opening_buttons

    # The recipient asks for this presentation's missing event proofs.
    QTest.mouseClick(recipient.opening_buttons[(vh.pre, message.said)], Qt.MouseButton.LeftButton)
    request = recipient._response_dialog
    assert request.state.text() == 'State openings needed'
    assert not request.cancel.isVisible() and not request.review.isVisible()
    QTest.mouseClick(request.request, Qt.MouseButton.LeftButton)
    assert request.state.text() == 'Waiting for state openings'
    _, _, query, _ = vo.outgoing.popleft()
    query = query()  # Requests are signed when delivery starts.
    _deliver_ipex(holder.vault, query)
    qapp.processEvents()

    # A signed request alone cannot authorize the presenter to release proofs.
    assert not ho.outgoing
    QTest.mouseClick(presenter.opening_buttons[(hh.pre, message.said)], Qt.MouseButton.LeftButton)
    approval = presenter._response_dialog
    assert approval.state.text() == 'Opening approval needed'
    assert not approval.cancel.isVisible()
    QTest.mouseClick(approval.approve, Qt.MouseButton.LeftButton)
    assert approval.state.text() == 'Opening reply prepared'
    assert approval.delivery.isVisible() and not approval.review.isVisible()
    assert not verifier.vault.exc.complete(message.said)
    assert verifier.vault.db.accepted.get((acdc.said,)) is None
    _, _, reply, _ = ho.outgoing.popleft()
    _deliver_ipex(verifier.vault, reply)
    qapp.processEvents()

    # Verification of the exact Grant enables review, never automatic Admit.
    QTest.mouseClick(recipient.opening_buttons[(vh.pre, message.said)], Qt.MouseButton.LeftButton)
    verified = recipient._response_dialog
    assert verified.state.text() == 'State openings verified'
    assert verifier.hby.db.exns.get((message.said,)).raw == message.raw
    assert verifier.hby.mgr.getRegistryRoot(vh.pre, registry.regk) is None
    assert verifier.vault.db.accepted.get((acdc.said,)) is None
    location = holder.hby.db.locs.get((hh.pre, kering.Schemes.http))
    _deliver_ipex(verifier.vault, hh.makeLocScheme(url=location.url))
    _deliver_ipex(verifier.vault, hh.makeEndRole(eid=hh.pre, role=kering.Roles.mailbox))
    QTest.mouseClick(verified.review, Qt.MouseButton.LeftButton)
    review = recipient._response_dialog
    qapp.processEvents()
    assert isinstance(review, AcceptGrantDialog)
    assert verifier.vault.db.accepted.get((acdc.said,)) is None
    QTest.mouseClick(review.admit_button, Qt.MouseButton.LeftButton)
    accepted = verifier.vault.db.accepted.get((acdc.said,))
    assert accepted is not None, review.error_label.text()
    assert accepted.grant == message.said
    assert credentialing.credential(holder.vault, acdc.said, grant=issuance.said)['proof'] == retained


def test_missing_opening_waits_until_the_presenter_cancels(qapp, ipex_vaults):
    holder, verifier, hh, vh, acdc, _, _, _, message, _, _ = live_presentation(ipex_vaults, blinded=True)
    ho, vo = holder.vault.auxiliary, verifier.vault.auxiliary
    vo.request_openings(vh, message.said)
    _, _, query, _ = vo.outgoing.popleft()
    query = query()  # Requests are signed when delivery starts.
    _deliver_ipex(holder.vault, query)
    window = QWidget()
    window.app = holder
    page = CredentialActivityPage(window)
    page.set_vault_name(holder.name)
    page.show()
    QTest.mouseClick(page.opening_buttons[(hh.pre, message.said)], Qt.MouseButton.LeftButton)
    dialog = page._response_dialog
    QTest.mouseClick(dialog.approve, Qt.MouseButton.LeftButton)
    assert dialog.state.text() == 'Waiting for state openings'
    assert dialog.error.text() and not ho.outgoing
    QTest.mouseClick(dialog.cancel, Qt.MouseButton.LeftButton)
    assert dialog.state.text() == 'Opening request cancelled'
    assert not dialog.approve.isVisible() and not dialog.review.isVisible()
    assert verifier.vault.db.accepted.get((acdc.said,)) is None


def test_wrong_event_opening_is_visibly_refused(qapp, ipex_vaults):
    holder, verifier, hh, vh, acdc, _, issuance, _, message, _, _ = live_presentation(ipex_vaults)
    ho, vo = holder.vault.auxiliary, verifier.vault.auxiliary
    window = QWidget()
    window.app = verifier
    page = CredentialActivityPage(window)
    page.set_vault_name(verifier.name)
    page.show()
    QTest.mouseClick(page.opening_buttons[(vh.pre, message.said)], Qt.MouseButton.LeftButton)
    dialog = page._response_dialog
    QTest.mouseClick(dialog.request, Qt.MouseButton.LeftButton)
    _, _, query, _ = vo.outgoing.popleft()
    query = query()  # Requests are signed when delivery starts.
    _deliver_ipex(holder.vault, query)
    ho.approve_openings(hh, message.said)
    _, _, reply, _ = ho.outgoing.popleft()

    # Substitute a genuine older proof into the reply for the newer event.
    response = Parser(version=kering.Vrsn_2_0).parseOne(ims=bytearray(reply), processive=False)
    original, = exchanging.loadParsedNestedSubstreams(holder.hby, issuance.said)
    assert original.bsqs
    response.bsqs = original.bsqs
    _deliver_ipex(verifier.vault, exchanging.serializeParsedSubstream(response))
    qapp.processEvents()
    assert dialog.state.text() == 'State openings refused'
    assert dialog.error.text() and not dialog.review.isVisible()
    assert not verifier.vault.exc.complete(message.said)
    assert verifier.vault.db.accepted.get((acdc.said,)) is None


def test_revoked_opening_is_delivered_but_never_enables_admit(qapp, ipex_vaults):
    """Core protocol completion does not authorize issued use of a revoked credential."""
    holder, verifier, hh, vh, acdc, _, issuance, retained, message, _, _ = live_presentation(
        ipex_vaults, state='revoked')
    ho, vo = holder.vault.auxiliary, verifier.vault.auxiliary
    window = QWidget()
    window.app = verifier
    page = CredentialActivityPage(window)
    page.set_vault_name(verifier.name)
    page.show()
    QTest.mouseClick(page.opening_buttons[(vh.pre, message.said)], Qt.MouseButton.LeftButton)
    dialog = page._response_dialog
    QTest.mouseClick(dialog.request, Qt.MouseButton.LeftButton)
    _, _, query, _ = vo.outgoing.popleft()
    query = query()  # Requests are signed when delivery starts.
    _deliver_ipex(holder.vault, query)
    ho.approve_openings(hh, message.said)
    assert holder.hby.db.exrs.get((message.said, acdc.said)).state == 'revoked'
    assert ho.status(hh.pre, message.said)['phase'] == 'answered'
    _, _, reply, _ = ho.outgoing.popleft()
    _deliver_ipex(verifier.vault, reply)
    qapp.processEvents()
    assert dialog.state.text() == 'State openings refused'
    assert 'revoked' in dialog.error.text() and not dialog.review.isVisible()
    assert verifier.vault.db.accepted.get((acdc.said,)) is None
    assert verifier.hby.db.erpy.get((message.said,)) is None
    assert credentialing.credential(holder.vault, acdc.said, grant=issuance.said)['proof'] == retained
