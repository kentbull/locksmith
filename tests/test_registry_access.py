"""Real Qt controls approve registry events without a salt agreement ceremony."""
import pytest
from PySide6.QtWidgets import QWidget
from keri import kering
from keri.acdc import Registrar, acdcmap
from keri.peer.exchanging import serializeMessage
from locksmith.core.salt_actions import SaltActions
from locksmith.ui.vault.credentials.registry_access import RegistryAccessPage
from locksmith.ui.vault.notifications.list import NotificationsListPage
from test_keri_v2_compat import ipex_vaults
from salt_helpers import group_vaults


def page_for(app):
    """Build the real screen under a lightweight QWidget navigation owner."""
    parent = QWidget()
    parent.app = app
    page = RegistryAccessPage(parent)
    page.refresh()
    return parent, page


def choose(combo, aid):
    """Select an exact domain AID in the existing combo widget."""
    index = combo.combo_box.findData(aid)
    assert index >= 0
    combo.setCurrentIndex(index)


def finish(app, qapp, dialog):
    """Advance the production scheduler until this finite UI action completes."""
    assert dialog.worker is not None
    for _ in range(1100):
        app.qtask.run()
        qapp.processEvents()
        if dialog.worker.done:
            break
    assert dialog.worker.done and not dialog.worker.error, dialog.worker.error


def deliver(source, target, route):
    """Deliver an actual retained member wrapper through the recipient's parser."""
    wrapper = next(body for _, body in source.hby.db.exns.getTopItemIter()
                   if body.route == route and source.hby.habByPre(body.pre) is not None)
    target.vault.mbx.parser.parse(ims=serializeMessage(source.hby, wrapper.said), local=False)
    return wrapper


def test_group_rip_and_bup_review_uses_existing_approval_without_offline_third(ipex_vaults, qapp):
    """Two actual signers accept exact native events; opening review needs no root."""
    apps, people, groups = group_vaults(ipex_vaults)
    parents, pages = zip(*(page_for(app) for app in apps[:2]))
    try:
        pages[0].open_action('create')
        creator = pages[0].dialog
        choose(creator.local, groups[0].pre)
        creator.name.setText('group registry')
        creator.submit.click()
        for _ in range(4):
            apps[0].qtask.run()
        original = deliver(apps[0], apps[1], '/multisig/rip')
        notifications = NotificationsListPage(parents[1])
        notifications._load_notifications()
        row = next(row for row in notifications.table._static_data if row.get('_said') == original.said)
        assert 'Review registry access' in notifications._get_row_actions(row)[0]
        parents[1].show_registry_access = pages[1].show_proposal
        notifications._on_row_action_signal(row, 'Review registry access')
        review = pages[1].dialog
        rip = review.body
        assert rip.ilk == 'rip' and review.worker is None
        assert apps[1].rgy.store.seqEvent(rip.said, 0) is None
        review.close()  # Refusal adds no signature or consent.
        assert apps[1].rgy.store.seqEvent(rip.said, 0) is None
        pages[1].show_proposal(original.said)
        review = pages[1].dialog
        review.submit.click()
        for _ in range(4):
            apps[1].qtask.run()
        deliver(apps[1], apps[0], '/multisig/rip')
        for _ in range(64):
            for app in apps[:2]:
                app.qtask.run()
            if creator.worker.done and review.worker.done:
                break
        assert creator.worker.done and review.worker.done
        assert not creator.worker.error and not review.worker.error
        assert all(app.rgy.store.seqEvent(rip.said, 0).said == rip.said for app in apps[:2])
        roots = [app.vault.salts.custody._load(rip.said).salt for app in apps[:2]]
        assert roots[0] == roots[1]
        assert not apps[2].vault.hby.ks.custody.get((rip.said,))
        # A public opening is independent of the retained reusable salt.
        registry = apps[0].rgy.regs[rip.said]
        acdc = acdcmap(israid=groups[0].pre, regid=rip.said, attribute={'d': '', 'value': 'test'})
        opening, update = Registrar(rgy=apps[0].rgy).issue(registry, acdc)
        outgoing, attachments = SaltActions(apps[0].vault).registryApproval(groups[0].pre).approve(
            update, opening=opening)
        apps[1].vault.mbx.parser.parse(ims=bytearray(outgoing.raw + attachments), local=False)
        pages[1].show_proposal(outgoing.said)
        review = pages[1].dialog
        assert review.body.raw == update.raw and opening.qb64 in review.preview.toPlainText()
        review.submit.click()
        finish(apps[1], qapp, review)
        assert apps[1].rgy.store.headEvent(rip.said).said == update.said
        assert apps[1].vault.salts.custody._load(rip.said).salt == roots[1]
        assert people[2].pre not in [member.qb64 for member in
                                    apps[1].hby.db.maids.get((update.said,))]
    finally:
        for page, parent in zip(pages, parents):
            if page.dialog:
                page.dialog.close()
            parent.close()




@pytest.mark.real_routes
def test_group_reply_approval_delivers_signature_to_initiator(ipex_vaults, qapp):
    """Two reviewers complete a salt reply; HTTP signature return finishes before cleanup."""
    from time import monotonic, sleep
    from keri.core import Salter
    from salt_helpers import capture_http
    apps, people, groups = group_vaults(ipex_vaults)
    recipient = apps[0].hby.makeHab(name='local-discloser')
    for app in apps[1:]:
        app.vault.mbx.parser.parse(ims=recipient.replay(gvrsn=kering.Vrsn_2_0), local=False)
    registry = Registrar(rgy=apps[0].rgy).makeRegistry(name='reply-source', prefix=groups[0].pre)
    rip = apps[0].rgy.store.event(registry.regk)
    first, atc = SaltActions(apps[0].vault).registryApproval(groups[0].pre).approve(rip)
    actions = SaltActions(apps[1].vault)
    apps[1].vault.mbx.parser.parse(ims=bytearray(first.raw + atc), local=False)
    event, anchor, _ = actions.inspect(first.said)
    second, atc = actions.registryApproval(groups[1].pre).approve(event, anchor)
    apps[0].vault.mbx.parser.parse(ims=bytearray(second.raw + atc), local=False)
    # Registry acceptance follows the ordinary KEL/TEL escrows, not parsing alone.
    for _ in range(64):
        for app in apps[:2]:
            app.qtask.run()
        if all(app.rgy.store.seqEvent(rip.said, 0) is not None for app in apps[:2]):
            break
    assert all(app.rgy.store.seqEvent(rip.said, 0) is not None for app in apps[:2])
    custody = apps[0].vault.salts.custody
    copies = custody.sealMembers(groups[0], Salter())
    custody.retainMemberCopy(rip.said, groups[0], copies)
    parents, pages = zip(*(page_for(app) for app in apps[:2]))
    try:
        with capture_http() as (port, received):
            routes = people[0].makeLocScheme(url=f'http://127.0.0.1:{port}',
                version=kering.Vrsn_2_0, gvrsn=kering.Vrsn_2_0)
            routes.extend(people[0].makeEndRole(eid=people[0].pre, role=kering.Roles.controller,
                version=kering.Vrsn_2_0, gvrsn=kering.Vrsn_2_0))
            apps[1].vault.mbx.parser.parse(ims=routes, local=False)
            pages[0].open_action('share', dict(party=groups[0].pre, registry=rip.said))
            starter = pages[0].dialog
            choose(starter.recipient, recipient.pre)
            starter.submit.click()
            body = starter.body
            starter.submit.click()
            for _ in range(4):
                apps[0].qtask.run()
            wrapper = deliver(apps[0], apps[1], '/multisig/rpy')
            pages[1].show_proposal(wrapper.said)
            review = pages[1].dialog
            assert review.worker is None and review.body.raw == body.raw
            review.close()
            pages[1].show_proposal(wrapper.said)
            review = pages[1].dialog
            review.submit.click()
            deadline = monotonic() + 8
            while monotonic() < deadline:
                apps[1].qtask.run()
                while received:
                    apps[0].vault.mbx.parser.parse(ims=bytearray(received.pop(0)), local=False)
                apps[0].qtask.run()
                if starter.worker.done and review.worker.done:
                    break
                sleep(0.001)
            assert starter.worker.done and review.worker.done
            assert not starter.worker.error and not review.worker.error
            assert 'initiator submits' in review.worker.result['state']
            assert apps[0].hby.db.rpys.get((body.said,)).raw == body.raw
            assert not apps[2].hby.db.rpys.get((body.said,))
    finally:
        for page, parent in zip(pages, parents):
            if page.dialog:
                page.dialog.close()
            parent.close()
