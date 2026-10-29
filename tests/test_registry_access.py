"""Actual operator controls retain explicit exact registry-access consent."""

import pytest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from time import monotonic, sleep
from PySide6.QtWidgets import QWidget
from keri.app import registry_salt_replies as replies
from keri import kering
from keri.acdc import Registrar, acdcmap
from keri.peer.exchanging import serializeMessage
from keri.core import Diger

from locksmith.core.salt_actions import SaltActions
from locksmith.ui.vault.credentials.registry_access import RegistryAccessPage
from locksmith.ui.vault.notifications.list import NotificationsListPage
from test_keri_v2_compat import ipex_vaults as ipex_vaults
from salt_helpers import capture_http, group_vaults


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


@pytest.mark.real_routes
@pytest.mark.parametrize('initiator', ['issuer', 'discloser'])
def test_independent_wallet_buttons_supply_public_rip_dependencies(ipex_vaults, qapp, initiator):
    """Both live directions work without preimported rip or private evidence files."""
    issuer_app = ipex_vaults('independent-issuer-' + initiator, bran='0123456789abcdefghijk')
    peer_app = ipex_vaults('independent-discloser-' + initiator, bran='0123456789abcdefghijk')
    issuer = issuer_app.hby.makeHab(name='issuer', algo='randy')
    discloser = peer_app.hby.makeHab(name='discloser', algo='randy')
    for app in (issuer_app, peer_app):
        for person in (issuer, discloser):
            app.vault.mbx.parser.parse(ims=person.replay(gvrsn=kering.Vrsn_2_0), local=False)
            app.vault.salts.service.trustRoster(person.pre, [person.pre])
    parents, pages = zip(*(page_for(app) for app in (issuer_app, peer_app)))
    parties = dict(issuer=(issuer_app, issuer, pages[0]), discloser=(peer_app, discloser, pages[1]))
    try:
        with capture_http() as (issuer_port, issuer_mail), capture_http() as (peer_port, peer_mail):
            for person, port, target in ((issuer, issuer_port, peer_app), (discloser, peer_port, issuer_app)):
                for frame in (person.makeLocScheme(url=f'http://127.0.0.1:{port}', scheme=kering.Schemes.http),
                              person.makeEndRole(eid=person.pre, role=kering.Roles.controller)):
                    target.vault.mbx.parser.parse(ims=bytearray(frame), local=False)

            def execute(app, dialog):
                for _ in range(3000):
                    app.qtask.run()
                    qapp.processEvents()
                    if dialog.worker.done:
                        break
                    sleep(.001)
                assert dialog.worker.done and not dialog.worker.error, dialog.worker.error

            def intake(app, frames):
                while frames:
                    app.vault.mbx.parser.parse(ims=bytearray(frames.pop(0)), local=False)
                for _ in range(16):
                    app.qtask.run()  # Existing Revery/Rever dependency owners.

            pages[0].open_action('create')
            creator = pages[0].dialog
            choose(creator.local, issuer.pre)
            creator.name.setText('shared')
            creator.submit.click()
            execute(issuer_app, creator)
            registry = issuer_app.rgy.names['shared']
            assert peer_app.rgy.store.seqEvent(registry.regk, 0) is None
            with pytest.raises(kering.ValidationError, match='selected issuer'):
                SaltActions(issuer_app.vault).acceptedRegistry(registry.regk, discloser.pre)
            own_app, own, own_page = parties[initiator]
            other_app, other, other_page = parties['discloser' if initiator == 'issuer' else 'issuer']
            own_page.open_action('start')
            start = own_page.dialog
            choose(start.local, own.pre)
            choose(start.issuer, issuer.pre)
            choose(start.discloser, discloser.pre)
            if initiator == 'issuer':
                choose(start.registry, registry.regk)  # Explicit evidence hint, never an init field.
            start.submit.click()
            init = start.body
            assert 'registry' not in init.sad['a']
            if initiator == 'issuer':
                assert registry.regk in start.preview.toPlainText()
                assert 'Binding is approved separately' in start.preview.toPlainText()
            start.submit.click()
            execute(own_app, start)
            intake(other_app, peer_mail if other_app is peer_app else issuer_mail)
            assert other_app.vault.salts.state.proof(init.said)
            assert not list(other_app.vault.db.saltPending.getTopItemIter())
            assert other_app.rgy.store.seqEvent(registry.regk, 0) is not None
            other_page.open_action('bind', dict(said=init.said, party=other.pre, body=init))
            binder = other_page.dialog
            choose(binder.registry, registry.regk)
            binder.submit.click()
            bind = binder.body
            binder.submit.click()
            execute(other_app, binder)
            intake(own_app, peer_mail if own_app is peer_app else issuer_mail)
            assert issuer_app.vault.salts.state.proof(bind.said)
            pages[0].open_action('confirm', dict(said=bind.said, party=issuer.pre, body=bind))
            confirmer = pages[0].dialog
            confirmer.submit.click()
            confirm = confirmer.body
            confirmer.submit.click()
            execute(issuer_app, confirmer)
            intake(peer_app, peer_mail)
            assert peer_app.vault.salts.state.origin(registry.regk).confirm == confirm.said
            credential = Diger(ser=b'independent UI future credential').qb64
            assert issuer_app.vault.salts.custody.derive(registry.regk, 1, credential, 'issued').qb64 == (
                peer_app.vault.salts.custody.derive(registry.regk, 1, credential, 'issued').qb64)
    finally:
        for page, parent in zip(pages, parents):
            if page.dialog:
                page.dialog.close()
            parent.close()


@pytest.mark.parametrize('initiator', ['issuer', 'discloser'])
def test_buttons_establish_same_registry_and_explicitly_assign_later_party(ipex_vaults, qapp, initiator):
    """Real buttons perform both DH directions and later same-origin assignment."""
    app = ipex_vaults('access-' + initiator, bran='0123456789abcdefghijk')
    issuer, discloser, holder = [app.hby.makeHab(name=name) for name in ('issuer', 'discloser', 'holder')]
    parent, page = page_for(app)
    try:
        page.open_action('create')
        create = page.dialog
        choose(create.local, issuer.pre)
        create.name.setText('shared registry')
        create.submit.click()
        finish(app, qapp, create)
        registry = app.vault.rgy.names['shared registry']
        assert app.vault.rgy.store.seqEvent(registry.regk, 0) is not None
        assert not app.vault.salts.state.origins()
        assert not list(app.vault.db.custody.getTopItemIter())
        page.open_action('start')
        start = page.dialog
        own = issuer if initiator == 'issuer' else discloser
        other = discloser if initiator == 'issuer' else issuer
        choose(start.local, own.pre)
        choose(start.issuer, issuer.pre)
        choose(start.discloser, discloser.pre)
        start.submit.click()
        init = start.body
        assert init is not None and init.route == replies.INIT_ROUTE
        assert start.preview.toPlainText() and start.worker is None
        assert app.vault.salts.state.proof(init.said) is None
        assert app.vault.salts.state.hasPending(init.said, own.pre)
        start.submit.click()
        finish(app, qapp, start)
        assert app.vault.salts.state.proof(init.said)
        page.open_action('bind', dict(kind='statement', said=init.said, party=other.pre, body=init))
        bind_dialog = page.dialog
        choose(bind_dialog.registry, registry.regk)
        bind_dialog.submit.click()
        bind = bind_dialog.body
        assert bind and app.vault.salts.state.proof(bind.said) is None
        bind_dialog.submit.click()
        finish(app, qapp, bind_dialog)
        page.open_action('confirm', dict(kind='statement', said=bind.said, party=issuer.pre, body=bind))
        confirm_dialog = page.dialog
        confirm_dialog.submit.click()
        confirm = confirm_dialog.body
        assert confirm and not app.vault.salts.state.origins()
        confirm_dialog.submit.click()
        finish(app, qapp, confirm_dialog)
        origin = app.vault.salts.state.origin(registry.regk)
        assert origin.confirm == confirm.said and origin.init == init.said
        cipher = app.vault.db.custody.get((registry.regk,))
        page.open_action('assign', dict(kind='registry', said=registry.regk, party=issuer.pre,
                                       registry=registry.regk, origin=origin.confirm))
        assignment = page.dialog
        choose(assignment.recipient, holder.pre)
        assignment.submit.click()
        assert assignment.body.sad['a']['origin'] == origin.confirm
        assignment.submit.click()
        finish(app, qapp, assignment)
        assert app.vault.salts.state.assignment(registry.regk, holder.pre) == assignment.body.said
        assert app.vault.salts.state.origin(registry.regk) == origin
        assert app.vault.db.custody.get((registry.regk,)) == cipher
        assert len(app.vault.salts.state.origins()) == 1
    finally:
        if page.dialog:
            page.dialog.close()
        parent.close()


def test_cancel_and_reopen_recovers_exact_unsigned_draft_without_new_material(ipex_vaults, qapp):
    """Display reads only public keys; explicit recovery reuses protected pending DH."""
    app = ipex_vaults('access-recovery', bran='0123456789abcdefghijk')
    issuer, discloser = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='discloser')
    parent, page = page_for(app)
    page.open_action('start')
    dialog = page.dialog
    choose(dialog.local, issuer.pre)
    choose(dialog.issuer, issuer.pre)
    choose(dialog.discloser, discloser.pre)
    dialog.submit.click()
    original = dialog.body.raw
    init = dialog.body.said
    dialog.close()
    assert app.vault.salts.state.proof(init) is None
    parent.close()
    app.close_vault()
    app = ipex_vaults('access-recovery', bran='0123456789abcdefghijk')
    parent, page = page_for(app)
    try:
        # No root/private-key access is needed to list the encrypted draft.
        decrypter = app.hby.mgr.decrypter
        app.hby.mgr.decrypter = None
        page.refresh()
        draft = next(row for row in page.rows if row['kind'] == 'draft')
        app.hby.mgr.decrypter = decrypter
        page.open_action('recover', draft)
        dialog = page.dialog
        dialog.submit.click()
        assert dialog.body.raw == original and dialog.worker is None
        dialog.submit.click()
        finish(app, qapp, dialog)
        assert app.vault.salts.state.proof(init)
        assert not app.vault.salts.state.origins()
    finally:
        if page.dialog:
            page.dialog.close()
        parent.close()


def test_confirmed_remote_member_map_is_explicit_and_grants_no_entitlement(ipex_vaults, qapp):
    """A map action persists only the core accepted roster, never a salt/root."""
    app = ipex_vaults('access-roster')
    person = app.hby.makeHab(name='known person')
    parent, page = page_for(app)
    try:
        page.open_action('roster')
        dialog = page.dialog
        choose(dialog.recipient, person.pre)
        assert dialog.maps['recipient'][1].toPlainText() == person.pre
        assert app.vault.salts.state.roster(person.pre) is None
        dialog.submit.click()
        assert SaltActions(app.vault).roster(person.pre) == [person.pre]
        assert not app.vault.salts.state.origins()
        assert not list(app.vault.db.custody.getTopItemIter())
    finally:
        page.dialog.close()
        parent.close()


def deliver(source, target, route):
    """Deliver an actual retained member wrapper through the recipient's parser."""
    wrapper = next(body for _, body in source.hby.db.exns.getTopItemIter()
                   if body.route == route and source.hby.habByPre(body.pre) is not None)
    target.vault.mbx.parser.parse(ims=serializeMessage(source.hby, wrapper.said), local=False)
    return wrapper


def test_group_rip_and_bup_review_uses_existing_approval_without_offline_third(ipex_vaults, qapp):
    """Two actual signers accept exact native events; opening review needs no root."""
    apps, people, groups = group_vaults(ipex_vaults)
    record = apps[0].hby.db.habs.get((groups[0].pre,))
    accepted = list(record.smids)
    record.smids = list(reversed(accepted))
    apps[0].hby.db.habs.pin((groups[0].pre,), record)
    assert SaltActions(apps[0].vault).roster(groups[0].pre) == []
    record.smids = accepted
    apps[0].hby.db.habs.pin((groups[0].pre,), record)
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
        assert all(not app.vault.salts.state.origins() for app in apps)
        # A real public bup proposal is reviewable without derivation custody.
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
        assert not list(apps[1].vault.db.custody.getTopItemIter())
        assert people[2].pre not in [member.qb64 for member in
                                    apps[1].hby.db.maids.get((update.said,))]
    finally:
        for page, parent in zip(pages, parents):
            if page.dialog:
                page.dialog.close()
            parent.close()


def test_group_reply_review_requires_exact_consent_and_finishes_at_two_signers(ipex_vaults, qapp):
    """A missing optional third-member route cannot become an all-member gate."""
    apps, people, groups = group_vaults(ipex_vaults)
    discloser = apps[0].hby.makeHab(name='discloser')
    for app in apps:
        app.vault.mbx.parser.parse(ims=discloser.replay(gvrsn=kering.Vrsn_2_0), local=False)
        app.vault.salts.service.trustRoster(groups[0].pre, [member.pre for member in people])
        app.vault.salts.service.trustRoster(discloser.pre, [discloser.pre])
    parents, pages = zip(*(page_for(app) for app in apps[:2]))
    try:
        pages[0].open_action('start')
        start = pages[0].dialog
        choose(start.local, groups[0].pre)
        choose(start.issuer, groups[0].pre)
        choose(start.discloser, discloser.pre)
        start.submit.click()
        body = start.body
        start.submit.click()
        for _ in range(4):
            apps[0].qtask.run()
        wrapper = deliver(apps[0], apps[1], '/multisig/rpy')
        pages[1].show_proposal(wrapper.said)
        refused = pages[1].dialog
        assert refused.body.raw == body.raw and refused.worker is None
        refused.close()
        assert apps[1].vault.salts.state.proof(body.said) is None
        assert not apps[1].vault.salts.state.hasPending(body.said, people[1].pre)
        pages[1].show_proposal(wrapper.said)
        review = pages[1].dialog
        review.submit.click()
        for _ in range(4):
            apps[1].qtask.run()
        deliver(apps[1], apps[0], '/multisig/rpy')
        for _ in range(64):
            for app in apps[:2]:
                app.qtask.run()
            if start.worker.done and review.worker.done:
                break
        assert start.worker.done and review.worker.done
        assert not start.worker.error and not review.worker.error
        assert all(app.vault.salts.state.proof(body.said) for app in apps[:2])
        assert review.worker.result['state'] == 'Statement authenticated'
        assert review.worker.result['transport'] == 'Peer submission remains pending'
        assert not apps[2].vault.salts.state.proof(body.said)
        rotation = people[0].rotate(version=kering.Vrsn_2_0, gvrsn=kering.Vrsn_2_0)
        apps[2].vault.mbx.parser.parse(ims=bytearray(rotation), local=False)
        assert apps[0].vault.salts.service.checkLive(body) is body
        with pytest.raises(kering.ValidationError, match='representative'):
            apps[2].vault.salts.service.receive(apps[0].vault.salts.state.proof(body.said))
        assert apps[2].vault.salts.state.proof(body.said) is None
    finally:
        for page, parent in zip(pages, parents):
            if page.dialog:
                page.dialog.close()
            parent.close()


@pytest.mark.real_routes
def test_one_peer_submission_finishes_without_waiting_for_other_group_members(ipex_vaults, qapp):
    """One real HTTP 204 beats an offline member and a missing optional route."""
    apps, people, groups = group_vaults(ipex_vaults)
    source = ipex_vaults('access-http-source', bran='0123456789abcdefghijk')
    issuer = source.hby.makeHab(name='issuer', algo='randy')
    for person in people:
        source.vault.mbx.parser.parse(ims=person.replay(gvrsn=kering.Vrsn_2_0), local=False)
    source.vault.mbx.parser.parse(ims=groups[0].replay(gvrsn=kering.Vrsn_2_0), local=False)
    source.vault.salts.service.trustRoster(groups[0].pre, [person.pre for person in people])
    for app in apps:
        app.vault.mbx.parser.parse(ims=issuer.replay(gvrsn=kering.Vrsn_2_0), local=False)
        app.vault.salts.service.trustRoster(issuer.pre, [issuer.pre])
        app.vault.salts.service.trustRoster(groups[0].pre, [person.pre for person in people])
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_PUT(self):
            received.append(self.rfile.read(int(self.headers['Content-Length'])))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            """Keep envelope diagnostics out of HTTP logs."""

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    parent, page = page_for(source)
    try:
        # The first member lacks a route; its readiness must not abort the
        # healthy second member or make the offline third an extra quorum.
        for person, port in ((people[1], server.server_port), (people[2], 1)):
            for frame in (person.makeLocScheme(url=f'http://127.0.0.1:{port}', scheme=kering.Schemes.http),
                          person.makeEndRole(eid=person.pre, role=kering.Roles.controller)):
                source.vault.mbx.parser.parse(ims=bytearray(frame), local=False)
        page.open_action('start')
        dialog = page.dialog
        choose(dialog.local, issuer.pre)
        choose(dialog.issuer, issuer.pre)
        choose(dialog.discloser, groups[0].pre)
        dialog.submit.click()
        body = dialog.body
        dialog.submit.click()
        start = monotonic()
        while not dialog.worker.done and monotonic() - start < 3:
            source.qtask.run()
            qapp.processEvents()
            sleep(.001)
        assert dialog.worker.done and not dialog.worker.error, dialog.worker.error
        assert received and monotonic() - start < 3
        assert dialog.worker.result['transport'] == 'Submitted to peer transport; remote acceptance unconfirmed'
        assert not dialog.worker.deeds
        assert all(not attempt.deeds for attempt in dialog.worker.children)
        assert apps[1].vault.salts.state.proof(body.said) is None
        for frame in received:
            apps[1].vault.mbx.parser.parse(ims=bytearray(frame), local=False)
        assert apps[1].vault.salts.state.proof(body.said)
        assert not list(apps[1].vault.db.saltPending.getTopItemIter())
    finally:
        page.dialog.close()
        parent.close()
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.real_routes
def test_failed_peer_submission_recovers_exact_signed_reply_without_refresh(ipex_vaults, qapp, monkeypatch):
    """A later route resumes saved authenticated bytes, never another DH or rpy signature."""
    source = ipex_vaults('resend-source', bran='0123456789abcdefghijk')
    target = ipex_vaults('resend-target', bran='0123456789abcdefghijk')
    issuer, peer = source.hby.makeHab(name='issuer', algo='randy'), target.hby.makeHab(name='peer', algo='randy')
    for app in (source, target):
        for person in (issuer, peer):
            app.vault.mbx.parser.parse(ims=person.replay(gvrsn=kering.Vrsn_2_0), local=False)
            app.vault.salts.service.trustRoster(person.pre, [person.pre])
    parent, page = page_for(source)
    try:
        page.open_action('start')
        start = page.dialog
        choose(start.local, issuer.pre)
        choose(start.issuer, issuer.pre)
        choose(start.discloser, peer.pre)
        start.submit.click()
        body = start.body
        start.submit.click()
        finish(source, qapp, start)
        assert start.worker.result['transport'] == 'Peer submission remains pending'
        saved = source.vault.salts.state.proof(body.said)
        pending = source.vault.db.saltPending.get((body.said, issuer.pre))
        original = issuer.endorse

        def only_outer(serder, *args, **kwa):
            assert serder.said != body.said, 'Recovery must not re-sign its authenticated reply'
            return original(serder, *args, **kwa)

        monkeypatch.setattr(issuer, 'endorse', only_outer)
        with capture_http() as (port, frames):
            for frame in (peer.makeLocScheme(url=f'http://127.0.0.1:{port}', scheme=kering.Schemes.http),
                          peer.makeEndRole(eid=peer.pre, role=kering.Roles.controller)):
                source.vault.mbx.parser.parse(ims=bytearray(frame), local=False)
            page.open_action('recover', dict(kind='statement', said=body.said, party=issuer.pre, body=body))
            recover = page.dialog
            recover.submit.click()
            assert recover.body.raw == body.raw and recover.worker is None
            recover.submit.click()
            for _ in range(1024):
                source.qtask.run()
                if recover.worker.done:
                    break
                sleep(.001)
            assert recover.worker.done and not recover.worker.error
            assert frames
            for frame in frames:
                target.vault.mbx.parser.parse(ims=bytearray(frame), local=False)
            assert target.vault.salts.state.proof(body.said) == saved
            assert source.vault.salts.state.proof(body.said) == saved
            assert source.vault.db.saltPending.get((body.said, issuer.pre)) == pending
            assert not target.vault.salts.state.origins()
    finally:
        page.dialog.close()
        parent.close()
