"""Group identifier consent uses retained v2 KERI events and real mailboxes."""
from contextlib import ExitStack
from time import monotonic, sleep
import socket

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QLabel, QWidget
from hio.base import doing
from hio.core import http
from keri import Vrsn_2_0 as V2
from keri import kering
from keri.app import habbing, indirecting, storing
from keri.core import Number, Prefixer, SerderACDC
from keri.db import openLMDB

from locksmith.core.grouping import (CounselingCompletionDoer, get_pending_multisig_proposals, inception_proposal,
                                     pending_registry_proposals, registry_proposal)
from locksmith.ui.vault.credentials.activity import CredentialActivityPage
from locksmith.ui.vault.credentials.issued.issue import IssueCredentialDialog
from locksmith.ui.vault.credentials.schema.add import AddSchemaDialog
from locksmith.ui.vault.groups.create import CreateGroupIdentifierDialog
from locksmith.ui.vault.groups.accept_multisig import AcceptMultisigProposalDialog
from test_keri_v2_compat import _deliver_ipex, ipex_vaults as ipex_vaults
from test_credential_ui import schema


@pytest.mark.real_routes
def test_create_join_v2_group_preserves_inception_and_reopens(ipex_vaults, qapp, tmp_path):
    """Two encrypted member stores explicitly contribute over witnessed mailboxes."""
    names = ('group-ui-one', 'group-ui-two')
    passcode = '0123456789abcdefghijk'
    apps = [ipex_vaults(name, bran=passcode, registry_services=True) for name in names]
    # The stores share a deterministic test salt; distinct stems give independent members.
    members = [app.hby.makeHab(f'member-{index}', version=V2) for index, app in enumerate(apps)]
    assert len({member.pre for member in members}) == 2
    failures = []
    for app in apps:
        app.vault.signals.doer_event.connect(
            lambda doer, event, data: failures.append(data) if event.endswith('_failed') else None)
    with ExitStack() as owned:
        witnesses, doers = [], []
        for index in range(3):
            hby, witness = owned.enter_context(habbing.openHab(name=f'group-mailbox-{index}',
                temp=True, transferable=False, version=V2))
            mail = owned.enter_context(openLMDB(cls=storing.Mailboxer,
                name=f'group-mailbox-{index}', temp=True))
            with socket.socket() as reserve:
                reserve.bind(('127.0.0.1', 0))
                port = reserve.getsockname()[1]
            children = indirecting.setupWitness(hby, alias=witness.name, mbx=mail,
                tcpPort=None, httpPort=port, version=V2)
            server = next(child.server for child in children if isinstance(child, http.ServerDoer))
            server.servant.eha = server.servant.ha
            url = f'http://127.0.0.1:{server.servant.ha[1]}'
            route = witness.replay(gvrsn=V2) + witness.makeLocScheme(url=url, scheme='http', gvrsn=V2)
            for app in apps:
                _deliver_ipex(app.vault, route)
            for member in members:
                hby.psr.parse(ims=bytearray(member.replay(gvrsn=V2)), local=False)
            witnesses.append(witness)
            doers.extend(children)
        scheduler = doing.Doist(doers=doers, tock=.03125)
        scheduler.enter()
        owned.callback(scheduler.exit)

        def pump(until):
            cutoff = monotonic() + 20
            while not until() and monotonic() < cutoff:
                scheduler.recur()
                for app in apps:
                    app.qtask.run()
                qapp.processEvents()
                assert not failures, failures
                sleep(.005)
            assert until(), 'Group UI operation did not complete'

        # Member KELs acquire actual HTTP receipts; signed witness locations reach both stores.
        for app, member in zip(apps, members):
            member.rotate(adds=[witness.pre for witness in witnesses], toad=2, version=V2, gvrsn=V2)
            app.vault.receiptor.msgs.append(dict(pre=member.pre, sn=member.kever.sn))
        pump(lambda: all(app.hby.db.fullyWitnessed(member.kever.serder)
                         for app, member in zip(apps, members)))
        for source, member in zip(apps, members):
            target = apps[1] if source is apps[0] else apps[0]
            _deliver_ipex(target.vault, member.replay(gvrsn=V2))
            target.vault.org.update(member.pre, {'alias': member.name})
        one, two = apps
        parent = QWidget()
        create = CreateGroupIdentifierDialog(':/assets/material-icons/group_add.svg', one, parent)
        create.open()
        create.name_field.setText('group')
        create.signing_threshold_field.setText('2')
        create.rotation_threshold_field.setText('2')
        create.establishment_only_checkbox.setChecked(True)
        create.do_not_delegate_checkbox.setChecked(True)
        create.participants_selector.selector_dropdown.setCurrentIndex(0)
        assert create.create_button.isEnabled()
        QTest.mouseClick(create.create_button, Qt.MouseButton.LeftButton)
        pump(lambda: bool(get_pending_multisig_proposals(two)))
        proposal, = get_pending_multisig_proposals(two)
        _, event = inception_proposal(two.vault, proposal['said'])
        gid, original = event.pre, event.raw
        assert event.traits == [kering.TraitDex.EstOnly, kering.TraitDex.DoNotDelegate]
        assert gid not in one.hby.kevers and gid not in two.hby.kevers
        assert two.hby.habByName('group') is None

        # Join signs the exact authenticated child; ordinary upstream thresholds complete both stores.
        join = AcceptMultisigProposalDialog(two, parent, proposal['said'])
        assert not getattr(join, 'proposal_error', None)
        join.open()
        details = {}
        layout = join.content_layout.itemAt(0).widget().widget().layout()
        for index in range(layout.count()):
            row = layout.itemAt(index).layout()
            if row and row.count() == 2 and isinstance(row.itemAt(0).widget(), QLabel):
                details[row.itemAt(0).widget().text()] = row.itemAt(1).widget().text()
        assert details['Signing Threshold:'] == details['Rotation Threshold:'] == '2'
        assert details['Rotation Members:'] == 'Same as signing members'
        assert details['Witnesses:'] == 'None' and details['Witness Threshold:'] == '0'
        assert details['Traits:'] == 'Establishment Only, Do Not Delegate'
        join.group_identifier_alias.setText('group')
        QTest.mouseClick(join.accept_button, Qt.MouseButton.LeftButton)
        pump(lambda: all(app.vault.counselor.complete(Prefixer(qb64=gid), Number(num=0))
                         for app in apps))
        for app in apps:
            group = app.hby.habByName('group')
            assert group.kever.serder.raw == original and group.kever.tholder.sith == '2'
            assert not group.kever.wits  # Member mailboxes are witnessed; this group is unwitnessed.
            assert app.hby.ks.gbls.get('aeid')
        create.close()
        join.close()
        for app in apps:
            app.close_vault()
        apps[:] = [ipex_vaults(name, bran=passcode, registry_services=True) for name in names]
        for app, member in zip(apps, members):
            group = app.hby.habByName('group')
            assert group.pre == gid and group.mhab.pre == member.pre
            assert group.kever.serder.raw == original

        # EO group anchors use member keys that were independently rotated and witnessed first.
        one, two = apps
        members = [app.hby.habByName(f'member-{index}') for index, app in enumerate(apps)]
        issuance = []
        for app in apps:
            app.vault.signals.doer_event.connect(
                lambda name, event, data: failures.append(data) if event.endswith('_failed') else None)
        two.vault.signals.doer_event.connect(
            lambda name, event, data: issuance.append((event, data)) if name == 'IssueCredentialDoer' else None)

        def rotate_members():
            for app, member in zip(apps, members):
                member.rotate(version=V2, gvrsn=V2)
                app.vault.receiptor.msgs.append(dict(pre=member.pre, sn=member.kever.sn))
            pump(lambda: all(app.hby.db.fullyWitnessed(member.kever.serder)
                             for app, member in zip(apps, members)))
            for index, member in enumerate(members):
                _deliver_ipex(apps[1 - index].vault, member.replay(gvrsn=V2))

        rotate_members()
        # Actual schema selection makes member 1 the issuer; member 0 remains the elected witnesser.
        schemer = schema()
        source = tmp_path / 'group-schema.json'
        source.write_bytes(schemer.raw)
        load = AddSchemaDialog(two)
        load.open()
        load.file_radio.setChecked(True)
        load.file_path_field.setText(str(source))
        load.enable_issuance_checkbox.setChecked(True)
        load.issuer_dropdown.setCurrentIndex(next(index for index in range(load.issuer_dropdown.count())
                                                if load.issuer_dropdown.itemData(index) == gid))
        QTest.mouseClick(load.load_button, Qt.MouseButton.LeftButton)
        pump(lambda: two.vault.db.issuers.get((schemer.said,)) == gid)
        load.close()
        parent.app = one
        page = CredentialActivityPage(parent)
        page.set_vault_name(one.name)
        page.show()
        issue = IssueCredentialDialog(two, parent)
        issue.open()
        issue.schema_dropdown.setCurrentIndex(next(index for index in range(issue.schema_dropdown.count())
                                                  if issue.schema_dropdown.itemData(index) == schemer.said))
        issue.recipient_dropdown.setCurrentIndex(next(index for index in range(issue.recipient_dropdown.count())
                                                     if issue.recipient_dropdown.itemData(index) == members[0].pre))
        issue._dynamic_field_widgets['nickname']['widget'].setText('Group credential')
        publication = issue.state_options.mode.combo_box
        publication.setCurrentIndex(publication.findData('public'))
        QTest.mouseClick(issue.issue_button, Qt.MouseButton.LeftButton)

        accepted = []
        stale = None
        for ordinal, route in enumerate(('/multisig/rip', '/multisig/bup')):
            pump(lambda: any(proposal.route == route for proposal in pending_registry_proposals(one.vault)))
            proposal, = [proposal for proposal in pending_registry_proposals(one.vault) if proposal.route == route]
            _, children, group = registry_proposal(one.vault, proposal.said)
            tel, anchor = [child.serder for child in children]
            regid = tel.said if ordinal == 0 else tel.sad['rd']
            assert proposal.pre == members[1].pre and group.mhab.pre == members[0].pre
            assert anchor.ilk == 'rot' and anchor.sn == ordinal + 1
            assert not one.hby.db.sigs.get((gid, anchor.said))
            assert all(app.vault.rgy.store.seqEvent(regid, ordinal) is None for app in apps)
            assert not any(event == 'credential_issued' for event, _ in issuance)

            # Receipt and closing a review do not contribute a signature or accept a TEL event.
            QTest.mouseClick(page.table.header.add_button, Qt.MouseButton.LeftButton)
            QTest.mouseClick(page.group_registry_buttons[proposal.said], Qt.MouseButton.LeftButton)
            review = page._response_dialog
            assert tel.said in review.summary.text() and anchor.said in review.summary.text()
            review.close()
            assert not one.hby.db.sigs.get((gid, anchor.said))
            if ordinal == 0:
                stale = review
                rotate_members()  # Prepare the next committed keys before RIP approval releases the BUP.
            else:
                # The old RIP review cannot sign again once the group has accepted a newer parent.
                before = [siger.qb64 for siger in one.hby.db.sigs.get((gid, accepted[0][1].said))]
                stale.open()
                QTest.mouseClick(stale.approve, Qt.MouseButton.LeftButton)
                assert stale.error.text()
                assert [siger.qb64 for siger in one.hby.db.sigs.get((gid, accepted[0][1].said))] == before
                stale.close()
                assert all(app.vault.rgy.store.headEvent(regid).said == accepted[0][0].said for app in apps)

            QTest.mouseClick(page.group_registry_buttons[proposal.said], Qt.MouseButton.LeftButton)
            review = page._response_dialog
            QTest.mouseClick(review.approve, Qt.MouseButton.LeftButton)
            pump(lambda: all((event := app.vault.rgy.store.seqEvent(regid, ordinal)) is not None
                             and event.said == tel.said for app in apps))
            assert one.hby.habByName('group').witnesser(sn=anchor.sn, dig=anchor.said)
            assert not two.hby.habByName('group').witnesser(sn=anchor.sn, dig=anchor.said)
            accepted.append((tel, anchor))
            review.close()

        pump(lambda: any(event == 'credential_issued' for event, _ in issuance))
        ((_,), record), = two.vault.db.issued.getTopItemIter()
        credential = SerderACDC(raw=record.raw.encode())
        assert credential.sad['i'] == gid and credential.regid == regid
        for app in apps:
            for tel, anchor in accepted:
                assert app.vault.rgy.store.seqEvent(regid, Number(numh=tel.sad['n']).num).raw == tel.raw
                assert app.hby.db.evts.get((gid, anchor.said)).raw == anchor.raw
                assert app.vault.rgy.store.anchor(tel.said)[1].qb64 == anchor.said
            assert app.hby.db.evts.get((gid, gid)).raw == original
        issue.close()
        page.close()


def _stale_rotation(ipex_vaults):
    """An accepted group rotation adding Carol whose members were never committed."""
    from test_root_replicating import _rotated_group
    w = _rotated_group(ipex_vaults)
    group = w.alice.hby.habs[w.gid]
    rotation = w.alice.hby.db.evts.get(keys=(w.gid, w.rotation))
    assert w.ch.pre not in group.smids
    assert w.ch.pre not in w.alice.hby.db.habs.get(keys=(w.gid,)).smids
    return w, group, rotation, [w.ah.pre, w.bh.pre, w.ch.pre]


def test_accepted_rotation_members_commit_when_the_vault_reopens(ipex_vaults):
    w, group, rotation, members = _stale_rotation(ipex_vaults)
    # The wallet closed after acceptance and before the live loop committed members.
    w.alice.close_vault()

    alice = ipex_vaults('roots-alice', bran='0123456789abcdefghijk')
    group = alice.hby.habs[w.gid]
    assert group.smids == members and group.rmids == members
    assert alice.hby.db.habs.get(keys=(w.gid,)).smids == members
    assert w.ch.pre in alice.hby.db.signingMembers(pre=w.gid)


def test_counseling_completion_commits_members_accepted_after_reopen(ipex_vaults, monkeypatch):
    w, group, rotation, members = _stale_rotation(ipex_vaults)
    app = w.alice
    monkeypatch.setattr(app.vault.counselor, 'complete', lambda prefixer, number, diger=None: True)
    doer = CounselingCompletionDoer(app.vault, Prefixer(qb64=w.gid), Number(sn=rotation.sn), group)
    app.vault.extend([doer])
    for _ in range(5):
        app.qtask.run()
    assert group.smids == members and group.rmids == members
    assert app.hby.db.habs.get(keys=(w.gid,)).rmids == members
