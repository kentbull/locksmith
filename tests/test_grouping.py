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
from keri.core import Number, Prefixer
from keri.db import openLMDB

from locksmith.core.grouping import get_pending_multisig_proposals, inception_proposal
from locksmith.ui.vault.groups.create import CreateGroupIdentifierDialog
from locksmith.ui.vault.groups.accept_multisig import AcceptMultisigProposalDialog
from test_keri_v2_compat import _deliver_ipex, ipex_vaults as ipex_vaults


@pytest.mark.real_routes
def test_create_join_v2_group_preserves_inception_and_reopens(ipex_vaults, qapp):
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
