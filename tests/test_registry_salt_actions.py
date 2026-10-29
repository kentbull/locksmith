"""Passive action composition reuses real accepted KEL/TEL/reply processors."""

from time import sleep

import pytest
from keri import kering
from keri.acdc import Registrar, acdcmap
from keri.core import Encrypter
from keri.peer.exchanging import serializeMessage

from locksmith.core import registry_authoring
from locksmith.core.salt_actions import SaltActions, SaltActionDoer
from salt_helpers import establish, capture_http, group_vaults
from test_keri_v2_compat import ipex_vaults as ipex_vaults


def test_public_dependencies_exclude_root_private_opening_and_inventory(ipex_vaults):
    """Only controller KEL and the exact rip accompany registry-access statements."""
    app = ipex_vaults('action-public-evidence', bran='0123456789abcdefghijk')
    issuer, peer = app.hby.makeHab(name='issuer'), app.hby.makeHab(name='discloser')
    registry = establish(app.vault, issuer, peer)
    acdc = acdcmap(israid=issuer.pre, regid=registry.regk, attribute={'d': '', 'value': 'private'})
    opening, update, _ = registry_authoring.stage(app.vault, registry, acdc, 'issued', 'derived')
    issuer.interact(data=[dict(s=update.sad['n'], d=update.said)])
    assert registry.anchorMsg(update.said)
    custody = app.vault.salts.custody
    verfer = issuer.kever.verfers[0]
    root = custody.openRoot(custody.sealRoot(registry.regk, Encrypter(verkey=verfer.qb64)), verfer)
    frames = SaltActions(app.vault).publicEvidence(registry.regk, issuer.pre)
    wire = b''.join(body.raw + atc for body, atc in frames)
    assert all(secret not in wire for secret in (root.raw, root.qb64b, opening.qb64b, update.raw, acdc.raw))
    assert [body.said for body, _ in frames if body.ilk == 'rip'] == [registry.regk]
    assert app.vault.mbx.parser is app.vault.salts.service.parser


@pytest.mark.real_routes
def test_group_bind_proposal_carries_public_rip_before_cosigner_review(ipex_vaults):
    """A real second signer lacking the rip can inspect and approve after fanout."""
    apps, people, groups = group_vaults(ipex_vaults)
    actions = [SaltActions(app.vault) for app in apps]
    registry = Registrar(rgy=apps[0].rgy).makeRegistry('group registry', groups[0].pre)
    rip = apps[0].rgy.store.event(registry.regk)
    first, atc = actions[0].registryApproval(groups[0].pre).approve(rip)
    apps[1].vault.mbx.parser.parse(ims=bytearray(first.raw + atc), local=False)
    event, anchor, opening = actions[1].inspect(first.said)
    second, atc = actions[1].registryApproval(groups[1].pre).approve(event, anchor, opening=opening)
    apps[0].vault.mbx.parser.parse(ims=bytearray(second.raw + atc), local=False)
    for _ in range(16):
        for app in apps[:2]:
            app.qtask.run()
    assert apps[0].rgy.store.seqEvent(registry.regk, 0) is not None
    assert apps[2].rgy.store.seqEvent(registry.regk, 0) is None
    peer = apps[0].hby.makeHab(name='discloser', algo='randy')
    for app in apps:
        app.vault.mbx.parser.parse(ims=peer.replay(gvrsn=kering.Vrsn_2_0), local=False)
        app.vault.salts.service.trustRoster(groups[0].pre, [person.pre for person in people])
        app.vault.salts.service.trustRoster(peer.pre, [peer.pre])
    init = actions[0].prepare('start', peer.pre, issuer=groups[0].pre, discloser=peer.pre)
    approved = actions[0].service.approveReply(init)
    actions[2].service.receive(approved.stream)
    bind = actions[0].prepare('bind', groups[0].pre, init=init.said, registry=registry.regk)
    with capture_http() as (port, frames):
        for frame in (people[2].makeLocScheme(url=f'http://127.0.0.1:{port}', scheme=kering.Schemes.http),
                      people[2].makeEndRole(eid=people[2].pre, role=kering.Roles.controller)):
            apps[0].vault.mbx.parser.parse(ims=bytearray(frame), local=False)
        worker = SaltActionDoer(apps[0].vault, bind)
        apps[0].vault.extend([worker])
        for _ in range(512):
            apps[0].qtask.run()
            if any(attempt.done and not attempt.error for attempt in worker.children):
                break
            sleep(.001)
        assert frames and not worker.done
        for frame in frames:
            apps[2].vault.mbx.parser.parse(ims=bytearray(frame), local=False)
        for _ in range(16):
            apps[2].qtask.run()
        accepted = apps[2].rgy.store.seqEvent(registry.regk, 0)
        assert accepted is not None and accepted.said == registry.regk
        proposal = next(body for _, body in apps[2].hby.db.exns.getTopItemIter()
                        if body.route == '/multisig/rpy')
        displayed, _, _ = actions[2].inspect(proposal.said)
        assert displayed.raw == bind.raw and actions[2].service.state.proof(bind.said) is None
        cosigner = SaltActionDoer(apps[2].vault, displayed, proposal=proposal.said)
        apps[2].vault.extend([cosigner])
        for _ in range(4):
            apps[2].qtask.run()
        outgoing = next(body for _, body in apps[2].hby.db.exns.getTopItemIter()
                        if body.route == '/multisig/rpy' and body.pre == people[2].pre)
        apps[0].vault.mbx.parser.parse(ims=serializeMessage(apps[2].hby, outgoing.said), local=False)
        for _ in range(64):
            for app in (apps[0], apps[2]):
                app.qtask.run()
            if worker.done and cosigner.done:
                break
        assert worker.done and cosigner.done and not worker.error and not cosigner.error
        assert actions[0].service.state.proof(bind.said) and actions[2].service.state.proof(bind.said)
        assert not actions[2].service.state.hasPending(init.said, people[2].pre)
