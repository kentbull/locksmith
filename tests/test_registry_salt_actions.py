"""Passive action composition reuses real accepted KEL/TEL/reply processors."""

from keri.acdc import acdcmap
from keri.core import Encrypter

from locksmith.core import registry_authoring
from locksmith.core.salt_actions import SaltActions
from salt_helpers import establish
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
    assert app.vault.salts.service.rvy is app.vault.rvy
