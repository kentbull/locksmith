"""Explicit real local DH setup for optional registry-root adapter tests."""

from keri.acdc import Registrar


def establish(vault, issuer, discloser):
    """Create/accept a registry and explicitly approve both parties' exact replies."""
    registry = Registrar(rgy=vault.rgy).makeRegistry(name='established', prefix=issuer.pre)
    rip = vault.rgy.store.event(registry.regk)
    issuer.interact(data=[dict(i=registry.regk, s=rip.sad['n'], d=rip.said)])
    assert registry.anchorMsg(rip.said)
    service = vault.salts.service
    for hab in (issuer, discloser):
        service.trustRoster(hab.pre, [hab.pre])
    init = service.prepareInit(issuer=issuer.pre, discloser=discloser.pre,
                              party=issuer.pre, representative=issuer.pre)
    service.approveReply(init)
    bind = service.prepareBind(init.said, registry.regk, discloser.pre)
    service.approveReply(bind)
    confirm = service.prepareConfirm(init.said, bind.said)
    service.approveReply(confirm)
    assert vault.salts.state.origin(registry.regk).confirm == confirm.said
    return registry
