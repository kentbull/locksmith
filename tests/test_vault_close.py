"""Vault close is one sequence: a failing scheduler exit cannot keep stores open."""
from test_keri_v2_compat import ipex_vaults as ipex_vaults


def test_close_vault_closes_stores_when_a_doer_exit_fails(ipex_vaults, monkeypatch):
    app = ipex_vaults('failing-exit')
    vault = app.vault
    for _ in range(3):
        app.qtask.run()

    def fail():
        raise RuntimeError('doer exit failed')

    monkeypatch.setattr(vault.toast_doer, 'exit', fail)
    app.close_vault()  # Logs the failed exit instead of aborting the close sequence.
    assert vault.closed
    assert not vault.db.opened and not vault.hby.db.opened
    assert not vault.rep.mbx.opened and not vault.notifier.noter.opened
    assert app.vault is None and app.qtask is None and app.hby is None and app.rgy is None


def test_root_import_consent_closes_with_the_session_not_on_child_removal(ipex_vaults, monkeypatch):
    """Vault has no exit override, so HIO's remove() is not a session close."""
    app = ipex_vaults('child-removal')
    vault = app.vault
    closed = []
    monkeypatch.setattr(vault.root_copies, 'close', lambda: closed.append(True))
    vault.remove([vault.toast_doer])
    assert not closed and vault.toast_doer not in vault.doers
    app.close_vault()
    assert closed == [True] and not vault.db.opened
