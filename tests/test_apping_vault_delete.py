from pathlib import Path
from types import SimpleNamespace

from keri.app.configing import Configer

from locksmith.core.apping import LocksmithApplication


class FakeCloser:
    def __init__(self, name: str, calls: list[tuple]):
        self._name = name
        self._calls = calls

    def close(self, clear: bool = False):
        self._calls.append((self._name, clear))


class FakeQTask:
    def __init__(self, calls: list[tuple]):
        self._calls = calls

    def shutdown(self):
        self._calls.append(("qtask.shutdown",))

    def cleanup(self):
        self._calls.append(("qtask.cleanup",))


class FakeHabery(FakeCloser):
    def __init__(self, name: str, calls: list[tuple], *, cf=None):
        super().__init__(name, calls)
        self.name = name
        self.cf = cf


def _make_app(plugin_manager, calls=None):
    app = LocksmithApplication(
        config=SimpleNamespace(
            protected_url="",
            api_aid="",
            unprotected_url="",
        )
    )
    app.plugin_manager = plugin_manager

    calls = calls if calls is not None else []
    vault = SimpleNamespace(
        db=FakeCloser("vault.db", calls),
        roots=FakeCloser("vault.roots", calls),
        rep=SimpleNamespace(mbx=FakeCloser("vault.rep.mbx", calls)),
        notifier=SimpleNamespace(noter=FakeCloser("vault.notifier.noter", calls)),
        hby=SimpleNamespace(name="test-vault"),
    )
    hby = FakeHabery("hby", calls, cf=FakeCloser("hby.cf", calls))

    app.name = "test-vault"
    app.vault = vault
    app.hby = hby
    app.rgy = SimpleNamespace(baser=FakeCloser("rgy.baser", calls))
    app.qtask = FakeQTask(calls)
    return app, calls


def test_delete_vault_prepares_plugins_before_local_clear():
    timeline: list[tuple] = []

    class PluginManager:
        def prepare_vault_deletion(self, vault):
            timeline.append(("prepare", vault))

        def on_vault_closed(self, vault, *, clear=False):
            timeline.append(("plugin_close", vault, clear))

    app, calls = _make_app(PluginManager(), calls=timeline)
    original_vault = app.vault

    success = app.delete_vault("test-vault")

    assert success is True
    assert timeline[0] == ("prepare", original_vault)
    assert timeline[1:4] == [("vault.roots", False), ("qtask.shutdown",), ("qtask.cleanup",)]
    assert timeline[4] == ("plugin_close", original_vault, True)
    assert ("vault.db", True) in timeline
    assert ("vault.rep.mbx", True) in timeline
    assert ("vault.notifier.noter", True) in timeline
    assert ("rgy.baser", True) in timeline
    assert timeline.index(("rgy.baser", True)) < timeline.index(("hby", True))
    assert ("hby.cf", True) in timeline
    assert ("hby", True) in timeline
    assert app.vault is None
    assert app.hby is None
    assert app.qtask is None


def test_delete_vault_aborts_when_plugin_prepare_fails():
    events: list[tuple] = []

    class PluginManager:
        def prepare_vault_deletion(self, vault):
            events.append(("prepare", vault))
            raise RuntimeError("boom")

        def on_vault_closed(self, vault, *, clear=False):
            events.append(("plugin_close", vault, clear))

    app, calls = _make_app(PluginManager())
    original_vault = app.vault
    original_hby = app.hby

    success = app.delete_vault("test-vault")

    assert success is False
    assert events == [("prepare", original_vault)]
    assert calls == []
    assert app.vault is original_vault
    assert app.hby is original_hby
    assert app.qtask is not None


def test_delete_vault_clears_habery_config_file(tmp_path):
    calls: list[tuple] = []
    cf = Configer(name="test-vault", base="", headDirPath=str(tmp_path), reopen=True)
    cf_path = Path(cf.path)

    class PluginManager:
        def prepare_vault_deletion(self, vault):
            calls.append(("prepare", vault))

        def on_vault_closed(self, vault, *, clear=False):
            calls.append(("plugin_close", vault, clear))

    app, _ = _make_app(PluginManager(), calls=calls)
    app.hby = FakeHabery("hby", calls, cf=cf)

    success = app.delete_vault("test-vault")

    assert success is True
    assert not cf_path.exists()
