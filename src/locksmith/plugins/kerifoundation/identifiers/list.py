# -*- encoding: utf-8 -*-
"""
locksmith.plugins.kerifoundation.identifiers.list module

Plugin-local identifier list used to choose which local AID should receive
hosted witnesses.
"""
from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget
from keri import help

from locksmith.plugins.kerifoundation.core.identifiers import iter_local_identifier_choices
from locksmith.ui.toolkit.tables.paginated import PaginatedTableWidget
from locksmith.ui.toolkit.widgets import (
    FloatingLabelComboBox,
    LocksmithButton,
    LocksmithDialog,
    LocksmithInvertedButton,
)

logger = help.ogler.getLogger(__name__)


def _shrink_empty_state_title(table: PaginatedTableWidget, font_size: int = 20):
    target_text = f"NO {table.title.upper()}"
    for label in table.empty_state.findChildren(QLabel):
        if label.text() != target_text:
            continue
        label.setStyleSheet(
            label.styleSheet().replace("font-size: 24px;", f"font-size: {font_size}px;")
        )
        break


class IdentifierListPage(QWidget):
    add_witnesses_requested = Signal(str)

    def __init__(self, app=None, parent=None, *, provider_name="KERI Foundation", allow_provisioning=True):
        super().__init__(parent)
        self._app = app
        self._db = None
        self._provider_name = provider_name
        self._allow_provisioning = allow_provisioning
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._setup_ui()

    def set_db(self, db):
        self._db = db
        if db is None:
            self._table.set_static_data([])

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._table = PaginatedTableWidget(
            columns=["Alias", "Prefix", "Seq No.", "Witnesses"],
            title=f"{self._provider_name} Identifiers",
            icon_path=":/assets/custom/identifiers.png",
            show_search=True,
            show_add_button=True,
            add_button_text="Add Identifier",
            items_per_page=10,
            row_actions=["Add Witnesses"] if self._allow_provisioning else [],
            row_action_icons={"Add Witnesses": ":/assets/material-icons/witness1.svg"},
            monospace_columns=["Prefix"],
        )
        _shrink_empty_state_title(self._table)
        self._table.add_clicked.connect(self._on_add_identifier_clicked)
        self._table.row_action_triggered.connect(self._on_row_action)
        layout.addWidget(self._table)

    def on_show(self):
        self._table.set_static_data(self._build_rows())

    def _build_rows(self):
        if not self._app or not getattr(self._app, "vault", None) or self._db is None:
            return []

        rows = []
        hby = self._app.vault.hby
        for prefix in self._db.list_attached_identifier_prefixes():
            hab = hby.habByPre(prefix)
            if hab is None:
                continue
            rows.append(
                {
                    "Alias": hab.name,
                    "Prefix": prefix,
                    "Seq No.": hab.kever.sn if hab and hab.kever else "N/A",
                    "Witnesses": len(hab.kever.wits) if hab and hab.kever else "N/A",
                }
            )

        return rows

    def _available_identifier_choices(self):
        if not self._app or self._db is None:
            return []

        return [
            (alias, prefix)
            for alias, prefix in iter_local_identifier_choices(self._app)
            if not self._db.is_identifier_attached(prefix)
        ]

    def _choose_identifier_prefix(self) -> str:
        choices = self._available_identifier_choices()
        if not choices:
            logger.info("No additional local identifiers available for the KF provider")
            return ""

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 8, 0, 0)
        content_layout.setSpacing(16)

        selector = FloatingLabelComboBox("Local Identifier")
        selector.setFixedWidth(360)
        selector.addItem("Select an identifier...")
        for alias, prefix in choices:
            selector.addItem(f"{alias} - {prefix}", prefix)
        content_layout.addWidget(selector)

        button_row = QHBoxLayout()
        button_row.addStretch()

        cancel_button = LocksmithInvertedButton("Cancel")
        add_button = LocksmithButton("Add Identifier")
        button_row.addWidget(cancel_button)
        button_row.addWidget(add_button)

        dialog = LocksmithDialog(
            parent=self,
            title="Add Identifier",
            title_icon=":/assets/custom/identifiers.png",
            content=content,
            buttons=button_row,
        )
        dialog.setFixedWidth(420)
        cancel_button.clicked.connect(dialog.reject)
        add_button.clicked.connect(
            lambda: dialog.accept() if selector.currentIndex() > 0 else None
        )

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return ""

        return selector.currentData() or ""

    def _on_add_identifier_clicked(self):
        if self._db is None:
            return

        prefix = self._choose_identifier_prefix()
        if not prefix:
            return

        self._db.attach_identifier(prefix)
        self._table.set_static_data(self._build_rows())

    def _on_row_action(self, row_data, action):
        if action != "Add Witnesses":
            return

        self.add_witnesses_requested.emit(row_data["Prefix"])
