# -*- encoding: utf-8 -*-
"""
locksmith.ui.vault.identifiers.view module

Dialog for viewing identifier details
"""
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QHBoxLayout
)
from keri import help

from locksmith.core import habbing
from locksmith.ui import colors
from locksmith.ui.toolkit.widgets import (
    LocksmithDialog,
    LocksmithInvertedButton
)
from locksmith.ui.vault.identifiers.identifier_sections import IdentifierViewSectionsMixin

logger = help.ogler.getLogger(__name__)


class ViewIdentifierDialog(IdentifierViewSectionsMixin, LocksmithDialog):
    """Dialog for viewing identifier details."""

    def __init__(self, icon_path, app, identifier_alias, parent=None):
        """
        Initialize the ViewIdentifierDialog.

        Args:
            icon_path: Path to the identifier icon
            app: Application instance
            identifier_alias: Alias of the identifier to view
            parent: Parent widget (typically VaultPage)
        """
        self.app = app
        self.identifier_alias = identifier_alias

        # Get the hab (identifier)
        try:
            self.hab = self.app.vault.hby.habByName(identifier_alias)
            if not self.hab:
                raise ValueError(f"Identifier '{identifier_alias}' not found")
        except Exception as e:
            logger.error(f"Error loading identifier: {e}")
            raise

        # Get identifier details
        self.details = habbing.get_identifier_details(self.app, self.hab)

        # Create content widget
        content_widget = QWidget()
        content_widget.setStyleSheet(f"background-color: {colors.BACKGROUND_CONTENT};")
        layout = QVBoxLayout(content_widget)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(15)

        # AID Section
        self._build_aid_section(layout)

        # Key Event Log Section
        self._build_kel_section(layout)

        # KEL Information Section (from mixin)
        self._build_kel_info_section(layout, self.details)

        # Resubmit Section (from mixin)
        self._build_resubmit_section(layout, self.details)

        # OOBI Section (if witnesses exist)
        if len(self.details['witnesses']) > 0:
            self._build_oobi_section(layout)

        # Refresh Key State Section (for group multisig)
        if self.details['is_group_multisig']:
            self._build_refresh_keystate_section(layout)

        layout.addStretch()

        # Create button row
        button_row = QHBoxLayout()
        self.close_button = LocksmithInvertedButton("Close")
        button_row.addWidget(self.close_button)

        # Create title content
        title_content_widget = QWidget()
        title_content = QHBoxLayout()
        icon = QIcon(icon_path)
        icon_label = QLabel()
        icon_label.setPixmap(icon.pixmap(32, 32))
        icon_label.setFixedSize(32, 32)
        title_content.addWidget(icon_label)

        title_label = QLabel(f"  {identifier_alias}")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        title_content.addWidget(title_label)
        title_content_widget.setLayout(title_content)

        # Initialize parent dialog
        super().__init__(
            parent=parent,
            title_content=title_content_widget,
            show_close_button=True,
            content=content_widget,
            buttons=button_row,
            show_overlay=False
        )

        # Set initial size
        self.setFixedSize(640, 940)

        # Connect buttons
        self.close_button.clicked.connect(self.close)

        # Connect to vault signal bridge if available
        if self.app and hasattr(self.app, 'vault') and self.app.vault and hasattr(self.app.vault, 'signals'):
            self.app.vault.signals.doer_event.connect(self._on_doer_event)
            logger.info("ViewIdentifierDialog: Connected to vault signal bridge")