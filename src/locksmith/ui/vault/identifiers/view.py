# -*- encoding: utf-8 -*-
"""
locksmith.ui.vault.identifiers.view module

Dialog for viewing identifier details
"""
import asyncio

from PySide6.QtGui import QIcon
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QHBoxLayout
)
from keri import help

from locksmith.core import habbing
from locksmith.core.indirecting import receiving_endpoints
from locksmith.ui import colors
from locksmith.ui.toolkit.widgets import (
    LocksmithDialog,
    LocksmithInvertedButton
)
from locksmith.ui.vault.identifiers import mailbox
from locksmith.ui.vault.identifiers.identifier_sections import IdentifierViewSectionsMixin
from locksmith.ui.vault.shared.export import export_identifier_to_cesr

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
        self.vault = app.vault
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
        self.delegation_status = QLabel()
        self.delegation_status.setObjectName('delegation_status')
        self.delegation_status.setWordWrap(True)
        self.delegation_status.setStyleSheet(f"font-size: 13px; color: {colors.TEXT_DARK};")
        layout.addWidget(self.delegation_status)
        self._refresh_delegation()
        self.receiving_status = QLabel()
        self.receiving_status.setWordWrap(True)
        layout.addWidget(self.receiving_status)
        self.mailbox_button = LocksmithInvertedButton('Set up mailbox')
        self.mailbox_button.hide()
        layout.addWidget(self.mailbox_button)
        self._mailbox_task = None
        self._mailbox_message = ''
        self.share_button = LocksmithInvertedButton('Share introduction')
        layout.addWidget(self.share_button)

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
        self.share_button.clicked.connect(self._share_introduction)
        self.mailbox_button.clicked.connect(self._set_up_mailbox)
        self.status_timer = QTimer(self)
        self.status_timer.timeout.connect(self._refresh_receiving)
        self.status_timer.start(1000)
        self.finished.connect(self.status_timer.stop)
        self._refresh_receiving()

        # Connect to vault signal bridge if available
        if self.app and hasattr(self.app, 'vault') and self.app.vault and hasattr(self.app.vault, 'signals'):
            self.app.vault.signals.doer_event.connect(self._on_doer_event)
            logger.info("ViewIdentifierDialog: Connected to vault signal bridge")

    def _refresh_receiving(self):
        if self.app.vault is not self.vault or getattr(self.vault, 'closed', False):
            self.status_timer.stop()
            self.receiving_status.setText('Vault closed')
            self.share_button.setEnabled(False)
            return
        self._refresh_delegation()
        endpoints = receiving_endpoints(self.hab)
        pollers = [poller for poller in self.vault.mbx.pollers if poller.pre == self.hab.pre]
        errors = [poller.error for poller in pollers if poller.error]
        text = ('Receiving is not configured' if not endpoints else
                'Receiving needs attention: ' + errors[0] if errors else
                f'Receiving through {len(endpoints)} configured mailbox endpoint{"" if len(endpoints) == 1 else "s"}')
        working = self._mailbox_task is not None and not self._mailbox_task.done()
        found = mailbox.mailbox_provider(self.app, self.hab) if mailbox.needs_mailbox(self.hab) else None
        if mailbox.needs_mailbox(self.hab):
            text = self._mailbox_message or (text if found else mailbox.no_provider_text(self.app, self.hab))
        self.receiving_status.setText(text)
        self.mailbox_button.setVisible(found is not None)
        self.mailbox_button.setEnabled(not working)

    def _set_up_mailbox(self):
        """Ask the provider for this delegate's own mailbox."""
        found = mailbox.mailbox_provider(self.app, self.hab)
        if found is None or self._mailbox_task is not None and not self._mailbox_task.done():
            return
        self._mailbox_message = mailbox.working_text(self.hab, found[1])
        self._mailbox_task = asyncio.ensure_future(self._run_mailbox_setup(found[1]))
        self._refresh_receiving()

    async def _run_mailbox_setup(self, provider):
        try:
            await mailbox.set_up_mailbox(self.app, self.hab)
        except asyncio.CancelledError:
            raise
        except Exception as ex:
            logger.exception(f"Mailbox setup failed for {self.hab.name}")
            self._mailbox_message = mailbox.failed_text(self.hab, provider, ex)
        else:
            self._mailbox_message = ''
        if self.app.vault is self.vault and not getattr(self.vault, 'closed', False):
            self._refresh_receiving()

    def _refresh_delegation(self):
        """Show who delegated this identifier and where the approval is anchored."""
        status = habbing.delegation_status(self.app, self.hab)
        self.delegation_status.setVisible(status is not None)
        if status is not None:
            self.delegation_status.setText(status['text'])
            self.delegation_status.setToolTip(status['delegator'])

    def _share_introduction(self):
        if self.app.vault is self.vault and not getattr(self.vault, 'closed', False):
            export_identifier_to_cesr(self, self.app, self.identifier_alias)
