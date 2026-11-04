# -*- encoding: utf-8 -*-
"""
locksmith.ui.vault.credentials.received.list module

Received credentials list content page (displayed within VaultPage container).
"""
from typing import Dict, Any, TYPE_CHECKING

from PySide6.QtWidgets import QVBoxLayout, QSizePolicy
from keri import help
from keri.help import helping

from locksmith.core import credentialing
from locksmith.ui.toolkit.tables import PaginatedTableWidget
from locksmith.ui.vault.shared.base_list_page import BaseListPage
from locksmith.ui.vault.credentials.received.accept import AcceptCredentialDialog
from locksmith.ui.vault.credentials.received.delete import DeleteReceivedCredentialDialog

if TYPE_CHECKING:
    from locksmith.ui.vault.page import VaultPage

logger = help.ogler.getLogger(__name__)


class ReceivedCredentialsListPage(BaseListPage):
    """
    Received credentials list content page.

    This is a content-only page that displays within the VaultPage container.
    The VaultPage manages the navigation menu.
    """

    def __init__(self, parent: "VaultPage" = None):
        """
        Initialize the ReceivedCredentialsListPage.

        Args:
            parent: Parent widget (VaultPage container)
        """
        super().__init__(parent)

        self.vault_name = None
        self.parent = parent
        self.app = self.parent.app

        # Ensure widget fills parent
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        # Create main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Set background using palette instead of stylesheet for better control
        from PySide6.QtGui import QPalette, QColor
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor("#F8F9FF"))
        self.setPalette(palette)
        self.setAutoFillBackground(True)

        # Create table widget
        self.icon_path = ":/assets/material-icons/in-badge.svg"
        self.table = PaginatedTableWidget(
            columns=["Schema", "Recipient", "Status", "Received Date", "Actions"],
            column_widths={"Schema": 220, "Status": 120, "Received Date": 165, "Actions": 50},
            title="Received Credentials",
            icon_path=self.icon_path,
            items_per_page=10,
            show_search=True,
            show_add_button=True,
            add_button_text="Accept Credential Issuance",
            row_actions=["View", "Delete", "Export"],
            row_action_icons={
                "View": ":/assets/material-icons/view.svg",
                "Delete": ":/assets/material-icons/delete.svg",
                "Export": ":/assets/material-icons/export.svg"
            }
        )

        # Connect signals
        self.table.search_changed.connect(self._on_search)
        self.table.page_changed.connect(self._on_page_changed)
        self.table.sort_changed.connect(self._on_sort_changed)
        self.table.add_clicked.connect(self._on_accept_credential)
        self.table.row_action_triggered.connect(self._on_row_action)
        self.table.row_clicked.connect(self._on_row_clicked)

        main_layout.addWidget(self.table)

        logger.info("ReceivedCredentialsListPage initialized with table widget")

    def _load_received_credentials_data(self):
        """
        Load received credentials data from the opened vault.

        This method is called after a vault is opened and hby is available.
        """
        try:
            received_credentials_data = []
            creds = credentialing.credentials(self.app.vault, received=True)

            for credential in creds:
                sad = credential['sad']
                schemer = credential.get("schema") or {}
                status = credential.get("status", {})

                recp = credential['recipient']
                recipient_hab = self.app.vault.hby.habByPre(recp) if recp else None
                recipient_name = f'Unknown ({recp})' if recp else 'Not specified'
                if recipient_hab is not None:
                    recipient_name = f'{recipient_hab.name} ({recp})'

                # Determine status text based on event type
                status_text = {
                    'issued': 'Received / Active',
                    'revoked': 'Received / Revoked',
                    'pending': 'Pending verification',
                    'unknown': 'Unknown state',
                }.get(status['et'], 'Unknown state')

                dt = helping.fromIso8601(status['dt']) if status.get('dt') else None

                cred_dict = {
                    "Schema": schemer.get("title", ""),
                    "Recipient": recipient_name,
                    "Status": status_text,
                    "Received Date": dt.strftime("%b %d, %Y %I:%M %p") if dt else "Unknown",
                    "SAID": sad['d']  # Store SAID for view operation
                }
                received_credentials_data.append(cred_dict)

            self.table.set_static_data(received_credentials_data)
            logger.info(f"Loaded {len(received_credentials_data)} received credentials")
        except Exception as e:
            logger.exception(f"Error loading received credentials data: {e}")
            self.table.set_static_data([])

    def _on_accept_credential(self):
        """Handle accept credential button click."""
        logger.info("Accept credential clicked")
        dialog = AcceptCredentialDialog(app=self.app, parent=self.parent)
        dialog.open()

    def _on_row_action(self, row_data: Dict[str, Any], action: str):
        """Handle row action from skewer menu."""
        credential_schema = row_data.get('Schema', 'Unknown')
        credential_issuer = row_data.get('Issuer', 'Unknown')
        credential_said = row_data.get('SAID', '')
        logger.info(f"Row action '{action}' triggered for: {credential_schema} <- {credential_issuer}")

        if action == "View":
            # TODO: Open view credential dialog
            logger.info(f"View received credential: {credential_schema} (SAID: {credential_said})")
        elif action == "Delete":
            # Open delete confirmation dialog
            dialog = DeleteReceivedCredentialDialog(
                schema_name=credential_schema,
                said=credential_said,
                icon_path=self.icon_path,
                app=self.app,
                parent=self.parent
            )
            dialog.open()
        elif action == "Export":
            # TODO: Export credential
            logger.info(f"Export received credential: {credential_schema} (SAID: {credential_said})")
        else:
            logger.info(f"Action '{action}' not yet implemented")

    def set_vault_name(self, vault_name: str):
        """
        Set the vault name for this page and load credentials data.

        This is called by VaultPage.on_show() after a vault is opened,
        ensuring that self.app.vault.hby is available.

        Args:
            vault_name: Name of the open vault
        """
        self.vault_name = vault_name

        # Now that the vault is open and hby is available, load the data
        if self.app.vault and self.app.vault.hby:
            self._load_received_credentials_data()

            # Connect to vault signal bridge for automatic list updates
            if hasattr(self.app.vault, 'signals'):
                self.app.vault.signals.doer_event.connect(self._on_doer_event)
                logger.info("ReceivedCredentialsListPage: Connected to vault signal bridge")
        else:
            logger.warning(f"Cannot load received credentials data - vault or hby not available")

    def _on_doer_event(self, doer_name: str, event_type: str, data: dict):
        """
        Handle doer events from the signal bridge.

        Args:
            doer_name: Name of the doer that emitted the event
            event_type: Type of event
            data: Event data dictionary
        """
        logger.debug(f"ReceivedCredentialsListPage received doer_event: {doer_name} - {event_type}")

        # Refresh list when a credential is received
        if doer_name == "ReceiveCredentialDoer" and event_type == "credential_received":
            logger.info(f"Credential received: {data.get('schema')}, refreshing list")
            self._load_received_credentials_data()

        # Refresh list when a credential is deleted
        elif doer_name == "DeleteReceivedCredential" and event_type == "credential_deleted":
            logger.info(f"Received credential deleted: {data.get('schema')}, refreshing list")
            self._load_received_credentials_data()

        elif doer_name == "Ipex" and event_type in ("accepted", "transport_submitted", "send_failed"):
            self._load_received_credentials_data()
