# -*- encoding: utf-8 -*-
"""
locksmith.ui.vault.credentials.issued.view module

Dialog for viewing issued credential details
"""
import json
import logging
from typing import TYPE_CHECKING

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QHBoxLayout
)
from locksmith.core import credentialing
from keri.help import helping

from locksmith.ui.toolkit.widgets import (
    LocksmithInvertedButton
)
from locksmith.ui.toolkit.widgets.buttons import LocksmithCopyButton
from locksmith.ui.toolkit.widgets.dialogs import LocksmithDialog
from locksmith.ui.toolkit.widgets.fields import (
    LocksmithLineEdit,
    LocksmithPlainTextEdit
)

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class ViewIssuedCredentialDialog(LocksmithDialog):
    """Dialog for viewing issued credential details."""
    def __init__(self, icon_path, app, credential_said, parent=None):
        """
        Initialize the ViewIssuedCredentialDialog.

        Args:
            icon_path: Path to the credential icon
            app: Application instance
            credential_said: SAID of the credential to view
            parent: Parent widget (typically VaultPage)
        """
        self.app = app
        self.credential_said = credential_said

        # Get the credential details from the app
        try:
            self.credential = credentialing.credential(self.app.vault, self.credential_said)

            # Get schema info
            self.schema_title = (self.credential.get("schema") or {}).get("title", "Unknown Schema")

        except Exception as e:
            logger.error(f"Error loading credential: {e}")
            raise

        # Create title content FIRST (before super().__init__)
        title_content_widget = QWidget()
        title_content = QHBoxLayout()
        icon = QIcon(icon_path)
        icon_label = QLabel()
        icon_label.setPixmap(icon.pixmap(32, 32))
        icon_label.setFixedSize(32, 32)
        title_content.addWidget(icon_label)

        title_label = QLabel(f"  {self.schema_title}")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        title_content.addWidget(title_label)
        title_content_widget.setLayout(title_content)

        # Create content widget
        content_widget = QWidget()
        content_widget.setStyleSheet("background-color: #F8F9FF;")
        layout = QVBoxLayout(content_widget)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(15)

        # Create button row
        button_row = QHBoxLayout()
        self.close_button = LocksmithInvertedButton("Close")
        button_row.addWidget(self.close_button)

        # Initialize parent dialog EARLY
        super().__init__(
            parent=parent,
            title_content=title_content_widget,
            show_close_button=True,
            content=content_widget,
            buttons=button_row,
            show_overlay=False
        )

        # Set initial size
        self.setFixedSize(520, 750)

        # NOW build sections (after super().__init__ has been called)
        # SAID Section
        self._build_said_section(layout)

        # Schema Section
        self._build_schema_section(layout)

        # Issuer Section
        self._build_issuer_section(layout)

        # Recipient Section
        self._build_recipient_section(layout)

        # Status Section
        self._build_status_section(layout)

        # Issued Date Section
        self._build_issued_date_section(layout)

        # Credential Content Section (JSON)
        self._build_credential_content_section(layout)

        layout.addStretch()

        # Connect buttons
        self.close_button.clicked.connect(self.close)

    def _build_said_section(self, layout):
        """Build the SAID section with copy button."""
        said_label_row = QHBoxLayout()
        said_label_row.setSpacing(5)
        said_label = QLabel("Credential SAID")
        said_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        said_label_row.addWidget(said_label)

        self.copy_said_button = LocksmithCopyButton(copy_content=self.credential_said)
        self.copy_said_button.setFixedHeight(36)
        said_label_row.addWidget(self.copy_said_button)
        said_label_row.addStretch()
        layout.addLayout(said_label_row)

        self.said_field = LocksmithLineEdit("Credential SAID")
        self.said_field.setText(self.credential_said)
        self.said_field.setReadOnly(True)
        self.said_field.setCursorPosition(0)
        self.said_field.setMinimumWidth(420)
        layout.addWidget(self.said_field)

    def _build_schema_section(self, layout):
        """Build the schema section."""
        schema_label = QLabel("Schema")
        schema_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(schema_label)

        self.schema_field = LocksmithLineEdit("Schema")
        self.schema_field.setText(self.schema_title)
        self.schema_field.setReadOnly(True)
        self.schema_field.setCursorPosition(0)
        self.schema_field.setMinimumWidth(420)
        layout.addWidget(self.schema_field)

    def _build_issuer_section(self, layout):
        """Build the issuer section."""
        issuer_label = QLabel("Issuer")
        issuer_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(issuer_label)

        # Get issuer prefix from credential
        issuer_pre = self.credential['sad']['i']

        # Try to find issuer name if it's a local identifier
        issuer_display = issuer_pre
        try:
            for hab_pre, hab in self.app.vault.hby.habs.items():
                if hab.pre == issuer_pre:
                    issuer_display = f"{hab.name} ({issuer_pre[:35]}...)"
                    break
        except:
            pass

        self.issuer_field = LocksmithLineEdit("Issuer")
        self.issuer_field.setText(issuer_display)
        self.issuer_field.setReadOnly(True)
        self.issuer_field.setCursorPosition(0)
        self.issuer_field.setMinimumWidth(420)
        layout.addWidget(self.issuer_field)

    def _build_recipient_section(self, layout):
        """Build the recipient section."""
        recipient_label = QLabel("Recipient")
        recipient_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(recipient_label)

        # Get recipient from credential attributes
        recipient_pre = self.credential['sad']['a'].get('i', '')

        # Try to find recipient name if it's a local identifier
        recipient_display = recipient_pre or "Not specified"
        try:
            for hab_pre, hab in self.app.vault.hby.habs.items():
                if hab.pre == recipient_pre:
                    recipient_display = f"{hab.name} ({recipient_pre[:35]}...)"
                    break
        except:
            pass

        self.recipient_field = LocksmithLineEdit("Recipient")
        self.recipient_field.setText(recipient_display)
        self.recipient_field.setReadOnly(True)
        self.recipient_field.setCursorPosition(0)
        self.recipient_field.setMinimumWidth(420)
        layout.addWidget(self.recipient_field)

    def _build_status_section(self, layout):
        """Build the status section."""
        status_label = QLabel("Status")
        status_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(status_label)

        # Determine credential status
        status = self.credential.get("status", {})
        status_text = {
            'issued': 'Issued / Active',
            'revoked': 'Issued / Revoked',
            'pending': 'Pending verification',
            'unknown': 'Unknown state',
        }.get(status['et'], 'Unknown state')

        self.status_field = LocksmithLineEdit("Status")
        self.status_field.setText(status_text)
        self.status_field.setReadOnly(True)
        self.status_field.setCursorPosition(0)
        self.status_field.setMinimumWidth(420)
        layout.addWidget(self.status_field)

    def _build_issued_date_section(self, layout):
        """Build the issued date section."""
        date_label = QLabel("Issued Date")
        date_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(date_label)

        # Get issued date from credential attributes
        status = self.credential.get("status", {})
        dt = helping.fromIso8601(status['dt']) if status.get('dt') else None

        self.date_field = LocksmithLineEdit("Issued Date")
        self.date_field.setText(dt.strftime("%b %d, %Y %I:%M %p") if dt else "Unknown")
        self.date_field.setReadOnly(True)
        self.date_field.setCursorPosition(0)
        self.date_field.setMinimumWidth(420)
        layout.addWidget(self.date_field)

    def _build_credential_content_section(self, layout):
        """Build the credential content section showing full JSON."""
        content_label_row = QHBoxLayout()
        content_label_row.setSpacing(5)
        content_label = QLabel("Credential Content")
        content_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        content_label_row.addWidget(content_label)

        # Add copy button for credential content
        credential_json = json.dumps(self.credential['sad'], indent=2)
        self.copy_content_button = LocksmithCopyButton(copy_content=credential_json)
        self.copy_content_button.setFixedHeight(36)
        content_label_row.addWidget(self.copy_content_button)
        content_label_row.addStretch()
        layout.addLayout(content_label_row)

        self.content_field = LocksmithPlainTextEdit()
        self.content_field.setPlainText(credential_json)
        self.content_field.setReadOnly(True)
        self.content_field.setFixedHeight(200)
        self.content_field.setMaximumWidth(480)
        # Use monospace font for JSON
        font = self.content_field.font()
        font.setFamily("Menlo, SF Mono, Monaco, Courier New, monospace")
        font.setPointSize(11)
        self.content_field.setFont(font)
        layout.addWidget(self.content_field)
