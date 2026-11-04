# -*- encoding: utf-8 -*-
"""
locksmith.ui.vault.credentials.issued.grant module

Dialog for granting (sending or saving) issued credentials.
"""
from typing import TYPE_CHECKING

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QHBoxLayout,
    QButtonGroup, QFileDialog
)
from keri import help

from locksmith.core import ipexing
from locksmith.ui import colors
from locksmith.ui.toolkit.widgets import (
    LocksmithDialog,
    LocksmithButton,
    LocksmithInvertedButton
)
from locksmith.ui.toolkit.widgets.buttons import LocksmithRadioButton, LocksmithIconButton
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox, FloatingLabelLineEdit

if TYPE_CHECKING:
    from locksmith.core.apping import LocksmithApplication
    from locksmith.ui.vault.page import VaultPage

logger = help.ogler.getLogger(__name__)


class GrantCredentialDialog(LocksmithDialog):
    """Dialog for granting (sending or saving) an issued credential.

    Two modes:
    - Send: Share credential with a remote identifier via IPEX
    - Save: Export credential to CESR file
    """

    def __init__(
        self,
        app: "LocksmithApplication",
        parent: "VaultPage",
        credential_said: str,
        credential_schema: str,
        credential_issuer: str
    ):
        """
        Initialize the GrantCredentialDialog.

        Args:
            app: Application instance
            parent: Parent widget (VaultPage)
            credential_said: SAID of the credential to grant
            credential_schema: Schema name/title for display
            credential_issuer: Issuer/Recipient identifier for display
        """
        self.app = app
        self.parent_widget = parent
        self.credential_said = credential_said
        self.credential_schema = credential_schema
        self.credential_issuer = credential_issuer

        # Create content widget
        content_widget = QWidget()
        content_widget.setStyleSheet(f"background-color: {colors.BACKGROUND_CONTENT};")
        layout = QVBoxLayout(content_widget)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Credential info section
        info_label = QLabel("Credential Details")
        info_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(info_label)

        schema_label = QLabel(f"Schema: {credential_schema}")
        schema_label.setStyleSheet(f"color: {colors.TEXT_SECONDARY}; font-size: 13px;")
        layout.addWidget(schema_label)

        issuer_label = QLabel(f"Recipient: {credential_issuer}")
        issuer_label.setStyleSheet(f"color: {colors.TEXT_SECONDARY}; font-size: 13px;")
        layout.addWidget(issuer_label)

        layout.addSpacing(10)

        # Recipient dropdown
        recipient_label = QLabel("Grant To")
        recipient_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(recipient_label)

        self.recipient_dropdown = FloatingLabelComboBox(label_text="Recipient")
        self.recipient_dropdown.setFixedWidth(400)
        self._populate_recipients()
        layout.addWidget(self.recipient_dropdown)

        layout.addSpacing(10)

        # Optional message field
        message_label = QLabel("Message (Optional)")
        message_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(message_label)

        self.message_field = FloatingLabelLineEdit(label_text="Message")
        self.message_field.setFixedWidth(400)
        layout.addWidget(self.message_field)

        layout.addSpacing(10)

        # Grant type radio buttons
        grant_type_label = QLabel("Grant Type")
        grant_type_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(grant_type_label)

        radio_layout = QHBoxLayout()
        radio_layout.setSpacing(30)

        self.send_radio = LocksmithRadioButton("Send")
        self.send_radio.setChecked(True)
        radio_layout.addWidget(self.send_radio)

        self.save_radio = LocksmithRadioButton("Save")
        radio_layout.addWidget(self.save_radio)

        radio_layout.addStretch()
        layout.addLayout(radio_layout)

        layout.addSpacing(10)

        # Input container for swappable fields (only used in Save mode)
        input_container = QWidget()
        input_layout = QVBoxLayout(input_container)
        input_layout.setContentsMargins(0, 0, 0, 0)
        input_layout.setSpacing(8)

        # File name field and browse button (hidden in Send mode)
        file_row = QHBoxLayout()
        file_row.setSpacing(8)

        self.file_name_field = FloatingLabelLineEdit(label_text="File Name")
        self.file_name_field.setFixedWidth(370)
        default_filename = self._generate_default_filename()
        self.file_name_field.setText(default_filename)
        self.file_name_field.setVisible(False)
        file_row.addWidget(self.file_name_field)

        self.browse_button = LocksmithIconButton(":/assets/material-icons/browse.svg", tooltip="Browse files")
        self.browse_button.setFixedHeight(48)
        self.browse_button.setFixedWidth(48)
        self.browse_button.setVisible(False)
        file_row.addWidget(self.browse_button)

        file_row.addStretch()
        input_layout.addLayout(file_row)

        layout.addWidget(input_container)

        layout.addStretch()

        # Buttons
        button_row = QHBoxLayout()
        button_row.addStretch()

        self.cancel_button = LocksmithInvertedButton("Cancel")
        button_row.addWidget(self.cancel_button)

        button_row.addSpacing(10)

        self.action_button = LocksmithButton("Grant")
        button_row.addWidget(self.action_button)

        # Initialize parent dialog
        super().__init__(
            parent=parent,
            title="Grant Credential",
            title_icon=":/assets/material-icons/share.svg",
            content=content_widget,
            buttons=button_row,
            show_overlay=False
        )

        self.setFixedSize(540, 630)

        # Define dialog sizes for each mode
        self._send_mode_size = (540, 630)
        self._save_mode_size = (540, 675)

        # Create button group for radio buttons
        self.grant_type_group = QButtonGroup(self)
        self.grant_type_group.addButton(self.send_radio)
        self.grant_type_group.addButton(self.save_radio)

        # Connect signals
        self.cancel_button.clicked.connect(self.close)
        self.send_radio.toggled.connect(self._on_grant_type_changed)
        self.save_radio.toggled.connect(self._on_grant_type_changed)
        self.browse_button.clicked.connect(self._browse_file)
        self.action_button.clicked.connect(self._on_grant)

        # Set initial size for Send mode (default)
        self.setFixedSize(*self._send_mode_size)

    def _populate_recipients(self):
        """Populate recipient dropdown from vault organizer (remote identifiers)."""
        self.recipient_dropdown.clear()

        if not self.app or not self.app.vault:
            return

        try:
            org = self.app.vault.org
            remote_ids = org.list()

            default_index = -1
            current_index = 0

            for remote_id in remote_ids:
                alias = remote_id.get('alias', 'Unknown')
                pre = remote_id.get('id', '')

                # Display format: "Alice (EAbCD...)"
                display_text = f"{alias} ({pre})" if len(pre) > 10 else f"{alias} ({pre})"

                # Store full prefix as userData
                self.recipient_dropdown.addItem(display_text, userData=pre)

                # Check if this is the credential's recipient (default selection)
                if pre == self.credential_issuer:
                    default_index = current_index

                current_index += 1

            # Set default selection to credential's recipient if found
            if default_index >= 0:
                self.recipient_dropdown.setCurrentIndex(default_index)
            elif self.recipient_dropdown.count() > 0:
                self.recipient_dropdown.setCurrentIndex(0)

            if self.recipient_dropdown.count() == 0:
                # No remote identifiers available
                self.recipient_dropdown.addItem("No remote identifiers available")
                self.recipient_dropdown.setCurrentIndex(0)
                self.recipient_dropdown.setEnabled(False)

        except Exception as e:
            logger.exception(f"Error loading recipients: {e}")
            self.recipient_dropdown.addItem("Error loading recipients")
            self.recipient_dropdown.setEnabled(False)
            self.show_error(f"Failed to load recipients: {str(e)}")

    def _generate_default_filename(self) -> str:
        """
        Generate a default filename for credential export.

        Format: {schema-name}-{short-said}.cesr
        Example: driver-license-EAbCD123.cesr
        """
        # Sanitize schema name
        schema_safe = self.credential_schema.lower()
        schema_safe = schema_safe.replace(' ', '-')
        schema_safe = ''.join(c for c in schema_safe if c.isalnum() or c == '-')

        # Get short SAID (first 8 characters)
        short_said = self.credential_said[:8] if len(self.credential_said) > 8 else self.credential_said

        return f"{schema_safe}-{short_said}.cesr"

    def _on_grant_type_changed(self):
        """Handle grant type radio button changes."""
        if self.send_radio.isChecked():
            # Show Send mode UI
            self.file_name_field.hide()
            self.browse_button.hide()
            self.action_button.setText("Grant")
            self.setFixedSize(*self._send_mode_size)
        else:
            # Show Save mode UI
            self.file_name_field.show()
            self.browse_button.show()
            self.action_button.setText("Save")
            self.setFixedSize(*self._save_mode_size)

    def _browse_file(self):
        """Open file save dialog to select output path."""
        # Get current filename as default
        default_filename = self.file_name_field.text().strip() or "credential.cesr"

        # Ensure .cesr extension
        if not default_filename.endswith('.cesr'):
            default_filename += '.cesr'

        # Open save dialog
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Credential",
            default_filename,
            "CESR Files (*.cesr);;All Files (*)"
        )

        if file_path:
            # Update filename field with selected path
            self.file_name_field.setText(file_path)

    def _validate_fields(self) -> bool:
        """
        Validate all required fields based on current mode.

        Returns:
            bool: True if validation passes, False otherwise
        """
        # Clear any previous errors
        self.clear_error()

        failed_fields = []

        if not self.send_radio.isChecked():
            # Validate Save mode: File name must be provided
            file_name = self.file_name_field.text().strip()
            if not file_name:
                failed_fields.append("File Name")
                self.file_name_field.setProperty("error", True)
                self.file_name_field.style().unpolish(self.file_name_field)
                self.file_name_field.style().polish(self.file_name_field)

        if failed_fields:
            field_text = "field" if len(failed_fields) == 1 else "fields"
            self.show_error(f"Please fill in required {field_text}: {', '.join(failed_fields)}")
            return False

        return True

    def _on_grant(self):
        """Create a grant after the user selects its recipient and delivery mode."""
        self.clear_error()
        if not self._validate_fields():
            return
        self.action_button.setEnabled(False)
        self.action_button.setText("Processing...")
        try:
            hab = self.app.vault.hby.habByPre(self.credential_issuer)
            if hab is None:
                raise ValueError("The credential issuer is not a local identifier")
            serder, attachment = ipexing.grant(
                self.app.vault, hab, self.credential_said,
                self.recipient_dropdown.currentData(), self.message_field.text(),
            )
            if self.send_radio.isChecked():
                self._send_grant(hab, serder, attachment)
            else:
                stream = ipexing.prepare(self.app.vault, hab, serder, attachment)
                self._save_grant(stream)
        except Exception as error:
            logger.exception("Failed to create credential grant")
            self.show_error(f"Failed to create grant: {error}")
            self._reset_button()

    def _send_grant(self, hab, serder, attachment):
        """Submit the signed grant through the vault's transport."""
        self._pending_said = serder.said
        doer = ipexing.SendIpexDoer(self.app.vault, hab, serder, attachment)
        self.app.vault.signals.doer_event.connect(self._on_doer_event)
        self.app.vault.extend([doer])
        self.action_button.setText("Sending...")

    def _on_doer_event(self, doer_name: str, event_type: str, data: dict):
        """Show the transport result for this grant."""
        if doer_name != "Ipex" or data.get('said') != self._pending_said:
            return
        if event_type not in ("transport_submitted", "send_failed"):
            return
        self.app.vault.signals.doer_event.disconnect(self._on_doer_event)
        if event_type == "transport_submitted":
            self.show_success("Grant submitted for delivery")
            QTimer.singleShot(2000, self.accept)
        else:
            self.show_error(f"Failed to send: {data.get('error', 'Unknown error')}")
            self._reset_button()

    def _save_grant(self, grant: bytes):
        """Save credential to file in CESR format."""
        file_path = self.file_name_field.text().strip()

        # Ensure .cesr extension
        if not file_path.endswith('.cesr'):
            file_path += '.cesr'

        try:
            logger.info(f"Saving credential {self.credential_said} to {file_path}")

            # Write to file
            with open(file_path, 'wb') as f:
                f.write(grant)

            logger.info(f"Grant message saved successfully to {file_path}")

            # Show success and close
            self.show_success(f"Grant message saved to {file_path}")

            # Close dialog after short delay to show success message
            QTimer.singleShot(1500, self.accept)

        except Exception as e:
            logger.exception(f"Failed to save credential: {e}")
            self.show_error(f"Failed to save credential: {str(e)}")
            self._reset_button()

    def _reset_button(self):
        """Reset action button to enabled state."""
        self.action_button.setEnabled(True)
        button_text = "Grant" if self.send_radio.isChecked() else "Save"
        self.action_button.setText(button_text)
