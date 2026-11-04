# -*- encoding: utf-8 -*-
"""
locksmith.ui.vault.credentials.received.accept_grant module

Dialog for accepting and admitting credentials from IPEX grant messages.
"""
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QHBoxLayout, QScrollArea, QCheckBox, QFileDialog,
    QFrame, QTextEdit
)
from keri import help
from keri.help import helping

from locksmith.core import ipexing
from locksmith.ui import colors
from locksmith.ui.toolkit.widgets import (
    LocksmithDialog,
    LocksmithButton,
    LocksmithInvertedButton
)
from locksmith.ui.toolkit.widgets.fields import FloatingLabelLineEdit

if TYPE_CHECKING:
    from locksmith.core.apping import LocksmithApplication
    from locksmith.ui.vault.page import VaultPage

logger = help.ogler.getLogger(__name__)


class AcceptGrantDialog(LocksmithDialog):
    """Dialog for accepting credentials from IPEX grant messages.

    Displays the grant message details, optional message from grantor,
    and credential attributes parsed from the schema in read-only format.
    """

    def __init__(
        self,
        app: "LocksmithApplication",
        parent: "VaultPage",
        grant_said: str,
        save: bool = True
    ):
        """
        Initialize the AcceptGrantDialog.

        Args:
            app: Application instance
            parent: Parent widget (VaultPage)
            grant_said: SAID of the grant exn message to process
        """
        self.app = app
        self.parent_widget = parent
        self.grant_said = grant_said

        self.save = save

        # Initialize storage for UI elements
        self._field_widgets = []

        # Load grant message data
        try:
            self._load_grant_message()
        except Exception as e:
            logger.exception(f"Failed to load grant message: {e}")
            # Create a minimal UI to show error
            self.grant_error = str(e)
            self._build_error_ui()
            return

        # Build the dialog UI
        self._build_ui()

        # Initialize parent dialog
        super().__init__(
            parent=self.parent_widget,
            title="Accept Credential Grant",
            title_icon=":/assets/material-icons/in-badge.svg",
            content=self.scroll_area,
            buttons=self.button_row,
            show_overlay=False
        )

        self.setFixedSize(600, 950)

        # Connect signals
        self.cancel_button.clicked.connect(self.close)
        self.admit_button.clicked.connect(self._on_admit)


    def _load_grant_message(self):
        """Load a verified native grant and its disclosed credential."""
        exn = self.app.vault.hby.db.exns.get(keys=(self.grant_said,))
        if exn is None or exn.pvrsn.major != 2 or exn.route != '/ipex/grant':
            raise ValueError("A verified ACDC V2 grant is required")
        credential = ipexing.grant_credential(self.app.vault, self.grant_said)
        self.sender = exn.sad['i']
        self.recipient = exn.sad['ri']
        self.message = exn.sad['a'].get('m', '')
        self.timestamp = exn.sad.get('dt', '')
        self.acdc_ked = credential.sad
        self.credential_said = credential.said
        self.issuer = credential.sad['i']
        schema = credential.schema
        self.schema_said = schema['$id'] if isinstance(schema, dict) else schema
        if isinstance(schema, dict):
            self.schema = schema
        else:
            schemer = self.app.vault.hby.db.schema.get(keys=(schema,))
            self.schema = schemer.sed if schemer is not None else {}
        self.credential_attrs = credential.sad.get('a', {})

    def _build_error_ui(self):
        """Build error UI when grant loading fails"""
        content_widget = QWidget()
        content_widget.setStyleSheet(f"background-color: {colors.BACKGROUND_CONTENT};")
        layout = QVBoxLayout(content_widget)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        error_label = QLabel(f"Failed to load grant message:\n\n{self.grant_error}")
        error_label.setStyleSheet(f"color: {colors.DANGER}; font-size: 14px;")
        error_label.setWordWrap(True)
        layout.addWidget(error_label)

        layout.addStretch()

        # Close button
        button_row = QHBoxLayout()
        button_row.addStretch()
        close_button = LocksmithButton("Close")
        button_row.addWidget(close_button)

        # Initialize parent dialog
        super().__init__(
            parent=self.parent_widget,
            title="Accept Credential Grant",
            title_icon=":/assets/material-icons/in-badge.svg",
            content=content_widget,
            buttons=button_row,
            show_overlay=False
        )

        self.setFixedSize(500, 300)
        close_button.clicked.connect(self.close)

    def _build_ui(self):
        """Build dialog UI with all sections"""
        # Create scrollable content widget
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet(f"""
            QScrollArea {{
                background-color: {colors.BACKGROUND_CONTENT};
                border: none;
            }}
            QScrollBar:vertical {{
                border: none;
                background: #F0F0F0;
                width: 10px;
                margin: 0px;
            }}
            QScrollBar::handle:vertical {{
                background: #CCCCCC;
                border-radius: 5px;
                min-height: 20px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: #AAAAAA;
            }}
        """)

        content_widget = QWidget()
        content_widget.setStyleSheet(f"background-color: {colors.BACKGROUND_CONTENT};")
        layout = QVBoxLayout(content_widget)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Grant info section
        self._create_grant_info_section(layout)

        layout.addSpacing(10)

        # Optional message section (only if message exists and not blank)
        if self.message and self.message.strip():
            self._create_message_section(layout)
            layout.addSpacing(10)

        # Credential details section
        self._create_credential_details_section(layout)

        layout.addSpacing(10)

        # Dynamic read-only fields section
        self._create_credential_fields_section(layout)

        layout.addSpacing(15)

        # Horizontal separator
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        separator.setStyleSheet("""
            QFrame {
                color: #D0D0D0;
                background-color: #D0D0D0;
                max-height: 1px;
            }
        """)
        layout.addWidget(separator)

        layout.addSpacing(15)

        # Optional message field for recipient to send back to grantor
        self._create_response_message_section(layout)

        layout.addStretch()

        self.scroll_area.setWidget(content_widget)

        # Buttons
        self.button_row = QHBoxLayout()
        self.button_row.addStretch()

        self.cancel_button = LocksmithInvertedButton("Cancel")
        self.button_row.addWidget(self.cancel_button)

        self.button_row.addSpacing(10)

        self.admit_button = LocksmithButton("Admit")
        self.button_row.addWidget(self.admit_button)

    def _create_grant_info_section(self, layout: QVBoxLayout):
        """Display grant metadata (sender and timestamp)"""
        # Section header
        info_label = QLabel("Grant Information")
        info_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(info_label)

        # Resolve sender name if possible
        sender_display = self._resolve_identifier_name(self.sender)

        # From field
        from_label = QLabel(f"From: {sender_display}")
        from_label.setStyleSheet(f"color: {colors.TEXT_SECONDARY}; font-size: 13px;")
        from_label.setWordWrap(True)
        layout.addWidget(from_label)

        # Timestamp field
        if self.timestamp:
            try:
                dt = helping.fromIso8601(self.timestamp)
                timestamp_display = dt.strftime("%b %d, %Y %I:%M %p")
            except Exception as e:
                logger.warning(f"Failed to parse timestamp: {e}")
                timestamp_display = self.timestamp
        else:
            timestamp_display = "Unknown"

        date_label = QLabel(f"Date: {timestamp_display}")
        date_label.setStyleSheet(f"color: {colors.TEXT_SECONDARY}; font-size: 13px;")
        layout.addWidget(date_label)

    def _create_message_section(self, layout: QVBoxLayout):
        """Display message from grantor"""
        # Section header
        message_header = QLabel("Message from Grantor:")
        message_header.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(message_header)

        # Message content in a styled container
        message_widget = QLabel(self.message)
        message_widget.setStyleSheet(f"""
            QLabel {{
                background-color: #F0F4FF;
                border: 1px solid #D0D0D0;
                border-radius: 6px;
                padding: 12px;
                font-size: 13px;
                color: {colors.TEXT_PRIMARY};
            }}
        """)
        message_widget.setWordWrap(True)
        message_widget.setMaximumHeight(150)
        layout.addWidget(message_widget)

    def _create_credential_details_section(self, layout: QVBoxLayout):
        """Display schema and issuer info"""
        # Section header
        details_label = QLabel("Credential Details")
        details_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(details_label)

        # Get schema info
        schema_display = self._get_schema_display()
        schema_label = QLabel(f"Schema: {schema_display}")
        schema_label.setStyleSheet(f"color: {colors.TEXT_SECONDARY}; font-size: 13px;")
        schema_label.setWordWrap(True)
        layout.addWidget(schema_label)

        # Resolve issuer name if possible
        issuer_display = self._resolve_identifier_name(self.issuer)
        issuer_label = QLabel(f"Issuer: {issuer_display}")
        issuer_label.setStyleSheet(f"color: {colors.TEXT_SECONDARY}; font-size: 13px;")
        issuer_label.setWordWrap(True)
        layout.addWidget(issuer_label)

    def _create_credential_fields_section(self, layout: QVBoxLayout):
        """Parse schema and create read-only field widgets"""
        # Section header
        fields_label = QLabel("Credential Attributes")
        fields_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(fields_label)

        # Parse schema to get field definitions
        field_defs = self._parse_schema_fields()

        if not field_defs:
            message = ("Load this credential's schema before accepting it"
                       if not self.schema else "No credential attributes to display")
            no_fields_label = QLabel(message)
            no_fields_label.setStyleSheet(f"color: {colors.TEXT_SECONDARY}; font-size: 13px; font-style: italic;")
            layout.addWidget(no_fields_label)
            return

        # Create read-only field widget for each field
        for field_def in field_defs:
            field_name = field_def['name']
            value = self.credential_attrs.get(field_name)

            # Create read-only field widget
            field_widget = self._create_read_only_field(field_def, value)
            layout.addWidget(field_widget)
            self._field_widgets.append(field_widget)

    def _create_response_message_section(self, layout: QVBoxLayout):
        """Create optional message field for recipient to send back to grantor"""
        # Section header
        message_header = QLabel("Message to Grantor (Optional)")
        message_header.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(message_header)

        # Description
        description = QLabel("You can include an optional message with your admission response.")
        description.setStyleSheet(f"color: {colors.TEXT_SECONDARY}; font-size: 12px;")
        description.setWordWrap(True)
        layout.addWidget(description)

        layout.addSpacing(8)

        # Message text field
        self.response_message_field = QTextEdit()
        self.response_message_field.setPlaceholderText("Enter your message here...")
        self.response_message_field.setMaximumHeight(100)
        self.response_message_field.setStyleSheet(f"""
            QTextEdit {{
                background-color: #FFFFFF;
                border: 1px solid #CCCCCC;
                border-radius: 6px;
                padding: 8px;
                font-size: 13px;
                color: {colors.TEXT_PRIMARY};
            }}
            QTextEdit:focus {{
                border: 2px solid #F57B03;
            }}
        """)
        layout.addWidget(self.response_message_field)

    def _parse_schema_fields(self) -> list[dict]:
        """
        Parse the loaded schema to get attribute field definitions.

        Supports a direct object definition or an object within a.oneOf.
        Excludes the credential metadata fields d, i, dt, and u.

        Returns:
            List of field definition dictionaries, or an empty list if the
            schema is unavailable or its attribute definition cannot be parsed.
        """
        try:
            schema = self.schema
            if not schema:
                return []
            props = schema.get('properties', {})

            attribute_definition = props.get('a', {})
            candidates = attribute_definition.get('oneOf', [attribute_definition])
            attributes_obj = next((item for item in candidates
                                   if isinstance(item, dict) and item.get('type') == 'object'), None)
            if attributes_obj is None:
                return []

            # Get properties and required list
            properties = attributes_obj.get('properties', {})
            required_fields = set(attributes_obj.get('required', []))

            # Filter and build field definitions
            field_defs = []
            excluded_fields = {'d', 'i', 'dt', 'u'}

            for prop_name, prop_def in properties.items():
                if prop_name in excluded_fields:
                    continue

                field_def = {
                    'name': prop_name,
                    'description': prop_def.get('description', prop_name),
                    'type': prop_def.get('type', 'string'),
                    'format': prop_def.get('format'),
                    'required': prop_name in required_fields
                }
                field_defs.append(field_def)

            logger.info(f"Parsed {len(field_defs)} fields from schema {self.schema_said}")
            return field_defs

        except Exception as e:
            logger.exception(f"Error parsing schema fields: {e}")
            return []

    @staticmethod
    def _create_read_only_field(field_def: dict, value: Any) -> QWidget:
        """
        Create read-only version of field widget.

        Args:
            field_def: Field definition dict with name, description, type, format
            value: Current value of the field

        Returns:
            QWidget: Read-only widget displaying the field and value
        """
        field_type = field_def['type']
        field_format = field_def.get('format')
        label = field_def['description']

        # Container for field
        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 8)
        container_layout.setSpacing(4)

        # Field label
        label_widget = QLabel(label)
        label_widget.setStyleSheet("font-weight: bold; font-size: 12px; color: #636466;")
        container_layout.addWidget(label_widget)

        # Value display based on type
        if field_type == 'boolean':
            # Boolean: disabled checkbox
            checkbox = QCheckBox()
            checkbox.setChecked(bool(value) if value is not None else False)
            checkbox.setEnabled(False)
            checkbox.setStyleSheet("""
                QCheckBox {
                    font-size: 14px;
                    spacing: 8px;
                }
                QCheckBox::indicator {
                    width: 20px;
                    height: 20px;
                    border: 2px solid #CCCCCC;
                    border-radius: 4px;
                    background-color: #F0F0F0;
                }
                QCheckBox::indicator:checked {
                    background-color: #AAAAAA;
                    border-color: #AAAAAA;
                }
                QCheckBox::indicator:disabled {
                    background-color: #F0F0F0;
                }
            """)
            container_layout.addWidget(checkbox)

        elif field_type == 'string' and field_format == 'date-time':
            # Date-time: formatted display
            if value:
                try:
                    dt = helping.fromIso8601(value)
                    display_value = dt.strftime("%b %d, %Y %I:%M %p")
                except Exception as e:
                    logger.warning(f"Failed to parse date-time value: {e}")
                    display_value = str(value)
            else:
                display_value = ""

            value_label = QLabel(display_value)
            value_label.setStyleSheet("""
                QLabel {
                    background-color: #F0F0F0;
                    color: #666666;
                    border: 1px solid #CCCCCC;
                    border-radius: 6px;
                    padding: 12px;
                    font-size: 14px;
                }
            """)
            container_layout.addWidget(value_label)

        else:
            # All other types: read-only text field
            display_value = str(value) if value is not None else ""

            value_field = FloatingLabelLineEdit(label_text="")
            value_field.setText(display_value)
            value_field.setReadOnly(True)
            value_field.setFixedWidth(500)
            value_field.setStyleSheet("""
                QLineEdit {
                    background-color: #F0F0F0;
                    color: #666666;
                    border: 1px solid #CCCCCC;
                    border-radius: 6px;
                    padding: 12px;
                    font-size: 14px;
                }
            """)
            container_layout.addWidget(value_field)

        return container

    def _resolve_identifier_name(self, pre: str) -> str:
        """
        Resolve identifier name from contacts or local identifiers.

        Args:
            pre: Identifier prefix to resolve

        Returns:
            Display string with name and prefix
        """
        # Try to find in local identifiers
        try:
            hab = self.app.hby.habByPre(pre)
            if hab:
                return f"{hab.name} ({pre})"
        except Exception:
            pass

        # Try to find in remote identifiers (contacts)
        try:
            org = self.app.vault.org
            remote_ids = org.list()
            for remote_id in remote_ids:
                if remote_id.get('id') == pre:
                    alias = remote_id.get('alias', 'Unknown')
                    return f"{alias} ({pre})"
        except Exception:
            pass

        # Default: just show prefix
        return pre

    def _get_schema_display(self) -> str:
        """Show a disclosed or cached schema title."""
        if self.schema:
            title = self.schema.get('title', 'Untitled')
            version = self.schema.get('version', '')
            return f"{title} v{version}" if version else title
        return self.schema_said

    def _on_admit(self):
        """Handle Admit button click"""
        # Disable button during processing
        self.admit_button.setEnabled(False)
        self.admit_button.setText("Processing...")

        logger.info(f"Admitting credential {self.credential_said}")

        # Get optional message from text field
        message = self.response_message_field.toPlainText().strip()

        if self.save:
            # Save-only mode: create admit synchronously
            self._save_admit_sync(message)
        else:
            # Send the acknowledgment after acceptance
            self._send_admit_async(message)

    def _save_admit_sync(self, message: str):
        """Accept the credential and save its signed acknowledgment."""
        try:
            hab = self.app.vault.hby.habByPre(self.recipient)
            serder, attachment = ipexing.admit(self.app.vault, hab, self.grant_said, message)
            stream = ipexing.prepare(self.app.vault, hab, serder, attachment)
            self.app.vault.signals.emit_doer_event("Ipex", "accepted", {'said': serder.said})
            self._save_admit_to_file(serder.said, stream)
        except Exception as error:
            logger.exception("Failed to accept credential")
            self.show_error(f"Failed to accept credential: {error}")
            self._reset_button()

    def _send_admit_async(self, message: str):
        """Accept the credential and submit its acknowledgment for delivery."""
        try:
            hab = self.app.vault.hby.habByPre(self.recipient)
            serder, attachment = ipexing.admit(self.app.vault, hab, self.grant_said, message)
            self._pending_said = serder.said
            doer = ipexing.SendIpexDoer(self.app.vault, hab, serder, attachment)
            self.app.vault.signals.emit_doer_event("Ipex", "accepted", {'said': serder.said})
            self.app.vault.signals.doer_event.connect(self._on_doer_event)
            self.app.vault.extend([doer])
            self.admit_button.setText("Sending acknowledgment...")
        except Exception as error:
            logger.exception("Failed to submit credential acknowledgment")
            self.show_error(f"Failed to submit acknowledgment: {error}")
            self._reset_button()

    def _on_doer_event(self, doer_name: str, event_type: str, data: dict):
        """Show the transport result without inferring the grantor's receipt."""
        if doer_name != "Ipex" or data.get('said') != self._pending_said:
            return
        if event_type not in ("transport_submitted", "send_failed"):
            return
        self.app.vault.signals.doer_event.disconnect(self._on_doer_event)
        if event_type == "transport_submitted":
            self.show_success("Credential accepted. Acknowledgment submitted for delivery.")
            QTimer.singleShot(2000, self.accept)
        else:
            self.show_error(f"Credential accepted, but acknowledgment delivery failed: {data.get('error', 'Unknown error')}")
            self._reset_button()

    def _save_admit_to_file(self, admit_said: str, admit_message: bytes):
        """
        Save admit message to file.

        Args:
            admit_said: SAID of the admit message
            admit_message: Serialized admit message bytes
        """
        # Open save dialog
        default_filename = f"admit-{admit_said}.cesr"
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Admit Message",
            default_filename,
            "CESR Files (*.cesr);;All Files (*)"
        )

        if file_path:
            try:
                # Write to file
                with open(file_path, 'wb') as f:
                    f.write(admit_message)

                logger.info(f"Admit message saved successfully to {file_path}")

                # Show success and close
                self.show_success(f"Admit message saved to {file_path}")

                # Close dialog after short delay to show success message
                QTimer.singleShot(1500, self.accept)

            except Exception as e:
                logger.exception(f"Failed to save admit message: {e}")
                self.show_error(f"Failed to save file: {str(e)}")
                self._reset_button()
        else:
            # User cancelled save dialog
            self._reset_button()

    def _reset_button(self):
        """Reset admit button to enabled state."""
        self.admit_button.setEnabled(True)
        self.admit_button.setText("Admit")
