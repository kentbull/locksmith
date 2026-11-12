# -*- encoding: utf-8 -*-
"""
locksmith.ui.vaults.create module

Dialog for creating new vaults
"""
import asyncio
from types import SimpleNamespace

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QHBoxLayout, QButtonGroup
from keri import help
from keri.core import signing

from locksmith.core import habbing
from locksmith.ui import colors
from locksmith.ui.toolkit.widgets import (
    LocksmithDialog,
    FloatingLabelLineEdit,
    LocksmithButton,
    LocksmithInvertedButton
)
from locksmith.ui.toolkit.widgets.buttons import LocksmithRadioButton, LocksmithCheckbox
from locksmith.ui.toolkit.widgets.collapsible import CollapsibleSection
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox, LocksmithLineEdit
from locksmith.ui.vault.identifiers import mailbox
from locksmith.ui.vault.shared.delegation_mixin import DelegationMixin
from locksmith.ui.vault.shared.witness_auth_mixin import (
    WitnessAuthenticationPanel,
    witness_auth_dialog_height
)

logger = help.ogler.getLogger(__name__)


class CreateIdentifierDialog(DelegationMixin, LocksmithDialog):
    """Dialog for initializing a new vault."""

    identifier_created = Signal(str, str)
    identifier_creation_failed = Signal(str)

    def __init__(self, icon_path, app, parent=None, config=None):
        """
        Initialize the CreateVaultDialog.

        Args:
            parent: Parent widget (typically main window)
            config: LocksmithConfig instance
        """
        self.config = config
        self.app = app
        self._auth_panel = None
        self._pending_params = None
        self._mailbox_hab = None
        self._mailbox_step = None  # None, 'working', 'retry' or 'done'
        self._mailbox_task = None

        # Create content widget
        content_widget = QWidget()
        content_widget.setStyleSheet(f"background-color: {colors.BACKGROUND_CONTENT};")
        self._form_widget = QWidget()
        outer_layout = QVBoxLayout(content_widget)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(self._form_widget)
        self._outer_layout = outer_layout
        layout = QVBoxLayout(self._form_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        layout.addSpacing(10)

        self.name_field = FloatingLabelLineEdit("Alias")
        self.name_field.setFixedWidth(360)
        layout.addWidget(self.name_field)
        layout.addSpacing(15)

        # Create button row
        button_row = QHBoxLayout()
        self.cancel_button = LocksmithInvertedButton("Cancel")
        button_row.addWidget(self.cancel_button)
        button_row.addSpacing(10)
        self.create_button = LocksmithButton("Create")
        button_row.addWidget(self.create_button)

        # Create title content
        title_content_widget = QWidget()
        title_content = QHBoxLayout()
        icon = QIcon(icon_path)
        icon_label = QLabel()
        icon_label.setPixmap(icon.pixmap(32, 32))
        icon_label.setFixedSize(32, 32)
        title_content.addWidget(icon_label)

        title_label = QLabel("  Add a Local Identifier")
        title_label.setStyleSheet("font-size: 16px;")
        title_content.addWidget(title_label)
        title_content_widget.setLayout(title_content)

        # Initialize parent dialog
        super().__init__(
            parent=parent,
            title_content=title_content_widget,
            show_close_button=True,
            content=content_widget,
            initial_focus=self.name_field.line_edit,
            buttons=button_row,
            show_overlay=False
        )

        # Set initial size (will expand when error is shown or collapsible sections expand)
        self.setFixedSize(420, 320)

        # Connect buttons
        self.cancel_button.clicked.connect(self._on_cancel_clicked)
        self.create_button.clicked.connect(self._on_create_clicked)

        # Add collapsible advanced configuration section
        self.advanced_config = CollapsibleSection(title="Advanced Configuration", parent=self)
        advanced_config_widget = QWidget()
        advanced_config_layout = QVBoxLayout(advanced_config_widget)
        advanced_config_layout.addSpacing(20)

        # Key type label and radio buttons
        key_type_label = QLabel("Key Type")
        key_type_label.setStyleSheet("font-weight: 600; font-size: 15px;")
        advanced_config_layout.addWidget(key_type_label)

        advanced_config_layout.addSpacing(15)

        self.key_chain_radio = LocksmithRadioButton("Key Chain     ")
        self.random_key_radio = LocksmithRadioButton("Random Key    ")
        # Set one as default
        self.key_chain_radio.setChecked(True)

        # Create button group for key type radios
        self.key_type_button_group = QButtonGroup(self)
        self.key_type_button_group.addButton(self.key_chain_radio)
        self.key_type_button_group.addButton(self.random_key_radio)

        radio_layout = QHBoxLayout()
        radio_layout.setSpacing(10)
        radio_layout.addWidget(self.key_chain_radio)
        radio_layout.addWidget(self.random_key_radio)
        radio_layout.addStretch()
        advanced_config_layout.addLayout(radio_layout)

        # Generate random salt by default
        default_salt = signing.Salter().qb64[2:23]
        self.key_salt_field = FloatingLabelLineEdit("Key Salt", password_mode=True)
        self.key_salt_field.setText(default_salt)
        advanced_config_layout.addWidget(self.key_salt_field)

        # Connect radio buttons to handler
        self.key_chain_radio.toggled.connect(self._on_key_type_radio_changed)
        self.random_key_radio.toggled.connect(self._on_key_type_radio_changed)

        advanced_config_layout.addSpacing(15)

        #Number of keys and threshold label and fields
        keys_and_thresholds_label = QLabel("Number of Keys / Thresholds")
        keys_and_thresholds_label.setStyleSheet("font-weight: 600; font-size: 15px;")
        advanced_config_layout.addWidget(keys_and_thresholds_label)

        advanced_config_layout.addSpacing(15)

        signing_keys_and_thresholds_layout = QHBoxLayout()
        self.num_signing_keys_field = FloatingLabelLineEdit("Signing Keys")
        self.num_signing_keys_field.setText("1")
        self.signing_threshold_field = FloatingLabelLineEdit("Signing Threshold")
        self.signing_threshold_field.setText("1")

        signing_keys_and_thresholds_layout.addWidget(self.num_signing_keys_field)
        signing_keys_and_thresholds_layout.addWidget(self.signing_threshold_field)

        advanced_config_layout.addLayout(signing_keys_and_thresholds_layout)


        rotation_keys_and_thresholds_layout = QHBoxLayout()
        self.num_rotation_keys_field = FloatingLabelLineEdit("Rotation Keys")
        self.num_rotation_keys_field.setText("1")
        self.rotation_threshold_field = FloatingLabelLineEdit("Rotation Threshold")
        self.rotation_threshold_field.setText("1")

        rotation_keys_and_thresholds_layout.addWidget(self.num_rotation_keys_field)
        rotation_keys_and_thresholds_layout.addWidget(self.rotation_threshold_field)
        advanced_config_layout.addLayout(rotation_keys_and_thresholds_layout)

        checkbox_layout = QHBoxLayout()
        self.establishment_only_checkbox = LocksmithCheckbox("Establishment Only")
        self.do_not_delegate_checkbox = LocksmithCheckbox("Do Not Delegate")
        checkbox_layout.addWidget(self.establishment_only_checkbox)
        checkbox_layout.addWidget(self.do_not_delegate_checkbox)
        advanced_config_layout.addLayout(checkbox_layout)

        advanced_config_layout.addSpacing(20)

        delegation_label = QLabel("Delegation")
        delegation_label.setStyleSheet("font-weight: 600; font-size: 15px;")
        advanced_config_layout.addWidget(delegation_label)

        advanced_config_layout.addSpacing(15)

        delegation_radio_layout = QHBoxLayout()
        self.no_delegation_radio = LocksmithRadioButton("None")
        self.local_delegation_radio = LocksmithRadioButton("Local")
        self.remote_delegation_radio = LocksmithRadioButton("Remote")

        # Create button group for delegation radios
        self.delegation_button_group = QButtonGroup(self)
        self.delegation_button_group.addButton(self.no_delegation_radio)
        self.delegation_button_group.addButton(self.local_delegation_radio)
        self.delegation_button_group.addButton(self.remote_delegation_radio)

        self.no_delegation_radio.setChecked(True)

        delegation_radio_layout.addWidget(self.no_delegation_radio)
        delegation_radio_layout.addSpacing(10)
        delegation_radio_layout.addWidget(self.local_delegation_radio)
        delegation_radio_layout.addSpacing(10)
        delegation_radio_layout.addWidget(self.remote_delegation_radio)
        delegation_radio_layout.addStretch()
        advanced_config_layout.addLayout(delegation_radio_layout)
        advanced_config_layout.addSpacing(15)

        self.delegator_dropdown = FloatingLabelComboBox("Delegator")
        self.delegator_dropdown.setFixedWidth(360)
        self.delegator_dropdown.addItem("None")
        advanced_config_layout.addWidget(self.delegator_dropdown)
        self.delegator_dropdown.hide()
        self.delegator_dropdown.currentIndexChanged.connect(self._update_delegation_help)
        self.delegation_help = QLabel()
        self.delegation_help.setWordWrap(True)
        self.delegation_help.setFixedWidth(360)
        self.delegation_help.setStyleSheet(f"font-size: 12px; color: {colors.TEXT_SECONDARY};")
        advanced_config_layout.addWidget(self.delegation_help)
        self.delegation_help.hide()

        self.delegate_proxy_dropdown = FloatingLabelComboBox("Delegate Proxy")
        self.delegate_proxy_dropdown.setFixedWidth(360)
        self.delegate_proxy_dropdown.addItem("None")
        advanced_config_layout.addWidget(self.delegate_proxy_dropdown)
        self.delegate_proxy_dropdown.hide()

        # Connect delegation radio buttons to handler
        self.no_delegation_radio.toggled.connect(self._on_delegation_radio_changed)
        self.local_delegation_radio.toggled.connect(self._on_delegation_radio_changed)
        self.remote_delegation_radio.toggled.connect(self._on_delegation_radio_changed)
        self.local_delegation_radio.toggled.connect(self._update_delegation_help)

        advanced_config_layout.addSpacing(10)

        toad_layout = QHBoxLayout()
        toad_label = QLabel("Threshold of Acceptable Duplicity:  ")
        toad_label.setStyleSheet("font-weight: 600; font-size: 15px;")
        toad_layout.addWidget(toad_label)
        self.toad_field = LocksmithLineEdit()
        self.toad_field.setText("0")
        self.toad_field.setFixedWidth(50)
        self.toad_field.setAlignment(Qt.AlignmentFlag.AlignCenter)

        toad_layout.addWidget(self.toad_field)
        toad_layout.addStretch()

        advanced_config_layout.addLayout(toad_layout)

        self.advanced_config.set_content_layout(advanced_config_layout)
        layout.addWidget(self.advanced_config)
        layout.addSpacing(10)

        # Link collapsible section to dialog for synchronized resize animations
        self.advanced_config.set_dialog(self)
        layout.addStretch() # Always add stretch after collapsible sections

        # Connect to vault signal bridge if available
        if self.app and hasattr(self.app, 'vault') and self.app.vault and hasattr(self.app.vault, 'signals'):
            self.app.vault.signals.doer_event.connect(self._on_doer_event)
            logger.info("CreateIdentifierDialog: Connected to vault signal bridge")

    def _local_delegator(self):
        """Return the selected local delegator hab, or ``None``."""
        if not self.local_delegation_radio.isChecked():
            return None
        delpre = self.delegator_dropdown.currentData()
        return self.app.vault.hby.habByPre(delpre) if delpre else None

    def _update_delegation_help(self, *_):
        """Explain how a local delegator approves the new identifier."""
        delegator = self._local_delegator()
        if delegator is None:
            self.delegation_help.hide()
        else:
            wits = len(delegator.kever.wits)
            text = f"{delegator.name} anchors this identifier in its KEL"
            if wits:
                text += (f" and collects receipts from its {wits} witness{'es' if wits != 1 else ''}; "
                         "you will enter their codes next.")
            else:
                text += "."
            # Providers decide from the delegator alone, before the delegate exists.
            delegate = SimpleNamespace(name='this identifier', kever=SimpleNamespace(delpre=delegator.pre))
            found = mailbox.mailbox_provider(self.app, delegate) if self.app.vault else None
            text += (f" {found[1]} then hosts this identifier's own mailbox, so it can send credentials"
                     " and receive replies." if found else
                     f" No provider hosts a mailbox for {delegator.name}'s delegates, so this identifier"
                     f" cannot send credentials or receive replies until {delegator.name} is onboarded"
                     " with one.")
            self.delegation_help.setText(text)
            self.delegation_help.show()
        if hasattr(self, 'advanced_config'):
            self.advanced_config.update_content_height()

    def _on_create_clicked(self):
        if self._mailbox_step == 'retry':
            self._start_mailbox_setup(self._mailbox_hab)
        elif self._mailbox_step == 'done':
            self._finish_created(self._mailbox_hab)
        elif self._auth_panel is not None:
            self._submit_auth_step()
        else:
            self.create_identifier()

    def _on_cancel_clicked(self):
        if self._mailbox_step is not None:
            self._finish_created(self._mailbox_hab)
        elif self._auth_panel is not None:
            self._show_form_step()
        else:
            self.close()

    def _show_auth_step(self, delegator):
        """Collect the delegator's witness codes before anchoring the delegation."""
        self.clear_error(resize_dialog=False)
        self._base_height = None
        self._form_widget.hide()
        self._auth_panel = WitnessAuthenticationPanel(
            app=self.app, hab=delegator, witness_ids=list(delegator.kever.wits), parent=self)
        heading = QLabel(f"Authenticate {delegator.name}'s witnesses to anchor the delegation")
        heading.setWordWrap(True)
        heading.setStyleSheet("font-weight: 600; font-size: 14px;")
        self._auth_heading = heading
        self._outer_layout.addWidget(heading)
        self._outer_layout.addWidget(self._auth_panel)
        self.cancel_button.setText("Back")
        self.create_button.setText("Authenticate")
        self.setFixedSize(700, witness_auth_dialog_height(
            self._auth_panel.individual_witnesses, self._auth_panel.batch_groups) + 40)
        self.center_on_parent()

    def _show_form_step(self):
        self.clear_error(resize_dialog=False)
        self._base_height = None
        for widget in (self._auth_panel, getattr(self, '_auth_heading', None)):
            if widget is not None:
                self._outer_layout.removeWidget(widget)
                widget.setParent(None)
                widget.deleteLater()
        self._auth_panel = self._auth_heading = None
        self._form_widget.show()
        self.cancel_button.setText("Cancel")
        self.create_button.setText("Create")
        self.create_button.setEnabled(True)
        self.setFixedSize(420, 320)
        self.advanced_config.update_content_height()
        self.center_on_parent()

    def _submit_auth_step(self):
        self.clear_error()
        valid, codes, error_message = self._auth_panel.validate_authentication_codes()
        if not valid:
            self.show_error(error_message)
            return
        self.create_button.setEnabled(False)
        self.create_button.setText("Anchoring...")
        self._launch(dict(self._pending_params, codes=codes))

    def create_identifier(self):
        """Create a new identifier using the form values."""
        logger.info("Creating new identifier...")

        # Get alias
        alias = self.name_field.text().strip()
        if not alias:
            logger.error("Alias is required")
            # TODO: Show error message to user
            return

        # Determine key type
        if self.key_chain_radio.isChecked():
            key_type = 'salty'
        elif self.random_key_radio.isChecked():
            key_type = 'randy'
        else:
            key_type = 'salty'

        # Build parameters
        params = {
            'icount': self.num_signing_keys_field.text() or '1',
            'isith': self.signing_threshold_field.text() or '1',
            'ncount': self.num_rotation_keys_field.text() or '1',
            'nsith': self.rotation_threshold_field.text() or '1',
            'toad': self.toad_field.text() or '0',
            'wits': [],  # Will add witness support later
            'estOnly': self.establishment_only_checkbox.isChecked(),
            'DnD': self.do_not_delegate_checkbox.isChecked(),
        }

        # Add salt for key chain type
        if key_type == 'salty':
            params['salt'] = self.key_salt_field.text()

        # Determine delegation type
        if self.no_delegation_radio.isChecked():
            params['delegation_type'] = 'none'
        elif self.local_delegation_radio.isChecked():
            params['delegation_type'] = 'local'
            delegator = self._local_delegator()
            if delegator is None:
                self.show_error("Choose the local identifier that delegates this one")
                return
            params['delpre'] = delegator.pre
        elif self.remote_delegation_radio.isChecked():
            params['delegation_type'] = 'remote'
            # Get delegator and proxy if selected
            if self.delegator_dropdown.currentData():
                params['delpre'] = self.delegator_dropdown.currentData()
            proxy = self.delegate_proxy_dropdown.currentText()
            if proxy and proxy != "None":
                params['proxy_alias'] = proxy.split('|')[0].strip() if '|' in proxy else proxy

        params.update(alias=alias, key_type=key_type)
        delegator = self._local_delegator()
        if delegator is not None and delegator.kever.wits:
            self._pending_params = params
            self._show_auth_step(delegator)
            return
        self._launch(params)

    def _launch(self, params):
        """Start identifier creation with the reviewed ``params``."""
        result = habbing.create_identifier(app=self.app, **params)

        # Handle result
        if result['success']:
            logger.info(f"Identifier creation initiated: {result['message']}")
            # Keep dialog open if async operation, it will close when InceptDoer signals completion
            if not result.get('async'):
                self.identifier_created.emit(params['alias'], result.get('pre', ''))
                # Synchronous creation succeeded, close dialog
                self.close()
        else:
            logger.error(f"Identifier creation failed: {result['message']}")
            self.identifier_creation_failed.emit(result['message'])
            self.show_error(result['message'])
            self.create_button.setEnabled(True)
            self.create_button.setText("Authenticate" if self._auth_panel is not None else "Create")

    def _on_doer_event(self, doer_name: str, event_type: str, data: dict):
        """
        Handle doer events from the signal bridge.

        Args:
            doer_name: Name of the doer that emitted the event
            event_type: Type of event
            data: Event data dictionary
        """
        # Only handle identifier creation doer events
        if doer_name != "InceptDoer":
            return

        logger.info(f"CreateIdentifierDialog received doer_event: {doer_name} - {event_type} - {data}")

        # Handle identifier creation completion
        if event_type == "identifier_created":
            logger.info(f"Identifier created successfully: {data.get('alias')} ({data.get('pre')})")
            if data.get('alias') != self.name_field.text().strip() or self._mailbox_step is not None:
                return
            hab = self.app.vault.hby.habByPre(data.get('pre', ''))
            if hab is not None and mailbox.needs_mailbox(hab):
                # This event arrives inside the vault's running task; start the
                # provider task from the Qt loop instead.
                self._mailbox_step = 'working'
                QTimer.singleShot(0, lambda: self._start_mailbox_setup(hab))
                return
            self.identifier_created.emit(data.get('alias', ''), data.get('pre', ''))
            self.close()
        elif event_type == "identifier_creation_failed":
            logger.error(f"Identifier creation failed: {data.get('error')}")
            self.identifier_creation_failed.emit(data.get('error', ''))
            self.show_error(f"Identifier creation failed: {data.get('error')}")
            self.create_button.setEnabled(True)
            self.create_button.setText("Authenticate" if self._auth_panel is not None else "Create")
            # Keep dialog open so user can try again

    def _show_mailbox_panel(self):
        """Replace the form or witness codes with the mailbox step."""
        self.clear_error(resize_dialog=False)
        for widget in (self._auth_panel, getattr(self, '_auth_heading', None)):
            if widget is not None:
                self._outer_layout.removeWidget(widget)
                widget.setParent(None)
                widget.deleteLater()
        self._auth_panel = self._auth_heading = None
        self._form_widget.hide()
        if getattr(self, 'mailbox_status', None) is None:
            self.mailbox_status = QLabel()
            self.mailbox_status.setObjectName('mailbox_status')
            self.mailbox_status.setWordWrap(True)
            self.mailbox_status.setFixedWidth(380)
            self.mailbox_status.setStyleSheet(f"font-size: 13px; color: {colors.TEXT_DARK};")
            self._outer_layout.addWidget(self.mailbox_status)
        self.cancel_button.setText("Close")
        self.setFixedSize(420, 260)

    def _start_mailbox_setup(self, hab):
        """Give a new delegate its own mailbox, or say plainly why it cannot have one yet."""
        self._mailbox_hab = hab
        self._show_mailbox_panel()
        found = mailbox.mailbox_provider(self.app, hab)
        if found is None:
            self._mailbox_step = 'done'
            self.mailbox_status.setText(mailbox.no_provider_text(self.app, hab))
            self.create_button.setText("Done")
            self.create_button.setEnabled(True)
            return
        plugin, provider = found
        self._mailbox_step = 'working'
        self.mailbox_status.setText(mailbox.working_text(hab, provider))
        self.create_button.setText("Setting up mailbox...")
        self.create_button.setEnabled(False)
        self._mailbox_task = asyncio.ensure_future(self._run_mailbox_setup(plugin, hab, provider))

    async def _run_mailbox_setup(self, plugin, hab, provider):
        try:
            await plugin.provide_mailbox(self.app.vault, hab)
        except asyncio.CancelledError:
            raise
        except Exception as ex:
            logger.exception(f"Mailbox setup failed for {hab.name}")
            self._mailbox_step = 'retry'
            self.mailbox_status.setText(mailbox.failed_text(hab, provider, ex))
            self.create_button.setText("Try again")
            self.create_button.setEnabled(True)
            return
        self._finish_created(hab)

    def _finish_created(self, hab):
        if self._mailbox_task is not None and not self._mailbox_task.done():
            self._mailbox_task.cancel()
        self._mailbox_step = None
        self.identifier_created.emit(hab.name, hab.pre)
        self.close()

    def _on_key_type_radio_changed(self):
        """Handle key type radio button selection changes."""
        if self.key_chain_radio.isChecked():
            self.key_salt_field.show()
            self.num_signing_keys_field.show()
            self.num_rotation_keys_field.show()
        elif self.random_key_radio.isChecked():
            self.key_salt_field.hide()
            self.num_signing_keys_field.show()
            self.num_rotation_keys_field.show()

        # Update collapsible section height to reflect content changes
        self.advanced_config.update_content_height()
