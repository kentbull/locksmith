# -*- encoding: utf-8 -*-
"""
locksmith.ui.vault.groups.create module

Dialog for creating new group multisig identifiers.
"""
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QHBoxLayout, QButtonGroup
from keri import help

from locksmith.core import habbing
from locksmith.core.grouping import get_contacts_for_multisig
from locksmith.ui import colors
from locksmith.ui.toolkit.widgets import (
    LocksmithDialog,
    FloatingLabelLineEdit,
    LocksmithButton,
    LocksmithInvertedButton
)
from locksmith.ui.toolkit.widgets.buttons import LocksmithRadioButton, LocksmithCheckbox
from locksmith.ui.toolkit.widgets.extensible import ExtensibleSelectorWidget
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox, LocksmithLineEdit
from locksmith.ui.vault.shared.delegation_mixin import DelegationMixin

logger = help.ogler.getLogger(__name__)


class CreateGroupIdentifierDialog(DelegationMixin, LocksmithDialog):

    def __init__(self, icon_path, app, parent=None, config=None):
        logger.info("Creating CreateGroupIdentifierDialog...")
        self.config = config
        self.app = app

        # Create content widget
        content_widget = QWidget()
        content_widget.setStyleSheet(f"background-color: {colors.BACKGROUND_CONTENT};")
        layout = QVBoxLayout(content_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(15)

        layout.addSpacing(10)

        self.name_field = FloatingLabelLineEdit("Group Identifier Alias")
        self.name_field.setFixedWidth(400)
        layout.addWidget(self.name_field)

        layout.addSpacing(15)

        local_member_label = QLabel("Your Signing Identifier")
        local_member_label.setStyleSheet("font-weight: 600; font-size: 14px;")
        layout.addWidget(local_member_label)

        self.local_member_dropdown = FloatingLabelComboBox("Select Local Identifier")
        self.local_member_dropdown.setFixedWidth(400)
        layout.addWidget(self.local_member_dropdown)

        layout.addSpacing(15)

        participants_label = QLabel("Group Participants")
        participants_label.setStyleSheet("font-weight: 600; font-size: 14px;")
        layout.addWidget(participants_label)

        self.participants_selector = None
        self.participants_selector_container = QWidget()
        self.participants_selector_layout = QVBoxLayout(self.participants_selector_container)
        self.participants_selector_layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.participants_selector_container)

        thresholds_label = QLabel("Thresholds")
        thresholds_label.setStyleSheet("font-weight: 600; font-size: 14px;")
        layout.addWidget(thresholds_label)

        threshold_row = QHBoxLayout()
        self.signing_threshold_field = FloatingLabelLineEdit("Signing Threshold")
        self.signing_threshold_field.setText("1")
        self.signing_threshold_field.setFixedWidth(190)
        threshold_row.addWidget(self.signing_threshold_field)

        threshold_row.addSpacing(5)

        self.rotation_threshold_field = FloatingLabelLineEdit("Rotation Threshold")
        self.rotation_threshold_field.setText("1")
        self.rotation_threshold_field.setFixedWidth(190)
        threshold_row.addWidget(self.rotation_threshold_field)

        threshold_row.addStretch()
        layout.addLayout(threshold_row)

        checkbox_layout = QHBoxLayout()
        self.establishment_only_checkbox = LocksmithCheckbox("Establishment Only")
        checkbox_layout.addWidget(self.establishment_only_checkbox)
        checkbox_layout.addSpacing(10)
        self.do_not_delegate_checkbox = LocksmithCheckbox("Do Not Delegate")
        checkbox_layout.addWidget(self.do_not_delegate_checkbox)
        checkbox_layout.addStretch()
        layout.addLayout(checkbox_layout)


        layout.addSpacing(15)

        delegation_label = QLabel("Delegation (Optional)")
        delegation_label.setStyleSheet("font-weight: 600; font-size: 14px;")
        layout.addWidget(delegation_label)

        self.no_delegation_radio = LocksmithRadioButton("None")
        self.local_delegation_radio = LocksmithRadioButton("Local")
        self.remote_delegation_radio = LocksmithRadioButton("Remote")
        self.no_delegation_radio.setChecked(True)

        # Don't create QButtonGroup yet - wait until after super().__init__()
        delegation_radio_layout = QHBoxLayout()
        delegation_radio_layout.setSpacing(10)
        delegation_radio_layout.addWidget(self.no_delegation_radio)
        delegation_radio_layout.addWidget(self.local_delegation_radio)
        delegation_radio_layout.addWidget(self.remote_delegation_radio)
        delegation_radio_layout.addStretch()
        layout.addLayout(delegation_radio_layout)

        self.delegator_dropdown = FloatingLabelComboBox("Select Delegator")
        self.delegator_dropdown.setFixedWidth(400)
        self.delegator_dropdown.hide()
        layout.addWidget(self.delegator_dropdown)

        self.delegate_proxy_dropdown = FloatingLabelComboBox("Select Proxy")
        self.delegate_proxy_dropdown.setFixedWidth(400)
        self.delegate_proxy_dropdown.hide()
        layout.addWidget(self.delegate_proxy_dropdown)


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
        layout.addLayout(toad_layout)

        layout.addSpacing(15)
        layout.addStretch()

        button_row = QHBoxLayout()
        self.cancel_button = LocksmithInvertedButton("Cancel")
        button_row.addWidget(self.cancel_button)
        button_row.addSpacing(10)
        self.create_button = LocksmithButton("Create")
        button_row.addWidget(self.create_button)

        title_widget = QWidget()
        title_widget.setStyleSheet(f"background-color: {colors.BACKGROUND_CONTENT};")
        title_layout = QHBoxLayout(title_widget)
        title_layout.setContentsMargins(0, 0, 0, 0)

        icon = QLabel()
        pixmap = QIcon(icon_path).pixmap(32, 32)
        icon.setPixmap(pixmap)
        title_layout.addWidget(icon)

        title_label = QLabel("  Add a Group Identifier")
        title_label.setStyleSheet(f"color: {colors.TEXT_PRIMARY}; font-weight: 600; font-size: 20px;")
        title_layout.addWidget(title_label)
        title_layout.addStretch()

        super().__init__(
            parent=parent,
            title_content=title_widget,
            content=content_widget,
            initial_focus=self.name_field.line_edit,
            buttons=button_row,
            show_overlay=False
        )

        self.setFixedSize(455, 800)

        # NOW create the QButtonGroup after super().__init__() has been called
        delegation_button_group = QButtonGroup(self)
        delegation_button_group.addButton(self.no_delegation_radio)
        delegation_button_group.addButton(self.local_delegation_radio)
        delegation_button_group.addButton(self.remote_delegation_radio)

        # Connect delegation radio buttons
        self.no_delegation_radio.toggled.connect(self._on_delegation_radio_changed)
        self.local_delegation_radio.toggled.connect(self._on_delegation_radio_changed)
        self.remote_delegation_radio.toggled.connect(self._on_delegation_radio_changed)

        self.cancel_button.clicked.connect(self.close)
        self.create_button.clicked.connect(self.create_group_identifier)

        # Connect to vault signal bridge for doer events
        if hasattr(self.app.vault, 'signals'):
            self.app.vault.signals.doer_event.connect(self._on_doer_event)

        # Populate dropdowns and selector
        self._populate_local_member_dropdown()
        self._populate_participants_selector()

    def create_group_identifier(self):
        """Create a new group multisig identifier using the form values."""
        logger.info("Creating new group identifier...")

        # Get alias
        alias = self.name_field.text().strip()
        if not alias:
            logger.error("Alias is required")
            self.show_error("Alias is required")
            return

        # Get selected local member identifier
        mhab_data = self.local_member_dropdown.currentData()
        if not mhab_data:
            logger.error("Local member identifier is required for group multisig")
            self.show_error("Local member identifier is required for group multisig")
            return

        # Get selected participants
        if not self.participants_selector:
            logger.error("Participants selector not initialized")
            self.show_error("Participants selector not initialized")
            return

        selected_participants = self.participants_selector.get_selected_items()
        if not selected_participants:
            logger.error("At least one participant is required for group multisig")
            self.show_error("At least one participant is required for group multisig")
            return

        # Build smids list: local mhab + selected participants
        mhab_pre = mhab_data.get('aid')
        smids = [mhab_pre]

        for text, data in selected_participants:
            participant_pre = data.get('id')
            if participant_pre and participant_pre not in smids:
                smids.append(participant_pre)

        # Check for duplicate habs
        for (_,), habitat_record in self.app.vault.hby.db.habs.getFullItemIter():
            if habitat_record.smids and smids and set(habitat_record.smids) == set(smids):
                logger.error(f"Duplicate hab found for smids: {smids}")
                self.show_error(f"Duplicate hab found for smids: {smids}")
                return

        # Build parameters
        params = {
            'mhab_alias': mhab_data.get('alias'),
            'smids': smids,
            'rmids': smids,  # Default to same as smids
            'icount': str(len(smids)),
            'ncount': str(len(smids)),
            'isith': self.signing_threshold_field.text() or '1',
            'nsith': self.rotation_threshold_field.text() or '1',
            'toad': self.toad_field.text() or '0',
            'wits': [],  # Will add witness support later
            'estOnly': self.establishment_only_checkbox.isChecked(),
            'DnD': self.do_not_delegate_checkbox.isChecked(),
        }

        # Determine delegation type
        if self.no_delegation_radio.isChecked():
            params['delegation_type'] = 'none'
        elif self.local_delegation_radio.isChecked():
            params['delegation_type'] = 'local'
            delegator = self.delegator_dropdown.currentText()
            if delegator and delegator != "None":
                params['delpre'] = delegator.split('|')[0].strip() if '|' in delegator else delegator
        elif self.remote_delegation_radio.isChecked():
            params['delegation_type'] = 'remote'
            delegator = self.delegator_dropdown.currentText()
            if delegator and delegator != "None":
                params['delpre'] = delegator.split('|')[0].strip() if '|' in delegator else delegator
            proxy = self.delegate_proxy_dropdown.currentText()
            if proxy and proxy != "None":
                params['proxy_alias'] = proxy.split('|')[0].strip() if '|' in proxy else proxy

        logger.info(f"Group multisig with smids: {smids}")

        # Call the identifier creation function
        result = habbing.create_identifier(
            app=self.app,
            alias=alias,
            key_type='group',
            **params
        )

        # Handle result
        if result['success']:
            logger.info(f"Group identifier creation initiated: {result['message']}")
            if not result.get('async'):
                self.close()
        else:
            logger.error(f"Group identifier creation failed: {result['message']}")
            self.show_error(f"Group identifier creation failed: {result['message']}")

    def _on_doer_event(self, doer_name: str, event_type: str, data: dict):
        """
        Handle doer events from the signal bridge.

        Args:
            doer_name: Name of the doer that emitted the event
            event_type: Type of event
            data: Event data dictionary
        """
        # Only handle group identifier creation doer events
        if doer_name != "GroupMultisigInceptDoer":
            return

        logger.info(f"CreateGroupIdentifierDialog received doer_event: {doer_name} - {event_type} - {data}")

        # Handle group identifier creation completion
        if event_type == "group_identifier_created":
            logger.info(f"Group identifier created successfully: {data.get('alias')} ({data.get('pre')})")
            self.close()
        elif event_type == "group_inception_failed":
            logger.error(f"Group identifier creation failed: {data.get('error')}")
            self.show_error(f"Group identifier creation failed: {data.get('error')}")
        elif event_type == "group_inception_exn_queued":
            logger.info(f"Group inception proposal queued for: {data.get('pre')}")
            self.show_success(f"Group inception proposal queued for participants. If your mailbox is not already "
                              f"active, you may close this dialog and activate it now.")
            self.create_button.setText("Waiting...")
            self.create_button.setEnabled(False)

    def _populate_local_member_dropdown(self):
        """Populate the local member dropdown with local identifiers."""
        self.local_member_dropdown.clear()

        identifiers = habbing.get_local_non_multisig_identifiers_for_dropdown(self.app)
        for display_text, data in identifiers.items():
            self.local_member_dropdown.addItem(display_text, data)

        if self.local_member_dropdown.count() > 0:
            self.local_member_dropdown.setCurrentIndex(0)

    def _populate_participants_selector(self):
        """Create and populate the participants selector with eligible contacts."""
        # Remove existing selector if present
        if self.participants_selector:
            self.participants_selector_layout.removeWidget(self.participants_selector)
            self.participants_selector.deleteLater()
            self.participants_selector = None

        # Get eligible contacts (transferable remote identifiers)
        contacts = get_contacts_for_multisig(self.app)

        # Build items as (display_text, data_dict) tuples
        items = []
        for contact in contacts:
            display_text = contact.get('alias') or f"{contact['id'][:12]}..."
            items.append((display_text, contact))

        # Create new selector with populated items
        self.participants_selector = ExtensibleSelectorWidget(
            dropdown_label="Select Participant",
            selector_dropdown_items=items,
            parent=self,
            max_scrollable_height=150
        )
        self.participants_selector.setFixedWidth(400)

        # Add to container
        self.participants_selector_layout.addWidget(self.participants_selector)

