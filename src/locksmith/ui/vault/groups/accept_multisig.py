# -*- encoding: utf-8 -*-
"""
locksmith.ui.vault.groups.accept_multisig module

Dialog for accepting multisig group inception proposals.
"""
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QHBoxLayout, QScrollArea,
    QFrame
)
from keri import help, kering
from keri.help import helping
from locksmith.core.grouping import MultisigJoinDoer, inception_proposal
from locksmith.ui import colors
from locksmith.ui.toolkit.widgets import (
    LocksmithDialog,
    LocksmithButton,
    LocksmithInvertedButton, FloatingLabelLineEdit
)
from locksmith.ui.toolkit.widgets.fields import FloatingLabelComboBox
from locksmith.ui.vault.shared.display_helpers import resolve_alias, add_info_row

if TYPE_CHECKING:
    from locksmith.core.apping import LocksmithApplication
    from locksmith.ui.vault.page import VaultPage

logger = help.ogler.getLogger(__name__)


class AcceptMultisigProposalDialog(LocksmithDialog):
    """Dialog for accepting multisig group inception proposals.

    Displays the proposal details including participants and thresholds,
    allows selection of local identifier for signing, and accepts/rejects.
    """

    def __init__(
        self,
        app: "LocksmithApplication",
        parent: "VaultPage",
        proposal_said: str
    ):
        """
        Initialize the AcceptMultisigProposalDialog.

        Args:
            app: Application instance
            parent: Parent widget (VaultPage)
            proposal_said: SAID of the proposal exn message to process
        """
        self.app = app
        self.parent_widget = parent
        self.proposal_said = proposal_said

        # Load proposal message data
        try:
            self._load_proposal_message()
        except Exception as e:
            logger.exception(f"Failed to load proposal message: {e}")
            self.proposal_error = str(e)
            self._build_error_ui()
            return

        # Build the dialog UI
        self._build_ui()

        # Initialize parent dialog
        super().__init__(
            parent=self.parent_widget,
            title="Join Multisig Group",
            title_icon=":/assets/material-icons/group_add.svg",
            content=self.scroll_area,
            buttons=self.button_row,
            show_overlay=False
        )

        self.setFixedSize(550, 880)

        # Connect signals
        self.cancel_button.clicked.connect(self.close)
        self.accept_button.clicked.connect(self._on_accept)

        # Connect to vault signal bridge for doer events
        if self.app and hasattr(self.app, 'vault') and self.app.vault and hasattr(self.app.vault, 'signals'):
            self.app.vault.signals.doer_event.connect(self._on_doer_event)

    def _load_proposal_message(self):
        """Load proposal message using exchanging.cloneMessage()"""
        logger.info(f"Loading multisig proposal: {self.proposal_said}")

        self.exn, self.icp_serder = inception_proposal(self.app.vault, self.proposal_said)

        logger.debug(f"Proposal message loaded successfully: {self.exn.ked}")

        # Extract proposal metadata
        self.initiator = self.exn.ked['i']
        self.timestamp = self.exn.ked.get('dt', '')

        # Extract payload
        payload = self.exn.ked.get('a', {})
        self.gid = payload.get('gid', '')
        self.smids = payload.get('smids', [])
        self.rmids = payload.get('rmids', self.smids)
        self.delegator = self.icp_serder.ked.get('di')

        # Display numeric thresholds in decimal while preserving weighted expressions.
        tholder, ntholder = self.icp_serder.tholder, self.icp_serder.ntholder
        self.isith = tholder.sith if tholder.weighted else tholder.num
        self.nsith = ntholder.sith if ntholder.weighted else ntholder.num

        # Check if local identifier is in smids
        self.local_smids = []
        for pre, hab in self.app.vault.hby.habs.items():
            if hab.pre in self.smids:
                self.local_smids.append({'alias': hab.name, 'pre': hab.pre})

        if not self.local_smids:
            raise ValueError("None of your local identifiers are participants in this proposal")

        logger.info(f"Proposal for group {self.gid[:16]}... with {len(self.smids)} participants")

    def _build_ui(self):
        """Build the dialog UI."""
        # Create scroll area for content
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        # Content widget
        content_widget = QWidget()
        content_widget.setStyleSheet(f"background-color: {colors.BACKGROUND_CONTENT};")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(20, 20, 20, 20)
        content_layout.setSpacing(15)

        # Proposal Information Section
        info_section_label = QLabel("Proposal Information")
        info_section_label.setStyleSheet("font-weight: 600; font-size: 16px;")
        content_layout.addWidget(info_section_label)

        # Initiator
        initiator_alias = resolve_alias(self.app,self.initiator)
        initiator_display = initiator_alias if initiator_alias else f"{self.initiator[:24]}..."
        add_info_row(content_layout, "From:", initiator_display)

        # Timestamp
        if self.timestamp:
            try:
                ts_dt = helping.fromIso8601(self.timestamp)
                timestamp_display = ts_dt.strftime("%b %d, %Y %I:%M %p")
            except Exception:
                timestamp_display = self.timestamp
            add_info_row(content_layout, "Received:", timestamp_display)

        # Group ID
        add_info_row(content_layout, "Group ID:", f"{self.gid[:32]}...")

        content_layout.addSpacing(10)

        # Participants Section
        participants_section_label = QLabel("Participants")
        participants_section_label.setStyleSheet("font-weight: 600; font-size: 16px;")
        content_layout.addWidget(participants_section_label)

        for i, smid in enumerate(self.smids):
            alias = resolve_alias(self.app,smid)
            is_local = any(l['pre'] == smid for l in self.local_smids)
            suffix = " (You)" if is_local else ""
            display = f"{alias}{suffix}" if alias else f"{smid[:20]}...{suffix}"
            add_info_row(content_layout, f"Member {i+1}:", display)

        content_layout.addSpacing(10)

        # Configuration Section
        config_section_label = QLabel("Configuration")
        config_section_label.setStyleSheet("font-weight: 600; font-size: 16px;")
        content_layout.addWidget(config_section_label)

        add_info_row(content_layout, "Signing Threshold:", str(self.isith))
        add_info_row(content_layout, "Rotation Threshold:", str(self.nsith))
        add_info_row(content_layout, "Total Participants:", str(len(self.smids)))
        add_info_row(content_layout, "Rotation Members:", "Same as signing members"
                     if self.rmids == self.smids else ", ".join(self.rmids))

        # Consent includes the signed inception's witness policy and configuration traits.
        add_info_row(content_layout, "Witnesses:", ", ".join(self.icp_serder.ked['b']) or "None")
        add_info_row(content_layout, "Witness Threshold:", str(self.icp_serder.bner.num))
        trait_names = {kering.TraitDex.EstOnly: "Establishment Only",
                       kering.TraitDex.DoNotDelegate: "Do Not Delegate"}
        traits = [trait_names.get(trait, trait) for trait in self.icp_serder.traits]
        add_info_row(content_layout, "Traits:", ", ".join(traits) or "None")

        if self.delegator:
            delegator_alias = resolve_alias(self.app,self.delegator)
            delegator_display = delegator_alias if delegator_alias else f"{self.delegator[:20]}..."
            add_info_row(content_layout, "Delegator:", delegator_display)

        content_layout.addSpacing(20)

        # Local Identifier Selection Section
        local_id_section_label = QLabel("Select Your Identifier")
        local_id_section_label.setStyleSheet("font-weight: 600; font-size: 16px;")
        content_layout.addWidget(local_id_section_label)

        group_alias_note = QLabel("Assign a name for the local identifier group.")
        group_alias_note.setStyleSheet(f"color: {colors.TEXT_MUTED}; font-size: 13px;")
        group_alias_note.setFixedWidth(400)
        group_alias_note.setWordWrap(True)
        content_layout.addWidget(group_alias_note)
        self.group_identifier_alias = FloatingLabelLineEdit("Group Identifier Alias")
        self.group_identifier_alias.setFixedWidth(400)
        content_layout.addWidget(self.group_identifier_alias)

        local_id_note = QLabel("Select a local identifier to sign for this group. Only one identifier per vault may "
                               "sign for a given group.")
        local_id_note.setStyleSheet(f"color: {colors.TEXT_MUTED}; font-size: 13px;")
        local_id_note.setWordWrap(True)
        local_id_note.setFixedWidth(400)
        content_layout.addWidget(local_id_note)
        self.local_id_dropdown = FloatingLabelComboBox("Local Identifier")
        self.local_id_dropdown.setFixedWidth(400)

        for item in self.local_smids:
            self.local_id_dropdown.addItem(f"{item['alias']} ({item['pre']}...)", item)


        content_layout.addWidget(self.local_id_dropdown)

        content_layout.addStretch()

        self.scroll_area.setWidget(content_widget)

        # Button row
        self.button_row = QHBoxLayout()
        self.cancel_button = LocksmithInvertedButton("Close")
        self.button_row.addWidget(self.cancel_button)
        self.button_row.addSpacing(10)
        self.accept_button = LocksmithButton("Join")
        self.button_row.addWidget(self.accept_button)

    def _build_error_ui(self):
        """Build error UI when proposal loading fails."""
        content_widget = QWidget()
        content_widget.setStyleSheet(f"background-color: {colors.BACKGROUND_CONTENT};")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(20, 20, 20, 20)

        error_label = QLabel(f"Error loading proposal:\n\n{self.proposal_error}")
        error_label.setStyleSheet(f"color: {colors.DANGER};")
        error_label.setWordWrap(True)
        content_layout.addWidget(error_label)
        content_layout.addStretch()

        # Create scroll area
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setWidget(content_widget)

        # Button row
        self.button_row = QHBoxLayout()
        close_button = LocksmithInvertedButton("Close")
        close_button.clicked.connect(self.close)
        self.button_row.addWidget(close_button)

        # Initialize parent dialog
        super().__init__(
            parent=self.parent_widget,
            title="Error",
            content=self.scroll_area,
            buttons=self.button_row,
            show_overlay=False
        )

        self.setFixedSize(400, 250)

    def _on_accept(self):
        """Handle accept button click - join the multisig group."""
        logger.info("Accepting multisig proposal...")

        # Get selected local identifier
        mhab_data = self.local_id_dropdown.currentData()
        if not mhab_data:
            logger.error("No local identifier selected")
            return

        mhab_alias = mhab_data.get('alias')
        mhab = self.app.vault.hby.habByName(mhab_alias)

        if not mhab:
            logger.error(f"Could not find local identifier: {mhab_alias}")
            return

        # Disable buttons during processing
        self.accept_button.setEnabled(False)
        self.cancel_button.setEnabled(False)
        self.accept_button.setText("Joining...")

        # Create and launch MultisigJoinDoer
        try:
            join_doer = MultisigJoinDoer(
                app=self.app,
                alias=self.group_identifier_alias.text(),  # Use local alias as group name for now
                proposal_said=self.proposal_said,
                mhab=mhab,
                signal_bridge=self.app.vault.signals
            )
            self.app.vault.extend([join_doer])
            logger.info(f"MultisigJoinDoer started for proposal {self.proposal_said}")

        except Exception as e:
            logger.exception(f"Failed to start MultisigJoinDoer: {e}")
            self.accept_button.setEnabled(True)
            self.cancel_button.setEnabled(True)
            self.accept_button.setText("Accept & Join")

    def _on_doer_event(self, doer_name: str, event_type: str, data: dict):
        """Handle doer events from the signal bridge."""
        if doer_name != "MultisigJoinDoer":
            return

        logger.info(f"AcceptMultisigProposalDialog received: {event_type} - {data}")

        if event_type == "group_identifier_joined":
            logger.info(f"Successfully joined group: {data.get('alias')} ({data.get('pre')})")
            self.close()
        elif event_type == "group_join_failed":
            logger.error(f"Failed to join group: {data.get('error')}")
            self.accept_button.setEnabled(True)
            self.cancel_button.setEnabled(True)
            self.accept_button.setText("Accept & Join")
            # TODO: Show error message to user
