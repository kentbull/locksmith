# -*- encoding: utf-8 -*-
"""
locksmith.ui.window module

This module contains the main window for the Locksmith application.
"""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QHBoxLayout,
    QStackedWidget,
)
from keri import help

from locksmith.core.apping import LocksmithApplication
from locksmith.core.configing import LocksmithConfig
from locksmith.ui.home import HomePage
from locksmith.ui.navigation import NavigationManager, Pages
from locksmith.ui.toolbar import LocksmithToolbar
from locksmith.ui.toolkit.widgets.toast import NotificationToast
from locksmith.ui.vault.page import VaultPage
from locksmith.ui.vaults.drawer import VaultDrawer

logger = help.ogler.getLogger(__name__)


class LocksmithWindow(QMainWindow):
    """
    Main application window.

    Handles composition of components, navigation management,
    and delegates functionality to specialized components.
    """

    def __init__(self, config: LocksmithConfig | None = None):
        """
        Initialize the main window.

        Args:
            config: Application configuration.
        """
        super().__init__()

        self.app = LocksmithApplication(config=config)

        # Window setup
        self.setWindowTitle("Locksmith")
        self.setMinimumSize(1280, 1024)

        # Create navigation manager
        self.nav_manager = NavigationManager(self)
        self.nav_manager.page_changed.connect(self.on_page_changed)

        # Create and add toolbar
        self.toolbar = LocksmithToolbar(self.app, self)
        self.toolbar.settings_clicked.connect(self.on_settings)
        self.toolbar.vaults_clicked.connect(self.on_vaults)
        self.toolbar.lock_clicked.connect(self.on_lock_vault)
        self.toolbar.home_clicked.connect(self.on_home)
        self.toolbar.notifications_clicked.connect(self.on_notifications)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, self.toolbar)

        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Create stacked widget for pages (not StackAll mode)
        self.main_stack = QStackedWidget()
        self.main_stack.setContentsMargins(0, 0, 0, 0)

        # Create pages
        self.pages = {}
        self.pages[Pages.HOME] = HomePage(self)
        self.pages[Pages.VAULT] = VaultPage(self)

        # Store VaultPage reference for plugin access
        vault_page = self.pages[Pages.VAULT]
        self.app._vault_page = vault_page

        # Discover and initialize plugins (registers pages and menus)
        self.app.plugin_manager.discover_and_initialize(vault_page, vault_page.nav_menu)

        # Add pages to stack
        for page in self.pages.values():
            self.main_stack.addWidget(page)

        # Add stack to layout
        main_layout.addWidget(self.main_stack)

        # Create vault drawer (homepage-specific, overlays on top)
        self.vault_drawer = VaultDrawer(self, self.toolbar)
        self.vault_drawer.drawer_opened.connect(lambda: self.toolbar.set_vaults_active(True))
        self.vault_drawer.drawer_closed.connect(lambda: self.toolbar.set_vaults_active(False))

        # Toast notification tracking (only one toast at a time)
        self.current_toast: NotificationToast | None = None
        self._toast_signal_connected = False

        # Start on home page
        self.nav_manager.navigate_to(Pages.HOME)

        logger.info("LocksmithHome initialized")

    def on_page_changed(self, page_name: str, params: dict):
        """
        Handle page change from NavigationManager.

        Args:
            page_name (str): Name of the page to show
            params (dict): Parameters for the page
        """
        try:
            page_enum = Pages(page_name)
            page = self.pages.get(page_enum)

            if page is None:
                logger.error(f"Page not found: {page_name}")
                return

            logger.info(f"Switching to page: {page_name} with params: {params}")

            # Get the current page (to call on_hide)
            current_page = self.main_stack.currentWidget()
            if current_page and hasattr(current_page, 'on_hide'):
                current_page.on_hide()

            # Switch to new page
            self.main_stack.setCurrentWidget(page)

            # Update toolbar configuration
            toolbar_config = page.get_toolbar_config()
            logger.info(f"Toolbar config: {toolbar_config}")
            self.toolbar.update_for_config(toolbar_config)

            # Update page-specific UI elements
            self._update_page_ui(page_enum)

            # Call on_show for new page
            if hasattr(page, 'on_show'):
                page.on_show(**params)

        except ValueError:
            logger.error(f"Invalid page name: {page_name}")

    def _update_page_ui(self, page: Pages):
        """
        Update page-specific UI elements (drawers, menus, etc.).

        Args:
            page (Pages): The page being shown
        """
        if page == Pages.HOME:
            # Home page: vault drawer is available
            self.vault_drawer.show_drawer_widgets()
            # Ensure drawer is properly positioned after showing
            self.vault_drawer.handle_resize(
                self.width(),
                self.height(),
                self.toolbar.height()
            )
            # Disconnect toast signals when leaving vault
            self._disconnect_toast_signals()

        elif page == Pages.VAULT:
            # Vault page: hide vault drawer (nav menu is in VaultPage)
            self.vault_drawer.hide_drawer_widgets()
            # Connect toast signals when vault is active
            self._connect_toast_signals()

    def _connect_toast_signals(self):
        """Connect to vault signals for toast notifications."""
        if not self._toast_signal_connected and self.app.vault:
            try:
                self.app.vault.signals.doer_event.connect(self._on_notification_event)
                self._toast_signal_connected = True
                logger.info("Connected to vault notification signals")
            except Exception as e:
                logger.exception(f"Error connecting toast signals: {e}")

    def _disconnect_toast_signals(self):
        """Disconnect from vault signals."""
        if self._toast_signal_connected and self.app.vault:
            try:
                self.app.vault.signals.doer_event.disconnect(self._on_notification_event)
                self._toast_signal_connected = False
                logger.info("Disconnected from vault notification signals")
            except Exception as e:
                logger.exception(f"Error disconnecting toast signals: {e}")

    def _on_notification_event(self, doer_name: str, event_type: str, data: dict):
        """
        Handle notification events from the vault.

        Args:
            doer_name: Name of the doer that emitted the event
            event_type: Type of event
            data: Event data dictionary
        """
        if doer_name == "NotificationToast" and event_type == "new_notification":
            # Show the toast with notification details
            datetime = data.get('datetime', '')
            message = data.get('message', 'New notification')
            pending_count = data.get('pending_count', 1)

            self.show_notification_toast(datetime, message, pending_count)

    def resizeEvent(self, event):
        """
        Handle window resize - delegate to components.

        Args:
            event: Resize event.
        """
        super().resizeEvent(event)

        # Always update vault drawer positioning to keep geometry in sync
        # even when drawer is hidden (ensures correct positioning when shown later)
        if hasattr(self, 'vault_drawer'):
            self.vault_drawer.handle_resize(
                self.width(),
                self.height(),
                self.toolbar.height()
            )

        # Reposition toast if it exists and is visible
        if self.current_toast and self.current_toast.isVisible():
            self.current_toast.position_in_parent(
                self.width(),
                self.height(),
                self.toolbar.height()
            )

    def on_settings(self):
        """Handle settings button click."""
        logger.info("Settings clicked")
        # Settings dialog is shown by toolbar
        pass

    def on_vaults(self):
        """Handle vaults button click - delegate to drawer."""
        logger.info("Vaults clicked")
        self.vault_drawer.toggle()

    def on_lock_vault(self):
        """Handle lock button click - close vault and return to home."""
        logger.info("Lock button clicked - closing vault")

        # Disconnect toast signals before closing vault
        self._disconnect_toast_signals()

        # Close any visible toast
        if self.current_toast:
            self.current_toast.close_toast()

        # Close the vault (cleanup QtTask, etc.)
        self.app.close_vault()

        # Clear navigation stack (we're going back to home, not "back" navigation)
        self.nav_manager.clear_navigation_stack()

        # Navigate to home page
        self.nav_manager.navigate_to(Pages.HOME)

        # Reset title
        self.setWindowTitle("Locksmith")

    def on_home(self):
        """Handle home icon click - close vault if open and navigate to home."""
        logger.info("Home icon clicked")

        # If a vault is open, close it first
        if self.app.is_vault_open:
            # Disconnect toast signals before closing vault
            self._disconnect_toast_signals()

            # Close any visible toast
            if self.current_toast:
                self.current_toast.close_toast()

            self.app.close_vault()

        # Clear navigation stack
        self.nav_manager.clear_navigation_stack()

        # Navigate to home page
        self.nav_manager.navigate_to(Pages.HOME)

    def show_notification_toast(self, datetime: str, message: str, pending_notifications: int):
        """
        Show a notification toast in the lower right corner.

        Only one toast can be shown at a time. If a toast is already visible,
        it will be closed before showing the new one.

        Args:
            datetime: The datetime string to display
            message: The notification message text
            pending_notifications: Number of pending notifications
        """
        # Close existing toast if any
        if self.current_toast:
            self.current_toast.close_toast()
            self.current_toast.deleteLater()
            self.current_toast = None

        # Create new toast
        self.current_toast = NotificationToast(datetime, message, pending_notifications, self)

        # Connect signals
        self.current_toast.clicked.connect(self._on_toast_clicked)
        self.current_toast.closed.connect(self._on_toast_closed)

        # Position and show
        self.current_toast.position_in_parent(
            self.width(),
            self.height(),
            self.toolbar.height()
        )
        self.current_toast.show_toast()

        logger.info(f"Notification toast shown: {message[:50]}...")

    def _on_toast_clicked(self):
        """Handle toast click - navigate to notification screen."""
        logger.info("Toast clicked - navigating to notifications page")

        # Close the toast
        if self.current_toast:
            self.current_toast.close_toast()

        # Navigate to vault page if not already there
        current_page = self.main_stack.currentWidget()
        vault_page = self.pages.get(Pages.VAULT)

        if vault_page and current_page != vault_page:
            self.nav_manager.navigate_to(Pages.VAULT)

        # Show notifications page
        if vault_page:
            vault_page.show_notifications()

    def _on_toast_closed(self):
        """Handle toast closed - cleanup reference."""
        if self.current_toast:
            self.current_toast.deleteLater()
            self.current_toast = None
        logger.info("Toast closed")

    def on_notifications(self):
        """Handle notifications button click - show notifications page in vault."""
        logger.info("Notifications button clicked")

        # Only show notifications if we're on the vault page
        vault_page = self.pages.get(Pages.VAULT)
        if vault_page and self.main_stack.currentWidget() == vault_page:
            vault_page.show_notifications()