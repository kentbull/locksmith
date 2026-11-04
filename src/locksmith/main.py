import asyncio
import ctypes
import logging
import os
import platform
import sys
from ctypes.util import find_library
from pathlib import Path

from PySide6.QtNetwork import QSslCertificate, QSslConfiguration
from PySide6.QtWidgets import (
    QApplication
)
from keri import help
from qasync import QEventLoop

# This import is necessary for locating assets via shortened directory paths
from locksmith import resources_rc

# Configure KERI ogler logging
FORMAT = '%(asctime)s [%(name)s] %(levelname)-8s %(message)s'
LOG_LEVEL = "INFO"

help.ogler.level = logging.getLevelName(LOG_LEVEL)
baseFormatter = logging.Formatter(FORMAT)
baseFormatter.default_msec_format = None
help.ogler.baseConsoleHandler.setFormatter(baseFormatter)

logger = help.ogler.getLogger(__name__)


def configure_tls_trust(cafile):
    """Add an explicit SSL_CERT_FILE bundle to Qt's existing trusted roots."""
    if cafile is None:
        return
    path = Path(cafile).expanduser().resolve()
    try:
        certificates = QSslCertificate.fromData(path.read_bytes())
    except OSError as error:
        raise ValueError(f'Cannot read SSL_CERT_FILE CA bundle: {path}') from error
    if not certificates:
        raise ValueError(f'SSL_CERT_FILE contains no valid PEM certificates: {path}')
    config = QSslConfiguration.defaultConfiguration()
    config.setCaCertificates(config.caCertificates() + certificates)
    QSslConfiguration.setDefaultConfiguration(config)

# Custom Libsodium Loader #
# This code has to be in the main module to avoid a partially initialized module error
# for the 'locksmith' module.
# ###########################

def load_custom_libsodium():
    """
    Instruct the pysodium library to load a custom libsodium dylib from the appdir/libsodium
    """
    if getattr(sys, 'frozen', False):
        appdir = sys._MEIPASS
        print(f'Running from frozen bundle at {appdir}')
    else:
        return

    set_load_path_or_link(appdir)
    set_load_env_vars(appdir)

    custom_path = os.path.expanduser(f'{os.path.dirname(os.path.abspath(__file__))}/libsodium/libsodium.dylib')
    logger.info(f'Loading custom libsodium from {custom_path}')
    if os.path.exists(custom_path):
        logger.info(f'Found custom libsodium at {custom_path}')
        ctypes.cdll.LoadLibrary(custom_path)
    else:
        logger.info('Custom libsodium not found, loading from system')
        libsodium_path = find_library('sodium')
        if libsodium_path is not None:
            logger.info(f'Found libsodium at {libsodium_path}')
            ctypes.cdll.LoadLibrary(libsodium_path)
            logger.info(f'Loaded libsodium from {libsodium_path}')
        else:
            raise OSError('libsodium not found')


def set_load_path_or_link(appdir):
    """
    Symlinks the correct libsodium dylib based on the architecture of the system.
    """
    lib_home = f'{appdir}/libsodium'
    match platform.processor():
        case 'x86_64':
            sodium_lib = 'libsodium.26.x86_64.dylib'
        case 'arm' | 'arm64' | 'aarch64':
            sodium_lib = 'libsodium.23.arm.dylib'
        # doesn't work
        case 'i386':
            sodium_lib = 'libsodium.23.i386.dylib'
        case _:
            raise OSError(f'Unsupported architecture: {platform.processor()}')

    lib_path = Path(os.path.join(lib_home, sodium_lib))

    logger.info(f'Arch: {platform.processor()} Linking libsodium lib: {sodium_lib} at path: {lib_path}')

    if not lib_path.exists():
        logger.error(f'libsodium for architecture {platform.processor()} missing at {lib_path}, cannot link')
        raise FileNotFoundError(f'libsodium for architecture {platform.processor()} missing at {lib_path}')

    link_path = Path(os.path.join(lib_home, 'libsodium.dylib'))
    logger.info(f'Symlinking {lib_path} to {link_path}')
    try:
        os.symlink(f'{lib_path}', f'{link_path}')
    except FileExistsError:
        os.remove(f'{link_path}')
        os.symlink(f'{lib_path}', f'{link_path}')
    logger.info(f'Linked libsodium dylib: {link_path}')


def set_load_env_vars(appdir):
    """
    Sets the DYLD_LIBRARY_PATH and LD_LIBRARY_PATH that pysodium uses to find libsodium to the custom libsodium dylib.
    """
    local_path = appdir

    logger.info(f'Setting DYLD_LIBRARY_PATH to {local_path}/libsodium')
    os.environ['DYLD_LIBRARY_PATH'] = f'{local_path}/libsodium'

    logger.info(f'Setting LD_LIBRARY_PATH to {local_path}/libsodium')
    os.environ['LD_LIBRARY_PATH'] = f'{local_path}/libsodium'


# End Custom Libsodium Loader ########

if __name__ == "__main__":
    # Check if running in MCP server mode (for PyInstaller bundle subprocess)
    if len(sys.argv) > 1 and sys.argv[1] == "--mcp-server":
        logger.info("MCP server mode detected")
        logger.info(f"sys.argv: {sys.argv}")
        logger.info(f"sys.executable: {sys.executable}")
        logger.info(f"Frozen: {getattr(sys, 'frozen', False)}")


    if platform.system() == 'Darwin':
        load_custom_libsodium()

    # from archie import resources_rc
    from locksmith.ui.styles import set_global_styles
    from locksmith.core.configing import LocksmithConfig
    from locksmith.ui.window import LocksmithWindow

    app = QApplication(sys.argv)
    configure_tls_trust(os.environ.get('SSL_CERT_FILE'))
    set_global_styles(app)

    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)

    config = LocksmithConfig.get_instance()
    window = LocksmithWindow(config)
    window.show()

    with loop:
        sys.exit(loop.run_forever())
