"""Registry for package handlers."""

import logging
from typing import TYPE_CHECKING

from composer_ebuild.package_handlers.base import PackageHandler
from composer_ebuild.package_handlers.composer import ComposerHandler
from composer_ebuild.package_handlers.jsonrainbow_json_schema import JsonrainbowJsonSchemaHandler
from composer_ebuild.package_handlers.theseer_autoload import TheseerAutoloadHandler
from composer_ebuild.package_handlers.theseer_directoryscanner import TheseerDirectoryScannerHandler
from composer_ebuild.package_handlers.zetacomponents_base import ZetacomponentsBaseHandler
from composer_ebuild.package_handlers.zetacomponents_console_tools import ZetacomponentsConsoleToolsHandler

if TYPE_CHECKING:
    from composer_ebuild.package import ComposerPackage

logger = logging.getLogger(__name__)


class HandlerRegistry:

    """Registry to manage and lookup package handlers."""

    _handlers: list[PackageHandler]

    def __init__(self) -> None:
        """Initialize the handler registry and register default handlers."""
        self._handlers = []
        self._register_default_handlers()

    def _register_default_handlers(self) -> None:
        """Register all default handlers."""
        logger.debug("Registering default package handlers")
        self.register(ComposerHandler())
        self.register(JsonrainbowJsonSchemaHandler())
        self.register(TheseerAutoloadHandler())
        self.register(TheseerDirectoryScannerHandler())
        self.register(ZetacomponentsBaseHandler())
        self.register(ZetacomponentsConsoleToolsHandler())

    def register(self, handler: PackageHandler) -> None:
        """
        Register a new handler.

        Args:
            handler: The PackageHandler instance to register

        """
        logger.debug("Registering handler: %s", handler.__class__.__name__)
        self._handlers.append(handler)

    def get_handler(self, package_name: str) -> PackageHandler | None:
        """
        Get the appropriate handler for a package.

        Args:
            package_name: The name of the package

        Returns:
            The appropriate PackageHandler instance, or None if no handler matches

        """
        logger.debug("Looking for handler for package: %s", package_name)
        for handler in self._handlers:
            if handler.can_handle(package_name):
                logger.debug("Found handler: %s", handler.__class__.__name__)
                return handler
        logger.debug("No custom handler found for package: %s", package_name)
        return None

    def get_blockers(self, package_name: str, package: "ComposerPackage") -> list[str]:
        """
        Get blockers for a package if a handler exists.

        Args:
            package_name: The name of the package
            package: The ComposerPackage instance

        Returns:
            List of blocker strings, or empty list if no handler or no blockers

        """
        logger.debug("Getting blockers for package: %s", package_name)
        handler = self.get_handler(package_name)
        if handler:
            blockers = handler.get_blockers(package)
            logger.debug("Found %d blocker(s) for %s", len(blockers), package_name)
            return blockers
        logger.debug("No handler found for %s, no blockers to add", package_name)
        return []
