"""Handler for zetacomponents/Base package."""

import logging
from typing import TYPE_CHECKING

from composer_ebuild.package_handlers.base import PackageHandler
from composer_ebuild.utils import get_package_name

if TYPE_CHECKING:
    from composer_ebuild.package import ComposerPackage

logger = logging.getLogger(__name__)


class ZetacomponentsBaseHandler(PackageHandler):

    """Special handling for zetacomponents/Base package."""

    def can_handle(self, package_name: str) -> bool:
        """
        Check if this handler can handle the zetacomponents/Base package.

        Args:
            package_name: The name of the package to check

        Returns:
            True if the package is zetacomponents/Base, False otherwise

        """
        normalized_name = get_package_name(package_name)
        can_handle = normalized_name == "zetacomponents-base"
        logger.debug("Checking if ZetacomponentsBaseHandler can handle '%s': %s", package_name, can_handle)
        return can_handle

    def get_blockers(self, _package: "ComposerPackage") -> list[str]:
        """
        Get list of blocker dependencies for zetacomponents/Base.

        Args:
            _package: The ComposerPackage instance (unused)

        Returns:
            List containing blocker for old package name

        """
        logger.debug("Getting blockers for zetacomponents/Base")
        return ["!dev-php/zetacomponents-Base"]
