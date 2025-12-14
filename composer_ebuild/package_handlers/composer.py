"""Handler for composer/composer package."""

import logging
from typing import TYPE_CHECKING

from composer_ebuild.package_handlers.base import PackageHandler
from composer_ebuild.utils import get_package_name

if TYPE_CHECKING:
    from composer_ebuild.package import ComposerPackage

logger = logging.getLogger(__name__)


class ComposerHandler(PackageHandler):

    """Special handling for composer/composer package."""

    def can_handle(self, package_name: str) -> bool:
        """
        Check if this handler can handle the composer/composer package.

        Args:
            package_name: The name of the package to check

        Returns:
            True if the package is composer/composer, False otherwise

        """
        normalized_name = get_package_name(package_name)
        can_handle = normalized_name == "composer"
        logger.debug("Checking if ComposerHandler can handle '%s': %s", package_name, can_handle)
        return can_handle

    def get_src_prepare(self, package: "ComposerPackage") -> str:
        """
        Generate custom src_prepare section for composer/composer.

        Composer does not work well with the defaults, so we need special handling.

        Args:
            package: The ComposerPackage instance

        Returns:
            Custom src_prepare section as a string

        """
        logger.debug("Generating custom src_prepare for composer/composer")

        src_prepare = "default\n\n"
        src_prepare += "\tmkdir vendor || die\n\n"
        src_prepare += "\tphpab \\\n"
        src_prepare += "\t\t--quiet \\\n"
        src_prepare += "\t\t--output vendor/autoload.php \\\n"
        src_prepare += '\t\t--template "${FILESDIR}"/autoload.php.tpl \\\n'
        src_prepare += "\t\t--basedir src \\\n"
        src_prepare += "\t\tsrc \\\n"
        src_prepare += "\t\t|| die\n"

        dependency_autoloads = package.get_src_dependency_autoloads(autoload_file="vendor/autoload.php")
        if dependency_autoloads:
            src_prepare += dependency_autoloads

        return src_prepare

    def get_src_install(self, _package: "ComposerPackage") -> str:
        """
        Generate custom src_install section for composer/composer.

        Args:
            _package: The ComposerPackage instance (unused)

        Returns:
            Custom src_install section as a string

        """
        logger.debug("Generating custom src_install for composer/composer")

        src_install = 'insinto "/usr/share/composer"\n'
        src_install += "\tdoins -r LICENSE res src vendor\n\n"

        # Install bin directory and create symlink
        src_install += '\tinsinto "/usr/share/composer"\n'
        src_install += "\tdoins -r bin\n"
        src_install += '\tfperms +x "/usr/share/composer/bin"/composer\n\n'
        src_install += '\tdosym "/usr/share/composer/bin/composer" "/usr/bin/composer"'

        return src_install
