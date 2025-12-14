"""Handler for theseer/autoload package."""

import logging
from typing import TYPE_CHECKING

from composer_ebuild.package_handlers.base import PackageHandler
from composer_ebuild.utils import get_package_name

if TYPE_CHECKING:
    from composer_ebuild.package import ComposerPackage

logger = logging.getLogger(__name__)


class TheseerAutoloadHandler(PackageHandler):

    """Special handling for theseer/autoload package."""

    def can_handle(self, package_name: str) -> bool:
        """
        Check if this handler can handle the theseer/autoload package.

        Args:
            package_name: The name of the package to check

        Returns:
            True if the package is theseer/autoload, False otherwise

        """
        normalized_name = get_package_name(package_name)
        can_handle = normalized_name == "theseer-autoload"
        logger.debug("Checking if TheseerAutoloadHandler can handle '%s': %s", package_name, can_handle)
        return can_handle

    def get_src_prepare(self, _package: "ComposerPackage") -> str:
        """
        Generate custom src_prepare section for theseer/autoload.

        Args:
            _package: The ComposerPackage instance (unused)

        Returns:
            Custom src_prepare section as a string

        """
        logger.debug("Generating custom src_prepare for theseer/autoload")

        src_prepare = "default\n\n"
        src_prepare += "\t# Set version\n"
        src_prepare += "\tsed -i \\\n"
        src_prepare += '\t\t-e "s/%development%/${PV}/" \\\n'
        src_prepare += "\t\tphpab.php \\\n"
        src_prepare += "\t\tcomposer/bin/phpab \\\n"
        src_prepare += "\t\t|| die\n\n"
        src_prepare += "\tcp --target-directory src/templates/ci \\\n"
        src_prepare += '\t\t"${FILESDIR}"/fedora.php.tpl \\\n'
        src_prepare += '\t\t"${FILESDIR}"/fedora2.php.tpl \\\n'
        src_prepare += "\t\t|| die\n\n"
        src_prepare += "\t# Mimick layout to bootstrap phpab\n"
        src_prepare += "\tmkdir --parents \\\n"
        src_prepare += "\t\tvendor/theseer/directoryscanner \\\n"
        src_prepare += "\t\tvendor/zetacomponents/console-tools \\\n"
        src_prepare += "\t\t|| die\n\n"
        src_prepare += '\tln -s "${EPREFIX}/usr/share/php/Theseer/Directoryscanner/src" '
        src_prepare += "vendor/theseer/directoryscanner/src || die\n"
        src_prepare += '\tln -s "${EPREFIX}/usr/share/php/Zetacomponents/Console-Tools/src" '
        src_prepare += "vendor/zetacomponents/console-tools/src  || die\n\n"
        src_prepare += "\t./phpab.php \\\n"
        src_prepare += "\t\t--output src/autoload.php \\\n"
        src_prepare += '\t\t--template "${FILESDIR}"/autoload.php.tpl \\\n'
        src_prepare += "\t\t--basedir src \\\n"
        src_prepare += "\t\tsrc || die"

        return src_prepare

    def get_src_install(self, _package: "ComposerPackage") -> str:
        """
        Generate custom src_install section for theseer/autoload.

        Args:
            _package: The ComposerPackage instance (unused)

        Returns:
            Custom src_install section as a string

        """
        logger.debug("Generating custom src_install for theseer/autoload")

        src_install = "insinto /usr/share/php/Theseer/Autoload\n"
        src_install += "\tdoins -r src/*\n\n"

        # Install bin directory and create symlink
        src_install += "\tinsinto /usr/share/php/Theseer/Autoload\n"
        src_install += '\tdoins -r "${S}"/composer/bin\n'
        src_install += "\tfperms +x /usr/share/php/Theseer/Autoload/bin/phpab\n\n"
        src_install += "\tdosym /usr/share/php/Theseer/Autoload/bin/phpab /usr/bin/phpab\n\n"
        src_install += "\teinstalldocs"

        return src_install

    def get_blockers(self, _package: "ComposerPackage") -> list[str]:
        """
        Get list of blocker dependencies for theseer/autoload.

        Args:
            _package: The ComposerPackage instance (unused)

        Returns:
            List containing blocker for old package name

        """
        logger.debug("Getting blockers for theseer/autoload")
        return ["!dev-php/theseer-Autoload"]
