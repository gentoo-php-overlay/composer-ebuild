"""Base handler for package-specific customizations."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from composer_ebuild.package import ComposerPackage


class PackageHandler(ABC):

    """Base class for package-specific handlers."""

    @abstractmethod
    def can_handle(self, package_name: str) -> bool:
        """
        Check if this handler can handle the given package.

        Args:
            package_name: The name of the package to check

        Returns:
            True if this handler can handle the package, False otherwise

        """

    def get_src_prepare(self, _package: "ComposerPackage") -> str | None:
        """
        Generate custom src_prepare section for the ebuild.

        Args:
            _package: The ComposerPackage instance (unused in base implementation)

        Returns:
            Custom src_prepare section as a string, or None to use default behavior

        """
        return None

    def get_src_install(self, _package: "ComposerPackage") -> str | None:
        """
        Generate custom src_install section for the ebuild.

        Args:
            _package: The ComposerPackage instance (unused in base implementation)

        Returns:
            Custom src_install section as a string, or None to use default behavior

        """
        return None

    def get_blockers(self, _package: "ComposerPackage") -> list[str]:
        """
        Get list of blocker dependencies for the package.

        Args:
            _package: The ComposerPackage instance (unused in base implementation)

        Returns:
            List of blocker strings (e.g., ["!dev-php/old-package-name"]), or empty list if no blockers

        """
        return []
