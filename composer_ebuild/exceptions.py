"""Exception classes for the composer_ebuild package."""

import logging
import sys

logger = logging.getLogger(__name__)


class EQueryNotFoundError(OSError):

    """Exception raised when equery executable is not found or not executable."""

    def __init__(self, path: str) -> None:
        """
        Initialize the exception with the path that was not found.

        Args:
            path: The path where equery was not found.

        """
        self.message = f"equery executable not found or not executable at {path}"
        super().__init__(self.message)


class ComposerJsonError(Exception):

    """
    Exception raised for errors in the composer.json file.

    Attributes:
        message (str): Explanation of the error.

    """

    NO_EXTRACTED_DIR = "No extracted directory found"

    def __init__(self, message: str) -> None:
        """
        Initialize the exception with a message.

        Args:
            message: The error message to display.

        """
        self.message = message
        super().__init__(self.message)
        logger.exception(self.message)
        sys.exit(1)


class ComposerPackageInstallError(Exception):

    """
    Exception raised for errors during the installation of a Composer package.

    Attributes:
        message (str): Explanation of the error.

    """

    def __init__(self, message: str) -> None:
        """
        Initialize the exception with a message.

        Args:
            message: The error message to display.

        """
        self.message = message
        super().__init__(self.message)


class EbuildGenerationError(Exception):

    """
    Exception raised for errors during the ebuild generation process.

    Attributes:
        message (str): Explanation of the error.

    """

    def __init__(self, message: str) -> None:
        """
        Initialize the exception with a message.

        Args:
            message: The error message to display.

        """
        self.message = message
        super().__init__(self.message)
