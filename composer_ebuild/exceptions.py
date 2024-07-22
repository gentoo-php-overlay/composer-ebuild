import sys


class ComposerJsonException(Exception):
    """
    Exception raised for errors in the composer.json file.

    Attributes:
        message (str): Explanation of the error.
    """

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(self.message)
        print(self.message)
        sys.exit(1)


class ComposerPackageInstallException(Exception):
    """
    Exception raised for errors during the installation of a Composer package.

    Attributes:
        message (str): Explanation of the error.
    """
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(self.message)


class EbuildGenerationException(Exception):
    """
    Exception raised for errors during the ebuild generation process.

    Attributes:
        message (str): Explanation of the error.
    """
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(self.message)
