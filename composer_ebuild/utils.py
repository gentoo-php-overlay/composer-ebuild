"""Utility functions for composer ebuild generation."""

import logging
import os
import subprocess
import sys
from pathlib import Path

from composer_ebuild.exceptions import EQueryNotFoundError

logger = logging.getLogger(__name__)


def validate_equery_args() -> tuple[str, list[str]]:
    """
    Validate the equery executable and arguments.

    :return: Tuple of (executable path, argument list)
    :raises OSError: If equery executable is not found or not executable
    :raises ValueError: If arguments contain invalid characters
    """
    equery_path = Path("/usr/bin/equery")
    if not equery_path.is_file() or not os.access(str(equery_path), os.X_OK):
        raise EQueryNotFoundError(str(equery_path))

    # Hardcoded safe arguments
    args = ["--no-color", "u", "dev-lang/php"]

    # Additional validation of arguments
    for arg in args:
        if not arg.replace("-", "").replace("/", "").isalnum():
            error_msg = f"Invalid character in argument: {arg}"
            raise ValueError(error_msg)
        if ".." in arg or arg.startswith("/"):
            error_msg = f"Potentially unsafe argument: {arg}"
            raise ValueError(error_msg)

    return str(equery_path), args


def is_running_in_ide() -> bool:
    """
    Check if the code is running within an IDE.

    Detects common IDEs like PyCharm, VS Code, Spyder, and Jupyter
    by checking environment variables and loaded modules.

    :return: True if running in an IDE, False otherwise
    """
    logger.debug("Checking if running in IDE")

    # Check environment variables
    ide_env_vars = [
        "PYCHARM_HOSTED",  # PyCharm
        "VSCODE_PID",      # VS Code
        "SPYDER_ARGS",     # Spyder
        "JUPYTER_CONFIG_DIR",  # Jupyter
    ]

    # Check loaded modules
    ide_modules = [
        "IPython",         # Jupyter/IPython
        "spyder",          # Spyder
        "pydevd",         # PyCharm debugger
        "debugpy",        # VS Code debugger
    ]

    is_ide = (
        any(var in os.environ for var in ide_env_vars) or
        any(module in sys.modules for module in ide_modules)
    )

    logger.debug("Running in IDE: %s", is_ide)
    return is_ide


def get_php_useflags() -> list[str]:
    """
    Get the USE flags for dev-lang/php by calling 'equery --no-color u dev-lang/php'.

    :return: A list of enabled USE flags for dev-lang/php.
    :raises OSError: If equery executable is not found or not executable
    """
    try:
        equery_path, args = validate_equery_args()
        result = subprocess.run(
            [equery_path, *args], capture_output=True, text=True, check=True,
        )
        output = result.stdout.split("\n")

        use_flags = []
        for line in output:
            if line.startswith(" + "):
                flag = line.split()[2]
                use_flags.append(flag)
        # ruff: noqa: TRY300
        return use_flags
    except subprocess.CalledProcessError as e:
        logger.info("Error running equery: %s", e)
        return []
    except OSError as e:
        logger.info("System or I/O error: %s", e)
        return []
