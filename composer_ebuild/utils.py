"""Utility functions for composer ebuild generation."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from packaging import version

from composer_ebuild.exceptions import EQueryNotFoundError

# Constants
EQUERY_PATH = Path("/usr/bin/equery")
EQUERY_ARGS = ["--no-color", "u", "dev-lang/php"]

logger = logging.getLogger(__name__)


def add_item_to_set(item: str, target_set: set[str], item_type: str, source: str) -> None:
    """
    Add an item to the specified set and log the action.

    Args:
        item: The item to add to the set
        target_set: The set to add the item to
        item_type: The type of item (for logging)
        source: The source of the item (for logging)

    """
    target_set.add(item)
    logger.debug("Added %s from %s: %s", item_type, source, item)


def compare_versions(version1: str, version2: str) -> int:
    """
    Compare two version strings using packaging.version.

    Args:
        version1: First version string
        version2: Second version string

    Returns:
        -1 if version1 < version2, 0 if version1 == version2, 1 if version1 > version2

    """
    v1 = version.parse(version1)
    v2 = version.parse(version2)
    return 0 if v1 == v2 else (1 if v1 > v2 else -1)


def copy_files_directory(template_path: Path, package_dir: Path) -> None:
    """
    Copy the files directory from templates to the package directory.

    Looks for files in templates/files/{package_name} where {package_name} is the
    last part of the package_dir path.

    Args:
        template_path: Path to the template directory
        package_dir: Path to the package directory where files will be copied

    """
    # Get the package name from the package_dir
    package_name = package_dir.name

    # Check for files in templates/files/{package_name}
    template_files_dir = Path(template_path) / "files" / package_name

    if template_files_dir.exists() and template_files_dir.is_dir():
        logger.debug("Found files directory for %s at %s", package_name, template_files_dir)
        package_files_dir = package_dir / "files"
        if package_files_dir.exists():
            shutil.rmtree(package_files_dir)
        shutil.copytree(template_files_dir, package_files_dir)
        logger.debug("Copied files directory to %s", package_files_dir)
    else:
        logger.debug("No specific files directory found for %s", package_name)


def execute_equery_command() -> str:
    """
    Execute the equery command to get PHP USE flags.

    Returns:
        The raw output from the equery command.

    Raises:
        EQueryNotFoundError: If equery executable is not found or not executable.
        OSError: If a system or I/O error occurs.
        subprocess.CalledProcessError: If the command execution fails.

    """
    logger.debug("Executing equery command to get PHP USE flags")
    equery_path, args = validate_equery_args()
    _, stdout, _ = run_subprocess([equery_path, *args], check=True)
    return stdout or ""


def filter_subdirectories(doins_set: set[str]) -> set[str]:
    """
    Filter out subdirectories if the base directory is already in the set.

    Args:
        doins_set: Set of directories and files to filter

    Returns:
        Filtered set with subdirectories removed

    """
    logger.debug("Filtering subdirectories from doins set")
    filtered_set = set()

    for item in doins_set:
        # Always keep items ending with /*
        if item.endswith("/*"):
            filtered_set.add(item)
            continue

        # Check if any base directory of this item is already in the list
        parts = item.split("/")
        is_subdirectory = False
        for i in range(1, len(parts)):
            base_dir = "/".join(parts[:i])
            if base_dir in doins_set:
                logger.debug("Skipping %s as base directory %s is already included", item, base_dir)
                is_subdirectory = True
                break

        if not is_subdirectory:
            filtered_set.add(item)

    logger.debug("Filtered doins set: %s", filtered_set)
    return filtered_set


def format_path(path: str) -> str:
    """
    Format the path for doins command, handling the 'src' directory case.

    Args:
        path: The original path

    Returns:
        The formatted path for doins command

    """
    # Strip trailing slashes
    path = path.rstrip("/")

    if path == "src":
        return "src/*"
    return f"{path}"


def get_package_name(name: str) -> str:
    """
    Convert a Composer package name to a standardized format.

    If the vendor and package name are the same, only use the package name.
    If the vendor is 'composer', only use the package name.

    Args:
        name: The full package name (vendor/package)

    Returns:
        The standardized package name

    """
    logger.debug("Converting package name: %s", name)
    vendor, package = name.split("/")
    return package if vendor in {package, "composer"} else f"{vendor}-{package}"


def get_php_useflags() -> list[str]:
    """
    Get the USE flags for dev-lang/php by calling 'equery --no-color u dev-lang/php'.

    Returns:
        A list of enabled USE flags for dev-lang/php.

    Raises:
        EQueryNotFoundError: If equery executable is not found or not executable.
        OSError: If a system or I/O error occurs.

    """
    try:
        equery_output = execute_equery_command()
        return parse_php_useflags(equery_output)
    except subprocess.CalledProcessError as e:
        logger.debug("Error running equery: %s", e)
        return []
    except OSError as e:
        logger.debug("System or I/O error: %s", e)
        return []


def is_running_in_ide() -> bool:
    """
    Check if the code is running within an IDE.

    Detects common IDEs like PyCharm, VS Code, Spyder, and Jupyter
    by checking environment variables and loaded modules.

    Returns:
        True if running in an IDE, False otherwise.

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


def parse_php_useflags(equery_output: str) -> list[str]:
    """
    Parse the output of equery command to extract enabled USE flags.

    Args:
        equery_output: Raw output from the equery command.

    Returns:
        A list of enabled USE flags for dev-lang/php.

    """
    logger.debug("Parsing equery output for PHP USE flags")
    output_lines = equery_output.split("\n")

    use_flags = []
    for line in output_lines:
        if line.startswith(" + "):
            flag = line.split()[2]
            use_flags.append(flag)

    logger.debug("Found %d enabled PHP USE flags", len(use_flags))
    return use_flags


def run_subprocess(
    command: list[str],
    cwd: str | None = None,
    *,
    capture_output: bool = True,
    check: bool = False,
    log_output: bool = False,
) -> tuple[int, str | None, str | None]:
    """
    Run a subprocess command and return the result.

    Args:
        command: The command to run as a list of strings
        cwd: The working directory to run the command in
        capture_output: Whether to capture stdout and stderr
        check: Whether to raise an exception if the command fails
        log_output: Whether to log the command output at debug level

    Returns:
        A tuple containing (return_code, stdout, stderr)

    Raises:
        subprocess.CalledProcessError: If check is True and the command fails

    """
    logger.debug("Running command: %s", " ".join(command))

    kwargs: dict[str, Any] = {"cwd": cwd} if cwd else {}
    if capture_output:
        kwargs.update({"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "text": True})

    try:
        process = subprocess.run(command, check=check, **kwargs)

        stdout = process.stdout if capture_output else None
        stderr = process.stderr if capture_output else None

        if log_output and stdout:
            logger.debug("Command output: %s", stdout)
        if stderr and process.returncode != 0:
            logger.debug("Command error: %s", stderr)
    except subprocess.CalledProcessError as e:
        logger.debug("Command failed with return code %d: %s", e.returncode, e)
        if check:
            raise
        return e.returncode, e.stdout, e.stderr
    else:
        return process.returncode, stdout, stderr


def validate_equery_args() -> tuple[str, list[str]]:
    """
    Validate the equery executable and arguments.

    Returns:
        Tuple containing the executable path and list of arguments.

    Raises:
        EQueryNotFoundError: If equery executable is not found or not executable.
        ValueError: If arguments contain invalid characters.

    """
    if not EQUERY_PATH.is_file() or not os.access(str(EQUERY_PATH), os.X_OK):
        raise EQueryNotFoundError(str(EQUERY_PATH))

    # Use the constant for arguments
    args = EQUERY_ARGS.copy()

    # Additional validation of arguments
    for arg in args:
        if not arg.replace("-", "").replace("/", "").isalnum():
            error_msg = f"Invalid character in argument: {arg}"
            raise ValueError(error_msg)
        if ".." in arg or arg.startswith("/"):
            error_msg = f"Potentially unsafe argument: {arg}"
            raise ValueError(error_msg)

    return str(EQUERY_PATH), args
