"""Utility functions for composer ebuild generation."""

from __future__ import annotations

import logging
import os
import re
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


def copy_files_directory(template_path: Path, package_dir: Path, package_name: str) -> None:
    """
    Copy the files directory from templates to the package directory.

    Looks for files in templates/files/{package_name} where {package_name} is the
    standardized package name (e.g., 'composer' for composer/composer, 'theseer-autoload' for theseer/autoload).

    Args:
        template_path: Path to the template directory
        package_dir: Path to the package directory where files will be copied
        package_name: Standardized package name from get_package_name()

    """
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

    Also filter out wildcarded versions (e.g., "src/*") if the base directory exists.

    Args:
        doins_set: Set of directories and files to filter

    Returns:
        Filtered set with subdirectories and wildcarded duplicates removed

    """
    logger.debug("Filtering subdirectories from doins set")
    filtered_set = set()

    for item in doins_set:
        # Remove wildcard suffix if present for comparison
        item_without_wildcard = item.rstrip("/*")

        # Check if this is a wildcarded version and the base directory exists
        if item.endswith("/*") and item_without_wildcard in doins_set:
            logger.debug("Skipping wildcarded version %s as base directory %s exists", item, item_without_wildcard)
            continue

        # Check if any base directory of this item is already in the list
        parts = item_without_wildcard.split("/")
        is_subdirectory = False
        for i in range(1, len(parts)):
            base_dir = "/".join(parts[:i])
            if base_dir in doins_set or f"{base_dir}/*" in doins_set:
                logger.debug("Skipping %s as base directory %s is already included", item, base_dir)
                is_subdirectory = True
                break

        if not is_subdirectory:
            filtered_set.add(item)

    logger.debug("Filtered doins set: %s", filtered_set)
    return filtered_set


def format_path(path: str) -> str:
    """
    Format the path for doins command.

    Args:
        path: The original path

    Returns:
        The formatted path for doins command

    """
    # Strip trailing slashes
    return path.rstrip("/")


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


def get_package_dir(name: str) -> str:
    """
    Get the full package directory path for a package name.

    Args:
        name: The package name (can be either full vendor/package or standardized name)

    Returns:
        The full package directory path (dev-php/PACKAGE_NAME)

    """
    logger.debug("Getting package directory for: %s", name)
    package_name = get_package_name(name) if "/" in name else name
    return f"dev-php/{package_name}"


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
    except subprocess.CalledProcessError:
        logger.exception("Error running equery")
        return []
    except OSError:
        logger.exception("System or I/O error")
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
            logger.error("Command failed: %s", stderr)
    except subprocess.CalledProcessError as e:
        logger.exception("Command failed with return code %d", e.returncode)
        if check:
            raise
        return e.returncode, e.stdout, e.stderr
    else:
        return process.returncode, stdout, stderr


def scan_classmap_directories(temp_install_dir: str, directories: list[str]) -> dict[str, str]:
    """
    Scan classmap directories and extract class/interface/trait names with their file paths.

    Args:
        temp_install_dir: The temporary installation directory path
        directories: List of directories to scan for PHP classes

    Returns:
        Dictionary mapping fully qualified class names to their relative file paths

    """
    logger.debug("Scanning classmap directories for class definitions")
    classmap = {}

    for directory in directories:
        dir_path = Path(temp_install_dir) / directory
        if not dir_path.exists():
            logger.warning("Classmap directory does not exist: %s", dir_path)
            continue

        # Recursively find all PHP files
        for php_file in dir_path.rglob("*.php"):
            logger.debug("Scanning file: %s", php_file)
            try:
                with php_file.open(encoding="utf-8") as f:
                    content = f.read()

                # Extract namespace - support both bracketed and unbracketed syntax
                # Unbracketed: namespace Foo\Bar;
                # Bracketed: namespace Foo\Bar { ... }
                namespace = ""
                namespace_match = re.search(r"^\s*namespace\s+([\w\\]+)\s*[;{]", content, re.MULTILINE)
                if namespace_match:
                    namespace = namespace_match.group(1)

                # Extract class, interface, and trait names
                # Match class/interface/trait declarations
                pattern = r"^\s*(?:abstract\s+|final\s+)?(class|interface|trait)\s+(\w+)"
                matches = re.finditer(pattern, content, re.MULTILINE)

                for match in matches:
                    class_name = match.group(2)
                    full_class_name = f"{namespace}\\{class_name}" if namespace else class_name

                    # Get relative path from temp_install_dir
                    relative_path = php_file.relative_to(Path(temp_install_dir))

                    # Store with original casing preserved
                    classmap[full_class_name] = f"/{relative_path}"
                    logger.debug("Found class: %s -> %s", full_class_name, relative_path)

            except (OSError, UnicodeDecodeError) as e:
                logger.warning("Failed to parse file %s: %s", php_file, e)

    logger.debug("Found %d classes in classmap", len(classmap))
    return classmap


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
