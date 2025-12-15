"""Module for handling Composer packages and generating ebuilds."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Any

import requests
from github import Github
from github.GithubException import GithubException

from composer_ebuild.exceptions import ComposerJsonError
from composer_ebuild.package_handlers.registry import HandlerRegistry
from composer_ebuild.utils import (
    add_item_to_set,
    compare_versions,
    copy_files_directory,
    filter_subdirectories,
    format_path,
    get_package_dir,
    get_package_name,
    get_php_useflags,
    run_subprocess,
    scan_classmap_directories,
)

if TYPE_CHECKING:
    from github.Repository import Repository

# Constants
DEFAULT_PHP_MIN_VERSION: str = "7.4"
EAPI_VERSION: int = 8
HTTP_FORBIDDEN: int = 403
MIN_NAMESPACE_PARTS: int = 2

# Virtual packages provided by Composer runtime, not installable
COMPOSER_VIRTUAL_PACKAGES = {
    "composer-runtime-api",
    "composer-plugin-api",
}

logger = logging.getLogger(__name__)


@dataclass
class PackageConfig:

    """Configuration for ComposerPackage initialization."""

    github_token: str | None = None
    cache_dir: str | None = None


class ComposerPackage:

    """Class to represent a Composer package and generate its ebuild."""

    autoload: dict[str, Any]
    bin_files: list[str]
    cache_dir: str | None
    dependencies: dict
    description: str
    github_repo: Repository | None
    github_tag: str | None
    github_token: str | None
    install_path: str
    licenses: list[str]
    lock_name: str
    name: str
    output_dir: str | None
    php_min_version: str
    repository_url: str | None
    requires: dict[str, str]
    sha: str | None
    src_uri: str | None
    temp_dir: str
    temp_install_dir: str
    upstream_base_dir: str
    version: str
    work_dir: str

    def __init__(
        self,
        lock_name: str,
        version: str,
        temp_dir: str,
        config: PackageConfig | None = None,
    ) -> None:
        """
        Initialize the ComposerPackage.

        Args:
            lock_name: The name of the package as it appears in composer.lock (may be an alias)
            version: The version of the Composer package
            temp_dir: The temporary directory where the Composer package is installed
            config: Optional configuration object with github_token and cache_dir

        """
        config = config or PackageConfig()

        self.autoload: dict[str, Any] = {}
        self.bin_files: list[str] = []
        self.cache_dir: str | None = config.cache_dir
        self.dependencies: dict[str, dict[str, Any]] = {}
        self.github_repo: Repository | None = None
        self.github_tag: str | None = None
        self.github_token: str | None = config.github_token
        self.licenses: list[str] = []
        self.lock_name = lock_name
        self.php_min_version: str = DEFAULT_PHP_MIN_VERSION
        self.repository_url: str | None = None
        self.requires: dict[str, str] = {}
        self.sha: str | None = None
        self.src_uri: str | None = None
        self.temp_dir: str = temp_dir
        self.temp_install_dir: str = str(Path(temp_dir) / "vendor" / lock_name.replace("/", os.sep))
        self.upstream_base_dir: str = ""
        self.version: str = re.sub(r"^v", "", version)
        self._handler_registry = HandlerRegistry()

        logger.debug("Version: %s", self.version)

        try:
            self._load_composer_info()
            self._process_main_dependencies()
            self._set_workdir()
            self._set_install_path()
        except ComposerJsonError:
            # The exception will handle printing and exiting
            pass

    def create_ebuild(self, output_dir: str, templates_dir: Path, *, create_metadata: bool = False) -> None:
        """
        Create an ebuild file for the package.

        Args:
            output_dir: The directory to place the generated ebuild file
            templates_dir: Directory containing the ebuild templates
            create_metadata: Whether to create metadata.xml files

        """
        self.output_dir = output_dir

        current_date = datetime.now(tz=UTC).strftime("%Y")
        # Use the standard template file
        template_file = templates_dir / "ebuild"

        with template_file.open() as f:
            ebuild_template = f.read().replace("{{date}}", current_date)

        # Replace version in SRC_URI with ${PV} if it matches the package version
        if f"{self.version}" in self.src_uri:
            src_uri = self.src_uri.replace(f"{self.version}", "${PV}")
        else:
            src_uri = self.src_uri

        # Build RDEPEND string with proper ordering:
        # 1. dev-lang/php (always first)
        # 2. Any blockers (if present)
        # 3. dev-php/fedora-autoloader (for all packages except theseer/autoload)
        # 4. All other dependencies
        rdepend_parts = []

        # Add dev-lang/php first (it's already sorted to be first by _sort_dependencies)
        if "php" in self.dependencies:
            rdepend_parts.append(self.dependencies["php"]["ebuild"])

        # Add blockers if any exist for this package
        blockers = self._handler_registry.get_blockers(self.name, self)
        if blockers:
            logger.debug("Adding %d blocker(s) for %s", len(blockers), self.name)
            rdepend_parts.extend(blockers)

        # Add fedora-autoloader (for all packages except theseer/autoload)
        if self.name != "theseer/autoload":
            rdepend_parts.append("dev-php/fedora-autoloader")

        # Add all other main dependencies
        for dep, info in self.dependencies.items():
            if info.get("type") == "main" and dep != "php":
                rdepend_parts.append(info["ebuild"])

        rdepend_string = "\n\t".join(rdepend_parts)

        # Get standardized package name for template lookups
        package_name = get_package_name(self.name)

        # Check for patch files
        patches_string = self._get_patches_string(templates_dir, package_name)

        # Generate BDEPEND string
        bdepend_string = self._get_bdepend_string()

        ebuild_content = (
            ebuild_template.replace("{{eapi}}", str(EAPI_VERSION))
            .replace("{{homepage}}", self.repository_url or f"https://packagist.org/packages/{self.name}")
            .replace("{{description}}", self.description or "No description available")
            .replace("{{src_uri}}", src_uri + " -> ${P}.tar.gz")
            .replace("{{license}}", " ".join(self.licenses).strip() or "Unknown")
            .replace("{{rdepend}}", "\t" + rdepend_string)
            .replace("{{patches}}", patches_string)
            .replace("{{src_prepare}}", "\t" + self._get_src_prepare())
            .replace("{{src_install}}", "\t" + self._get_src_install())
            .replace("{{workdir}}", self.work_dir)
        )

        # Handle BDEPEND replacement - remove the line entirely if empty
        if bdepend_string:
            ebuild_content = ebuild_content.replace("{{bdepend}}", bdepend_string)
        else:
            # Remove the entire line containing {{bdepend}}
            ebuild_content = re.sub(r"^.*\{\{bdepend\}\}.*\n", "", ebuild_content, flags=re.MULTILINE)

        ebuild_filename = f"{package_name}-{self.version.lstrip('v')}.ebuild"
        package_dir = Path(f"{self.output_dir}/{get_package_dir(package_name)}")
        package_dir.mkdir(parents=True, exist_ok=True)
        ebuild_output_file = package_dir / ebuild_filename

        with ebuild_output_file.open("w") as f:
            f.write(ebuild_content)

        logger.debug("Created ebuild at %s", ebuild_output_file)

        # Create metadata.xml file if requested
        if create_metadata:
            self._create_metadata_xml(package_dir)

        # Copy files directory if it exists - pass the standardized package name
        copy_files_directory(templates_dir, package_dir, package_name)

    def add_dependency_instance(self, dep_name: str, dep_instance: ComposerPackage) -> None:
        """
        Add a dependency instance to the package.

        Args:
            dep_name: The name of the dependency
            dep_instance: The ComposerPackage instance of the dependency

        """
        logger.debug("Adding dependency instance for %s", dep_name)
        if dep_name in self.dependencies:
            self.dependencies[dep_name]["instance"] = dep_instance
        else:
            logger.warning("Dependency %s not found in dependencies", dep_name)

    def add_sub_dependency(self, sub_dep_name: str, sub_dep_instance: ComposerPackage) -> None:
        """
        Add a sub-dependency instance to the package.

        This method adds dependencies of dependencies, excluding duplicates,
        'php', and 'ext-' dependencies.

        Args:
            sub_dep_name: The name of the sub-dependency
            sub_dep_instance: The ComposerPackage instance of the sub-dependency

        """
        logger.debug("Adding sub-dependency: %s", sub_dep_name)

        # Check if it's not a main dependency and not already a sub-dependency
        if (
            sub_dep_name not in self.dependencies
            and sub_dep_name not in [dep for dep in self.dependencies.values() if dep.get("type") == "sub"]
            and not sub_dep_name.startswith("php")
            and not sub_dep_name.startswith("ext-")
        ):
            self.dependencies[sub_dep_name] = {
                "ebuild": get_package_dir(sub_dep_name),
                "instance": sub_dep_instance,
                "type": "sub",
            }
            logger.debug("Added sub-dependency: %s", sub_dep_name)
        else:
            logger.debug("Skipped adding sub-dependency: %s (already exists or excluded)", sub_dep_name)

        self._sort_dependencies()

    def get_src_dependency_autoloads(self, autoload_file: str = "autoload.php") -> str | None:
        """
        Get the dependency_autoload section for src_prepare.

        This is a public method that can be called by package handlers.

        Args:
            autoload_file: The name of the autoload file to modify

        Returns:
            String containing dependency autoload information or None if no dependencies

        """
        # Collect dependency autoloads first
        dependency_autoloads = []
        for dep_info in self.dependencies.values():
            if "instance" in dep_info and hasattr(dep_info["instance"], "install_path"):
                install_path = dep_info["instance"].install_path
                dependency_autoloads.append(
                    f"\"${{VENDOR_DIR}}{install_path.replace('/usr/share/php', '')}/autoload.php\"",
                )

        # We have no dependencies
        if not dependency_autoloads:
            return None

        # Build the dependency string
        dependencies = '\n\tVENDOR_DIR="${EPREFIX}/usr/share/php"'
        dependencies += f'\n\tcat >> {autoload_file} <<EOF || die "failed to extend autoload.php"'
        dependencies += "\n\n// Dependencies"
        dependencies += "\n\\Fedora\\Autoloader\\Dependencies::required(["
        dependencies += '\n\t"${VENDOR_DIR}/Fedora/Autoloader/autoload.php",\n\t'
        dependencies += ",\n\t".join(dependency_autoloads)
        dependencies += "\n]);"
        dependencies += "\nEOF"
        return dependencies

    def _load_composer_json(self) -> dict:
        """
        Load and parse the composer.json file.

        Returns:
            A dictionary containing the parsed composer.json data

        Raises:
            ComposerJsonError: If the file is not found or cannot be parsed

        """
        logger.debug("Reading composer.json file")
        composer_json_path = Path(self.temp_install_dir) / "composer.json"
        try:
            with composer_json_path.open() as composer_json_file:
                composer_json_info = json.load(composer_json_file)
            logger.debug("Successfully loaded composer.json")
        except FileNotFoundError as e:
            error_msg = f"composer.json not found for {self.lock_name}"
            raise ComposerJsonError(error_msg) from e
        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse composer.json for {self.lock_name}"
            raise ComposerJsonError(error_msg) from e
        else:
            return composer_json_info

    def _load_composer_show(self) -> dict:
        """
        Load the output of the 'composer show' command for the current package.

        Returns:
            A dictionary containing the parsed 'composer show' output

        Raises:
            ComposerJsonError: If the command fails or the output cannot be parsed

        """
        logger.debug("Running composer show command for %s", self.lock_name)
        try:
            command = ["/usr/bin/composer", "show", self.lock_name, "--format=json"]
            logger.debug("Running command in directory %s: %s", self.temp_dir, " ".join(command))
            _, stdout, _stderr = run_subprocess(command, cwd=self.temp_dir, capture_output=True, check=True)
            composer_show_info = json.loads(stdout)
            logger.debug("Successfully loaded composer show information")
        except subprocess.CalledProcessError as e:
            error_msg = (f"Failed to run composer show command for {self.lock_name}: {e}\n"
                         f"Command output: {e.stderr if hasattr(e, 'stderr') else ''}")
            raise ComposerJsonError(error_msg) from e
        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse composer show output for {self.lock_name}: {e}"
            raise ComposerJsonError(error_msg) from e
        else:
            return composer_show_info

    def _load_composer_info(self) -> None:
        """
        Load the package information from composer.json file and composer show command.

        Some info is missing or misleading in composer.json and better formatted in "composer show".
        For other info it is the same, the other way around.

        Raises:
            ComposerJsonError: If the required information is not found

        """
        composer_json_info = self._load_composer_json()
        logger.debug("Loaded composer.json information: %s", composer_json_info)

        # Get the actual package name from composer.json
        self.name = composer_json_info.get("name", self.lock_name)
        if self.name != self.lock_name:
            logger.debug("Package has actual name %s (lock name: %s)", self.name, self.lock_name)

        composer_show_info = self._load_composer_show()
        logger.debug("Loaded composer show information: %s", composer_show_info)

        self.description = composer_json_info.get("description")
        self.repository_url = composer_show_info.get("source", {}).get("url", "").replace(".git", "")
        self.licenses = composer_json_info.get("license", [])
        if isinstance(self.licenses, str):
            self.licenses = [self.licenses]
        self.requires = composer_json_info.get("require", {})
        self.bin_files = composer_json_info.get("bin", [])
        if isinstance(self.bin_files, str):
            self.bin_files = [self.bin_files]
        logger.debug("Loaded licenses: %s", self.licenses)
        logger.debug("Loaded requires: %s", self.requires)
        logger.debug("Loaded bin files: %s", self.bin_files)

        # Load autoload information
        self._process_autoload_info(composer_json_info.get("autoload", {}))

        if not self.description or not self.repository_url:
            error_msg = "Missing required description or repository URL in composer.json"
            raise ComposerJsonError(error_msg)

        # Ensure repository URL is from GitHub
        if not self.repository_url or "github.com" not in self.repository_url:
            error_msg = f"Repository URL must be from GitHub: {self.repository_url}"
            raise ComposerJsonError(error_msg)

        # Set GitHub repository object if repository URL is available
        self._set_github_repo()
        self._set_github_tag_for_version()

        try:
            self._set_commit_sha()
            self._set_tagged_tarball_url()
        except ComposerJsonError:
            logger.warning("No tagged tarball URL found for %s %s. Using repository URL.", self.name, self.version)
            self.src_uri = f"{self.repository_url}/archive/{self.sha}.tar.gz"

        # Download and extract the package
        self._download_and_extract_package()

    def _get_cache_filename(self) -> str:
        """
        Generate a cache filename based on the package name and version.

        Returns:
            The cache filename

        """
        # Use package name and version for readability
        safe_name = self.name.replace("/", "_")
        return f"{safe_name}-{self.version}.tar.gz"

    def _get_cached_package(self) -> Path | None:
        """
        Check if the package exists in the cache directory.

        Returns:
            Path to the cached package if it exists, None otherwise

        """
        if not self.cache_dir:
            return None

        cache_path = Path(self.cache_dir)
        if not cache_path.exists():
            logger.debug("Cache directory does not exist: %s", cache_path)
            return None

        cached_file = cache_path / self._get_cache_filename()
        if cached_file.exists() and cached_file.is_file():
            logger.debug("Found cached package: %s", cached_file)
            return cached_file

        logger.debug("Package not found in cache: %s", cached_file)
        return None

    def _save_to_cache(self, temp_file_path: str) -> None:
        """
        Save the downloaded package to the cache directory.

        Args:
            temp_file_path: Path to the temporary file to cache

        """
        if not self.cache_dir:
            return

        cache_path = Path(self.cache_dir)
        cache_path.mkdir(parents=True, exist_ok=True)

        cached_file = cache_path / self._get_cache_filename()
        logger.debug("Saving package to cache: %s", cached_file)

        try:
            shutil.copy2(temp_file_path, cached_file)
            logger.debug("Successfully cached package: %s", cached_file)
        except OSError as e:
            logger.warning("Failed to cache package: %s", e)

    def _check_download_response(self, response: requests.Response) -> None:
        """
        Check if the download response is successful.

        Args:
            response: The HTTP response object

        Raises:
            ComposerJsonError: If the response status is not OK

        """
        if response.status_code != HTTPStatus.OK:
            error_message = f"Failed to download package from {self.src_uri}"
            raise ComposerJsonError(error_message)

    def _download_and_extract_package(self) -> None:
        """
        Download the package to temp_dir and extract it to self.temp_dir + '/package'.

        Extraction behaves exactly like 'tar xzf FILENAME.tar.gz'.

        Raises:
            ComposerJsonError: If download or extraction fails

        """
        logger.debug("Downloading and extracting package")

        # Check if package exists in cache
        cached_package = self._get_cached_package()
        if cached_package:
            logger.debug("Using cached package: %s", cached_package)
            temp_file_path = str(cached_package)
            # Extract the package
            self._extract_package(temp_file_path)
            return

        # Download the package
        try:
            # Create a temporary file to store the downloaded package
            with tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz") as temp_file:
                # Download the package
                logger.debug("Downloading package from %s", self.src_uri)
                response = requests.get(self.src_uri, timeout=30)
                self._check_download_response(response)
                temp_file.write(response.content)
                temp_file_path = temp_file.name

            # Save to cache if cache directory is configured
            self._save_to_cache(temp_file_path)

            # Extract the package
            self._extract_package(temp_file_path)

            # Clean up the temporary file if not using cache
            if not cached_package:
                Path(temp_file_path).unlink()

        except (ComposerJsonError, requests.RequestException) as e:
            error_msg = f"Failed to download package: {e}"
            raise ComposerJsonError(error_msg) from e

    def _extract_package(self, archive_path: str) -> None:
        """
        Extract a tar.gz archive to the package directory.

        Args:
            archive_path: Path to the tar.gz archive to extract

        Raises:
            ComposerJsonError: If extraction fails

        """
        extract_path = Path(self.temp_dir) / "package" / get_package_name(self.name)
        extract_path.mkdir(parents=True, exist_ok=True)

        # Use subprocess to run tar command, mimicking "tar xzf FILENAME.tar.gz" behavior
        try:
            return_code, _, stderr = run_subprocess(
                ["/bin/tar", "xzf", archive_path], cwd=str(extract_path), check=True,
            )
            if return_code != 0:
                error_msg = f"Failed to extract package. Error: {stderr}"
                raise ComposerJsonError(error_msg)
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to extract package: {e}"
            raise ComposerJsonError(error_msg) from e

        logger.debug("Package extracted to %s", extract_path)

    def _sort_dependencies(self) -> None:
        """
        Sort dependencies ensuring dev-lang/php is always on top.

        The rest are sorted alphabetically.
        """
        logger.debug("Sorting dependencies")
        sorted_deps = {}

        # Add dev-lang/php first
        if "php" in self.dependencies:
            sorted_deps["php"] = self.dependencies["php"]

        # Sort the rest of the dependencies by their ebuild names
        sorted_deps.update({
            dep: info for dep, info in sorted(self.dependencies.items(), key=lambda x: x[1]["ebuild"])
            if dep != "php"
        })
        self.dependencies = sorted_deps
        logger.debug("Sorted dependencies: %s", self.dependencies)

    def _normalize_autoload_directories(self, directories: str | list[str]) -> list[str]:
        """
        Normalize autoload directories to ensure we have a valid list.

        Args:
            directories: Directory or list of directories from autoload configuration

        Returns:
            Normalized list of directories, with "." as fallback if empty

        """
        if isinstance(directories, str):
            directories = [directories]
        # Ensure we have at least "." if directories is empty or contains empty strings
        if not directories or all(not d or d == "" for d in directories):
            directories = ["."]
        return directories

    def _process_autoload_info(self, autoload_info: dict[str, Any]) -> None:
        """
        Process the autoload information from composer.json.

        Args:
            autoload_info: The autoload information from composer.json

        Raises:
            ComposerJsonError: If the autoload_info is empty

        """
        logger.debug("Processing autoload information")
        if not autoload_info:
            error_msg = "Autoload information is empty"
            raise ComposerJsonError(error_msg)

        self.autoload = {"type": "", "namespace": "", "directories": [], "files": []}

        if "psr-4" in autoload_info:
            self.autoload["type"] = "psr-4"
            namespace = next(iter(autoload_info["psr-4"]))
            self.autoload["namespace"] = namespace
            directories = autoload_info["psr-4"][namespace]
            self.autoload["directories"] = self._normalize_autoload_directories(directories)
        elif "psr-0" in autoload_info:
            self.autoload["type"] = "psr-0"
            namespace = next(iter(autoload_info["psr-0"]))
            self.autoload["namespace"] = namespace
            directories = autoload_info["psr-0"][namespace]
            self.autoload["directories"] = self._normalize_autoload_directories(directories)
        elif "classmap" in autoload_info:
            self.autoload["type"] = "classmap"
            directories = autoload_info["classmap"]
            self.autoload["directories"] = self._normalize_autoload_directories(directories)

        if "files" in autoload_info:
            self.autoload["files"] = autoload_info["files"]

        logger.debug("Loaded autoload information: %s", self.autoload)

    def _process_php_version(self) -> str | None:
        """
        Process PHP version requirements and return minimum version.

        Returns:
            The minimum PHP version required, or None if not specified

        """
        php_min_version = None
        for dep, version_str in sorted(self.requires.items()):
            if dep.lower() == "php":
                version_match = re.search(r">=?\s*(\d+\.\d+)", version_str)
                if version_match:
                    required_version = version_match.group(1)
                    if php_min_version is None or compare_versions(required_version, php_min_version) > 0:
                        php_min_version = required_version
        return php_min_version

    def _process_php_extensions(self) -> set[str]:
        """
        Process PHP extension requirements and return USE flags.

        Returns:
            A set of PHP USE flags required by the package

        """
        php_use_flags = set()
        available_php_use_flags = set(get_php_useflags())
        logger.debug("Available PHP USE flags: %s", available_php_use_flags)

        for dep, _version_req in sorted(self.requires.items()):
            if dep.lower().startswith("ext-"):
                if dep.lower() == "ext-openssl":
                    if "ssl" in available_php_use_flags:
                        php_use_flags.add("ssl")
                    else:
                        logger.warning("ssl USE flag not available for PHP")
                else:
                    ext_name = dep[4:]  # Remove "ext-" prefix
                    if ext_name in available_php_use_flags:
                        php_use_flags.add(ext_name)
                    else:
                        logger.warning("%s USE flag not available for PHP", ext_name)
        return php_use_flags

    def _process_package_dependencies(self) -> None:
        """
        Process regular package dependencies.

        Adds non-PHP dependencies to the dependencies dictionary, excluding virtual packages.
        """
        for dep, _version_req in sorted(self.requires.items()):
            # Skip PHP, extensions, and virtual packages
            if (dep.lower() != "php"
                and not dep.lower().startswith("ext-")
                and dep not in COMPOSER_VIRTUAL_PACKAGES):
                self.dependencies[dep] = {"ebuild": get_package_dir(dep), "type": "main"}
                logger.debug("Added package dependency: %s", dep)
            elif dep in COMPOSER_VIRTUAL_PACKAGES:
                logger.debug("Skipping virtual package dependency: %s", dep)

    def _process_main_dependencies(self) -> None:
        """
        Process the requirements list and assign it to main dependencies.

        Translate "php" dependencies to "dev-lang/php:*".
        Handle "ext-..." dependencies by adding them to dev-lang/php use flags.
        Determine the minimum PHP version required.
        Add real PSR-4 namespace to dependencies except for "php".
        Add autoload location for each dependency.
        """
        logger.debug("Processing dependencies")
        self.dependencies = {}

        # Process PHP version and extensions
        php_min_version = self._process_php_version()
        php_use_flags = self._process_php_extensions()
        self.php_min_version = php_min_version if php_min_version else "7.4"

        # Process regular package dependencies
        self._process_package_dependencies()

        # Add dev-lang/php with the minimum version and use flags
        php_ebuild = f">=dev-lang/php-{self.php_min_version}:*"
        if php_use_flags:
            php_ebuild += f"[{','.join(sorted(php_use_flags))}]"
        self.dependencies["php"] = {"ebuild": php_ebuild, "type": "main"}

        self._sort_dependencies()

        logger.debug("Processed dependencies: %s", self.dependencies)
        logger.debug("Minimum PHP version: %s", self.php_min_version)

    def _process_autoload_directories(self, doins: set[str]) -> None:
        """
        Process directories from autoload information.

        Args:
            doins: Set to store doins entries

        """
        logger.debug("Processing autoload directories")
        if self.autoload["directories"]:
            # First, collect all directories and their formatted paths
            all_dirs = []
            for directory in self.autoload["directories"]:
                # Skip hidden directories (starting with .)
                dir_str = str(directory)
                if dir_str.startswith(".") or any(part.startswith(".") for part in dir_str.split("/")):
                    logger.debug("Skipping hidden directory: %s", directory)
                    continue

                formatted_path = format_path(dir_str)
                all_dirs.append((dir_str, formatted_path))

            # Sort by path length to process parent directories first
            all_dirs.sort(key=lambda x: len(x[0]))

            # Process directories
            for _dir_str, formatted_path in all_dirs:
                add_item_to_set(formatted_path, doins, "directory", "autoload")

    def _process_autoload_files(self, doins: set[str], php_files: set[str]) -> None:
        """
        Process files from autoload information.

        Args:
            doins: Set to store doins entries
            php_files: Set to store PHP files

        """
        logger.debug("Processing autoload files")
        if self.autoload["files"]:
            for file in self.autoload["files"]:
                if file.endswith(".php"):
                    add_item_to_set(file, php_files, "PHP file", "autoload")
                else:
                    add_item_to_set(file, doins, "file", "autoload")

    def _process_root_directory(self, doins: set[str], php_files: set[str]) -> None:
        """
        Process root directory content.

        Args:
            doins: Set to store doins entries
            php_files: Set to store PHP files

        """
        logger.debug("Processing root directory")
        for item_path in Path(self.temp_install_dir).iterdir():
            # Skip hidden directories and files (starting with .)
            if item_path.name.startswith("."):
                logger.debug("Skipping hidden item: %s", item_path.name)
                continue

            # Skip bin directories - they will be handled by dobin
            if item_path.is_dir() and item_path.name == "bin":
                logger.debug("Skipping bin directory: %s", item_path.name)
                continue

            if item_path.is_dir() and item_path.name not in self.autoload["directories"]:
                add_item_to_set(item_path.name, doins, "directory", "root")
            elif item_path.name.endswith(".php") and item_path.name not in self.autoload["files"]:
                add_item_to_set(item_path.name, php_files, "PHP file", "root")
            elif item_path.name.upper() == "LICENSE":
                # Composer expects the LICENSE file to be there, and the
                # easiest thing to do is to give it what it wants.
                add_item_to_set(item_path.name, doins, "license file", "root")

    def _get_psr4_base_directories(self) -> list[str]:
        """
        Get the top-level base directories from PSR-4 mapping.

        For PSR-4 packages, extract only the top-level directory from each path.
        For example, "src/JsonSchema" becomes "src", "lib" stays "lib".

        Returns:
            List of unique top-level base directories

        """
        logger.debug("Extracting PSR-4 base directories")

        if self.autoload["type"] != "psr-4":
            logger.debug("Not a PSR-4 package, returning empty list")
            return []

        directories = self.autoload.get("directories", [])
        if not directories:
            logger.debug("No directories in PSR-4 mapping")
            return []

        base_dirs = set()
        for directory in directories:
            dir_str = str(directory).rstrip("/")

            # Skip "." as it means current directory
            if dir_str in {".", ""}:
                continue

            # Extract the top-level directory (first part before /)
            top_level = dir_str.split("/")[0]
            base_dirs.add(top_level)
            logger.debug("Extracted top-level directory: %s from %s", top_level, dir_str)

        result = sorted(base_dirs)
        logger.debug("PSR-4 base directories: %s", result)
        return result

    def _get_upstream_base_dir(self) -> str:
        """
        Determine the upstream base directory for PSR-4 packages.

        This inspects the autoload directories and prefers common values like "src" or "lib".
        """
        logger.debug("Determining upstream base directory from autoload configuration")
        directories = [str(directory) for directory in self.autoload.get("directories", [])]

        for preferred in ("src", "lib"):
            if preferred in directories:
                logger.debug("Selected preferred upstream base directory: %s", preferred)
                self.upstream_base_dir = preferred
                return preferred

        if directories:
            # Use the first directory, even if it's "."
            logger.debug("Selected first autoload directory as upstream base directory: %s", directories[0])
            self.upstream_base_dir = directories[0]
            return directories[0]

        logger.debug("No autoload directories configured, defaulting upstream base directory to current directory")
        self.upstream_base_dir = "."
        return "."

    def _handle_psr4_package(self) -> str:
        """
        Handle src_prepare for PSR-4 packages.

        Returns:
            String containing the src_prepare section for PSR-4 packages

        """
        logger.debug("Package uses PSR-4, including phpab command")

        src_prepare = "default\n\n"
        src_prepare += "\tphpab \\\n"
        src_prepare += "\t\t--quiet \\\n"
        src_prepare += "\t\t--output autoload.php \\\n"
        src_prepare += "\t\t--template fedora2 \\\n"
        src_prepare += "\t\t--basedir . \\\n"
        src_prepare += "\t\t. \\\n"
        src_prepare += "\t\t|| die"

        dependency_autoloads = self.get_src_dependency_autoloads()
        if dependency_autoloads:
            src_prepare += "\n" + dependency_autoloads
        return src_prepare

    def _handle_other_package(self) -> str:
        """
        Handle src_prepare for non-PSR-4 packages.

        Returns:
            String containing the src_prepare section for non-PSR-4 packages

        """
        logger.debug("Package does not use PSR-4, creating manual autoload.php")
        src_prepare = "default\n\n"
        src_prepare += '\techo "<?php" > autoload.php\n'
        src_prepare += '\techo "require_once \\"${EPREFIX}/usr/share/php/Fedora/Autoloader/autoload.php\\";"'
        src_prepare += " >> autoload.php\n"

        if self.autoload["type"] == "psr-0":
            # We rather use single quotes here, in order to prevent quote issue when handing from Python to Bash to PHP
            src_prepare += "\n\techo \"\\\\Fedora\\\\Autoloader\\\\Autoload::addPsr0('"
            src_prepare += self.autoload["namespace"]
            src_prepare += "', __DIR__);\" >> autoload.php\n"
        elif self.autoload["type"] == "classmap":
            # Scan directories to build classmap
            classmap = scan_classmap_directories(self.temp_install_dir, self.autoload["directories"])

            if classmap:
                src_prepare += '\n\techo "" >> autoload.php\n'
                src_prepare += '\techo "\\\\Fedora\\\\Autoloader\\\\Autoload::addClassMap(array(" >> autoload.php\n'

                # Sort classmap entries for consistent output (case-insensitive sort)
                for class_name, file_path in sorted(classmap.items(), key=lambda x: x[0].lower()):
                    # Escape single quotes in class name and file path
                    escaped_class = class_name.replace("'", "\\'").lower()
                    escaped_path = file_path.replace("'", "\\'")
                    src_prepare += f"\techo \"    '{escaped_class}' => '{escaped_path}',\" >> autoload.php\n"

                src_prepare += '\techo "), __DIR__);" >> autoload.php\n'
            else:
                logger.warning("No classes found in classmap directories")

        # Add dependency autoloads for non-PSR-4 packages
        dependency_autoloads = self.get_src_dependency_autoloads()
        if dependency_autoloads:
            src_prepare += "\n" + dependency_autoloads

        return src_prepare

    def _get_src_prepare(self) -> str:
        """
        Generate the src_prepare section for the ebuild.

        Returns:
            The src_prepare section as a string

        """
        logger.debug("Generating src_prepare section")

        # Check for custom handler
        handler = self._handler_registry.get_handler(self.name)
        if handler:
            custom_prepare = handler.get_src_prepare(self)
            if custom_prepare is not None:
                src_prepare = custom_prepare
                # Add autoload files if present
                if self.autoload["files"]:
                    logger.debug("Adding files from autoload to manual autoload.php")
                    for file in self.autoload["files"]:
                        src_prepare += f'\n\techo "require_once __DIR__ . \\"/{file}\\";"'
                        src_prepare += " >> autoload.php\n"
                return src_prepare

        # Default handling for packages without custom handlers
        src_prepare = self._handle_psr4_package() if self.autoload["type"] == "psr-4" else self._handle_other_package()

        if self.autoload["files"]:
            logger.debug("Adding files from autoload to manual autoload.php")
            for file in self.autoload["files"]:
                src_prepare += f'\n\techo "require_once __DIR__ . \\"/{file}\\";"'
                src_prepare += " >> autoload.php\n"

        return src_prepare

    def _get_psr4_install_items(self) -> list[str]:
        """
        Build the list of directories and files to install for PSR-4 packages.

        For PSR-4 packages, install only the top-level base directories (like "src", "lib")
        to preserve the directory structure for static references.

        Returns:
            List of directories and files to be passed to doins -r.

        """
        logger.debug("Building PSR-4 install items")
        items: list[str] = []

        # Get the top-level base directories from PSR-4 mapping
        base_dirs = self._get_psr4_base_directories()

        if base_dirs:
            # Add each top-level base directory
            for base_dir in base_dirs:
                base_path = Path(self.temp_install_dir) / base_dir
                if base_path.is_dir():
                    items.append(base_dir)
                    logger.debug("Including PSR-4 base directory: %s", base_dir)
                else:
                    logger.debug("PSR-4 base directory %s does not exist in %s", base_dir, self.temp_install_dir)
        else:
            # When base_dir is ".", we need to include all PHP files and directories
            logger.debug("PSR-4 base directory is '.', including all content")
            for item_path in Path(self.temp_install_dir).iterdir():
                # Skip hidden items and bin directory
                if item_path.name.startswith(".") or item_path.name == "bin":
                    continue
                if item_path.is_dir() or item_path.name.endswith(".php"):
                    items.append(item_path.name)

        # Check for additional common directories that might not be in the PSR-4 mapping
        extra_dirs = ["res", "Resources", "config"]
        for directory in extra_dirs:
            dir_path = Path(self.temp_install_dir) / directory
            if dir_path.is_dir() and directory not in items:
                logger.debug("Including additional directory for install: %s", directory)
                items.append(directory)

        items.append("autoload.php")
        logger.debug("Final PSR-4 install items: %s", items)
        return items

    def _get_src_install(self) -> str:
        """
        Generate the src_install section for the ebuild.

        Returns:
            The src_install section as a string

        """
        logger.debug("Generating src_install section")

        # Check for custom handler
        handler = self._handler_registry.get_handler(self.name)
        if handler:
            custom_install = handler.get_src_install(self)
            if custom_install is not None:
                return custom_install

        # Default handling for packages without custom handlers
        if self.autoload["type"] == "psr-4":
            install_items = self._get_psr4_install_items()
            doins_content = f'doins -r {" ".join(install_items)} || die'
        else:
            doins_content = f"doins -r {self._get_doins()}"

        src_install = f'insinto "{self.install_path}"\n\t{doins_content}'

        # Handle bin files by installing them to the package directory and symlinking
        if self.bin_files:
            bin_install = self._get_bin_install()
            src_install += f"\n\n{bin_install}"

        return src_install

    @staticmethod
    def _get_patches_string(templates_dir: Path, package_name: str) -> str:
        """
        Generate the PATCHES section for the ebuild based on patch files in templates/files/{package_name}.

        Args:
            templates_dir: Directory containing the templates
            package_name: Standardized package name from get_package_name()

        Returns:
            String containing the PATCHES section or an empty string if no patches found

        """
        logger.debug("Checking for patch files for %s", package_name)

        # Check if there are patch files in templates/files/{package_name}
        package_files_dir = templates_dir / "files" / package_name
        if not package_files_dir.exists() or not package_files_dir.is_dir():
            logger.debug("No files directory found for %s", package_name)
            return ""

        # Find all .patch files
        patch_files = [f.name for f in package_files_dir.iterdir() if f.is_file() and f.name.endswith(".patch")]

        if not patch_files:
            logger.debug("No patch files found for %s", package_name)
            return ""

        # Generate the PATCHES section
        patches_string = "\nPATCHES=(\n"
        for patch_file in sorted(patch_files):
            patches_string += f'\t"${{FILESDIR}}"/{patch_file}\n'
        patches_string += ")\n"
        return patches_string

    def _get_bdepend_string(self) -> str:
        """
        Generate the BDEPEND section for the ebuild.

        For PSR-4 packages and composer: Include dev-php/theseer-autoload
        For other packages: No BDEPEND needed

        Returns:
            String containing the BDEPEND section

        """
        logger.debug("Generating BDEPEND section for %s", self.name)

        if self.autoload["type"] == "psr-4" or get_package_name(self.name) == "composer":
            # For PSR-4 packages and composer, add theseer-autoload as BDEPEND
            bdepend = 'BDEPEND="dev-php/theseer-autoload"'
            logger.debug("Added theseer-autoload as BDEPEND for PSR-4 package or composer")
        else:
            # For non-PSR-4 packages, no BDEPEND needed
            bdepend = ""
            logger.debug("No BDEPEND needed for non-PSR-4 package")

        return bdepend

    def _get_doins(self) -> str:
        """
        Get doins based on the autoload information and directory structure.

        Returns:
            A string containing the unique doins and dependency autoload information

        """
        logger.debug("Get list of files and directories to be installed")

        doins = set()
        php_files = set()

        self._process_autoload_directories(doins)
        self._process_autoload_files(doins, php_files)
        self._process_root_directory(doins, php_files)

        # Add autoload.php for non-PSR-4 packages (it's generated in src_prepare)
        if self.autoload["type"] != "psr-4":
            php_files.add("autoload.php")
            logger.debug("Added autoload.php for non-PSR-4 package")

        # Replace individual PHP files with *.php if there are any
        if php_files:
            doins.add("*.php")
            logger.debug("Replaced individual PHP files with *.php")

        # Filter out subdirectories if the base directory is already in the list
        filtered_doins = filter_subdirectories(doins)
        result = " ".join(sorted(filtered_doins)).strip(" ")
        logger.debug("Final doins string: %s", result)

        return result

    def _get_bin_install(self) -> str:
        """
        Generate the bin installation section for the ebuild.

        Installs bin files to the package directory and creates symlinks in /usr/bin.

        Returns:
            The bin installation section as a string

        """
        logger.debug("Generating bin installation section")

        if not self.bin_files:
            logger.debug("No bin files found")
            return ""

        bin_install = f'\tinsinto "{self.install_path}"\n'
        bin_install += "\tdoins -r bin\n"

        # Create symlinks for each bin file
        for bin_file in self.bin_files:
            # Extract just the filename from the path (e.g., "bin/composer" -> "composer")
            bin_name = Path(bin_file).name
            logger.debug("Symlinking to %s in %s", bin_name, self.install_path)
            bin_install += f'\tfperms +x "{self.install_path}/{bin_file}"\n\n'
            bin_install += f'\tdosym "{self.install_path}/{bin_file}" "/usr/bin/{bin_name}"'
            if bin_file != self.bin_files[-1]:
                bin_install += "\n"

        return bin_install

    def _set_workdir(self) -> None:
        """
        Set the WORKDIR string for the ebuild.

        This method reads the package root directory and sets the name of the extracted directory.
        It checks if the version is part of the directory name and replaces
        the version with "${PV}".

        Raises:
            ComposerJsonError: If no extracted directory is found

        """
        logger.debug("Setting WORKDIR string")
        package_dir = Path(self.temp_dir) / "package" / get_package_name(self.name)
        logger.debug("Package directory: %s", package_dir)

        # Get the name of the extracted directory
        package_path = Path(package_dir)
        extracted_dirs = [d.name for d in package_path.iterdir() if d.is_dir()]
        if not extracted_dirs:
            raise ComposerJsonError(ComposerJsonError.NO_EXTRACTED_DIR)

        work_dir = extracted_dirs[0]
        logger.debug("Extracted directory: %s", work_dir)

        # Replace version with ${PV} if it's in the directory name
        if self.version in work_dir:
            work_dir = work_dir.replace(self.version, "${PV}")
            logger.debug("Replaced version with ${PV}: %s", work_dir)

        self.work_dir = "${WORKDIR}/" + work_dir
        logger.debug("Package working directory: %s", self.work_dir)

    def _set_install_path(self) -> None:
        """Set the installation path based on the package name."""
        logger.debug("Setting package install path")

        # Parse the package name
        vendor, package = self.name.split("/")

        # Convert vendor to title case
        vendor_segment = vendor.capitalize()

        # Convert package name: split by hyphens, capitalize each part, and join with /
        package_parts = package.split("-")
        package_segments = [part.capitalize() for part in package_parts]
        package_segment = "-".join(package_segments)

        self.install_path = str(Path("/usr/share/php") / vendor_segment / package_segment)
        logger.debug("Install path: %s", self.install_path)

    def _set_github_repo(self) -> None:
        """
        Set the GitHub repository object as a class attribute.

        Raises:
            ComposerJsonError: If unable to get the repository or if rate limit is exceeded

        """
        g = Github(self.github_token, retry=None) if self.github_token else Github(retry=None)

        try:
            repo_name = self.repository_url.split("github.com/")[-1]
            self.github_repo = g.get_repo(repo_name)
            if not self.github_repo:
                error_msg = "GitHub repository not set"
                raise ComposerJsonError(error_msg)
        except GithubException as e:
            error_msg = f"Failed to get GitHub repository: {e}"
            raise ComposerJsonError(error_msg) from e

    def _set_github_tag_for_version(self) -> None:
        """
        Find a matching tag for the current version in the GitHub repository and set it as a class attribute.

        Raises:
            ComposerJsonError: If no matching tag is found or if GitHub API access fails

        """
        logger.debug("Looking for tag matching version %s", self.version)

        if not self.github_repo:
            error_msg = "GitHub repository not set"
            raise ComposerJsonError(error_msg)

        try:
            tags = self.github_repo.get_tags()
            for tag in tags:
                if tag.name in {self.version, f"v{self.version}"}:
                    logger.debug("Found matching tag: %s", tag.name)
                    self.github_tag = tag.name
                    return

            # If we get here, no matching tag was found
            error_msg = f"No matching tag found for version {self.version}"
            raise ComposerJsonError(error_msg)

        except GithubException as e:
            error_msg = f"Failed to fetch tags from GitHub API: {e}"
            logger.debug(error_msg)
            raise ComposerJsonError(error_msg) from e

    def _set_commit_sha(self) -> None:
        """
        Set the commit SHA for the specific version of the package.

        Raises:
            ComposerJsonError: If unable to fetch the SHA

        """
        if not self.github_repo or not self.github_tag:
            error_msg = "GitHub repository or tag not set"
            raise ComposerJsonError(error_msg)

        try:
            tag = self.github_repo.get_git_ref(f"tags/{self.github_tag}")
            if tag.object.type == "tag":
                # Annotated tag
                tag_obj = self.github_repo.get_git_tag(tag.object.sha)
                self.sha = tag_obj.object.sha
            else:
                # Lightweight tag
                self.sha = tag.object.sha
        except GithubException as e:
            error_msg = f"Failed to get commit SHA for tag {self.github_tag}: {e}"
            raise ComposerJsonError(error_msg) from e

    def _set_tagged_tarball_url(self) -> None:
        """
        Set the download URL for the specified tagged tar.gz archive from GitHub.

        Raises:
            ComposerJsonError: If the URL cannot be fetched or the version is not found

        """
        if not self.github_repo or not self.github_tag:
            error_msg = "GitHub repository or tag not set"
            raise ComposerJsonError(error_msg)

        self.src_uri = f"{self.repository_url}/archive/{self.github_tag}.tar.gz"
        logger.debug("Found tar.gz URL for version %s: %s", self.version, self.src_uri)

    def _create_metadata_xml(self, package_dir: Path) -> None:
        """
        Create a metadata.xml file for the package.

        Args:
            package_dir: The directory where the metadata.xml file will be created

        """
        logger.debug("Creating metadata.xml for %s", self.name)

        metadata_content = "<?xml version='1.0' encoding='utf-8'?>\n"
        metadata_content += '<!DOCTYPE pkgmetadata SYSTEM "https://www.gentoo.org/dtd/metadata.dtd">\n'
        metadata_content += "<pkgmetadata>\n"

        # Add upstream information if available
        if self.repository_url and "github.com" in self.repository_url:
            repo_name = self.repository_url.split("github.com/")[-1]
            metadata_content += "  <upstream>\n"
            metadata_content += f'    <remote-id type="github">{repo_name}</remote-id>\n'
            metadata_content += "  </upstream>\n"

        metadata_content += "</pkgmetadata>\n"

        metadata_file = package_dir / "metadata.xml"
        with metadata_file.open("w") as f:
            f.write(metadata_content)

        logger.debug("Created metadata.xml at %s", metadata_file)
