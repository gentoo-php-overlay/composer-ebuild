"""Module for handling Composer packages and generating ebuilds."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Any

import requests
from github import Github
from github.GithubException import GithubException

from composer_ebuild.exceptions import ComposerJsonError
from composer_ebuild.utils import (
    add_item_to_set,
    compare_versions,
    copy_files_directory,
    filter_subdirectories,
    format_path,
    get_package_name,
    get_php_useflags,
    run_subprocess,
)

if TYPE_CHECKING:
    from github.Repository import Repository

# Constants
DEFAULT_PHP_MIN_VERSION: str = "7.4"
EAPI_VERSION: int = 8
HTTP_FORBIDDEN: int = 403

logger = logging.getLogger(__name__)


class ComposerPackage:

    """Class to represent a Composer package and generate its ebuild."""

    autoload: dict[str, Any]
    bin_files: list[str]
    dependencies: dict
    description: str
    github_repo: Repository | None
    github_tag: str | None
    github_token: str | None
    install_path: str
    licenses: list[str]
    name: str
    output_dir: str | None
    php_min_version: str
    repository_url: str | None
    requires: dict[str, str]
    sha: str | None
    src_uri: str | None
    temp_dir: str
    temp_install_dir: str
    version: str
    work_dir: str

    def __init__(self, name: str, version: str, temp_dir: str, github_token: str | None = None) -> None:
        """
        Initialize the ComposerPackage.

        Args:
            name: The name of the Composer package
            version: The version of the Composer package
            temp_dir: The temporary directory where the Composer package is installed
            github_token: Optional GitHub API token for authentication

        """
        self.autoload: dict[str, Any] = {}
        self.bin_files: list[str] = []
        self.dependencies: dict[str, dict[str, Any]] = {}
        self.github_repo: Repository | None = None
        self.github_tag: str | None = None
        self.github_token: str | None = github_token
        self.licenses: list[str] = []
        self.name = name
        self.php_min_version: str = DEFAULT_PHP_MIN_VERSION
        self.repository_url: str | None = None
        self.requires: dict[str, str] = {}
        self.sha: str | None = None
        self.src_uri: str | None = None
        self.temp_dir: str = temp_dir
        self.temp_install_dir: str = str(Path(temp_dir) / "vendor" / name.replace("/", os.sep))
        self.version: str = re.sub(r"^v", "", version)

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

        current_date = datetime.now(tz=timezone.utc).strftime("%Y")
        # Use the standard template file
        template_file = templates_dir / "ebuild"

        with template_file.open() as f:
            ebuild_template = f.read().replace("{{date}}", current_date)

        # Replace version in SRC_URI with ${PV} if it matches the package version
        if f"{self.version}" in self.src_uri:
            src_uri = self.src_uri.replace(f"{self.version}", "${PV}")
        else:
            src_uri = self.src_uri

        dependencies_string = "\n\t".join(
            [f"{info['ebuild']}" for dep, info in self.dependencies.items() if info.get("type") == "main"],
        )

        # Check for patch files
        package_name = get_package_name(self.name)
        patches_string = self._get_patches_string(templates_dir, package_name)

        ebuild_content = (
            ebuild_template.replace("{{eapi}}", str(EAPI_VERSION))
            .replace("{{homepage}}", self.repository_url or "https://packagist.org/packages/" + self.name)
            .replace("{{description}}", self.description or "No description available")
            .replace("{{src_uri}}", src_uri + " -> ${P}.tar.gz")
            .replace("{{license}}", " ".join(self.licenses).strip() or "Unknown")
            .replace("{{dependencies}}", "\t" + dependencies_string)
            .replace("{{patches}}", patches_string)
            .replace("{{src_prepare}}", "\t" + self._get_src_prepare())
            .replace("{{src_install}}", "\t" + self._get_src_install())
            .replace("{{workdir}}", self.work_dir)
        )

        package_name = get_package_name(self.name)
        ebuild_filename = f"{package_name}-{self.version.lstrip('v')}.ebuild"
        package_dir = Path(self.output_dir) / "dev-php" / package_name
        package_dir.mkdir(parents=True, exist_ok=True)
        ebuild_output_file = package_dir / ebuild_filename

        with ebuild_output_file.open("w") as f:
            f.write(ebuild_content)

        logger.debug("Created ebuild at %s", ebuild_output_file)

        # Create metadata.xml file if requested
        if create_metadata:
            self._create_metadata_xml(package_dir)

        # Copy files directory if it exists
        copy_files_directory(templates_dir, package_dir)

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
                "ebuild": f"dev-php/{get_package_name(sub_dep_name)}",
                "instance": sub_dep_instance,
                "type": "sub",
            }
            logger.debug("Added sub-dependency: %s", sub_dep_name)
        else:
            logger.debug("Skipped adding sub-dependency: %s (already exists or excluded)", sub_dep_name)

        self._sort_dependencies()

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
            error_msg = f"composer.json not found for {self.name}"
            raise ComposerJsonError(error_msg) from e
        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse composer.json for {self.name}"
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
        logger.debug("Running composer show command for %s", self.name)
        try:
            command = ["/usr/bin/composer", "show", self.name, "--format=json"]
            logger.debug("Running command in directory %s: %s", self.temp_dir, " ".join(command))
            _, stdout, stderr = run_subprocess(command, cwd=self.temp_dir, capture_output=True, check=True)
            composer_show_info = json.loads(stdout)
            logger.debug("Successfully loaded composer show information")
        except subprocess.CalledProcessError as e:
            error_msg = (f"Failed to run composer show command for {self.name}: {e}\n"
                         f"Command output: {e.stderr if hasattr(e, 'stderr') else ''}")
            raise ComposerJsonError(error_msg) from e
        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse composer show output for {self.name}: {e}"
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

    def _download_and_extract_package(self) -> None:
        """
        Download the package to temp_dir and extract it to self.temp_dir + '/package'.

        Extraction behaves exactly like 'tar xzf FILENAME.tar.gz'.

        Raises:
            ComposerJsonError: If download or extraction fails

        """
        logger.debug("Downloading and extracting package")
        # Create a temporary file to store the downloaded package
        with tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz") as temp_file:
            # Download the package
            response = requests.get(self.src_uri, timeout=30)
            if response.status_code != HTTPStatus.OK:
                error_message = f"Failed to download package from {self.src_uri}"
                raise ComposerJsonError(error_message)
            temp_file.write(response.content)
            temp_file_path = temp_file.name

        # Extract the package
        extract_path = Path(self.temp_dir) / "package" / get_package_name(self.name)
        extract_path.mkdir(parents=True, exist_ok=True)

        # Use subprocess to run tar command, mimicking "tar xzf FILENAME.tar.gz" behavior
        try:
            return_code, _, stderr = run_subprocess(
                ["/bin/tar", "xzf", temp_file_path], cwd=str(extract_path), check=True,
            )
            if return_code != 0:
                error_msg = f"Failed to extract package. Error: {stderr}"
                raise ComposerJsonError(error_msg)
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to extract package: {e}"
            raise ComposerJsonError(error_msg) from e

        # Clean up the temporary file
        Path(temp_file_path).unlink()
        logger.debug("Package extracted to %s", extract_path)

    def _sort_dependencies(self) -> None:
        """
        Sort dependencies ensuring dev-lang/php is always on top.

        Followed by dev-php/fedora-autoloader, while the rest are sorted alphabetically.
        """
        logger.debug("Sorting dependencies")
        sorted_deps = {}

        # Add dev-lang/php first
        if "php" in self.dependencies:
            sorted_deps["php"] = self.dependencies["php"]

        # Add dev-php/fedora-autoloader second
        if "fedora-autoloader" in self.dependencies:
            sorted_deps["fedora-autoloader"] = self.dependencies["fedora-autoloader"]

        # Sort the rest of the dependencies by their ebuild names
        sorted_deps.update({
            dep: info for dep, info in sorted(self.dependencies.items(), key=lambda x: x[1]["ebuild"])
            if dep not in ["php", "fedora-autoloader"]
        })
        self.dependencies = sorted_deps
        logger.debug("Sorted dependencies: %s", self.dependencies)

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
            if isinstance(directories, str):
                directories = [directories]
            self.autoload["directories"] = directories
        elif "psr-0" in autoload_info:
            self.autoload["type"] = "psr-0"
            namespace = next(iter(autoload_info["psr-0"]))
            self.autoload["namespace"] = namespace
            directories = autoload_info["psr-0"][namespace]
            if isinstance(directories, str):
                directories = [directories]
            self.autoload["directories"] = directories
        elif "classmap" in autoload_info:
            self.autoload["type"] = "classmap"
            self.autoload["directories"] = autoload_info["classmap"]

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

        Adds non-PHP dependencies to the dependencies dictionary.
        """
        for dep, _version_req in sorted(self.requires.items()):
            if dep.lower() != "php" and not dep.lower().startswith("ext-"):
                package_name = get_package_name(dep)
                self.dependencies[dep] = {"ebuild": f"dev-php/{package_name}", "type": "main"}

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

        # Add dev-php/fedora-autoloader
        self.dependencies["fedora-autoloader"] = {"ebuild": "dev-php/fedora-autoloader", "type": "main"}

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
        for item in os.listdir(self.temp_install_dir):
            # Skip hidden directories and files (starting with .)
            if item.startswith("."):
                logger.debug("Skipping hidden item: %s", item)
                continue

            item_path = Path(self.temp_install_dir) / item
            if item_path.is_dir() and item not in self.autoload["directories"]:
                add_item_to_set(item, doins, "directory", "root")
            elif item.endswith(".php") and item not in self.autoload["files"]:
                add_item_to_set(item, php_files, "PHP file", "root")
            elif item.upper() == "LICENSE":
                # Composer expects the LICENSE file to be there, and the
                # easiest thing to do is to give it what it wants.
                add_item_to_set(item, doins, "license file", "root")

    def _handle_composer_package(self) -> tuple[str, str]:
        """
        Composer does not work well with the defaults. So we need to handle it with this method instead.

        Returns:
            Tuple containing (src_prepare, src_install) sections for composer package

        """
        src_prepare = "default\n\n"
        src_prepare += "\tmkdir vendor || die\n\n"
        src_prepare += "\tphpab \\\n"
        src_prepare += "\t\t--quiet \\\n"
        src_prepare += "\t\t--output vendor/autoload.php \\\n"
        src_prepare += '\t\t--template "${FILESDIR}"/autoload.php.tpl \\\n'
        src_prepare += "\t\t--basedir src \\\n"
        src_prepare += "\t\tsrc \\\n"
        src_prepare += "\t\t|| die\n"

        dependency_autoloads = self._get_src_dependency_autoloads(autoload_file="vendor/autoload.php")
        if dependency_autoloads:
            src_prepare += dependency_autoloads

        # Generate src_install section for composer
        src_install = 'insinto "/usr/share/composer"\n'
        src_install += "\tdoins -r LICENSE res src vendor\n\n"
        src_install += '\texeinto "/usr/share/composer/bin"\n'
        src_install += '\tdoexe "bin/composer"\n'
        src_install += '\tdosym "../share/composer/bin/composer" "/usr/bin/composer"'

        return src_prepare, src_install

    def _handle_psr4_package(self) -> str:
        """
        Handle src_prepare for PSR-4 packages.

        Returns:
            String containing the src_prepare section for PSR-4 packages

        """
        basedir = "src" if "src" in self.autoload["directories"] else "."
        logger.debug("Package uses PSR-4, including phpab command with basedir: %s", basedir)

        src_prepare = "default\n\n"
        src_prepare += "\tphpab \\\n"
        src_prepare += "\t\t--quiet \\\n"
        src_prepare += "\t\t--output autoload.php \\\n"
        src_prepare += "\t\t--template fedora2 \\\n"
        src_prepare += f"\t\t--basedir {basedir} \\\n"
        src_prepare += f"\t\t{basedir} \\\n"
        src_prepare += "\t\t|| die"

        dependency_autoloads = self._get_src_dependency_autoloads()
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
            src_prepare += '\n\techo "\\\\Fedora\\\\Autoloader\\\\Autoload::addClassMap(["'
            src_prepare += " >> autoload.php\n"
            for directory in self.autoload["directories"]:
                src_prepare += f'\techo "    "{directory}" => __DIR__ . "/{directory}","'
                src_prepare += " >> autoload.php\n"
            src_prepare += '\techo "]);"'
            src_prepare += " >> autoload.php\n"

        return src_prepare

    def _get_src_prepare(self) -> str:
        """
        Generate the src_prepare section for the ebuild.

        Returns:
            The src_prepare section as a string

        """
        logger.debug("Generating src_prepare section")

        # Get src_prepare for the package
        if get_package_name(self.name) == "composer":
            src_prepare, _ = self._handle_composer_package()
        elif self.autoload["type"] == "psr-4":
            src_prepare = self._handle_psr4_package()
        else:
            src_prepare = self._handle_other_package()

        if self.autoload["files"]:
            logger.debug("Adding files from autoload to manual autoload.php")
            for file in self.autoload["files"]:
                src_prepare += f'\n\techo "require_once __DIR__ . \\"/{file}\\";"'
                src_prepare += " >> autoload.php\n"

        return src_prepare

    def _get_src_install(self) -> str:
        """
        Generate the src_install section for the ebuild.

        Returns:
            The src_install section as a string

        """
        logger.debug("Generating src_install section")

        # For composer package, return the special src_install section
        if get_package_name(self.name) == "composer":
            _, src_install = self._handle_composer_package()
            return src_install

        # For regular packages, generate the standard src_install section
        doins_content = f"doins -r {self._get_doins()}"
        dobins_content = self._get_dobins()

        src_install = f'insinto "{self.install_path}"\n\t{doins_content}'
        if dobins_content:
            src_install += f"\n\n\t{dobins_content}"

        return src_install

    @staticmethod
    def _get_patches_string(templates_dir: Path, package_name: str) -> str:
        """
        Generate the PATCHES section for the ebuild based on patch files in templates/files/{package_name}.

        Args:
            templates_dir: Directory containing the templates
            package_name: Name of the package to check for patches

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

        # Add autoload.php if it's a PSR-4 package
        if self.autoload["type"] == "psr-4":
            php_files.add("autoload.php")
            logger.debug("Added autoload.php for PSR-4 package")

        # Replace individual PHP files with *.php if there are any
        if php_files:
            doins.add("*.php")
            logger.debug("Replaced individual PHP files with *.php")

        # Filter out subdirectories if the base directory is already in the list
        filtered_doins = filter_subdirectories(doins)
        result = " ".join(sorted(filtered_doins)).strip(" ")
        logger.debug("Final doins string: %s", result)

        return result

    def _get_dobins(self) -> str:
        """
        Generate the dobins section for the ebuild based on bin files in composer.json.

        Returns:
            The dobins section as a string

        """
        logger.debug("Generating dobins section")

        if not self.bin_files:
            logger.debug("No bin files found")
            return ""
        dobins_content = [f'exeinto "{self.install_path}/bin"']

        # Add doexe lines for each binary file
        for bin_file in self.bin_files:
            dobins_content.append(f'doexe "{bin_file}"')

            # Extract the filename from the path
            bin_filename = Path(bin_file).name

            # Add dosym line for each binary file
            dobins_content.append(f'dosym "{self.install_path}/bin/{bin_filename}" "/usr/bin/{bin_filename}"')

        # Join all lines with newline and tab
        return "\n\t".join(dobins_content)

    def _get_src_dependency_autoloads(self, autoload_file: str = "autoload.php") -> str | None:
        """
        Get the dependency_autoload section for src_prepare.

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
        extracted_dirs = [d for d in os.listdir(package_dir) if (package_path / d).is_dir()]
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
        """Set the installation path based on the autoload information."""
        logger.debug("Setting package install path")
        if self.autoload["type"] == "psr-4":
            logger.debug("Package uses PSR-4 layout")
            namespace = self.autoload["namespace"]
            self.install_path = str(Path("/usr/share/php") / namespace.replace("\\", "/").rstrip("/"))
            logger.debug("Install path: %s", self.install_path)
            return
        logger.warning("Package %s does not use PSR-4 autoloading", self.name)
        vendor, package = self.name.split("/")
        if vendor.lower() == "symfony":
            self.install_path = f"/usr/share/php/Symfony/Component/{package.title().replace('-', '')}"
            logger.debug("Symfony package detected. Install path: %s", self.install_path)
            return
        self.install_path = f"/usr/share/php/{get_package_name(self.name).capitalize()}"
        logger.debug("Non-PSR-4 package. Install path: %s", self.install_path)

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
