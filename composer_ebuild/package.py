"""Module for handling Composer packages and generating ebuilds."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
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
    check_github_rate_limit,
    compare_versions,
    format_path,
    get_github_tag_for_version,
    get_package_name,
    get_php_useflags,
    run_subprocess,
)

if TYPE_CHECKING:
    from github.Repository import Repository

logger = logging.getLogger(__name__)

EAPI_VERSION: int = 8


class ComposerPackage:

    """Class to represent a Composer package and generate its ebuild."""

    name: str
    description: str
    version: str
    install_dir: str
    temp_dir: str
    output_dir: str | None
    repository_url: str | None
    src_uri: str | None
    sha: str | None
    licenses: list[str]
    requires: dict[str, str]
    dependencies: dict
    autoload: dict[str, Any]
    php_min_version: str
    work_dir: str
    github_token: str | None

    def __init__(self, name: str, version: str, temp_dir: str, github_token: str | None = None) -> None:
        """
        Initialize the ComposerPackage.

        Args:
            name: The name of the Composer package
            version: The version of the Composer package
            temp_dir: The temporary directory where the Composer package is installed
            github_token: Optional GitHub API token for authentication

        """
        self.name = name
        self.version: str = re.sub(r"^v", "", version)
        self.temp_dir: str = temp_dir
        self.install_dir: str = str(Path(self.temp_dir) / "vendor" / name.replace("/", os.sep))
        self.repository_url: str | None = None
        self.src_uri: str | None = None
        self.sha: str | None = None
        self.licenses: list[str] = []
        self.requires: dict[str, str] = {}
        self.dependencies: dict[str, dict[str, Any]] = {}
        self.autoload: dict[str, Any] = {}
        self.php_min_version: str = "7.4"  # Default minimum PHP version
        self.github_token: str | None = github_token

        logger.debug("Version: %s", self.version)

        try:
            self._load_composer_info()
            self._process_main_dependencies()
            self.work_dir = self._get_workdir()
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

        # Get the package installation path
        install_path = self.get_install_path()

        logger.debug("Package install path: %s", install_path)

        current_date = datetime.now(tz=timezone.utc).strftime("%Y")
        # Select appropriate template directory based on package name
        package_name = get_package_name(self.name)
        template_path = templates_dir / ("composer" if package_name == "composer" else "")
        template_file = template_path / "ebuild"

        with template_file.open() as f:
            ebuild_template = f.read().replace("{{date}}", current_date)

        dependencies_string = "\n\t".join(
            [f"{info['ebuild']}" for dep, info in self.dependencies.items() if info.get("type") == "main"],
        )
        doins = f"doins -r {self._get_doins()}"

        # Replace version in SRC_URI with ${PV} if it matches the package version
        if f"{self.version}" in self.src_uri:
            src_uri = self.src_uri.replace(f"{self.version}", "${PV}")
        else:
            src_uri = self.src_uri

        ebuild_content = (
            ebuild_template.replace("{{eapi}}", str(EAPI_VERSION))
            .replace("{{homepage}}", self.repository_url or "https://packagist.org/packages/" + self.name)
            .replace("{{description}}", self.description or "No description available")
            .replace("{{src_uri}}", src_uri + " -> ${P}.tar.gz")
            .replace("{{license}}", " ".join(self.licenses).strip() or "Unknown")
            .replace("{{dependencies}}", dependencies_string)
            .replace("{{insinto}}", f'insinto "{install_path}"')
            .replace("{{doins}}", doins)
            .replace("{{src_prepare}}", self._get_src_prepare())
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
        self._copy_files_directory(template_path, package_dir)

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

    def get_install_path(self) -> str:
        """
        Get the installation path based on the autoload information.

        Returns:
            The directory path for the package

        """
        logger.debug("Getting package layout")
        if self.autoload["type"] == "psr-4":
            logger.debug("Package uses PSR-4 layout")
            namespace = self.autoload["namespace"]
            install_path = str(Path("/usr/share/php") / namespace.replace("\\", "/").rstrip("/"))
            logger.debug("Install path: %s", install_path)
            return install_path
        logger.warning("Package %s does not use PSR-4 autoloading", self.name)
        vendor, package = self.name.split("/")
        if vendor.lower() == "symfony":
            install_path = f"/usr/share/php/Symfony/Component/{package.title().replace('-', '')}"
            logger.debug("Symfony package detected. Install path: %s", install_path)
            return install_path
        install_path = f"/usr/share/php/{get_package_name(self.name).capitalize()}"
        logger.debug("Non-PSR-4 package. Install path: %s", install_path)
        return install_path

    def _load_composer_json(self) -> dict:
        """
        Load and parse the composer.json file.

        Returns:
            A dictionary containing the parsed composer.json data

        Raises:
            ComposerJsonError: If the file is not found or cannot be parsed

        """
        logger.debug("Reading composer.json file")
        composer_json_path = Path(self.install_dir) / "composer.json"
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
        logger.debug("Loaded licenses: %s", self.licenses)
        logger.debug("Loaded requires: %s", self.requires)

        # Load autoload information
        self._process_autoload_info(composer_json_info.get("autoload", {}))

        if not self.description or not self.repository_url:
            error_msg = "Missing required information in composer.json"
            raise ComposerJsonError(error_msg)

        # We can't get SHA from composer.json, so we'll need to fetch it from GitHub API
        try:
            self.sha = self._get_commit_sha()
            self.src_uri = self._get_tagged_tarball_url()
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
            for directory in self.autoload["directories"]:
                formatted_path = format_path(directory)
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
        for item in os.listdir(self.install_dir):
            item_path = Path(self.install_dir) / item
            if item_path.is_dir() and item not in self.autoload["directories"]:
                add_item_to_set(item, doins, "directory", "root")
            elif item.endswith(".php") and item not in self.autoload["files"]:
                add_item_to_set(item, php_files, "PHP file", "root")

    def _handle_composer_package(self) -> str:
        """
        Handle src_prepare for the composer package itself.

        Returns:
            String containing the src_prepare section for composer package

        """
        src_prepare = "default\n\n"
        src_prepare += "mkdir vendor || die\n\n"
        src_prepare += "\tphpab \\\n"
        src_prepare += "\t\t--output vendor/autoload.php \\\n"
        src_prepare += '\t\t--template "${FILESDIR}"/autoload.php.tpl \\\n'
        src_prepare += "\t\t--basedir src \\\n"
        src_prepare += "\t\tsrc \\\n"
        src_prepare += "\t\t|| die\n"

        dependency_autoloads = self._get_src_dependency_autoloads(autoload_file="vendor/autoload.php")
        if dependency_autoloads:
            src_prepare += dependency_autoloads
        return src_prepare

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
        src_prepare += "\t\t--output autoload.php \\\n"
        src_prepare += "\t\t--template fedora2 \\\n"
        src_prepare += f"\t\t--basedir {basedir} \\\n"
        src_prepare += f"\t\t{basedir} \\\n"
        src_prepare += "\t\t|| die"

        dependency_autoloads = self._get_src_dependency_autoloads()
        if dependency_autoloads:
            src_prepare += dependency_autoloads
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

        if get_package_name(self.name) == "composer":
            src_prepare = self._handle_composer_package()
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

    def _get_github_repo(self) -> Repository:
        """
        Get the GitHub repository object.

        Returns:
            The GitHub repository object

        Raises:
            ComposerJsonError: If unable to get the repository or if rate limit is exceeded

        """
        g = Github(self.github_token) if self.github_token else Github()

        # Check rate limit
        is_rate_limited, error_message = check_github_rate_limit(g)
        if is_rate_limited:
            raise ComposerJsonError(error_message)

        try:
            repo_name = self.repository_url.split("github.com/")[-1]
            return g.get_repo(repo_name)
        except GithubException as e:
            error_msg = f"Failed to get GitHub repository: {e}"
            raise ComposerJsonError(error_msg) from e

    def _get_commit_sha(self) -> str:
        """
        Get the commit SHA for the specific version of the package.

        Returns:
            The commit SHA for the specific version

        Raises:
            ComposerJsonError: If unable to fetch the SHA

        """
        repo = self._get_github_repo()
        success, error_msg, tag_name = get_github_tag_for_version(repo, self.version)

        if not success:
            raise ComposerJsonError(error_msg)

        try:
            tag = repo.get_git_ref(f"tags/{tag_name}")
            if tag.object.type == "tag":
                # Annotated tag
                tag_obj = repo.get_git_tag(tag.object.sha)
                return tag_obj.object.sha
            # Lightweight tag
            return tag.object.sha
        except GithubException as e:
            error_msg = f"Failed to get commit SHA for tag {tag_name}: {e}"
            raise ComposerJsonError(error_msg) from e

    def _get_tagged_tarball_url(self) -> str:
        """
        Get the download URL for the specified tagged tar.gz archive from GitHub.

        Returns:
            The download URL for the tar.gz archive

        Raises:
            ComposerJsonError: If the URL cannot be fetched or the version is not found

        """
        repo = self._get_github_repo()
        success, error_msg, tag_name = get_github_tag_for_version(repo, self.version)

        if not success:
            raise ComposerJsonError(error_msg)

        tarball_url = f"{self.repository_url}/archive/{tag_name}.tar.gz"
        logger.debug("Found tar.gz URL for version %s: %s", self.version, tarball_url)
        return tarball_url

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

        result = " ".join(sorted(doins)).strip(" ")
        logger.debug("Final doins string: %s", result)

        return result

    def _get_src_dependency_autoloads(self, autoload_file: str = "autoload.php") -> str | None:
        """
        Get the dependency_autoload section for src_prepare.

        Args:
            autoload_file: The name of the autoload file to modify

        Returns:
            String containing dependency autoload information or None if no dependencies

        """
        dependencies = ""
        # Add dependency autoload information
        dependency_autoloads = []
        for dep_info in self.dependencies.values():
            if "instance" in dep_info and hasattr(dep_info["instance"], "get_install_path"):
                install_path = dep_info["instance"].get_install_path()
                dependency_autoloads.append(
                    f"\"${{VENDOR_DIR}}{install_path.replace('/usr/share/php', '')}/autoload.php\"",
                )

        if dependency_autoloads:
            dependencies += "\n\n"
            dependencies += '\n\tVENDOR_DIR="${EPREFIX}/usr/share/php"'
            dependencies += f'\n\tcat >> {autoload_file} <<EOF || die "failed to extend autoload.php"'
            dependencies += "\n\n// Dependencies"
            dependencies += "\n\\Fedora\\Autoloader\\Dependencies::required(["
            dependencies += '\n\t"${VENDOR_DIR}/Fedora/Autoloader/autoload.php",\n\t'
            dependencies += ",\n\t".join(dependency_autoloads)
            dependencies += "\n]);"
            dependencies += "\nEOF"
            return dependencies
        return None

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

    def _get_workdir(self) -> str:
        """
        Get the WORKDIR string for the ebuild.

        This method reads the package root directory and returns the name of the extracted directory.
        It checks if the version is part of the directory name and replaces
        the version with "${PV}".

        Returns:
            The WORKDIR string for the ebuild

        Raises:
            ComposerJsonError: If no extracted directory is found

        """
        logger.debug("Getting WORKDIR string")
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

        logger.debug("Final WORKDIR string: %s", work_dir)
        return "${WORKDIR}/" + work_dir
    def _copy_files_directory(self, template_path: Path, package_dir: Path) -> None:
        """
        Copy the files directory from templates to the package directory.

        Args:
            template_path: Path to the template directory
            package_dir: Path to the package directory where files will be copied

        """
        files_dir = template_path / "files"
        if files_dir.exists():
            logger.debug("Found files directory at %s", files_dir)
            package_files_dir = package_dir / "files"
            if package_files_dir.exists():
                shutil.rmtree(package_files_dir)
            shutil.copytree(files_dir, package_files_dir)
            logger.debug("Copied files directory to %s", package_files_dir)
