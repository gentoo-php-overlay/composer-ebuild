"""Command line interface for generating Gentoo ebuilds from Composer packages."""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from composer_ebuild.exceptions import ComposerJsonError, ComposerPackageInstallError, EbuildGenerationError
from composer_ebuild.logger import configure_logging
from composer_ebuild.package import ComposerPackage
from composer_ebuild.utils import is_running_in_ide

logger = logging.getLogger(__name__)

DEFAULT_TEMP_DIR = str(Path(tempfile.gettempdir()) / "composer-ebuild")


@dataclass
class GeneratorConfig:

    """Configuration for the ComposerEbuildGenerator."""

    debug: bool = False
    github_token: str | None = None
    skip_downgrade: bool = False
    version: str = "latest"
    platform: str = "7.4"


class ComposerEbuildGenerator:

    """A class to generate ebuilds for a given Composer package."""

    package_name: str
    output_dir: str
    temp_dir: str
    debug: bool
    github_token: str
    packages: dict[str, ComposerPackage]
    templates_dir: Path
    version: str

    def __init__(
        self, package_name: str, output_dir: str, temp_dir: str = DEFAULT_TEMP_DIR,
        config: GeneratorConfig | None = None,
    ) -> None:
        """
        Initialize the ComposerEbuildGenerator.

        Args:
            package_name: Name of the Composer package to process
            output_dir: Directory where generated ebuilds will be saved
            temp_dir: Optional temporary directory for package installation
            config: Optional configuration object with debug, github_token and skip_downgrade settings

        """
        self.package_name = package_name
        self.output_dir = str(Path(output_dir).resolve())
        self.temp_dir = temp_dir
        self.config = config or GeneratorConfig()
        self.packages = {}
        self.version = self.config.version
        self._set_templates_dir()

    def run(self) -> None:
        """
        Run the ebuild generation process.

        This method creates a temporary directory, installs the Composer package,
        gathers information about all installed packages, and generates the ebuild files.

        """
        logger.debug("Starting ebuild generation for package: %s", self.package_name)
        try:
            if self.config.debug:
                self.cleanup_directories()

            if not Path(self.temp_dir).exists():
                Path(self.temp_dir).mkdir(parents=True)

            self.install_composer_package()
            if not self.config.skip_downgrade:
                self.update_composer_dependencies()
            self.gather_package_information()
            self.generate_ebuilds()
        except ComposerPackageInstallError:
            logger.exception("Failed to install Composer package")
        except ComposerJsonError:
            logger.exception("Error processing Composer JSON")
        except EbuildGenerationError:
            logger.exception("Failed to generate ebuilds")
        except Exception:
            logger.exception("Unexpected error occurred")
        finally:
            if not self.config.debug:
                self.cleanup_directories()

    def _set_templates_dir(self) -> None:
        """
        Set the templates directory path based on whether running in IDE or installed system.

        When running in an IDE, use the local template directory.
        Otherwise, use the system-wide installation path.
        """
        logger.debug("Setting templates directory path")
        if is_running_in_ide():
            self.templates_dir = Path(__file__).parent.parent / "templates"
            logger.debug("Running in IDE, using local templates: %s", self.templates_dir)
        else:
            self.templates_dir = Path("/usr/share/composer-ebuild/templates")
            logger.debug("Using system-wide templates: %s", self.templates_dir)

    def cleanup_directories(self) -> None:
        """Clean up the temporary and output directories."""
        if Path(self.temp_dir).exists():
            logger.debug("Deleting temporary directory: %s", self.temp_dir)
            shutil.rmtree(self.temp_dir)
        if Path(self.output_dir).exists():
            logger.debug("Deleting contents of output directory: %s", self.output_dir)
            for filename in os.listdir(self.output_dir):
                file_path = Path(self.output_dir) / filename
                if file_path.is_file() or file_path.is_symlink():
                    file_path.unlink()
                elif file_path.is_dir():
                    shutil.rmtree(file_path)

    def install_composer_package(self) -> None:
        """
        Install the Composer package in a temporary directory and lock its version.

        :raises ComposerPackageInstallError: If the installation fails.
        """
        logger.debug("Installing Composer package: %s", self.package_name)
        # First install the package
        package_spec = (
            f"{self.package_name}:{self.version}"
            if self.version != "latest"
            else self.package_name
        )
        command = [
            "/usr/bin/composer",
            "require",
            package_spec,
            "--working-dir",
            self.temp_dir,
        ]
        logger.debug("Running command: %s", " ".join(command))
        process = subprocess.run(command, check=False)
        return_code = process.returncode
        install_dir = Path(self.temp_dir) / "vendor" / self.package_name.replace("/", os.sep)

        if return_code != 0 or not install_dir.is_dir():
            error_message = f"Failed to install {self.package_name}. Return code: {return_code}"
            logger.error(error_message)
            raise ComposerPackageInstallError(error_message)

        # Get the installed version
        show_command = [
            "/usr/bin/composer",
            "show",
            self.package_name,
            "--format=json",
            "--working-dir",
            self.temp_dir,
        ]
        show_process = subprocess.run(show_command, capture_output=True, text=True, check=False)
        if show_process.returncode != 0:
            error_message = f"Failed to get version info for {self.package_name}"
            logger.error(error_message)
            raise ComposerPackageInstallError(error_message)

        package_info = json.loads(show_process.stdout)
        installed_version = package_info.get("versions", [""])[0]

        # Update composer.json to lock the version
        composer_json_path = Path(self.temp_dir) / "composer.json"
        with composer_json_path.open("r") as f:
            composer_data = json.load(f)

        composer_data["require"][self.package_name] = installed_version
        composer_data["config"] = composer_data.get("config", {})
        composer_data["config"]["platform"] = {
            "php": self.config.platform,
        }

        with composer_json_path.open("w") as f:
            json.dump(composer_data, f, indent=4)

        logger.debug("Successfully installed %s at version %s", self.package_name, installed_version)

    def update_composer_dependencies(self) -> None:
        """
        Downgrade all the dependencies to the lowest stable version.

        :raises ComposerPackageInstallError: If the installation fails.
        """
        logger.debug("Downgrading dependencies for: %s", self.package_name)
        command = [
            "/usr/bin/composer",
            "update",
            "--with-dependencies",
            "--prefer-stable",
            "--working-dir",
            self.temp_dir,
        ]
        logger.debug("Running command: %s", " ".join(command))
        process = subprocess.run(command, check=False)
        return_code = process.returncode
        if return_code == 0:
            logger.debug("Successfully downgraded dependencies for %s", self.package_name)
        else:
            error_message = f"Failed to downgrade dependencies for {self.package_name}. Return code: {return_code}"
            logger.error(error_message)
            raise ComposerPackageInstallError(error_message)

    def gather_package_information(self) -> None:
        """
        Gather information about every Composer package installed.

        Use composer.lock as it returns the exact version.
        """
        logger.debug("Gathering information about installed Composer packages")
        composer_lock_path = Path(self.temp_dir) / "composer.lock"
        if not composer_lock_path.exists():
            logger.debug("No composer.lock file found. Something went wrong with the Composer installation.")
            error_msg = "composer.lock file not found."
            raise EbuildGenerationError(error_msg)

        with Path(composer_lock_path).open() as composer_lock_file:
            composer_lock_data = json.load(composer_lock_file)

        for package in composer_lock_data.get("packages", []):
            name = package["name"]
            version = package["version"]
            if name != "composer":
                logger.debug("Gathering information for %s", name)
                try:
                    composer_package = ComposerPackage(name, version, self.temp_dir, self.config.github_token)
                    self.packages[name] = composer_package
                except ComposerJsonError as e:
                    logger.warning("Failed to create ComposerPackage for %s: %s", name, str(e))
                    # Create a minimal ComposerPackage object with available information
                    self.packages[name] = ComposerPackage(name, version, self.temp_dir, self.config.github_token)

        logger.debug("Gathered information for %d packages", len(self.packages))

    def generate_ebuilds(self) -> None:
        """Generate ebuild files for the installed Composer packages."""
        try:
            self.assign_dependencies()
            for name, package in self.packages.items():
                logger.debug("Creating Ebuild for %s", name)
                package.create_ebuild(self.output_dir, self.templates_dir)
        except (ComposerJsonError, OSError, ValueError) as e:
            error_msg = f"Failed to generate ebuilds: {e}"
            raise EbuildGenerationError(error_msg) from e

    def assign_dependencies(self) -> None:
        """Assign dependencies and their instances to each package."""
        logger.debug("Assigning dependency instances to packages")

        for package_name, package in self.packages.items():
            logger.debug("Processing dependencies for %s", package_name)
            self.process_dependencies(package)

    def process_dependencies(self, package: ComposerPackage) -> None:
        """
        Process dependencies for a package and assign them.

        :param package: The ComposerPackage instance to assign dependencies to.
        """
        command = ["composer", "show", package.name, "--tree", "--format=json"]
        logger.debug("Running command: %s", " ".join(command))
        process = subprocess.run(command, capture_output=True, text=True, cwd=self.temp_dir, check=False)

        if process.returncode == 0:
            dependency_tree = json.loads(process.stdout)
            logger.debug("Dependency tree for %s: %s", package.name, json.dumps(dependency_tree, indent=2))

            if not dependency_tree or "installed" not in dependency_tree:
                logger.info("Dependency tree is empty or invalid for %s, skipping", package.name)
                return

            installed_packages = dependency_tree["installed"]
            if not installed_packages:
                logger.info("No installed packages found for %s", package.name)
                return

            # We're only interested in the first (main) package
            main_package = installed_packages[0]
            if "requires" in main_package:
                self.assign_package_dependencies(package, main_package["requires"])
            else:
                logger.info("No dependencies found for %s", package.name)
        else:
            logger.warning("Failed to get dependency tree for %s", package.name)
            logger.warning("Error: %s", process.stderr)

    def assign_package_dependencies(self, package: ComposerPackage, dependencies: list[dict[str, Any]]) -> None:
        """
        Assign dependencies to a package.

        :param package: The ComposerPackage instance to assign dependencies to.
        :param dependencies: List of dependencies from the composer show output.
        """
        for dep in dependencies:
            dep_name = dep["name"]
            if dep_name in self.packages:
                if dep_name in package.dependencies and package.dependencies[dep_name].get("type") == "main":
                    package.add_dependency_instance(dep_name, self.packages[dep_name])
                    logger.debug("Added main dependency %s to %s", dep_name, package.name)
                else:
                    package.add_sub_dependency(dep_name, self.packages[dep_name])
                    logger.debug("Added sub-dependency %s to %s", dep_name, package.name)

                # Process sub-dependencies
                if "requires" in dep:
                    self.assign_package_dependencies(package, dep["requires"])
            elif dep_name != "php" and not dep_name.startswith("ext-"):
                logger.warning("Dependency %s not found in installed packages", dep_name)


def main() -> None:
    """Parse arguments and run the ebuild generator."""
    parser = argparse.ArgumentParser(description="Generate ebuilds for a Composer package.")
    parser.add_argument("package_name", type=str, help="The name of the Composer package (vendor/package)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "-o",
        "--output-dir",
        type=str,
        default=str(Path.cwd()),
        help="The directory to store the generated ebuild files",
    )
    parser.add_argument(
        "-t",
        "--temp-dir",
        type=str,
        default=DEFAULT_TEMP_DIR,
        help="Override the temporary directory (default: /tmp/composer-ebuild)",
    )
    parser.add_argument(
        "--github-token",
        type=str,
        help="GitHub API token for authentication (can also use GITHUB_TOKEN env variable)",
    )
    parser.add_argument(
        "--skip-downgrade",
        action="store_true",
        help="Skip downgrading dependencies to their lowest stable versions",
    )
    parser.add_argument(
        "--version",
        type=str,
        default="latest",
        help="Specific version to install (default: latest)",
    )
    parser.add_argument(
        "--platform",
        type=str,
        default="7.4",
        choices=["7.4", "8.0", "8.1", "8.2", "8.3"],
        help="PHP platform version (default: 7.4)",
    )
    args = parser.parse_args()

    # Get GitHub token from environment variable if not provided via command line
    github_token = args.github_token or os.getenv("GITHUB_TOKEN")

    configure_logging(debug=args.debug)
    logger.debug("Starting Composer Ebuild Generator")
    config = GeneratorConfig(
        debug=args.debug,
        github_token=github_token,
        skip_downgrade=args.skip_downgrade,
        version=args.version,
        platform=args.platform,
    )
    generator = ComposerEbuildGenerator(
        args.package_name,
        args.output_dir,
        args.temp_dir,
        config=config,
    )
    generator.run()


if __name__ == "__main__":
    main()
