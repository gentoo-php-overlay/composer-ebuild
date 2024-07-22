from typing import Dict, List, Any

import os
import argparse
import logging
import json
import shutil
import subprocess

from composer_ebuild.package import ComposerPackage
from composer_ebuild.exceptions import ComposerPackageInstallException, EbuildGenerationException, ComposerJsonException

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), '..', 'templates')


class ComposerEbuildGenerator:
    """
    A class to generate ebuilds for a given Composer package.
    """

    logger: logging.Logger
    package_name: str
    output_dir: str
    temp_dir: str
    debug: bool
    github_token: str
    packages: Dict[str, ComposerPackage]

    def __init__(
        self,
        package_name: str,
        output_dir: str,
        temp_dir: str = None,
        debug: bool = False,
        github_token: str = None
    ) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self.package_name = package_name
        self.output_dir = os.path.abspath(output_dir)
        self.temp_dir = temp_dir
        self.debug = debug
        self.github_token = github_token
        self.packages = {}

    def run(self) -> None:
        """
        Run the ebuild generation process.

        This method creates a temporary directory, installs the Composer package,
        gathers information about all installed packages, and generates the ebuild files.

        """
        self.logger.debug(f'Starting ebuild generation for package: {self.package_name}')
        try:
            if self.debug:
                self.cleanup_directories()

            if not os.path.exists(self.temp_dir):
                os.makedirs(self.temp_dir)

            self.install_composer_package()
            self.gather_package_information()
            self.generate_ebuilds()
        except ComposerPackageInstallException as e:
            self.logger.error(f"Failed to install Composer package: {str(e)}")
        except ComposerJsonException as e:
            self.logger.error(f"Error processing Composer JSON: {str(e)}")
        except EbuildGenerationException as e:
            self.logger.error(f"Failed to generate ebuilds: {str(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected error occurred: {str(e)}")
        finally:
            if not self.debug:
                self.cleanup_directories()

    def cleanup_directories(self) -> None:
        """
        Clean up the temporary and output directories.

        """
        if os.path.exists(self.temp_dir):
            self.logger.debug(f'Deleting temporary directory: {self.temp_dir}')
            shutil.rmtree(self.temp_dir)
        if os.path.exists(self.output_dir):
            self.logger.debug(f'Deleting contents of output directory: {self.output_dir}')
            for filename in os.listdir(self.output_dir):
                file_path = os.path.join(self.output_dir, filename)
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)

    def install_composer_package(self) -> None:
        """
        Install the Composer package in a temporary directory.

        :raises ComposerPackageInstallException: If the installation fails.
        """
        self.logger.debug(f'Installing Composer package: {self.package_name}')
        command = f'composer require {self.package_name} --working-dir {self.temp_dir}'
        self.logger.debug(f'Running command: {command}')
        return_code = os.system(command)
        install_dir = os.path.join(self.temp_dir, 'vendor', self.package_name.replace('/', os.sep))
        if return_code == 0 and os.path.isdir(install_dir):
            self.logger.debug(f'Successfully installed {self.package_name}')
        else:
            error_message = f'Failed to install {self.package_name}. Return code: {return_code}'
            self.logger.error(error_message)
            raise ComposerPackageInstallException(error_message)

    def gather_package_information(self) -> None:
        """
        Gather information about every Composer package installed.
        Use composer.lock as it returns the exact version.
        """
        self.logger.debug('Gathering information about installed Composer packages')
        composer_lock_path = os.path.join(self.temp_dir, 'composer.lock')
        if not os.path.exists(composer_lock_path):
            self.logger.debug('No composer.lock file found. Something went wrong with the Composer installation.')
            raise EbuildGenerationException('composer.lock file not found.')

        with open(composer_lock_path, 'r') as composer_lock_file:
            composer_lock_data = json.load(composer_lock_file)

        for package in composer_lock_data.get('packages', []):
            name = package['name']
            version = package['version']
            if name != 'composer':
                self.logger.debug(f'Gathering information for {name}')
                try:
                    composer_package = ComposerPackage(name, version, self.temp_dir, self.github_token)
                    self.packages[name] = composer_package
                except Exception as e:
                    self.logger.warning(f'Failed to create ComposerPackage for {name}: {str(e)}')
                    # Create a minimal ComposerPackage object with available information
                    self.packages[name] = ComposerPackage(name, version, self.temp_dir, self.github_token)

        self.logger.debug(f'Gathered information for {len(self.packages)} packages')

    def generate_ebuilds(self) -> None:
        """
        Generate ebuild files for the installed Composer packages.
        """
        try:
            self.assign_dependencies()
            for name, package in self.packages.items():
                self.logger.debug(f'Creating Ebuild for {name}')
                package.create_ebuild(self.output_dir)
        except Exception as e:
            raise EbuildGenerationException(f'Failed to generate ebuilds: {e}')

    def assign_dependencies(self) -> None:
        """
        Assign dependencies and their instances to each package.
        """
        self.logger.debug('Assigning dependency instances to packages')

        for package_name, package in self.packages.items():
            self.logger.debug(f'Processing dependencies for {package_name}')
            self.process_dependencies(package)

    def process_dependencies(self, package: ComposerPackage) -> None:
        """
        Process dependencies for a package and assign them.

        :param package: The ComposerPackage instance to assign dependencies to.
        """
        command = ['composer', 'show', package.name, '--tree', '--format=json']
        self.logger.debug(f'Running command: {" ".join(command)}')
        process = subprocess.run(command, capture_output=True, text=True, cwd=self.temp_dir)

        if process.returncode == 0:
            dependency_tree = json.loads(process.stdout)
            self.logger.debug(f'Dependency tree for {package.name}: {json.dumps(dependency_tree, indent=2)}')

            if not dependency_tree or 'installed' not in dependency_tree:
                self.logger.info(f'Dependency tree is empty or invalid for {package.name}, skipping')
                return

            installed_packages = dependency_tree['installed']
            if not installed_packages:
                self.logger.info(f'No installed packages found for {package.name}')
                return

            # We're only interested in the first (main) package
            main_package = installed_packages[0]
            if 'requires' in main_package:
                self.assign_package_dependencies(package, main_package['requires'])
            else:
                self.logger.info(f'No dependencies found for {package.name}')
        else:
            self.logger.warning(f'Failed to get dependency tree for {package.name}')
            self.logger.warning(f'Error: {process.stderr}')

    def assign_package_dependencies(self, package: ComposerPackage, dependencies: List[Dict[str, Any]]) -> None:
        """
        Assign dependencies to a package.

        :param package: The ComposerPackage instance to assign dependencies to.
        :param dependencies: List of dependencies from the composer show output.
        """
        for dep in dependencies:
            dep_name = dep['name']
            if dep_name in self.packages:
                if dep_name in package.dependencies and package.dependencies[dep_name].get('type') == 'main':
                    package.add_dependency_instance(dep_name, self.packages[dep_name])
                    self.logger.debug(f'Added main dependency {dep_name} to {package.name}')
                else:
                    package.add_sub_dependency(dep_name, self.packages[dep_name])
                    self.logger.debug(f'Added sub-dependency {dep_name} to {package.name}')

                # Process sub-dependencies
                if 'requires' in dep:
                    self.assign_package_dependencies(package, dep['requires'])
            elif dep_name != 'php' and not dep_name.startswith('ext-'):
                self.logger.warning(f'Dependency {dep_name} not found in installed packages')


def main() -> None:
    """
    The main function to parse arguments and run the ebuild generator.
    """
    parser = argparse.ArgumentParser(description='Generate ebuilds for a Composer package.')
    parser.add_argument('package_name', type=str, help='The name of the Composer package (vendor/package)')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    parser.add_argument(
        '-o', '--output-dir', type=str, default=os.getcwd(),
        help='The directory to store the generated ebuild files'
    )
    parser.add_argument('-t', '--temp-dir', type=str, help='Override the temporary directory')
    parser.add_argument('--github-token', type=str, help='GitHub API token for authentication')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.debug('Starting Composer Ebuild Generator')
    generator = ComposerEbuildGenerator(
        args.package_name,
        args.output_dir,
        args.temp_dir,
        args.debug,
        args.github_token
    )
    generator.run()


if __name__ == "__main__":
    main()
