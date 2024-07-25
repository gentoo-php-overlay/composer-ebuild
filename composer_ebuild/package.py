from typing import Optional, List, Dict, Any

import datetime
import json
import logging
import os
import re
import requests
import subprocess
import tempfile

from github import Github
from github.GithubException import GithubException

from composer_ebuild.utils import get_php_useflags
from composer_ebuild.exceptions import ComposerJsonException

EAPI_VERSION: int = 8


class ComposerPackage:
    """
    A class to represent a Composer package and generate its ebuild.
    """

    name: str
    description: str
    version: str
    install_dir: str
    temp_dir: str
    output_dir: Optional[str]
    repository_url: Optional[str]
    src_uri: Optional[str]
    sha: Optional[str]
    licenses: list
    requires: dict
    dependencies: dict
    autoload: Dict[str, Any]
    php_min_version: str
    work_dir: str
    github_token: Optional[str]

    def __init__(self, name: str, version: str, temp_dir: str, github_token: str = None) -> None:
        """
        Initialize the ComposerPackage.

        :param name: The name of the Composer package.
        :param version: The version of the Composer package.
        :param temp_dir: The temporary directory where the Composer package is installed.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        logging.basicConfig(
            format='%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
            level=logging.DEBUG
        )

        self.name = name
        self.version: str = re.sub(r'^v', '', version)
        self.temp_dir: str = temp_dir
        self.install_dir: str = os.path.join(self.temp_dir, 'vendor', name.replace('/', os.sep))
        self.repository_url: Optional[str] = None
        self.src_uri: Optional[str] = None
        self.sha: Optional[str] = None
        self.licenses: List[str] = []
        self.requires: Dict[str, str] = {}
        self.dependencies: List[str] = []
        self.autoload: Dict[str, Any] = {}
        self.php_min_version: str = '7.4'  # Default minimum PHP version
        self.github_token: Optional[str] = github_token

        self.logger.debug('Version: %s', self.version)

        try:
            self.load_composer_info()
            self.process_main_dependencies()
            self.work_dir = self.get_workdir()
        except ComposerJsonException:
            # The exception will handle printing and exiting
            pass

    @staticmethod
    def compare_versions(version1: str, version2: str) -> int:
        """
        Compare two version strings.

        :param version1: First version string
        :param version2: Second version string
        :return: -1 if version1 < version2, 0 if version1 == version2, 1 if version1 > version2
        """
        v1_parts = list(map(int, version1.split('.')))
        v2_parts = list(map(int, version2.split('.')))

        for i in range(max(len(v1_parts), len(v2_parts))):
            v1 = v1_parts[i] if i < len(v1_parts) else 0
            v2 = v2_parts[i] if i < len(v2_parts) else 0
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
        return 0

    def get_package_name(self, name: str) -> str:
        """
        Convert a Composer package name to a standardized format.

        If the vendor and package name are the same, only use the package name.
        If the vendor is 'composer', only use the package name.

        :param name: The full package name (vendor/package).
        :return: The standardized package name.
        """
        self.logger.debug(f"Converting package name: {name}")
        vendor, package = name.split('/')
        if vendor == package or vendor == 'composer':
            package_name = package
        else:
            package_name = f"{vendor}-{package}"
        return package_name

    @staticmethod
    def format_path(path: str) -> str:
        """
        Format the path for doins command, handling the 'src' directory case.

        :param path: The original path.
        :return: The formatted path for doins command.
        """
        # Strip trailing slashes
        path = path.rstrip('/')

        if path == "src":
            return 'src/*'
        else:
            return f'{path}'

    def load_composer_json(self) -> dict:
        """
        Load and parse the composer.json file.

        :return: A dictionary containing the parsed composer.json data.
        :raises ComposerJsonException: If the file is not found or cannot be parsed.
        """
        self.logger.debug('Reading composer.json file')
        composer_json_path = os.path.join(self.install_dir, 'composer.json')
        try:
            with open(composer_json_path, 'r') as composer_json_file:
                composer_json_info = json.load(composer_json_file)
            self.logger.debug('Successfully loaded composer.json')
            return composer_json_info
        except FileNotFoundError:
            self.logger.error(f'composer.json not found at {composer_json_path}')
            raise ComposerJsonException(f'composer.json not found for {self.name}')
        except json.JSONDecodeError as e:
            self.logger.error(f'Failed to parse composer.json for {self.name}. Error: {e}')
            raise ComposerJsonException(f'Failed to parse composer.json for {self.name}')

    def load_composer_show(self) -> dict:
        """
        Load the output of the 'composer show' command for the current package.

        :return: A dictionary containing the parsed 'composer show' output.
        :raises ComposerJsonException: If the command fails or the output cannot be parsed.
        """
        self.logger.debug(f'Running composer show command for {self.name}')
        try:
            command = ['/usr/bin/composer', 'show', self.name, '--format=json']
            self.logger.debug(f'Running command in directory {self.temp_dir}: {" ".join(command)}')
            result = subprocess.run(command,
                                    capture_output=True, text=True, check=True,
                                    cwd=self.temp_dir)
            composer_show_info = json.loads(result.stdout)
            self.logger.debug('Successfully loaded composer show information')
            return composer_show_info
        except subprocess.CalledProcessError as e:
            self.logger.error(f'Failed to run composer show command for {self.name}. Error: {e}')
            self.logger.error(f'Command output: {e.output}')
            raise ComposerJsonException(f'Failed to run composer show command for {self.name}: {e}')
        except json.JSONDecodeError as e:
            self.logger.error(f'Failed to parse composer show output for {self.name}. Error: {e}')
            raise ComposerJsonException(f'Failed to parse composer show output for {self.name}: {e}')

    def load_composer_info(self) -> None:
        """
        Load the package information from composer.json file and composer show command.

        Some info is missing or misleading in composer.json and better formatted in "composer show".
        For other info it is the same, the other way around.

        :raises ComposerJsonException: If the required information is not found.
        """
        composer_json_info = self.load_composer_json()
        self.logger.debug(f'Loaded composer.json information: {composer_json_info}')

        composer_show_info = self.load_composer_show()
        self.logger.debug(f'Loaded composer show information: {composer_show_info}')

        self.description = composer_json_info.get('description')
        self.repository_url = composer_show_info.get('source', {}).get('url', '').replace('.git', '')
        self.licenses = composer_json_info.get('license', [])
        if isinstance(self.licenses, str):
            self.licenses = [self.licenses]
        self.requires = composer_json_info.get('require', {})
        self.logger.debug(f'Loaded licenses: {self.licenses}')
        self.logger.debug(f'Loaded requires: {self.requires}')

        # Load autoload information
        self.process_autoload_info(composer_json_info.get('autoload', {}))

        if not self.description or not self.repository_url:
            raise ComposerJsonException('Missing required information in composer.json')

        # We can't get SHA from composer.json, so we'll need to fetch it from GitHub API
        try:
            self.sha = self.get_commit_sha()
            self.src_uri = self.get_tagged_tarball_url()
        except ComposerJsonException:
            self.logger.warning(f'No tagged tarball URL found for {self.name} {self.version}. Using repository URL.')
            self.src_uri = f'{self.repository_url}/archive/{self.sha}.tar.gz'

        # Download and extract the package
        self.download_and_extract_package()

    def get_github_repo(self):
        """
        Get the GitHub repository object.

        :return: The GitHub repository object.
        :raises ComposerJsonException: If unable to get the repository or if rate limit is exceeded.
        """
        g = Github(self.github_token) if self.github_token else Github()
        try:
            rate_limit = g.get_rate_limit()
            if rate_limit.core.remaining == 0:
                reset_time = rate_limit.core.reset.astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')
                message = f'GitHub API rate limit exceeded. Reset time: {reset_time}'
                raise ComposerJsonException(message)

            repo_name = self.repository_url.split('github.com/')[-1]
            return g.get_repo(repo_name)
        except GithubException as e:
            self.logger.error(f'Failed to get GitHub repository: {e}')
            raise ComposerJsonException(f'Failed to get GitHub repository: {e}')

    def get_commit_sha(self) -> str:
        """
        Get the commit SHA for the specific version of the package.

        :return: The commit SHA for the specific version.
        :raises ComposerJsonException: If unable to fetch the SHA.
        """
        repo = self.get_github_repo()
        try:
            tags = repo.get_tags()
            for tag in tags:
                if tag.name == self.version or tag.name == f'v{self.version}':
                    self.logger.debug(f'Found matching tag: {tag.name}')
                    return tag.commit.sha
            raise ComposerJsonException(f'No matching tag found for version {self.version}')
        except GithubException as e:
            self.logger.error(f'Failed to fetch tags from GitHub API: {e}')
            raise ComposerJsonException(f'Failed to fetch tags from GitHub API: {e}')

    def get_tagged_tarball_url(self) -> str:
        """
        Get the download URL for the specified tagged tar.gz archive from GitHub.

        :return: The download URL for the tar.gz archive.
        :raises ComposerJsonException: If the URL cannot be fetched or the version is not found.
        """
        repo = self.get_github_repo()
        try:
            tags = repo.get_tags()
            for tag in tags:
                if tag.name == self.version or tag.name == f'v{self.version}':
                    tarball_url = f'{self.repository_url}/archive/{tag.name}.tar.gz'
                    self.logger.debug(f'Found tar.gz URL for version {self.version}: {tarball_url}')
                    return tarball_url
            self.logger.error(f'No matching tag found for version {self.version}')
            raise ComposerJsonException(f'No matching tag found for version {self.version}')
        except GithubException as e:
            self.logger.error(f'Failed to fetch tags from GitHub API: {e}')
            raise ComposerJsonException(f'Failed to fetch tags from GitHub API: {e}')

    def download_and_extract_package(self) -> None:
        """
        Download the package to temp_dir and extract it to self.temp_dir + '/package'.
        Extraction behaves exactly like "tar xzf FILENAME.tar.gz".
        """
        self.logger.debug('Downloading and extracting package')
        # Create a temporary file to store the downloaded package
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz') as temp_file:
            # Download the package
            response = requests.get(self.src_uri)
            if response.status_code != 200:
                raise ComposerJsonException(f'Failed to download package from {self.src_uri}')
            temp_file.write(response.content)
            temp_file_path = temp_file.name

        # Extract the package
        extract_path = os.path.join(self.temp_dir, 'package', self.get_package_name(self.name))
        os.makedirs(extract_path, exist_ok=True)

        # Use subprocess to run tar command, mimicking "tar xzf FILENAME.tar.gz" behavior
        try:
            subprocess.run(['tar', 'xzf', temp_file_path], check=True, cwd=extract_path)
        except subprocess.CalledProcessError as e:
            raise ComposerJsonException(f'Failed to extract package: {e}')

        # Clean up the temporary file
        os.unlink(temp_file_path)
        self.logger.debug(f'Package extracted to {extract_path}')

    def process_autoload_info(self, autoload_info: Dict[str, Any]) -> None:
        """
        Process the autoload information from composer.json.

        :param autoload_info: The autoload information from composer.json.
        :raises ComposerJsonException: If the autoload_info is empty.
        """
        self.logger.debug('Processing autoload information')
        if not autoload_info:
            self.logger.error('Empty autoload information')
            raise ComposerJsonException('Autoload information is empty')

        self.autoload = {
            'type': '',
            'namespace': '',
            'directories': [],
            'files': []
        }

        if 'psr-4' in autoload_info:
            self.autoload['type'] = 'psr-4'
            namespace = next(iter(autoload_info['psr-4']))
            self.autoload['namespace'] = namespace
            directories = autoload_info['psr-4'][namespace]
            if isinstance(directories, str):
                directories = [directories]
            self.autoload['directories'] = directories
        elif 'psr-0' in autoload_info:
            self.autoload['type'] = 'psr-0'
            namespace = next(iter(autoload_info['psr-0']))
            self.autoload['namespace'] = namespace
            directories = autoload_info['psr-0'][namespace]
            if isinstance(directories, str):
                directories = [directories]
            self.autoload['directories'] = directories
        elif 'classmap' in autoload_info:
            self.autoload['type'] = 'classmap'
            self.autoload['directories'] = autoload_info['classmap']

        if 'files' in autoload_info:
            self.autoload['files'] = autoload_info['files']

        self.logger.debug(f'Loaded autoload information: {self.autoload}')

    def process_main_dependencies(self) -> None:
        """
        Process the requirements list and assign it to main dependencies.
        Translate "php" dependencies to "dev-lang/php:*".
        Handle "ext-..." dependencies by adding them to dev-lang/php use flags.
        Determine the minimum PHP version required.
        Add real PSR-4 namespace to dependencies except for "php".
        Add autoload location for each dependency.
        """
        self.logger.debug('Processing dependencies')
        self.dependencies: dict = {}
        php_use_flags = set()
        php_min_version = None

        # Get available PHP USE flags
        available_php_use_flags = set(get_php_useflags())
        self.logger.debug(f'Available PHP USE flags: {available_php_use_flags}')

        # Set php_min_version to the highest required version, or default to '7.4' if not specified
        self.php_min_version = php_min_version if php_min_version else '7.4'

        for dep, version in sorted(self.requires.items()):
            if dep.lower() == 'php':
                version_match = re.search(r'>=?\s*(\d+\.\d+)', version)
                if version_match:
                    required_version = version_match.group(1)
                    if php_min_version is None or self.compare_versions(required_version, php_min_version) > 0:
                        php_min_version = required_version
            elif dep.lower().startswith('ext-'):
                if dep.lower() == 'ext-openssl':
                    if 'ssl' in available_php_use_flags:
                        php_use_flags.add('ssl')
                    else:
                        self.logger.warning('ssl USE flag not available for PHP')
                else:
                    ext_name = dep[4:]  # Remove 'ext-' prefix
                    if ext_name in available_php_use_flags:
                        php_use_flags.add(ext_name)
                    else:
                        self.logger.warning(f'{ext_name} USE flag not available for PHP')
            else:
                package_name = self.get_package_name(dep)
                self.dependencies[dep] = {
                    'ebuild': f'dev-php/{package_name}',
                    'type': 'main'
                }

        # Add dev-lang/php with the minimum version and use flags
        php_ebuild = f'>=dev-lang/php-{self.php_min_version}:*'
        if php_use_flags:
            php_ebuild += f'[{",".join(sorted(php_use_flags))}]'
        self.dependencies['php'] = {'ebuild': php_ebuild, 'type': 'main'}

        # Add dev-php/fedora-autoloader
        self.dependencies['fedora-autoloader'] = {
            'ebuild': 'dev-php/fedora-autoloader',
            'type': 'main'
        }

        self.sort_dependencies()

        self.logger.debug(f'Processed dependencies: {self.dependencies}')
        self.logger.debug(f'Minimum PHP version: {self.php_min_version}')

    def sort_dependencies(self) -> None:
        """
        Sort dependencies ensuring dev-lang/php is always on top,
        followed by dev-php/fedora-autoloader, while the rest are sorted alphabetically.
        """
        self.logger.debug('Sorting dependencies')
        sorted_deps = {}

        # Add dev-lang/php first
        if 'php' in self.dependencies:
            sorted_deps['php'] = self.dependencies['php']

        # Add dev-php/fedora-autoloader second
        if 'fedora-autoloader' in self.dependencies:
            sorted_deps['fedora-autoloader'] = self.dependencies['fedora-autoloader']

        # Sort the rest of the dependencies by their ebuild names
        for dep, info in sorted(self.dependencies.items(), key=lambda x: x[1]['ebuild']):
            if dep not in ['php', 'fedora-autoloader']:
                sorted_deps[dep] = info

        self.dependencies = sorted_deps
        self.logger.debug(f'Sorted dependencies: {self.dependencies}')

    def get_install_path(self) -> str:
        """
        Get the install path based on the autoload information.

        :return: The directory path for the package.
        """
        self.logger.debug('Getting package layout')
        if self.autoload['type'] == 'psr-4':
            self.logger.debug('Package uses PSR-4 layout')
            namespace = self.autoload['namespace']
            install_path = os.path.join('/usr/share/php', namespace.replace('\\', '/').rstrip('/'))
            self.logger.debug(f'Install path: {install_path}')
            return install_path
        else:
            self.logger.warning(f"Package {self.name} does not use PSR-4 autoloading")
            vendor, package = self.name.split('/')
            if vendor.lower() == 'symfony':
                install_path = f'/usr/share/php/Symfony/Component/{package.title().replace("-", "")}'
                self.logger.debug(f'Symfony package detected. Install path: {install_path}')
                return install_path
            else:
                install_path = f'/usr/share/php/{self.get_package_name(self.name).capitalize()}'
                self.logger.debug(f'Non-PSR-4 package. Install path: {install_path}')
                return install_path

    def get_doins(self) -> str:
        """
        Get doins based on the autoload information and directory structure.

        :return: A string containing the unique doins and dependency autoload information.
        """
        self.logger.debug('Get list of files and directories to be installed')

        doins = set()
        php_files = set()

        # Add directories from autoload information
        if self.autoload['directories']:
            for directory in self.autoload['directories']:
                formatted_path = self.format_path(directory)
                doins.add(formatted_path)
                self.logger.debug(f'Added directory from autoload: {formatted_path}')

        # Add files from autoload information
        if self.autoload['files']:
            for file in self.autoload['files']:
                if file.endswith('.php'):
                    php_files.add(file)
                else:
                    doins.add(file)
                self.logger.debug(f'Added file from autoload: {file}')

        # Add root directory content
        for item in os.listdir(self.install_dir):
            item_path = os.path.join(self.install_dir, item)
            if os.path.isdir(item_path) and item not in self.autoload['directories']:
                doins.add(item)
                self.logger.debug(f'Added directory from root: {item}')
            elif item.endswith('.php') and item not in self.autoload['files']:
                php_files.add(item)
                self.logger.debug(f'Added PHP file from root: {item}')

        # Add autoload.php if it's a PSR-4 package
        if self.autoload['type'] == 'psr-4':
            php_files.add('autoload.php')
            self.logger.debug('Added autoload.php for PSR-4 package')

        # Replace individual PHP files with *.php if there are any
        if php_files:
            doins.add('*.php')
            self.logger.debug('Replaced individual PHP files with *.php')

        result = ' '.join(sorted(doins))
        self.logger.debug(f'Final doins string: {result}')

        return result

    def get_src_prepare(self) -> str:
        """
        Generate the src_prepare section for the ebuild.

        :return: The src_prepare section as a string.
        """
        self.logger.debug('Generating src_prepare section')

        # Add the default command
        src_prepare = 'default'

        if self.autoload['type'] == 'psr-4':
            if 'src' in self.autoload['directories']:
                basedir = 'src'
            else:
                basedir = '.'
            self.logger.debug(f'Package uses PSR-4, including phpab command with basedir: {basedir}')
            src_prepare += '\n\n'
            src_prepare += '\tphpab \\\n'
            src_prepare += '\t\t--output autoload.php \\\n'
            src_prepare += '\t\t--template fedora2 \\\n'
            src_prepare += f'\t\t--basedir {basedir} \\\n'
            src_prepare += f'\t\t{basedir} \\\n'
            src_prepare += '\t\t|| die\n'

            # Add dependency autoload information
            dependency_autoloads = []
            for dep_name, dep_info in self.dependencies.items():
                if 'instance' in dep_info and hasattr(dep_info['instance'], 'get_install_path'):
                    install_path = dep_info['instance'].get_install_path()
                    dependency_autoloads.append(
                        f"\"${{VENDOR_DIR}}{install_path.replace('/usr/share/php', '')}/autoload.php\""
                    )

            if dependency_autoloads:
                src_prepare += '\n\tVENDOR_DIR="${EPREFIX}/usr/share/php"'
                src_prepare += '\n\tcat >> autoload.php <<EOF || die "failed to extend autoload.php"'
                src_prepare += '\n\n// Dependencies'
                src_prepare += '\n\\Fedora\\Autoloader\\Dependencies::required(['
                src_prepare += '\n\t"${VENDOR_DIR}/Fedora/Autoloader/autoload.php",\n\t'
                src_prepare += ',\n\t'.join(dependency_autoloads)
                src_prepare += '\n]);'
                src_prepare += '\nEOF'
        else:
            self.logger.debug('Package does not use PSR-4, creating manual autoload.php')
            src_prepare += '\n\n'
            src_prepare += '\techo "<?php" > autoload.php\n'
            src_prepare += '\techo "require_once \\"${EPREFIX}/usr/share/php/Fedora/Autoloader/autoload.php\\";"'
            src_prepare += ' >> autoload.php\n'

            if self.autoload['type'] == 'psr-0':
                src_prepare += '\n\techo "\\\\Fedora\\\\Autoloader\\\\Autoload::addPsr0('
                src_prepare += f"'{self.autoload['namespace']}', __DIR__);\""
                src_prepare += ' >> autoload.php\n'
            elif self.autoload['type'] == 'classmap':
                src_prepare += '\n\techo "\\\\Fedora\\\\Autoloader\\\\Autoload::addClassMap(["'
                src_prepare += ' >> autoload.php\n'
                for directory in self.autoload['directories']:
                    src_prepare += f'\techo "    \'{directory}\' => __DIR__ . \'/{directory}\',"'
                    src_prepare += ' >> autoload.php\n'
                src_prepare += '\techo "]);" >> autoload.php\n'

        if self.autoload['files']:
            self.logger.debug('Adding files from autoload to manual autoload.php')
            for file in self.autoload['files']:
                src_prepare += f'\n\techo "require_once __DIR__ . \'/{file}\';"'
                src_prepare += ' >> autoload.php\n'

        return src_prepare

    def get_workdir(self) -> str:
        """
        Get the WORKDIR string for the ebuild.

        This method reads the package root directory and returns the name of the extracted directory.
        It checks if the version is part of the directory name and replaces
        the version with "${PV}".

        :return: The WORKDIR string for the ebuild.
        """
        self.logger.debug('Getting WORKDIR string')
        package_dir = os.path.join(self.temp_dir, 'package', self.get_package_name(self.name))
        self.logger.debug(f'Package directory: {package_dir}')

        # Get the name of the extracted directory
        extracted_dirs = [d for d in os.listdir(package_dir) if os.path.isdir(os.path.join(package_dir, d))]
        if not extracted_dirs:
            raise ComposerJsonException('No extracted directory found')

        work_dir = extracted_dirs[0]
        self.logger.debug(f'Extracted directory: {work_dir}')

        # Replace version with ${PV} if it's in the directory name
        if self.version in work_dir:
            work_dir = work_dir.replace(self.version, '${PV}')
            self.logger.debug(f'Replaced version with ${{PV}}: {work_dir}')

        self.logger.debug(f'Final WORKDIR string: {work_dir}')
        return '${WORKDIR}/' + work_dir

    def create_ebuild(self, output_dir: str) -> None:
        """
        Create an ebuild file for the package.

        :param output_dir: The directory to place the generated ebuild file.
        """
        self.output_dir = output_dir

        # Get the package install path
        install_path = self.get_install_path()

        self.logger.debug(f'Package install path: {install_path}')

        ebuild_template_path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'ebuild')

        current_date = datetime.datetime.now().strftime('%Y')
        with open(ebuild_template_path, 'r') as ebuild_template_file:
            ebuild_template = ebuild_template_file.read().replace('{{date}}', current_date)

        dependencies_string = '\n\t'.join([
            f'{info["ebuild"]}'
            for dep, info in self.dependencies.items()
            if info.get('type') == 'main'
        ])
        doins = f'doins -r {self.get_doins()}'

        # Replace version in SRC_URI with ${PV} if it matches the package version
        if f'{self.version}' in self.src_uri:
            src_uri = self.src_uri.replace(f'{self.version}', '${PV}')
        else:
            src_uri = self.src_uri

        ebuild_content = ebuild_template.replace('{{eapi}}', str(EAPI_VERSION)) \
            .replace('{{homepage}}', self.repository_url or 'https://packagist.org/packages/' + self.name) \
            .replace('{{description}}', self.description or 'No description available') \
            .replace('{{src_uri}}', src_uri + ' -> ${P}.tar.gz') \
            .replace('{{license}}', ' '.join(self.licenses).strip() or 'Unknown') \
            .replace('{{dependencies}}', dependencies_string) \
            .replace('{{insinto}}', f'insinto "{install_path}"') \
            .replace('{{doins}}', doins) \
            .replace('{{src_prepare}}', self.get_src_prepare()) \
            .replace('{{workdir}}', self.work_dir)

        package_name = self.get_package_name(self.name)
        ebuild_filename = f'{package_name}-{self.version.lstrip("v")}.ebuild'
        category_dir = os.path.join(self.output_dir, 'dev-php', package_name)
        os.makedirs(category_dir, exist_ok=True)
        ebuild_output_path = os.path.join(category_dir, ebuild_filename)

        with open(ebuild_output_path, 'w') as ebuild_output_file:
            ebuild_output_file.write(ebuild_content)

        self.logger.debug('Created ebuild at %s', ebuild_output_path)

    def add_dependency_instance(self, dep_name: str, dep_instance: 'ComposerPackage') -> None:
        """
        Add a dependency instance to the package.

        :param dep_name: The name of the dependency.
        :param dep_instance: The ComposerPackage instance of the dependency.
        """
        self.logger.debug(f'Adding dependency instance for {dep_name}')
        if dep_name in self.dependencies:
            self.dependencies[dep_name]['instance'] = dep_instance
        else:
            self.logger.warning(f'Dependency {dep_name} not found in dependencies')

    def add_sub_dependency(self, sub_dep_name: str, sub_dep_instance: 'ComposerPackage') -> None:
        """
        Add a sub-dependency instance to the package.

        This method adds dependencies of dependencies, excluding duplicates,
        'php', and 'ext-' dependencies.

        :param sub_dep_name: The name of the sub-dependency.
        :param sub_dep_instance: The ComposerPackage instance of the sub-dependency.
        """
        self.logger.debug(f'Adding sub-dependency: {sub_dep_name}')

        # Check if it's not a main dependency and not already a sub-dependency
        if (sub_dep_name not in self.dependencies and
                sub_dep_name not in [dep for dep in self.dependencies.values() if dep.get('type') == 'sub'] and
                not sub_dep_name.startswith('php') and
                not sub_dep_name.startswith('ext-')):
            self.dependencies[sub_dep_name] = {
                'ebuild': f'dev-php/{self.get_package_name(sub_dep_name)}',
                'instance': sub_dep_instance,
                'type': 'sub'
            }
            self.logger.debug(f'Added sub-dependency: {sub_dep_name}')
        else:
            self.logger.debug(f'Skipped adding sub-dependency: {sub_dep_name} (already exists or excluded)')

        self.sort_dependencies()
