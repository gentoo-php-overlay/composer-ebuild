# Composer Ebuild Generator

## Overview

Composer Ebuild Generator aims to create Gentoo Ebuild files from Composer packages.

## Features

- Automatically generates ebuilds from Composer packages
- Handles package dependencies
- Supports custom output directories

## Requirements

- Python 3.9 or higher
- Composer (PHP package manager)

## Installation

To install Composer Ebuild Generator on a Gentoo system, use the following emerge command:

```bash
emerge composer-ebuild
```

This will install the `composer-ebuild` command on your system, along with all necessary dependencies.

## Usage

To generate an ebuild for a Composer package, use the following command:

```bash
composer-ebuild <package_name> [options]
```

### Options:

- `-d, --debug`: Enable debug logging
- `-o, --output-dir`: Specify the output directory for generated ebuilds (default: current working directory)
- `-t, --temp-dir`: Override the temporary directory used during the process
- `--github-token`: GitHub API token for authentication (can also use GITHUB_TOKEN environment variable)
- `--skip-downgrade`: Skip downgrading dependencies to their lowest stable versions
- `--version`: Specify a particular version to install (default: latest)
- `--platform`: Specify PHP platform version (default: 7.4)

By default, the generator will install the lowest stable versions of all dependencies to ensure maximum compatibility. Use `--skip-downgrade` to keep the latest compatible versions instead.

### Authentication:

Since Composer is not entirely reliable on some info, we use the Github API to gather package information.
In order to prevent errors due to rate limits, you should provide a Github API token.

The GitHub token can be provided in two ways:
1. Via environment variable: `export GITHUB_TOKEN=your_token`
2. Via command line argument: `--github-token your_token`

### Example:

```bash
# Using environment variable
export GITHUB_TOKEN=your_github_token
composer-ebuild symfony/console -o ./ebuilds -d

# Or using command line argument
composer-ebuild symfony/console -o ./ebuilds -d --github-token your_github_token
```

This command will generate an ebuild for the `symfony/console` package, place it in the `./ebuilds` directory, and run in debug mode.

## Development

### Code Formatting and Linting

Usage of lazy imports is discouraged. We use Ruff for code formatting and linting:

```bash
# Format code
ruff format .

# Run linting
ruff check .

# Fix auto-fixable issues
ruff check --fix .
```
