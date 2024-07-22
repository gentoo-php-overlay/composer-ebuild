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

### Example:

```bash
composer-ebuild symfony/console -o ./ebuilds -d
```

This command will generate an ebuild for the `symfony/console` package, place it in the `./ebuilds` directory, and run in debug mode.

## Development

### Code Formatting and Linting

We use Black, isort, and Flake8 for code formatting and linting:

```bash
poetry run black .
poetry run isort .
poetry run flake8 composer_ebuild
```
