"""Logging configuration module for the composer-ebuild package."""

import logging
import sys


def configure_logging(*, debug: bool = False) -> None:
    """
    Configure logging for the entire application.

    Sets up the root logger with appropriate log level and formatter.
    This should be called as early as possible in the application lifecycle,
    before any other modules create their loggers.

    Args:
        debug: If True, set log level to DEBUG, otherwise INFO

    """
    log_level = logging.DEBUG if debug else logging.INFO

    # Get root logger first
    root_logger = logging.getLogger()

    # Set log level on root logger
    root_logger.setLevel(log_level)

    # Remove all existing handlers to prevent duplicate logging
    for existing_handler in root_logger.handlers[:]:
        root_logger.removeHandler(existing_handler)

    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
    )

    # Create and configure handler
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(log_level)
    handler.setFormatter(formatter)

    # Add handler to root logger
    root_logger.addHandler(handler)

    # Ensure propagation is enabled for all child loggers
    root_logger.propagate = True
