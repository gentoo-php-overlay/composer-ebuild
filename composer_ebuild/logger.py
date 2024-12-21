"""Logging configuration module for the composer-ebuild package."""

import logging


def configure_logging(*, debug: bool = False) -> None:
    """
    Configure logging for the entire application.

    :param debug: If True, set log level to DEBUG, otherwise INFO
    """
    log_level = logging.DEBUG if debug else logging.INFO

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers to prevent duplicate logging
    for existing_handler in root_logger.handlers[:]:
        root_logger.removeHandler(existing_handler)

    root_logger.addHandler(handler)
