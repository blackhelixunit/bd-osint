"""Clean terminal logging."""

from __future__ import annotations

import logging
import sys


class BdFormatter(logging.Formatter):
    COLORS = {
        "INFO": "\033[36m", "WARNING": "\033[33m",
        "ERROR": "\033[31m", "DEBUG": "\033[90m",
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        if record.levelname == "INFO":
            return f"{color}[+]{self.RESET} {record.getMessage()}"
        return f"{color}[{record.levelname[0]}]{self.RESET} {record.getMessage()}"


def setup_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    logger = logging.getLogger("bdosint")
    logger.setLevel(logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO))
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(BdFormatter())
        logger.addHandler(handler)
    return logger


def banner() -> str:
    return r"""
  ____  ____  _____  ___   ___  ___   _   _
 | __ )|  _ \|_   _|/ _ \ / _ \ / _ \ | \ | |
 |  _ \| |_) | | | | | | | | | | | | ||  \| |
 | |_) |  _ <  | | | |_| | |_| | |_| || |\  |
 |____/|_| \_\ |_|  \___/ \___/ \___/|_| \_|
        v3.0 — Passive OSINT for Bangladesh
   Authorized assessment use only. Active scan = opt-in.
"""
