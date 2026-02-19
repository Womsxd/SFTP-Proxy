import os
import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Optional
from src.config import get_config


class DatePrefixTimedRotatingFileHandler(TimedRotatingFileHandler):
    def __init__(self, filename: str, when: str = 'midnight', interval: int = 1,
                 backupCount: int = 0, encoding: str = 'utf-8', delay: bool = False):
        self._base_filename = filename
        super().__init__(filename, when, interval, backupCount, encoding, delay)

    def _open(self):
        log_dir = os.path.dirname(self.baseFilename)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        return super()._open()


def setup_logger(name: str, log_file: str, level: str = "INFO",
                 log_format: str = "%(asctime)s [%(levelname)s] %(message)s",
                 date_format: str = "%Y-%m-%d %H:%M:%S") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if logger.handlers:
        return logger

    formatter = logging.Formatter(log_format, datefmt=date_format)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    file_handler = DatePrefixTimedRotatingFileHandler(
        log_file,
        when='midnight',
        interval=1,
        backupCount=30,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


def get_api_logger(force: bool = False) -> logging.Logger:
    global _api_logger
    if _api_logger is None or force:
        cfg = get_config()
        log_file = os.path.join(cfg.log.get('dir', './logs'), "api", "api.log")
        _api_logger = setup_logger("api", log_file, cfg.log.get('level', 'INFO'),
                            cfg.log.get('format') or "%(asctime)s [%(levelname)s] %(message)s",
                            cfg.log.get('date_format') or "%Y-%m-%d %H:%M:%S")
    return _api_logger


def get_sftp_logger(force: bool = False) -> logging.Logger:
    global _sftp_logger
    if _sftp_logger is None or force:
        cfg = get_config()
        log_file = os.path.join(cfg.log.get('dir', './logs'), "sftp", "sftp.log")
        _sftp_logger = setup_logger("sftp", log_file, cfg.log.get('level', 'INFO'),
                            cfg.log.get('format') or "%(asctime)s [%(levelname)s] %(message)s",
                            cfg.log.get('date_format') or "%Y-%m-%d %H:%M:%S")
    return _sftp_logger


_api_logger: Optional[logging.Logger] = None
_sftp_logger: Optional[logging.Logger] = None
_default_level: Optional[str] = None


def _get_default_level() -> str:
    global _default_level
    if _default_level is None:
        try:
            _default_level = get_config().log.get('level', 'INFO')
        except Exception:
            _default_level = 'INFO'
    return _default_level


def reinit_loggers():
    global _api_logger, _sftp_logger, _default_level
    _api_logger = None
    _sftp_logger = None
    _default_level = None


def api_log(action: str, message: str, level: str = "INFO"):
    global _api_logger
    if _api_logger is None:
        _api_logger = get_api_logger()
    log_func = getattr(_api_logger, level.lower(), _api_logger.info)
    log_func(message, extra={"action": action})


def sftp_log(action: str, message: str, level: str = "INFO"):
    global _sftp_logger
    if _sftp_logger is None:
        _sftp_logger = get_sftp_logger()
    log_func = getattr(_sftp_logger, level.lower(), _sftp_logger.info)
    log_func(message, extra={"action": action})
