"""
日志工具模块
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional


def get_logger(name: str, level: str = None) -> logging.Logger:
    """
    获取日志记录器

    Args:
        name: 日志器名称
        level: 日志级别

    Returns:
        logging.Logger: 配置好的日志器
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    # 设置日志级别
    log_level = level or os.getenv("LOG_LEVEL", "INFO")
    logger.setLevel(getattr(logging, log_level.upper()))

    # 创建格式器
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 文件处理器
    log_file = os.getenv("LOG_FILE", "./logs/app.log")
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger
