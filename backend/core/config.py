"""
应用配置管理
"""

import os
from typing import Optional, List


class Settings:
    """应用配置"""

    def __init__(self):
        # 基本配置
        self.app_name = os.getenv("APP_NAME", "CodeVigil")
        self.app_version = os.getenv("APP_VERSION", "1.0.0")
        self.debug = os.getenv("DEBUG", "false").lower() == "true"

        # 服务器配置
        self.host = os.getenv("HOST", "0.0.0.0")
        self.port = int(os.getenv("PORT", "8000"))
        self.reload = os.getenv("RELOAD", "false").lower() == "true"

        # 数据库配置
        self.database_url = os.getenv("DATABASE_URL", "sqlite:///./data/codevigil.db")
        self.database_pool_size = int(os.getenv("DATABASE_POOL_SIZE", "10"))
        self.database_max_overflow = int(os.getenv("DATABASE_MAX_OVERFLOW", "20"))

        # Redis配置
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.redis_password = os.getenv("REDIS_PASSWORD")

        # AI分析配置
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.openai_model = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
        self.openai_max_tokens = int(os.getenv("OPENAI_MAX_TOKENS", "2000"))
        self.openai_temperature = float(os.getenv("OPENAI_TEMPERATURE", "0.1"))

        # 分析配置
        self.max_file_size = int(os.getenv("MAX_FILE_SIZE", str(1024 * 1024)))  # 1MB
        self.max_files_per_analysis = int(os.getenv("MAX_FILES_PER_ANALYSIS", "1000"))
        self.supported_languages = self._parse_list(
            os.getenv(
                "SUPPORTED_LANGUAGES",
                "python,javascript,typescript,java,c,cpp,csharp,php,ruby,go,rust,swift,kotlin,scala",
            )
        )

        # 存储配置
        self.data_dir = os.getenv("DATA_DIR", "./data")
        self.temp_dir = os.getenv("TEMP_DIR", "./data/temp")
        self.reports_dir = os.getenv("REPORTS_DIR", "./data/reports")
        self.repos_dir = os.getenv("REPOS_DIR", "./data/repos")

        # 安全配置
        self.secret_key = os.getenv(
            "SECRET_KEY", "your-secret-key-change-in-production"
        )
        self.access_token_expire_minutes = int(
            os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
        )

        # 日志配置
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.log_file = os.getenv("LOG_FILE")
        self.log_max_size = os.getenv("LOG_MAX_SIZE", "10MB")
        self.log_backup_count = int(os.getenv("LOG_BACKUP_COUNT", "5"))

        # Git配置
        self.git_timeout = int(os.getenv("GIT_TIMEOUT", "300"))  # 5分钟
        self.git_depth = int(os.getenv("GIT_DEPTH", "1"))  # 浅克隆深度

        # 速率限制配置
        self.rate_limit_enabled = (
            os.getenv("RATE_LIMIT_ENABLED", "false").lower() == "true"
        )
        self.rate_limit_calls = int(os.getenv("RATE_LIMIT_CALLS", "100"))
        self.rate_limit_period = int(os.getenv("RATE_LIMIT_PERIOD", "60"))

        # 任务队列配置
        self.task_queue_enabled = (
            os.getenv("TASK_QUEUE_ENABLED", "false").lower() == "true"
        )
        self.celery_broker_url = os.getenv("CELERY_BROKER_URL")
        self.celery_result_backend = os.getenv("CELERY_RESULT_BACKEND")

        # 监控配置
        self.monitoring_enabled = (
            os.getenv("MONITORING_ENABLED", "false").lower() == "true"
        )
        self.metrics_port = int(os.getenv("METRICS_PORT", "9090"))

        # 确保目录存在
        self._ensure_directories()

    def _parse_list(self, value: str) -> List[str]:
        """解析逗号分隔的字符串为列表"""
        if not value:
            return []
        return [item.strip() for item in value.split(",") if item.strip()]

    def _ensure_directories(self):
        """确保必要的目录存在"""
        directories = [
            self.data_dir,
            self.temp_dir,
            self.reports_dir,
            self.repos_dir,
        ]

        for directory in directories:
            os.makedirs(directory, exist_ok=True)

    @property
    def is_development(self) -> bool:
        """是否为开发环境"""
        return self.debug

    @property
    def is_production(self) -> bool:
        """是否为生产环境"""
        return not self.debug

    def get_database_config(self) -> dict:
        """获取数据库配置"""
        return {
            "url": self.database_url,
            "pool_size": self.database_pool_size,
            "max_overflow": self.database_max_overflow,
            "echo": self.debug,
        }

    def get_redis_config(self) -> dict:
        """获取Redis配置"""
        config = {"url": self.redis_url}
        if self.redis_password:
            config["password"] = self.redis_password
        return config

    def get_openai_config(self) -> dict:
        """获取OpenAI配置"""
        return {
            "api_key": self.openai_api_key,
            "model": self.openai_model,
            "max_tokens": self.openai_max_tokens,
            "temperature": self.openai_temperature,
        }


# 全局配置实例
settings = Settings()


def get_settings() -> Settings:
    """获取配置实例"""
    return settings
