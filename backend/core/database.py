"""
数据库配置和初始化
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from utils.logger import get_logger

logger = get_logger(__name__)

# 数据库配置
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/codevigil.db")

# 创建数据库引擎
engine = create_engine(
    DATABASE_URL, pool_pre_ping=True, echo=os.getenv("DEBUG", "False").lower() == "true"
)

# 创建会话
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 基础模型类
Base = declarative_base()


async def init_db():
    """初始化数据库"""
    try:
        # 确保数据目录存在
        if "sqlite" in DATABASE_URL:
            db_dir = os.path.dirname(DATABASE_URL.replace("sqlite:///", ""))
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)

        # 创建所有表
        Base.metadata.create_all(bind=engine)
        logger.info("数据库初始化完成")
    except Exception as e:
        logger.error(f"数据库初始化失败: {e}")
        raise


def get_db():
    """获取数据库会话"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
