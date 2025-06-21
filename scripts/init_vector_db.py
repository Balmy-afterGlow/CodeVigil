#!/usr/bin/env python3
"""
初始化CVE向量数据库脚本

使用时机：
1. 系统首次部署时
2. CVEfixes数据库更新后
3. 需要重建向量索引时

使用方法：
python scripts/init_vector_db.py [options]
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from backend.core.rag.cve_knowledge_base import (
    CVEfixesKnowledgeBase,
    VECTOR_SEARCH_AVAILABLE,
)

# 配置日志
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def check_prerequisites():
    """检查先决条件"""
    issues = []

    # 检查向量搜索依赖
    if not VECTOR_SEARCH_AVAILABLE:
        issues.append(
            "向量搜索依赖未安装，请运行: pip install faiss-cpu sentence-transformers"
        )

    # 检查CVEfixes数据库
    default_db_path = (
        "/home/moyu/Code/Project/CodeVigil/data/CVEfixes_v1.0.8/Data/CVEfixes.db"
    )
    if not os.path.exists(default_db_path):
        issues.append(f"CVEfixes数据库不存在: {default_db_path}")
        issues.append("请确保已下载并解压CVEfixes数据库")

    return issues


def build_vector_database(
    limit: int = 2000,
    severity_filter: str = None,
    language_filter: str = None,
    force_rebuild: bool = False,
):
    """构建向量数据库"""

    logger.info("=" * 60)
    logger.info("开始构建CVE向量数据库")
    logger.info("=" * 60)

    # 检查先决条件
    issues = check_prerequisites()
    if issues:
        logger.error("先决条件检查失败:")
        for issue in issues:
            logger.error(f"  - {issue}")
        return False

    try:
        # 初始化CVE知识库
        logger.info("初始化CVE知识库...")
        cve_kb = CVEfixesKnowledgeBase()

        # 检查是否已存在向量数据库
        if not force_rebuild:
            if os.path.exists(cve_kb.vector_index_path) and os.path.exists(
                cve_kb.vector_metadata_path
            ):
                logger.info("向量数据库已存在")
                try:
                    import faiss

                    index = faiss.read_index(cve_kb.vector_index_path)
                    logger.info(f"当前索引包含 {index.ntotal} 个CVE条目")

                    if not force_rebuild:
                        response = input("是否要重建向量数据库? (y/N): ")
                        if response.lower() != "y":
                            logger.info("跳过构建")
                            return True
                except Exception as e:
                    logger.warning(f"无法读取现有索引: {e}")

        # 显示构建参数
        logger.info("构建参数:")
        logger.info(f"  - 最大记录数: {limit}")
        logger.info(f"  - 严重性过滤: {severity_filter or '无'}")
        logger.info(f"  - 语言过滤: {language_filter or '无'}")
        logger.info(f"  - 强制重建: {force_rebuild}")

        # 开始构建
        logger.info("开始构建向量数据库...")
        success = cve_kb.build_vector_knowledge_base(
            limit=limit,
            severity_filter=severity_filter,
            language_filter=language_filter,
        )

        if success:
            logger.info("✅ 向量数据库构建成功!")

            # 显示最终统计
            try:
                import faiss

                if os.path.exists(cve_kb.vector_index_path):
                    index = faiss.read_index(cve_kb.vector_index_path)
                    file_size = os.path.getsize(cve_kb.vector_index_path) / 1024 / 1024
                    logger.info(f"📊 统计信息:")
                    logger.info(f"  - CVE条目数: {index.ntotal}")
                    logger.info(f"  - 索引文件大小: {file_size:.2f} MB")
                    logger.info(f"  - 索引文件路径: {cve_kb.vector_index_path}")
                    logger.info(f"  - 元数据路径: {cve_kb.vector_metadata_path}")
            except Exception as e:
                logger.warning(f"无法获取统计信息: {e}")

            return True
        else:
            logger.error("❌ 向量数据库构建失败")
            return False

    except Exception as e:
        logger.error(f"构建过程中发生错误: {e}", exc_info=True)
        return False


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="初始化CVE向量数据库",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  # 构建包含2000条记录的向量数据库
  python scripts/init_vector_db.py --limit 2000
  
  # 只构建高危漏洞的向量数据库
  python scripts/init_vector_db.py --severity critical --limit 1000
  
  # 只构建Python相关漏洞的向量数据库
  python scripts/init_vector_db.py --language python --limit 1500
  
  # 强制重建向量数据库
  python scripts/init_vector_db.py --force-rebuild
        """,
    )

    parser.add_argument(
        "--limit", type=int, default=2000, help="最大加载记录数量 (默认: 2000)"
    )

    parser.add_argument(
        "--severity", choices=["critical", "high", "medium", "low"], help="按严重性过滤"
    )

    parser.add_argument(
        "--language", help="按编程语言过滤 (例如: python, java, javascript)"
    )

    parser.add_argument(
        "--force-rebuild", action="store_true", help="强制重建，即使向量数据库已存在"
    )

    parser.add_argument(
        "--check-only", action="store_true", help="只检查先决条件，不构建数据库"
    )

    args = parser.parse_args()

    # 只检查先决条件
    if args.check_only:
        logger.info("检查先决条件...")
        issues = check_prerequisites()
        if issues:
            logger.error("发现以下问题:")
            for issue in issues:
                logger.error(f"  - {issue}")
            sys.exit(1)
        else:
            logger.info("✅ 所有先决条件满足")
            sys.exit(0)

    # 构建向量数据库
    success = build_vector_database(
        limit=args.limit,
        severity_filter=args.severity,
        language_filter=args.language,
        force_rebuild=args.force_rebuild,
    )

    if success:
        logger.info("🎉 向量数据库初始化完成!")
        sys.exit(0)
    else:
        logger.error("💥 向量数据库初始化失败!")
        sys.exit(1)


if __name__ == "__main__":
    main()
