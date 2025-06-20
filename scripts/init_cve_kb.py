#!/usr/bin/env python3
"""
CVE知识库初始化脚本
从CVEfixes数据集加载数据到本地知识库
"""

import os
import sys
import sqlite3
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from backend.core.cve_knowledge_base import CVEFixesKnowledgeBase, CVEFixKnowledge


def load_sample_cve_data():
    """加载一些示例CVE数据"""
    sample_cves = [
        {
            "cve_id": "CVE-2021-44228",
            "severity": "critical",
            "description": "Apache Log4j2 远程代码执行漏洞",
            "cwe_id": "CWE-502",
            "cvss_score": 10.0,
            "fix_hash": "a030969947",
            "repo_url": "https://github.com/apache/logging-log4j2",
            "repo_name": "logging-log4j2",
            "programming_language": "java",
            "repository_stars": 3200,
            "vulnerability_pattern": "JNDI lookup enabled without proper validation",
            "fix_pattern": "Disable JNDI lookup by default and add validation",
            "affected_files": [
                {
                    "filename": "JndiLookup.java",
                    "old_path": "log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JndiLookup.java",
                    "new_path": "log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JndiLookup.java",
                    "change_type": "modified",
                    "num_lines_added": 15,
                    "num_lines_deleted": 3,
                }
            ],
            "code_changes": [
                {
                    "filename": "JndiLookup.java",
                    "method_name": "lookup",
                    "start_line": 45,
                    "end_line": 60,
                    "code_before": "return ctx.lookup(key);",
                    "code_after": "if (JndiManager.isJndiEnabled()) { return ctx.lookup(key); } else { return null; }",
                    "change_type": "security_fix",
                }
            ],
        },
        {
            "cve_id": "CVE-2022-22965",
            "severity": "critical",
            "description": "Spring Framework 远程代码执行漏洞 (Spring4Shell)",
            "cwe_id": "CWE-94",
            "cvss_score": 9.8,
            "fix_hash": "b8de06f5",
            "repo_url": "https://github.com/spring-projects/spring-framework",
            "repo_name": "spring-framework",
            "programming_language": "java",
            "repository_stars": 55000,
            "vulnerability_pattern": "Improper data binding allowing class manipulation",
            "fix_pattern": "Add blacklist for dangerous class properties",
            "affected_files": [
                {
                    "filename": "BeanWrapperImpl.java",
                    "old_path": "spring-beans/src/main/java/org/springframework/beans/BeanWrapperImpl.java",
                    "new_path": "spring-beans/src/main/java/org/springframework/beans/BeanWrapperImpl.java",
                    "change_type": "modified",
                    "num_lines_added": 25,
                    "num_lines_deleted": 5,
                }
            ],
            "code_changes": [
                {
                    "filename": "BeanWrapperImpl.java",
                    "method_name": "setPropertyValue",
                    "start_line": 150,
                    "end_line": 170,
                    "code_before": "setPropertyValue(propertyName, value);",
                    "code_after": "if (!isBlacklistedProperty(propertyName)) { setPropertyValue(propertyName, value); }",
                    "change_type": "security_fix",
                }
            ],
        },
        {
            "cve_id": "CVE-2021-3129",
            "severity": "critical",
            "description": "Laravel框架远程代码执行漏洞",
            "cwe_id": "CWE-94",
            "cvss_score": 9.8,
            "fix_hash": "c1ede2bc",
            "repo_url": "https://github.com/laravel/framework",
            "repo_name": "laravel/framework",
            "programming_language": "php",
            "repository_stars": 32000,
            "vulnerability_pattern": "Unsafe deserialization in debug mode",
            "fix_pattern": "Disable debug mode in production and validate input",
            "affected_files": [
                {
                    "filename": "Ignition.php",
                    "old_path": "src/Solutions/MakeViewVariableOptionalSolution.php",
                    "new_path": "src/Solutions/MakeViewVariableOptionalSolution.php",
                    "change_type": "modified",
                    "num_lines_added": 10,
                    "num_lines_deleted": 2,
                }
            ],
            "code_changes": [
                {
                    "filename": "Ignition.php",
                    "method_name": "execute",
                    "start_line": 35,
                    "end_line": 45,
                    "code_before": "unserialize($serialized);",
                    "code_after": "if (config('app.debug')) { unserialize($serialized); }",
                    "change_type": "security_fix",
                }
            ],
        },
    ]

    return sample_cves


def init_cve_knowledge_base():
    """初始化CVE知识库"""
    print("正在初始化CVE知识库...")

    # 创建知识库实例
    cve_kb = CVEFixesKnowledgeBase()

    # 加载示例数据
    sample_cves = load_sample_cve_data()

    success_count = 0
    for cve_data in sample_cves:
        try:
            cve_fix = CVEFixKnowledge(**cve_data)
            if cve_kb.add_cve_fix(cve_fix):
                success_count += 1
                print(f"✓ 成功添加CVE: {cve_data['cve_id']}")
            else:
                print(f"✗ 添加CVE失败: {cve_data['cve_id']}")
        except Exception as e:
            print(f"✗ 处理CVE失败 {cve_data['cve_id']}: {e}")

    print(f"\n知识库初始化完成！成功加载 {success_count}/{len(sample_cves)} 条CVE记录")

    # 测试搜索功能
    print("\n测试搜索功能...")
    test_search_results = cve_kb.search_similar_vulnerabilities(
        vulnerability_description="远程代码执行", language="java", limit=3
    )
    print(f"搜索到 {len(test_search_results)} 条相关记录")

    # 测试diff上下文生成
    print("\n测试diff上下文生成...")
    diff_context = cve_kb.generate_diff_context_for_ai(
        vulnerability_description="JNDI注入远程代码执行",
        code_snippet="ctx.lookup(userInput)",
        language="java",
    )
    print("diff上下文生成成功")


if __name__ == "__main__":
    print("=== CodeVigil CVE知识库初始化工具 ===")

    # 确保数据目录存在
    data_dir = project_root / "data" / "knowledge_base"
    data_dir.mkdir(parents=True, exist_ok=True)

    try:
        init_cve_knowledge_base()
        print("\n✓ CVE知识库初始化成功！")
        print(f"数据库位置: {data_dir / 'cvefixes_kb.db'}")

    except Exception as e:
        print(f"\n✗ 初始化失败: {e}")
        sys.exit(1)
