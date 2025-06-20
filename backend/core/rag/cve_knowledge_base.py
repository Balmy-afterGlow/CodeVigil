"""
CVEfixes知识库模块
连接到CVEfixes_v1.0.8数据库，提供CVE检索和代码修复模式分析
支持AI三阶段分析中的第三阶段：CVE关联和diff生成
"""

import os
import sqlite3
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

# 配置日志
logger = logging.getLogger(__name__)


@dataclass
class CVEInfo:
    """CVE基础信息"""

    cve_id: str
    severity: str
    description: str
    cwe_id: Optional[str]
    cvss_score: Optional[float]
    published_date: Optional[str]


@dataclass
class FixCommitInfo:
    """修复提交信息"""

    commit_id: str
    repo_url: str
    commit_message: str
    author_date: str
    files_changed: int
    lines_added: int
    lines_removed: int


@dataclass
class FileChangeInfo:
    """文件变更信息"""

    file_id: str
    filename: str
    old_path: str
    new_path: str
    change_type: str  # A=Added, M=Modified, D=Deleted
    programming_language: str
    num_lines_added: int
    num_lines_deleted: int


@dataclass
class MethodChangeInfo:
    """方法变更信息（包含before/after代码）"""

    method_name: str
    signature: str
    parameters: str
    before_change: str  # 修改前的代码
    after_change: str  # 修改后的代码
    start_line: int
    end_line: int


@dataclass
class CVEKnowledgeItem:
    """完整的CVE知识条目"""

    cve_info: CVEInfo
    fix_commit: FixCommitInfo
    file_changes: List[FileChangeInfo]
    method_changes: List[MethodChangeInfo]


@dataclass
class CVEFixKnowledge:
    """CVE修复知识数据结构"""

    cve_id: str
    severity: str
    description: str
    cwe_id: Optional[str]
    cvss_score: Optional[float]
    fix_hash: str
    repo_url: str
    repo_name: str
    programming_language: str
    repository_stars: int
    vulnerability_pattern: str
    fix_pattern: str
    affected_files: List[Dict[str, Any]]
    code_changes: List[Dict[str, Any]]


class CVEfixesKnowledgeBase:
    """CVEfixes知识库 - 连接到真实的CVEfixes数据库"""

    def __init__(
        self,
        db_path: str = "/home/moyu/Code/Project/CodeVigil/data/CVEfixes_v1.0.8/Data/CVEfixes.db",
    ):
        self.db_path = db_path
        self._verify_database()

    def _verify_database(self):
        """验证数据库是否存在"""
        if not os.path.exists(self.db_path):
            logger.warning(f"CVEfixes数据库文件不存在: {self.db_path}")
            # 确保目录存在
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            # 初始化一个空数据库
            self.init_database()
        else:
            logger.info(f"CVEfixes数据库已连接: {self.db_path}")

    def ensure_directory(self):
        """确保数据库目录存在"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

    def init_database(self):
        """初始化数据库表结构"""
        with sqlite3.connect(self.db_path) as conn:
            # CVE基础信息表
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_fixes (
                    cve_id TEXT PRIMARY KEY,
                    severity TEXT,
                    description TEXT,
                    cwe_id TEXT,
                    cvss_score REAL,
                    fix_hash TEXT,
                    repo_url TEXT,
                    repo_name TEXT,
                    programming_language TEXT,
                    repository_stars INTEGER,
                    vulnerability_pattern TEXT,
                    fix_pattern TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 文件变更表
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT,
                    filename TEXT,
                    old_path TEXT,
                    new_path TEXT,
                    change_type TEXT,
                    num_lines_added INTEGER,
                    num_lines_deleted INTEGER,
                    complexity_before REAL,
                    complexity_after REAL,
                    FOREIGN KEY (cve_id) REFERENCES cve_fixes (cve_id)
                )
            """)

            # 代码变更详情表
            conn.execute("""
                CREATE TABLE IF NOT EXISTS code_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT,
                    file_change_id INTEGER,
                    method_name TEXT,
                    start_line INTEGER,
                    end_line INTEGER,
                    code_before TEXT,
                    code_after TEXT,
                    change_type TEXT,
                    FOREIGN KEY (cve_id) REFERENCES cve_fixes (cve_id),
                    FOREIGN KEY (file_change_id) REFERENCES file_changes (id)
                )
            """)

            # 全文搜索表
            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS cve_search_fts USING fts5(
                    cve_id, description, vulnerability_pattern, fix_pattern,
                    content='cve_fixes', content_rowid='rowid'
                )
            """)

            # 创建索引
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_severity ON cve_fixes(severity)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cwe ON cve_fixes(cwe_id)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_language ON cve_fixes(programming_language)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_filename ON file_changes(filename)"
            )

    def add_cve_fix(self, cve_fix: CVEFixKnowledge) -> bool:
        """添加CVE修复知识"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # 插入CVE基础信息
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cve_fixes 
                    (cve_id, severity, description, cwe_id, cvss_score, fix_hash, 
                     repo_url, repo_name, programming_language, repository_stars,
                     vulnerability_pattern, fix_pattern)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        cve_fix.cve_id,
                        cve_fix.severity,
                        cve_fix.description,
                        cve_fix.cwe_id,
                        cve_fix.cvss_score,
                        cve_fix.fix_hash,
                        cve_fix.repo_url,
                        cve_fix.repo_name,
                        cve_fix.programming_language,
                        cve_fix.repository_stars,
                        cve_fix.vulnerability_pattern,
                        cve_fix.fix_pattern,
                    ),
                )

                # 插入文件变更
                for file_change in cve_fix.affected_files:
                    cursor = conn.execute(
                        """
                        INSERT INTO file_changes 
                        (cve_id, filename, old_path, new_path, change_type, 
                         num_lines_added, num_lines_deleted, complexity_before, complexity_after)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            cve_fix.cve_id,
                            file_change.get("filename"),
                            file_change.get("old_path"),
                            file_change.get("new_path"),
                            file_change.get("change_type"),
                            file_change.get("num_lines_added", 0),
                            file_change.get("num_lines_deleted", 0),
                            file_change.get("complexity_before"),
                            file_change.get("complexity_after"),
                        ),
                    )

                    file_change_id = cursor.lastrowid

                    # 插入该文件的代码变更
                    for code_change in cve_fix.code_changes:
                        if code_change.get("filename") == file_change.get("filename"):
                            conn.execute(
                                """
                                INSERT INTO code_changes 
                                (cve_id, file_change_id, method_name, start_line, end_line,
                                 code_before, code_after, change_type)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                                (
                                    cve_fix.cve_id,
                                    file_change_id,
                                    code_change.get("method_name"),
                                    code_change.get("start_line"),
                                    code_change.get("end_line"),
                                    code_change.get("code_before"),
                                    code_change.get("code_after"),
                                    code_change.get("change_type"),
                                ),
                            )

                # 更新全文搜索索引
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cve_search_fts 
                    (rowid, cve_id, description, vulnerability_pattern, fix_pattern)
                    VALUES (last_insert_rowid(), ?, ?, ?, ?)
                """,
                    (
                        cve_fix.cve_id,
                        cve_fix.description,
                        cve_fix.vulnerability_pattern,
                        cve_fix.fix_pattern,
                    ),
                )

            return True
        except Exception as e:
            print(f"添加CVE修复知识失败: {e}")
            return False

    def search_similar_vulnerabilities(
        self,
        vulnerability_description: str,
        code_snippet: str = "",
        language: str = "",
        severity: str = "",
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        根据漏洞描述和代码片段搜索相似的CVE修复案例
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row

                # 构建搜索条件
                conditions = []
                params = []

                if language:
                    conditions.append("cf.programming_language = ?")
                    params.append(language)

                if severity:
                    conditions.append("cf.severity = ?")
                    params.append(severity)

                where_clause = " AND ".join(conditions) if conditions else "1=1"

                # 构建搜索查询
                search_query = f"{vulnerability_description} {code_snippet}".strip()

                if search_query:
                    # 全文搜索
                    sql = f"""
                        SELECT cf.*, 
                               GROUP_CONCAT(fc.filename) as affected_filenames,
                               COUNT(cc.id) as code_changes_count
                        FROM cve_fixes cf
                        JOIN cve_search_fts fts ON cf.rowid = fts.rowid
                        LEFT JOIN file_changes fc ON cf.cve_id = fc.cve_id
                        LEFT JOIN code_changes cc ON cf.cve_id = cc.cve_id
                        WHERE fts MATCH ? AND {where_clause}
                        GROUP BY cf.cve_id
                        ORDER BY rank
                        LIMIT ?
                    """
                    params = [search_query] + params + [str(limit)]
                else:
                    # 无搜索词时按严重性排序
                    sql = f"""
                        SELECT cf.*, 
                               GROUP_CONCAT(fc.filename) as affected_filenames,
                               COUNT(cc.id) as code_changes_count
                        FROM cve_fixes cf
                        LEFT JOIN file_changes fc ON cf.cve_id = fc.cve_id
                        LEFT JOIN code_changes cc ON cf.cve_id = cc.cve_id
                        WHERE {where_clause}
                        GROUP BY cf.cve_id
                        ORDER BY 
                            CASE cf.severity 
                                WHEN 'critical' THEN 1 
                                WHEN 'high' THEN 2 
                                WHEN 'medium' THEN 3 
                                ELSE 4 
                            END,
                            cf.cvss_score DESC
                        LIMIT ?
                    """
                    params = params + [str(limit)]

                cursor = conn.execute(sql, params)
                results = cursor.fetchall()

                return [dict(row) for row in results]

        except Exception as e:
            print(f"搜索相似漏洞失败: {e}")
            return []

    def get_fix_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """获取CVE修复的详细信息"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row

                # 获取基础信息
                cursor = conn.execute(
                    "SELECT * FROM cve_fixes WHERE cve_id = ?", (cve_id,)
                )
                cve_info = cursor.fetchone()

                if not cve_info:
                    return None

                # 获取文件变更
                cursor = conn.execute(
                    """
                    SELECT * FROM file_changes WHERE cve_id = ?
                """,
                    (cve_id,),
                )
                file_changes = [dict(row) for row in cursor.fetchall()]

                # 获取代码变更
                cursor = conn.execute(
                    """
                    SELECT cc.*, fc.filename 
                    FROM code_changes cc
                    JOIN file_changes fc ON cc.file_change_id = fc.id
                    WHERE cc.cve_id = ?
                """,
                    (cve_id,),
                )
                code_changes = [dict(row) for row in cursor.fetchall()]

                return {
                    "cve_info": dict(cve_info),
                    "file_changes": file_changes,
                    "code_changes": code_changes,
                }

        except Exception as e:
            print(f"获取CVE修复详情失败: {e}")
            return None

    def generate_diff_context(self, vulnerability_info: Dict[str, Any]) -> str:
        """
        为AI生成diff时提供上下文信息
        """
        vuln_type = vulnerability_info.get("type", "")
        code_snippet = vulnerability_info.get("code_snippet", "")
        language = vulnerability_info.get("language", "")
        severity = vulnerability_info.get("severity", "")

        # 搜索相似案例
        similar_cases = self.search_similar_vulnerabilities(
            vulnerability_description=vuln_type,
            code_snippet=code_snippet,
            language=language,
            severity=severity,
            limit=3,
        )

        if not similar_cases:
            return "未找到相似的CVE修复案例"

        context_parts = []
        context_parts.append("=== 相似CVE修复案例 ===\n")

        for i, case in enumerate(similar_cases, 1):
            context_parts.append(f"案例 {i}: {case['cve_id']}")
            context_parts.append(f"严重性: {case['severity']}")
            context_parts.append(f"描述: {case['description']}")

            if case["cwe_id"]:
                context_parts.append(f"CWE: {case['cwe_id']}")

            # 获取详细修复信息
            fix_details = self.get_fix_details(case["cve_id"])
            if fix_details:
                context_parts.append("修复模式:")
                context_parts.append(case["fix_pattern"])

                # 添加代码变更示例
                code_changes = fix_details["code_changes"]
                if code_changes:
                    context_parts.append("修复示例:")
                    for change in code_changes[:2]:  # 只显示前2个变更
                        if change["code_before"] and change["code_after"]:
                            context_parts.append(f"文件: {change['filename']}")
                            context_parts.append(f"修复前:\n{change['code_before']}")
                            context_parts.append(f"修复后:\n{change['code_after']}")

            context_parts.append("-" * 50)

        return "\n".join(context_parts)

    def load_from_cvefixes_db(self, cvefixes_db_path: str, limit: int = 1000):
        """
        从CVEFixes数据库加载数据
        """
        try:
            # 连接到CVEFixes数据库
            with sqlite3.connect(cvefixes_db_path) as source_conn:
                source_conn.row_factory = sqlite3.Row

                # 查询CVE、修复和代码变更信息
                query = """
                    SELECT 
                        c.cve_id,
                        c.severity,
                        c.description,
                        cwe.cwe_id,
                        c.cvss2_base_score as cvss_score,
                        f.hash as fix_hash,
                        r.repo_url,
                        r.repo_name,
                        r.repo_language as programming_language,
                        r.stars_count as repository_stars,
                        commits.msg as commit_message
                    FROM cve c
                    JOIN fixes f ON c.cve_id = f.cve_id
                    JOIN repository r ON f.repo_url = r.repo_url
                    JOIN commits ON f.hash = commits.hash
                    LEFT JOIN cwe_classification cc ON c.cve_id = cc.cve_id
                    LEFT JOIN cwe ON cc.cwe_id = cwe.cwe_id
                    LIMIT ?
                """

                cursor = source_conn.execute(query, (limit,))

                count = 0
                for row in cursor:
                    try:
                        # 获取文件变更
                        file_changes_query = """
                            SELECT filename, old_path, new_path, change_type,
                                   num_lines_added, num_lines_deleted,
                                   nloc as complexity_before
                            FROM file_change 
                            WHERE hash = ?
                        """
                        file_cursor = source_conn.execute(
                            file_changes_query, (row["fix_hash"],)
                        )
                        file_changes = [
                            dict(fc_row) for fc_row in file_cursor.fetchall()
                        ]

                        # 获取方法变更
                        code_changes = []
                        for file_change in file_changes:
                            method_changes_query = """
                                SELECT name as method_name, signature, start_line, end_line,
                                       code as code_after, before_change as code_before
                                FROM method_change mc
                                JOIN file_change fc ON mc.file_change_id = fc.file_change_id
                                WHERE fc.hash = ? AND fc.filename = ?
                            """
                            method_cursor = source_conn.execute(
                                method_changes_query,
                                (row["fix_hash"], file_change["filename"]),
                            )

                            for method_row in method_cursor:
                                code_changes.append(
                                    {
                                        **dict(method_row),
                                        "filename": file_change["filename"],
                                        "change_type": "modified",
                                    }
                                )

                        # 生成漏洞和修复模式
                        vulnerability_pattern = self._extract_vulnerability_pattern(
                            row["description"], code_changes
                        )
                        fix_pattern = self._extract_fix_pattern(
                            row["commit_message"], code_changes
                        )

                        # 创建CVEFixKnowledge对象
                        cve_fix = CVEFixKnowledge(
                            cve_id=row["cve_id"],
                            severity=row["severity"] or "medium",
                            description=row["description"] or "",
                            cwe_id=row["cwe_id"],
                            fix_hash=row["fix_hash"],
                            repo_url=row["repo_url"],
                            repo_name=row["repo_name"],
                            affected_files=file_changes,
                            code_changes=code_changes,
                            vulnerability_pattern=vulnerability_pattern,
                            fix_pattern=fix_pattern,
                            programming_language=row["programming_language"]
                            or "unknown",
                            repository_stars=row["repository_stars"] or 0,
                            cvss_score=row["cvss_score"],
                        )

                        # 添加到知识库
                        if self.add_cve_fix(cve_fix):
                            count += 1

                        if count % 100 == 0:
                            print(f"已加载 {count} 条CVE修复记录")

                    except Exception as e:
                        print(f"处理CVE {row['cve_id']} 失败: {e}")
                        continue

                print(f"CVEFixes知识库加载完成，共加载 {count} 条记录")

        except Exception as e:
            print(f"从CVEFixes数据库加载失败: {e}")

    def _extract_vulnerability_pattern(
        self, description: str, code_changes: List[Dict]
    ) -> str:
        """提取漏洞模式"""
        # 简化的模式提取逻辑
        patterns = []

        # 从描述中提取关键词
        keywords = [
            "injection",
            "xss",
            "overflow",
            "traversal",
            "authentication",
            "authorization",
        ]
        for keyword in keywords:
            if keyword in description.lower():
                patterns.append(keyword)

        # 从代码变更中提取函数调用模式
        for change in code_changes:
            if change.get("code_before"):
                # 简单的函数调用提取
                import re

                func_calls = re.findall(r"(\w+)\s*\(", change["code_before"])
                patterns.extend(func_calls[:3])  # 最多取3个

        return " ".join(set(patterns))

    def _extract_fix_pattern(
        self, commit_message: str, code_changes: List[Dict]
    ) -> str:
        """提取修复模式"""
        fix_patterns = []

        # 从提交信息中提取
        fix_keywords = ["validate", "sanitize", "escape", "check", "verify", "filter"]
        for keyword in fix_keywords:
            if keyword in commit_message.lower():
                fix_patterns.append(keyword)

        # 从代码变更中提取修复模式
        for change in code_changes:
            if change.get("code_after"):
                # 检查是否添加了验证逻辑
                if (
                    "validate" in change["code_after"]
                    or "check" in change["code_after"]
                ):
                    fix_patterns.append("input_validation")
                if (
                    "escape" in change["code_after"]
                    or "sanitize" in change["code_after"]
                ):
                    fix_patterns.append("output_encoding")

        return " ".join(set(fix_patterns))

    def generate_diff_context_for_ai(
        self,
        vulnerability_description: str,
        code_snippet: str = "",
        language: str = "",
        limit: int = 3,
    ) -> str:
        """
        为AI生成diff上下文，包含相关CVE的修复模式和示例代码
        这个方法专门用于AI二次分析时提供修复参考
        """
        try:
            # 搜索相似的CVE修复案例
            similar_cves = self.search_similar_vulnerabilities(
                vulnerability_description=vulnerability_description,
                code_snippet=code_snippet,
                language=language,
                limit=limit,
            )

            if not similar_cves:
                return "未找到相关的CVE修复案例参考。"

            context_parts = [
                "=== CVE修复参考案例 ===",
                f"基于漏洞描述 '{vulnerability_description}' 找到以下{len(similar_cves)}个相关修复案例：\n",
            ]

            for i, cve in enumerate(similar_cves, 1):
                context_parts.append(f"【CVE案例 {i}】")
                context_parts.append(f"CVE ID: {cve.get('cve_id', 'Unknown')}")
                context_parts.append(f"严重程度: {cve.get('severity', 'Unknown')}")
                context_parts.append(f"CWE分类: {cve.get('cwe_id', 'Unknown')}")
                context_parts.append(
                    f"描述: {cve.get('description', 'No description')}"
                )

                # 获取详细的修复信息
                fix_details = self.get_fix_details(cve.get("cve_id", ""))
                if fix_details and fix_details.get("code_changes"):
                    context_parts.append("修复代码示例:")

                    for change in fix_details["code_changes"][:2]:  # 限制显示数量
                        if change.get("code_before") and change.get("code_after"):
                            context_parts.append(
                                f"  文件: {change.get('filename', 'Unknown')}"
                            )
                            context_parts.append(
                                f"  方法: {change.get('method_name', 'Unknown')}"
                            )
                            context_parts.append("  修复前:")
                            context_parts.append(
                                f"    {change['code_before'][:500]}..."
                            )
                            context_parts.append("  修复后:")
                            context_parts.append(f"    {change['code_after'][:500]}...")

                # 添加修复模式总结
                fix_pattern = cve.get("fix_pattern", "")
                if fix_pattern:
                    context_parts.append(f"修复模式: {fix_pattern}")

                context_parts.append("-" * 60)

            context_parts.append("\n=== 修复建议总结 ===")
            context_parts.append("基于以上CVE修复案例，建议的修复方向:")

            # 分析共同的修复模式
            common_patterns = self._extract_common_fix_patterns(similar_cves)
            for pattern in common_patterns:
                context_parts.append(f"- {pattern}")

            return "\n".join(context_parts)

        except Exception as e:
            logger.error(f"生成diff上下文失败: {e}")
            return f"生成CVE修复参考失败: {str(e)}"

    def _extract_common_fix_patterns(self, cves: List[Dict[str, Any]]) -> List[str]:
        """从CVE列表中提取常见的修复模式"""
        patterns = []

        # 分析修复模式的关键词
        fix_keywords: Dict[str, int] = {}
        for cve in cves:
            fix_pattern = cve.get("fix_pattern", "").lower()
            vulnerability_pattern = cve.get("vulnerability_pattern", "").lower()

            # 常见修复关键词
            keywords = [
                "validation",
                "sanitize",
                "escape",
                "encode",
                "decrypt",
                "authentication",
                "authorization",
                "bounds check",
                "input validation",
                "sql injection",
                "xss prevention",
            ]

            for keyword in keywords:
                if keyword in fix_pattern or keyword in vulnerability_pattern:
                    fix_keywords[keyword] = fix_keywords.get(keyword, 0) + 1

        # 生成修复建议
        if fix_keywords:
            sorted_keywords = sorted(
                fix_keywords.items(), key=lambda x: x[1], reverse=True
            )
            for keyword, count in sorted_keywords[:3]:  # 取前3个最常见的模式
                if keyword == "validation":
                    patterns.append("加强输入验证和数据校验")
                elif keyword == "sanitize":
                    patterns.append("对用户输入进行净化和过滤")
                elif keyword == "escape":
                    patterns.append("对特殊字符进行转义处理")
                elif keyword == "authentication":
                    patterns.append("增强身份认证机制")
                elif keyword == "authorization":
                    patterns.append("完善权限控制和访问检查")
                elif keyword == "bounds check":
                    patterns.append("添加边界检查防止溢出")
                else:
                    patterns.append(f"关注{keyword}相关的安全措施")

        if not patterns:
            patterns.append("参考相关CVE修复案例进行对应的安全加固")

        return patterns


# 全局CVEFixes知识库实例（延迟初始化）
_cvefixes_knowledge_base = None


def get_cvefixes_knowledge_base() -> CVEfixesKnowledgeBase:
    """获取CVEFixes知识库实例"""
    global _cvefixes_knowledge_base
    if _cvefixes_knowledge_base is None:
        _cvefixes_knowledge_base = CVEfixesKnowledgeBase()
    return _cvefixes_knowledge_base
