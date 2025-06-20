"""
RAG 知识库管理器
用于管理安全漏洞知识库，提供基于检索增强生成的安全建议
"""

import os
import json
import sqlite3
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class VulnerabilityKnowledge:
    """漏洞知识条目"""

    id: str
    title: str
    description: str
    cwe_id: Optional[str]
    cvss_score: Optional[float]
    severity: str
    category: str
    language: Optional[str]
    pattern: str
    solution: str
    references: List[str]
    examples: List[str]
    tags: List[str]
    created_at: datetime
    updated_at: datetime


class KnowledgeBaseManager:
    """知识库管理器"""

    def __init__(self, db_path: str = "data/knowledge_base/security_kb.db"):
        self.db_path = db_path
        self.ensure_directory()
        self.init_database()

    def ensure_directory(self):
        """确保数据库目录存在"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

    def init_database(self):
        """初始化数据库"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    cwe_id TEXT,
                    cvss_score REAL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    language TEXT,
                    pattern TEXT NOT NULL,
                    solution TEXT NOT NULL,
                    references TEXT, -- JSON array
                    examples TEXT,   -- JSON array
                    tags TEXT,       -- JSON array
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_category ON vulnerabilities(category)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_language ON vulnerabilities(language)
            """)

            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS vulnerabilities_fts USING fts5(
                    title, description, pattern, solution, 
                    content='vulnerabilities', content_rowid='rowid'
                )
            """)

    def add_vulnerability(self, vuln: VulnerabilityKnowledge) -> bool:
        """添加漏洞知识条目"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO vulnerabilities 
                    (id, title, description, cwe_id, cvss_score, severity, 
                     category, language, pattern, solution, references, examples, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        vuln.id,
                        vuln.title,
                        vuln.description,
                        vuln.cwe_id,
                        vuln.cvss_score,
                        vuln.severity,
                        vuln.category,
                        vuln.language,
                        vuln.pattern,
                        vuln.solution,
                        json.dumps(vuln.references),
                        json.dumps(vuln.examples),
                        json.dumps(vuln.tags),
                    ),
                )

                # 更新全文搜索索引
                conn.execute(
                    """
                    INSERT OR REPLACE INTO vulnerabilities_fts 
                    (rowid, title, description, pattern, solution)
                    VALUES (last_insert_rowid(), ?, ?, ?, ?)
                """,
                    (vuln.title, vuln.description, vuln.pattern, vuln.solution),
                )

            return True
        except Exception as e:
            print(f"添加漏洞知识失败: {e}")
            return False

    def search_vulnerabilities(
        self,
        query: str,
        category: Optional[str] = None,
        language: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 10,
    ) -> List[VulnerabilityKnowledge]:
        """搜索漏洞知识"""
        conditions = []
        params = []

        if category:
            conditions.append("category = ?")
            params.append(category)

        if language:
            conditions.append("language = ? OR language IS NULL")
            params.append(language)

        if severity:
            conditions.append("severity = ?")
            params.append(severity)

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row

                # 首先尝试全文搜索
                if query.strip():
                    cursor = conn.execute(
                        f"""
                        SELECT v.* FROM vulnerabilities v
                        JOIN vulnerabilities_fts fts ON v.rowid = fts.rowid
                        WHERE fts MATCH ? AND {where_clause}
                        ORDER BY rank
                        LIMIT ?
                    """,
                        [query] + params + [limit],
                    )

                    results = cursor.fetchall()

                    # 如果全文搜索结果不足，补充模糊搜索
                    if len(results) < limit:
                        remaining = limit - len(results)
                        existing_ids = [r["id"] for r in results]
                        id_placeholders = (
                            ",".join(["?" for _ in existing_ids])
                            if existing_ids
                            else ""
                        )

                        additional_where = (
                            f" AND id NOT IN ({id_placeholders})"
                            if existing_ids
                            else ""
                        )

                        cursor = conn.execute(
                            f"""
                            SELECT * FROM vulnerabilities 
                            WHERE (title LIKE ? OR description LIKE ? OR pattern LIKE ?)
                            AND {where_clause} {additional_where}
                            ORDER BY severity DESC, cvss_score DESC
                            LIMIT ?
                        """,
                            [f"%{query}%", f"%{query}%", f"%{query}%"]
                            + params
                            + existing_ids
                            + [remaining],
                        )

                        results.extend(cursor.fetchall())
                else:
                    # 无查询条件时按严重性排序
                    cursor = conn.execute(
                        f"""
                        SELECT * FROM vulnerabilities 
                        WHERE {where_clause}
                        ORDER BY severity DESC, cvss_score DESC
                        LIMIT ?
                    """,
                        params + [limit],
                    )

                    results = cursor.fetchall()

                return [self._row_to_vulnerability(row) for row in results]

        except Exception as e:
            print(f"搜索漏洞知识失败: {e}")
            return []

    def get_vulnerability_by_id(self, vuln_id: str) -> Optional[VulnerabilityKnowledge]:
        """根据ID获取漏洞知识"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    "SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,)
                )
                row = cursor.fetchone()
                return self._row_to_vulnerability(row) if row else None
        except Exception as e:
            print(f"获取漏洞知识失败: {e}")
            return None

    def get_recommendations(
        self, vulnerability_type: str, language: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """获取修复建议"""
        # 搜索相关的漏洞知识
        vulns = self.search_vulnerabilities(
            query=vulnerability_type, language=language, limit=3
        )

        if not vulns:
            return {
                "recommendations": ["请查阅相关安全编码指南"],
                "references": [],
                "confidence": 0.1,
            }

        # 提取建议和引用
        recommendations = []
        references = []

        for vuln in vulns:
            if vuln.solution and vuln.solution not in recommendations:
                recommendations.append(vuln.solution)
            references.extend(vuln.references)

        # 去重引用
        references = list(set(references))

        return {
            "recommendations": recommendations[:5],  # 最多5条建议
            "references": references[:10],  # 最多10个引用
            "confidence": min(0.9, len(vulns) * 0.3),  # 基于匹配数量的置信度
            "related_cwe": [v.cwe_id for v in vulns if v.cwe_id],
            "severity_distribution": self._get_severity_stats(vulns),
        }

    def _row_to_vulnerability(self, row: sqlite3.Row) -> VulnerabilityKnowledge:
        """将数据库行转换为漏洞知识对象"""
        return VulnerabilityKnowledge(
            id=row["id"],
            title=row["title"],
            description=row["description"],
            cwe_id=row["cwe_id"],
            cvss_score=row["cvss_score"],
            severity=row["severity"],
            category=row["category"],
            language=row["language"],
            pattern=row["pattern"],
            solution=row["solution"],
            references=json.loads(row["references"] or "[]"),
            examples=json.loads(row["examples"] or "[]"),
            tags=json.loads(row["tags"] or "[]"),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def _get_severity_stats(
        self, vulns: List[VulnerabilityKnowledge]
    ) -> Dict[str, int]:
        """获取严重性统计"""
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for vuln in vulns:
            if vuln.severity in stats:
                stats[vuln.severity] += 1
        return stats

    def load_default_knowledge(self):
        """加载默认的安全知识库"""
        default_vulns = self._get_default_vulnerabilities()

        for vuln_data in default_vulns:
            vuln = VulnerabilityKnowledge(**vuln_data)
            self.add_vulnerability(vuln)

        print(f"已加载 {len(default_vulns)} 条默认漏洞知识")

    def _get_default_vulnerabilities(self) -> List[Dict[str, Any]]:
        """获取默认漏洞知识数据"""
        return [
            {
                "id": "sql-injection-001",
                "title": "SQL注入漏洞",
                "description": "通过在用户输入中插入恶意SQL代码来操纵数据库查询",
                "cwe_id": "CWE-89",
                "cvss_score": 9.8,
                "severity": "critical",
                "category": "注入攻击",
                "language": "python",
                "pattern": r"(execute|query|cursor)\s*\(\s*[\"'].*%s.*[\"']\s*%",
                "solution": "使用参数化查询或预编译语句，避免字符串拼接构建SQL",
                "references": [
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cwe.mitre.org/data/definitions/89.html",
                ],
                "examples": [
                    'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
                ],
                "tags": ["sql", "injection", "database"],
                "created_at": datetime.now(),
                "updated_at": datetime.now(),
            },
            {
                "id": "xss-stored-001",
                "title": "存储型XSS漏洞",
                "description": "恶意脚本被存储在服务器上，当其他用户访问时执行",
                "cwe_id": "CWE-79",
                "cvss_score": 8.8,
                "severity": "high",
                "category": "跨站脚本",
                "language": "javascript",
                "pattern": r"innerHTML|outerHTML|document\.write",
                "solution": "对用户输入进行HTML编码，使用安全的DOM操作方法",
                "references": [
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://cwe.mitre.org/data/definitions/79.html",
                ],
                "examples": [
                    "element.textContent = userInput; // 安全方式",
                    "element.innerHTML = DOMPurify.sanitize(userInput); // 使用净化库",
                ],
                "tags": ["xss", "javascript", "frontend"],
                "created_at": datetime.now(),
                "updated_at": datetime.now(),
            },
            {
                "id": "path-traversal-001",
                "title": "路径遍历漏洞",
                "description": "通过../等路径操作符访问服务器上的任意文件",
                "cwe_id": "CWE-22",
                "cvss_score": 7.5,
                "severity": "high",
                "category": "路径遍历",
                "language": None,
                "pattern": r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\",
                "solution": "验证和净化文件路径，使用白名单限制可访问的目录",
                "references": [
                    "https://owasp.org/www-community/attacks/Path_Traversal",
                    "https://cwe.mitre.org/data/definitions/22.html",
                ],
                "examples": ["os.path.join(safe_directory, secure_filename(filename))"],
                "tags": ["path-traversal", "file-access"],
                "created_at": datetime.now(),
                "updated_at": datetime.now(),
            },
            {
                "id": "hardcoded-secret-001",
                "title": "硬编码敏感信息",
                "description": "在源代码中直接写入密码、API密钥等敏感信息",
                "cwe_id": "CWE-798",
                "cvss_score": 6.5,
                "severity": "medium",
                "category": "信息泄露",
                "language": None,
                "pattern": r"(password|pwd|secret|key|token)\s*=\s*[\"'][^\"']+[\"']",
                "solution": "使用环境变量、配置文件或密钥管理服务存储敏感信息",
                "references": [
                    "https://cwe.mitre.org/data/definitions/798.html",
                    "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                ],
                "examples": [
                    "password = os.getenv('DB_PASSWORD')",
                    "api_key = config.get('API_KEY')",
                ],
                "tags": ["hardcoded", "credentials", "secrets"],
                "created_at": datetime.now(),
                "updated_at": datetime.now(),
            },
            {
                "id": "command-injection-001",
                "title": "命令注入漏洞",
                "description": "通过用户输入执行任意系统命令",
                "cwe_id": "CWE-78",
                "cvss_score": 9.8,
                "severity": "critical",
                "category": "注入攻击",
                "language": "python",
                "pattern": r"os\.system|subprocess\.call|exec|eval",
                "solution": "避免直接执行用户输入，使用参数化命令或输入验证",
                "references": [
                    "https://owasp.org/www-community/attacks/Command_Injection",
                    "https://cwe.mitre.org/data/definitions/78.html",
                ],
                "examples": ["subprocess.run(['ls', user_input], shell=False)"],
                "tags": ["command-injection", "system", "execution"],
                "created_at": datetime.now(),
                "updated_at": datetime.now(),
            },
        ]


# 全局知识库实例
knowledge_base = KnowledgeBaseManager()
