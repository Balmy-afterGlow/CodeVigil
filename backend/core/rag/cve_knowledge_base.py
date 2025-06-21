"""
CVEfixes知识库模块
连接到CVEfixes_v1.0.8数据库，提供CVE检索和代码修复模式分析
支持AI三阶段分析中的第三阶段：CVE关联和diff生成
使用向量数据库进行语义检索相关CVE知识片段
"""

import os
import sqlite3
import logging
import numpy as np
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

# 配置日志
logger = logging.getLogger(__name__)

# 标识是否已安装可选依赖
try:
    import faiss
    from sentence_transformers import SentenceTransformer

    VECTOR_SEARCH_AVAILABLE = True
except ImportError:
    logger.warning("faiss或sentence_transformers未安装，将使用基于文本的搜索")
    VECTOR_SEARCH_AVAILABLE = False


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


@dataclass
class VectorizedCVE:
    """向量化的CVE知识条目，用于FAISS索引"""

    id: str  # 唯一标识符，通常为cve_id
    cve_id: str  # CVE编号
    text_content: str  # 用于嵌入的文本内容
    vector: Optional[np.ndarray]  # 向量表示
    metadata: Dict[str, Any]  # 元数据，包含severity、cwe_id等信息

    def to_dict(self) -> Dict[str, Any]:
        """转换为可JSON序列化的字典"""
        result = {
            "id": self.id,
            "cve_id": self.cve_id,
            "text_content": self.text_content,
            "metadata": self.metadata,
        }
        # 向量不适合直接JSON序列化，所以排除
        return result


class CVEfixesKnowledgeBase:
    """CVEfixes知识库 - 连接到真实的CVEfixes数据库，并构建向量索引"""

    def __init__(
        self,
        db_path: str = "/home/moyu/Code/Project/CodeVigil/data/CVEfixes_v1.0.8/Data/CVEfixes.db",
        vector_db_path: str = "/home/moyu/Code/Project/CodeVigil/data/vector_db",
        embedding_model: str = "all-MiniLM-L6-v2",
        vector_dimension: int = 384,
    ):
        # SQLite数据库路径
        self.db_path = db_path

        # 向量数据库路径
        self.vector_db_path = vector_db_path
        self.vector_index_path = os.path.join(vector_db_path, "cve_index.bin")
        self.vector_metadata_path = os.path.join(vector_db_path, "cve_metadata.json")

        # 向量维度
        self.vector_dimension = vector_dimension

        # 初始化成员变量
        self.index = None
        self.metadata: Dict[str, Any] = {"cve_ids": [], "vectors": []}
        self.embedding_model = None
        self.embedding_model_name = embedding_model

        # 验证数据库并初始化向量索引
        self._verify_database()
        if VECTOR_SEARCH_AVAILABLE:
            self._init_vector_index()

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

    def _init_vector_index(self):
        """初始化向量索引"""
        if not VECTOR_SEARCH_AVAILABLE:
            logger.warning("向量搜索功能不可用，请安装faiss和sentence-transformers")
            return

        # 确保向量数据库目录存在
        os.makedirs(self.vector_db_path, exist_ok=True)

        # 加载嵌入模型
        try:
            self.embedding_model = SentenceTransformer(self.embedding_model_name)
            logger.info(f"成功加载嵌入模型: {self.embedding_model_name}")
        except Exception as e:
            logger.error(f"加载嵌入模型失败: {e}")
            self.embedding_model = None
            return

        # 检查现有索引
        if os.path.exists(self.vector_index_path) and os.path.exists(
            self.vector_metadata_path
        ):
            try:
                # 加载FAISS索引
                self.index = faiss.read_index(self.vector_index_path)

                # 加载元数据
                with open(self.vector_metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)

                logger.info(f"已加载向量索引，包含{self.index.ntotal}个CVE条目")
            except Exception as e:
                logger.error(f"加载向量索引失败: {e}")
                # 初始化一个新的索引
                self._create_new_index()
        else:
            # 创建新索引
            self._create_new_index()

    def _create_new_index(self):
        """创建新的FAISS索引"""
        if not VECTOR_SEARCH_AVAILABLE:
            return

        try:
            # 创建索引 - 使用L2距离和精确搜索
            self.index = faiss.IndexFlatL2(self.vector_dimension)
            self.metadata = {"cve_ids": [], "vectors": []}
            logger.info(f"已创建新的向量索引，维度为{self.vector_dimension}")
        except Exception as e:
            logger.error(f"创建向量索引失败: {e}")
            self.index = None

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
        优先使用向量搜索，如不可用则降级为SQL文本搜索
        """
        # 构建查询文本
        query_text = f"{vulnerability_description} {code_snippet}".strip()

        # 尝试使用向量搜索
        if (
            VECTOR_SEARCH_AVAILABLE
            and self.index is not None
            and self.embedding_model is not None
            and self.index.ntotal > 0
        ):
            try:
                return self._vector_search(query_text, language, severity, limit)
            except Exception as e:
                logger.error(f"向量搜索失败，降级为文本搜索: {e}")

        # 降级为SQL文本搜索
        return self._text_search(query_text, language, severity, limit)

    def _vector_search(
        self, query_text: str, language: str = "", severity: str = "", limit: int = 5
    ) -> List[Dict[str, Any]]:
        """使用向量搜索查找相似CVE"""
        # 编码查询文本
        query_vector = self.embedding_model.encode([query_text])[0].astype(np.float32)
        query_vector = np.array([query_vector])

        # 执行搜索
        distances, indices = self.index.search(
            query_vector, k=limit * 3
        )  # 多检索一些，以便过滤

        # 过滤结果
        results = []
        for i, idx in enumerate(indices[0]):
            if idx >= 0 and idx < len(self.metadata["cve_ids"]):
                cve_id = self.metadata["cve_ids"][idx]
                cve_data = next(
                    (item for item in self.metadata["vectors"] if item["id"] == cve_id),
                    None,
                )

                if cve_data:
                    # 应用过滤条件
                    metadata = cve_data.get("metadata", {})
                    if (
                        not language or metadata.get("programming_language") == language
                    ) and (not severity or metadata.get("severity") == severity):
                        # 添加距离信息
                        cve_data["similarity_score"] = 1.0 / (
                            1.0 + float(distances[0][i])
                        )
                        results.append(cve_data)

        # 按相似度排序并限制数量
        results = sorted(
            results, key=lambda x: x.get("similarity_score", 0), reverse=True
        )[:limit]

        # 丰富结果数据
        enriched_results = []
        for result in results:
            # 获取完整的CVE信息
            details = self.get_fix_details(result["cve_id"])
            if details:
                # 合并相似度分数
                details["similarity_score"] = result.get("similarity_score", 0)
                enriched_results.append(details)

        return enriched_results

    def _text_search(
        self, search_query: str, language: str = "", severity: str = "", limit: int = 5
    ) -> List[Dict[str, Any]]:
        """使用SQL文本搜索查找相似CVE"""
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
            logger.error(f"搜索相似漏洞失败: {e}")
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
        从向量数据库中检索相似的CVE案例，提供给大语言模型作为上下文
        """
        # 提取漏洞信息
        vuln_type = vulnerability_info.get("type", "")
        code_snippet = vulnerability_info.get("code_snippet", "")
        language = vulnerability_info.get("language", "")
        severity = vulnerability_info.get("severity", "")

        # 搜索相似案例 - 同时使用向量搜索和文本搜索
        similar_cases = self.search_similar_vulnerabilities(
            vulnerability_description=vuln_type,
            code_snippet=code_snippet,
            language=language,
            severity=severity,
            limit=5,  # 增加搜索结果数量，后面会基于相似度排序
        )

        if not similar_cases:
            return "未找到相似的CVE修复案例"

        # 按相似度排序 - 向量搜索结果已经有相似度得分，文本搜索结果没有
        similar_cases.sort(
            key=lambda x: x.get("similarity_score", 0.2),  # 文本搜索默认得分0.2
            reverse=True,
        )

        # 构建上下文
        context_parts = []
        context_parts.append("=== 相似CVE修复案例 ===\n")

        for i, case in enumerate(similar_cases[:3], 1):  # 只使用前3个最相关的案例
            # 添加相似度信息
            similarity = case.get("similarity_score", 0)
            similarity_str = f"(相似度: {similarity:.2f})" if similarity > 0 else ""

            context_parts.append(f"案例 {i}: {case['cve_id']} {similarity_str}")
            context_parts.append(f"严重性: {case['severity']}")
            context_parts.append(f"描述: {case['description']}")

            if case.get("cwe_id"):
                context_parts.append(f"CWE: {case['cwe_id']}")

            # 获取详细修复信息
            fix_details = self.get_fix_details(case["cve_id"])
            if fix_details:
                if case.get("fix_pattern"):
                    context_parts.append("修复模式:")
                    context_parts.append(case["fix_pattern"])

                # 添加代码变更示例
                code_changes = fix_details.get("code_changes", [])
                if code_changes:
                    context_parts.append("修复示例代码:")
                    for change in code_changes[:2]:  # 只显示前2个变更
                        if change.get("code_before") and change.get("code_after"):
                            context_parts.append(
                                f"文件: {change.get('filename', 'unknown')}"
                            )
                            context_parts.append(f"修复前:\n{change['code_before']}")
                            context_parts.append(f"修复后:\n{change['code_after']}")
                            context_parts.append(
                                f"修改说明: 删除{change.get('num_lines_deleted', 0)}行，添加{change.get('num_lines_added', 0)}行"
                            )

            context_parts.append("-" * 50)

        return "\n".join(context_parts)

    def load_from_cvefixes_db(
        self,
        cvefixes_db_path: str = None,
        limit: int = 1000,
        severity_filter: str = None,
        language_filter: str = None,
        batch_size: int = 100,
    ):
        """
        从CVEfixes数据库高效加载部分数据构建知识库

        Args:
            cvefixes_db_path: CVEfixes数据库路径，如果为None则使用默认路径
            limit: 最大加载记录数
            severity_filter: 严重性过滤（critical, high, medium, low）
            language_filter: 编程语言过滤
            batch_size: 批量处理大小，用于控制内存使用
        """
        if cvefixes_db_path is None:
            cvefixes_db_path = "/home/moyu/Code/Project/CodeVigil/data/CVEfixes_v1.0.8/Data/CVEfixes.db"

        if not os.path.exists(cvefixes_db_path):
            logger.error(f"CVEfixes数据库文件不存在: {cvefixes_db_path}")
            return False

        try:
            logger.info(f"开始从CVEfixes数据库加载数据: {cvefixes_db_path}")
            logger.info(
                f"限制: {limit} 条记录, 严重性: {severity_filter}, 语言: {language_filter}"
            )

            # 连接到源数据库，使用只读模式和优化设置
            with sqlite3.connect(
                f"file:{cvefixes_db_path}?mode=ro", uri=True
            ) as source_conn:
                source_conn.row_factory = sqlite3.Row
                # 数据库性能优化设置 - 针对大型数据库优化
                source_conn.execute(
                    "PRAGMA cache_size = -32000"
                )  # 32MB缓存，减少内存使用
                source_conn.execute("PRAGMA temp_store = MEMORY")
                source_conn.execute("PRAGMA journal_mode = OFF")  # 只读模式，关闭日志
                source_conn.execute("PRAGMA synchronous = OFF")  # 关闭同步，提高性能
                source_conn.execute("PRAGMA query_only = ON")  # 查询模式

                # 构建查询条件
                conditions = [
                    "c.description IS NOT NULL",
                    "c.description != ''",
                    "f.hash IS NOT NULL",
                ]
                params = []

                if severity_filter:
                    conditions.append("c.severity = ?")
                    params.append(severity_filter)

                if language_filter:
                    conditions.append("r.repo_language = ?")
                    params.append(language_filter)

                # 优先选择有较多星标的仓库和较高严重性的CVE
                where_clause = " AND ".join(conditions)

                # 优化后的查询，基于实际表结构，增加更多过滤条件
                query = f"""
                    SELECT 
                        c.cve_id,
                        c.severity,
                        c.description,
                        CAST(c.cvss2_base_score AS REAL) as cvss_score,
                        c.published_date,
                        f.hash as fix_hash,
                        r.repo_url,
                        r.repo_name,
                        r.repo_language as programming_language,
                        CAST(r.stars_count AS INTEGER) as repository_stars
                    FROM cve c
                    INNER JOIN fixes f ON c.cve_id = f.cve_id
                    INNER JOIN repository r ON f.repo_url = r.repo_url
                    WHERE {where_clause}
                        AND c.cvss2_base_score IS NOT NULL
                        AND c.cvss2_base_score != ''
                        AND r.stars_count IS NOT NULL
                        AND CAST(r.stars_count AS INTEGER) > 10
                    ORDER BY 
                        CASE c.severity 
                            WHEN 'CRITICAL' THEN 1 
                            WHEN 'HIGH' THEN 2 
                            WHEN 'MEDIUM' THEN 3 
                            WHEN 'LOW' THEN 4
                            ELSE 5 
                        END,
                        CAST(c.cvss2_base_score AS REAL) DESC,
                        CAST(r.stars_count AS INTEGER) DESC
                    LIMIT ?
                """

                params.append(str(limit))
                logger.info("执行主查询SQL，获取CVE记录...")

                cursor = source_conn.execute(query, params)

                count = 0
                processed = 0
                batch_data = []

                # 批量处理CVE记录
                for row in cursor:
                    processed += 1
                    batch_data.append(dict(row))

                    # 达到批量大小时处理一批数据
                    if len(batch_data) >= batch_size:
                        count += self._process_cve_batch(source_conn, batch_data)
                        batch_data = []

                        if processed % (batch_size * 2) == 0:
                            logger.info(
                                f"已处理 {processed} 条记录，成功加载 {count} 条"
                            )

                # 处理最后一批数据
                if batch_data:
                    count += self._process_cve_batch(source_conn, batch_data)

                logger.info(
                    f"CVEfixes知识库加载完成！处理了 {processed} 条记录，成功加载 {count} 条"
                )
                return count > 0

        except Exception as e:
            logger.error(f"从CVEfixes数据库加载失败: {e}")
            return False

    def _process_cve_batch(
        self, source_conn: sqlite3.Connection, batch_data: List[Dict]
    ) -> int:
        """批量处理CVE数据"""
        count = 0

        for row_data in batch_data:
            try:
                cve_id = row_data["cve_id"]
                fix_hash = row_data["fix_hash"]

                # 获取提交信息 (单独查询以减少主查询复杂性)
                commit_message = self._get_commit_message(
                    source_conn, fix_hash, row_data["repo_url"]
                )

                # 获取CWE分类信息
                cwe_id = self._get_cwe_for_cve(source_conn, cve_id)

                # 获取文件变更信息
                file_changes = self._get_file_changes(source_conn, fix_hash)

                if not file_changes:
                    continue  # 跳过没有文件变更的记录

                # 获取代码变更信息
                code_changes = self._get_code_changes(
                    source_conn, fix_hash, file_changes[:5]
                )

                # 生成漏洞和修复模式
                vulnerability_pattern = self._extract_vulnerability_pattern(
                    row_data["description"] or "", code_changes
                )
                fix_pattern = self._extract_fix_pattern(
                    commit_message or "", code_changes
                )

                # 创建CVEFixKnowledge对象
                cve_fix = CVEFixKnowledge(
                    cve_id=cve_id,
                    severity=row_data["severity"] or "MEDIUM",
                    description=row_data["description"] or "",
                    cwe_id=cwe_id,
                    cvss_score=row_data["cvss_score"],
                    fix_hash=fix_hash,
                    repo_url=row_data["repo_url"],
                    repo_name=row_data["repo_name"] or "",
                    programming_language=row_data["programming_language"] or "unknown",
                    repository_stars=row_data["repository_stars"] or 0,
                    vulnerability_pattern=vulnerability_pattern,
                    fix_pattern=fix_pattern,
                    affected_files=file_changes,
                    code_changes=code_changes,
                )

                # 添加到知识库
                if self.add_cve_fix(cve_fix):
                    count += 1

            except Exception as e:
                logger.warning(f"处理CVE {row_data.get('cve_id', 'Unknown')} 失败: {e}")
                continue

        return count

    def _get_cwe_for_cve(self, conn: sqlite3.Connection, cve_id: str) -> Optional[str]:
        """获取CVE的CWE分类"""
        try:
            cursor = conn.execute(
                """
                SELECT cc.cwe_id
                FROM cwe_classification cc
                WHERE cc.cve_id = ?
                LIMIT 1
            """,
                (cve_id,),
            )
            row = cursor.fetchone()
            return row["cwe_id"] if row else None
        except Exception:
            return None

    def _get_file_changes(
        self, conn: sqlite3.Connection, fix_hash: str
    ) -> List[Dict[str, Any]]:
        """获取修复的文件变更信息"""
        try:
            cursor = conn.execute(
                """
                SELECT 
                    filename, 
                    old_path, 
                    new_path, 
                    change_type,
                    CAST(num_lines_added AS INTEGER) as num_lines_added, 
                    CAST(num_lines_deleted AS INTEGER) as num_lines_deleted,
                    CAST(nloc AS INTEGER) as nloc,
                    CAST(complexity AS INTEGER) as complexity,
                    programming_language
                FROM file_change 
                WHERE hash = ?
                AND filename IS NOT NULL
                LIMIT 10
            """,
                (fix_hash,),
            )

            file_changes = []
            for row in cursor:
                file_changes.append(
                    {
                        "filename": row["filename"],
                        "old_path": row["old_path"],
                        "new_path": row["new_path"],
                        "change_type": row["change_type"],
                        "num_lines_added": row["num_lines_added"] or 0,
                        "num_lines_deleted": row["num_lines_deleted"] or 0,
                        "complexity_before": row["nloc"] or 0,
                        "complexity_after": row["complexity"] or 0,
                        "language": row["programming_language"],
                    }
                )

            return file_changes
        except Exception as e:
            logger.warning(f"获取文件变更失败 {fix_hash}: {e}")
            return []

    def _get_code_changes(
        self,
        conn: sqlite3.Connection,
        fix_hash: str,
        file_changes: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """获取代码变更信息"""
        code_changes = []

        try:
            for file_change in file_changes:
                filename = file_change["filename"]

                # 获取方法级别的变更
                cursor = conn.execute(
                    """
                    SELECT 
                        mc.name as method_name,
                        mc.signature,
                        mc.parameters,
                        CAST(mc.start_line AS INTEGER) as start_line,
                        CAST(mc.end_line AS INTEGER) as end_line,
                        mc.code as code_after,
                        mc.before_change as code_before
                    FROM method_change mc
                    INNER JOIN file_change fc ON mc.file_change_id = fc.file_change_id
                    WHERE fc.hash = ? AND fc.filename = ?
                    AND (mc.code IS NOT NULL OR mc.before_change IS NOT NULL)
                    LIMIT 5
                """,
                    (fix_hash, filename),
                )

                for row in cursor:
                    code_before = row["code_before"] or ""
                    code_after = row["code_after"] or ""

                    # 只保留有意义的代码变更
                    if len(code_before) > 10 or len(code_after) > 10:
                        code_changes.append(
                            {
                                "method_name": row["method_name"],
                                "signature": row["signature"],
                                "parameters": row["parameters"],
                                "start_line": row["start_line"],
                                "end_line": row["end_line"],
                                "code_before": code_before[:2000],  # 限制长度
                                "code_after": code_after[:2000],  # 限制长度
                                "filename": filename,
                                "change_type": "modified",
                            }
                        )

        except Exception as e:
            logger.warning(f"获取代码变更失败 {fix_hash}: {e}")

        return code_changes

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

    def add_to_vector_index(self, vectorized_cve: VectorizedCVE) -> bool:
        """
        将CVE知识添加到向量索引中
        """
        if (
            not VECTOR_SEARCH_AVAILABLE
            or self.index is None
            or self.embedding_model is None
        ):
            logger.warning("向量搜索功能不可用，无法添加到索引")
            return False

        try:
            # 确保向量已生成
            if vectorized_cve.vector is None:
                vector = self.embedding_model.encode([vectorized_cve.text_content])[0]
                vectorized_cve.vector = vector
            else:
                vector = vectorized_cve.vector

            # 添加到索引
            vector_np = np.array([vector]).astype(np.float32)
            self.index.add(vector_np)

            # 更新元数据
            self.metadata["cve_ids"].append(vectorized_cve.id)
            self.metadata["vectors"].append(vectorized_cve.to_dict())

            # 保存索引和元数据
            self._save_vector_index()

            return True
        except Exception as e:
            logger.error(f"添加到向量索引失败: {e}")
            return False

    def _save_vector_index(self):
        """保存向量索引和元数据"""
        if not VECTOR_SEARCH_AVAILABLE or self.index is None:
            return

        try:
            # 保存FAISS索引
            faiss.write_index(self.index, self.vector_index_path)

            # 保存元数据
            with open(self.vector_metadata_path, "w", encoding="utf-8") as f:
                json.dump(self.metadata, f, ensure_ascii=False, indent=2)

            logger.info(f"已保存向量索引，共{self.index.ntotal}个条目")
        except Exception as e:
            logger.error(f"保存向量索引失败: {e}")

    def vectorize_cve_knowledge(
        self, cve_fix: CVEFixKnowledge
    ) -> Optional[VectorizedCVE]:
        """
        将CVE修复知识转换为向量化格式
        """
        if not VECTOR_SEARCH_AVAILABLE or self.embedding_model is None:
            logger.warning("向量搜索不可用或嵌入模型未初始化")
            return None

        # 构建文本内容 - 包含所有重要信息
        text_content = f"""
CVE-ID: {cve_fix.cve_id}
描述: {cve_fix.description}
CWE-ID: {cve_fix.cwe_id if cve_fix.cwe_id else "Unknown"}
严重性: {cve_fix.severity}
编程语言: {cve_fix.programming_language}
漏洞模式: {cve_fix.vulnerability_pattern}
修复模式: {cve_fix.fix_pattern}
"""

        # 生成向量
        vector = None
        try:
            if self.embedding_model is not None:
                vector = self.embedding_model.encode([text_content])[0]
        except Exception as e:
            logger.error(f"向量编码失败: {e}")

        # 构建元数据
        metadata = {
            "cve_id": cve_fix.cve_id,
            "severity": cve_fix.severity,
            "cwe_id": cve_fix.cwe_id,
            "programming_language": cve_fix.programming_language,
            "cvss_score": cve_fix.cvss_score,
            "vuln_pattern": cve_fix.vulnerability_pattern[:100]
            if cve_fix.vulnerability_pattern
            else "",
            "fix_pattern": cve_fix.fix_pattern[:100] if cve_fix.fix_pattern else "",
        }

        # 返回向量化的CVE
        return VectorizedCVE(
            id=cve_fix.cve_id,
            cve_id=cve_fix.cve_id,
            text_content=text_content,
            vector=vector,
            metadata=metadata,
        )

    def build_vector_knowledge_base(
        self,
        cvefixes_db_path: Optional[str] = None,
        limit: int = 2000,
        severity_filter: Optional[str] = None,
        language_filter: Optional[str] = None,
    ) -> bool:
        """
        从CVEfixes数据库构建向量知识库

        Args:
            cvefixes_db_path: CVEfixes数据库路径
            limit: 最大加载记录数量
            severity_filter: 按严重性过滤
            language_filter: 按编程语言过滤

        Returns:
            bool: 是否成功构建知识库
        """
        if not VECTOR_SEARCH_AVAILABLE:
            logger.error("向量搜索功能不可用，请安装faiss和sentence_transformers")
            return False

        if self.embedding_model is None:
            logger.error("嵌入模型未初始化")
            return False

        # 使用默认路径
        if cvefixes_db_path is None:
            cvefixes_db_path = self.db_path

        if not os.path.exists(cvefixes_db_path):
            logger.error(f"CVEfixes数据库不存在: {cvefixes_db_path}")
            return False

        try:
            # 重置向量索引
            self._create_new_index()
            logger.info(f"开始从{cvefixes_db_path}构建向量知识库，限制{limit}条记录")

            with sqlite3.connect(f"file:{cvefixes_db_path}?mode=ro", uri=True) as conn:
                conn.row_factory = sqlite3.Row

                # 设置数据库性能选项
                conn.execute("PRAGMA cache_size = -32000")  # 32MB缓存
                conn.execute("PRAGMA temp_store = MEMORY")
                conn.execute("PRAGMA journal_mode = OFF")
                conn.execute("PRAGMA synchronous = OFF")
                conn.execute("PRAGMA query_only = ON")

                # 构建查询条件
                conditions = [
                    "description IS NOT NULL",
                    "description != ''",
                    "vulnerability_pattern IS NOT NULL",
                    "fix_pattern IS NOT NULL",
                ]
                params = []

                if severity_filter:
                    conditions.append("severity = ?")
                    params.append(severity_filter)

                if language_filter:
                    conditions.append("programming_language = ?")
                    params.append(language_filter)

                where_clause = " AND ".join(conditions)

                # 查询CVE数据
                query = f"""
                SELECT 
                    cve_id, severity, description, cwe_id, 
                    cvss_score, programming_language, 
                    vulnerability_pattern, fix_pattern
                FROM cve_fixes
                WHERE {where_clause}
                ORDER BY 
                    CASE severity 
                        WHEN 'critical' THEN 1 
                        WHEN 'high' THEN 2 
                        WHEN 'medium' THEN 3 
                        ELSE 4 
                    END,
                    cvss_score DESC
                LIMIT ?
                """

                cursor = conn.execute(query, params + [limit])
                cve_records = cursor.fetchall()

                logger.info(f"获取到{len(cve_records)}条CVE记录，开始处理...")
                success_count = 0

                # 批量处理
                batch_size = 50
                for i in range(0, len(cve_records), batch_size):
                    batch = cve_records[i : i + batch_size]
                    logger.info(f"处理第{i // batch_size + 1}批，共{len(batch)}条记录")

                    # 处理每个CVE记录
                    for record in batch:
                        # 构建CVE知识条目
                        cve_fix = CVEFixKnowledge(
                            cve_id=record["cve_id"],
                            severity=record["severity"],
                            description=record["description"],
                            cwe_id=record["cwe_id"],
                            cvss_score=record["cvss_score"],
                            fix_hash="",  # 这些字段不是必须的
                            repo_url="",
                            repo_name="",
                            programming_language=record["programming_language"],
                            repository_stars=0,
                            vulnerability_pattern=record["vulnerability_pattern"],
                            fix_pattern=record["fix_pattern"],
                            affected_files=[],
                            code_changes=[],
                        )

                        # 向量化CVE知识
                        vectorized_cve = self.vectorize_cve_knowledge(cve_fix)
                        if vectorized_cve is not None:
                            # 添加到向量索引
                            if self.add_to_vector_index(vectorized_cve):
                                success_count += 1

                    # 每处理一批次保存一次
                    self._save_vector_index()

                logger.info(f"向量知识库构建完成，成功添加{success_count}条记录")
                return success_count > 0

        except Exception as e:
            logger.error(f"构建向量知识库失败: {e}")
            return False
