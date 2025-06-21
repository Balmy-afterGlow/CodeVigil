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
        """验证数据库表结构（CVEfixes数据库是只读的，不需要初始化）"""
        # CVEfixes数据库是预构建的，包含以下表：
        # - cve: CVE基础信息
        # - fixes: CVE到修复提交的映射
        # - commits: 提交信息
        # - file_change: 文件变更
        # - method_change: 方法级变更
        # - cwe_classification: CVE到CWE的映射
        # - cwe: CWE信息
        # - repository: 仓库信息
        
        # 这里我们只验证表的存在，不创建新表
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('cve', 'fixes', 'file_change', 'method_change')"
                )
                tables = [row[0] for row in cursor.fetchall()]
                required_tables = ['cve', 'fixes', 'file_change', 'method_change']
                
                missing_tables = set(required_tables) - set(tables)
                if missing_tables:
                    logger.warning(f"数据库缺少必要的表: {missing_tables}")
                else:
                    logger.info("数据库表结构验证通过")
                    
        except Exception as e:
            logger.error(f"验证数据库表结构失败: {e}")

    def add_cve_fix(self, cve_fix: CVEFixKnowledge) -> bool:
        """添加CVE修复知识到向量索引（不修改原始数据库）"""
        # CVEfixes数据库是只读的，我们只能将新知识添加到向量索引中
        # 而不能修改原始数据库
        try:
            # 如果有向量搜索功能，将知识向量化并添加到索引
            if VECTOR_SEARCH_AVAILABLE and self.embedding_model is not None:
                vectorized_cve = self.vectorize_cve_knowledge(cve_fix)
                if vectorized_cve:
                    return self.add_to_vector_index(vectorized_cve)
            
            logger.warning("向量搜索功能不可用，无法添加CVE修复知识")
            return False
            
        except Exception as e:
            logger.error(f"添加CVE修复知识失败: {e}")
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
                conditions = ["c.description IS NOT NULL"]
                params = []

                if language:
                    conditions.append("r.repo_language = ?")
                    params.append(language)

                if severity:
                    conditions.append("c.severity = ?")
                    params.append(severity.upper())  # CVEfixes数据库中severity是大写

                where_clause = " AND ".join(conditions)

                if search_query:
                    # 基于描述的文本搜索
                    conditions.append("c.description LIKE ?")
                    params.append(f"%{search_query}%")
                    where_clause = " AND ".join(conditions)

                # 使用实际的CVEfixes数据库表结构
                sql = f"""
                    SELECT DISTINCT
                        c.cve_id, 
                        c.severity, 
                        c.description, 
                        cwe.cwe_id,
                        c.cvss2_base_score as cvss_score,
                        r.repo_language as programming_language
                    FROM cve c
                    LEFT JOIN cwe_classification cc ON c.cve_id = cc.cve_id
                    LEFT JOIN cwe ON cc.cwe_id = cwe.cwe_id  
                    LEFT JOIN fixes f ON c.cve_id = f.cve_id
                    LEFT JOIN repository r ON f.repo_url = r.repo_url
                    WHERE {where_clause}
                    ORDER BY 
                        CASE c.severity 
                            WHEN 'CRITICAL' THEN 1 
                            WHEN 'HIGH' THEN 2 
                            WHEN 'MEDIUM' THEN 3 
                            WHEN 'LOW' THEN 4
                            ELSE 5 
                        END,
                        c.cvss2_base_score DESC
                    LIMIT ?
                """

                cursor = conn.execute(sql, params + [limit])
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

                # 获取CVE基础信息
                cursor = conn.execute(
                    """
                    SELECT c.*, cwe.cwe_id, cwe.cwe_name
                    FROM cve c
                    LEFT JOIN cwe_classification cc ON c.cve_id = cc.cve_id
                    LEFT JOIN cwe ON cc.cwe_id = cwe.cwe_id
                    WHERE c.cve_id = ?
                    """, 
                    (cve_id,)
                )
                cve_info = cursor.fetchone()

                if not cve_info:
                    return None

                # 获取修复相关的文件变更信息
                cursor = conn.execute(
                    """
                    SELECT fc.*, c.hash as commit_hash
                    FROM file_change fc
                    JOIN commits c ON fc.hash = c.hash
                    JOIN fixes f ON c.hash = f.hash AND c.repo_url = f.repo_url
                    WHERE f.cve_id = ?
                    """,
                    (cve_id,),
                )
                file_changes = [dict(row) for row in cursor.fetchall()]

                # 获取方法级别的代码变更信息
                cursor = conn.execute(
                    """
                    SELECT mc.*, fc.filename
                    FROM method_change mc
                    JOIN file_change fc ON mc.file_change_id = fc.file_change_id
                    JOIN commits c ON fc.hash = c.hash
                    JOIN fixes f ON c.hash = f.hash AND c.repo_url = f.repo_url
                    WHERE f.cve_id = ?
                    """,
                    (cve_id,),
                )
                method_changes = [dict(row) for row in cursor.fetchall()]

                return {
                    "cve_info": dict(cve_info),
                    "file_changes": file_changes,
                    "method_changes": method_changes,  # 改名以匹配实际的表结构
                }

        except Exception as e:
            logger.error(f"获取CVE修复详情失败: {e}")
            return None

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
                if fix_details and fix_details.get("method_changes"):
                    context_parts.append("修复代码示例:")

                    for change in fix_details["method_changes"][:2]:  # 限制显示数量
                        if change.get("before_change") and change.get("code"):
                            context_parts.append(
                                f"  文件: {change.get('filename', 'Unknown')}"
                            )
                            context_parts.append(
                                f"  方法: {change.get('name', 'Unknown')}"
                            )
                            context_parts.append("  修复前:")
                            # method_change表中before_change字段可能为空，使用code作为修复后的代码
                            if change.get("before_change"):
                                context_parts.append(
                                    f"    {change['before_change'][:500]}..."
                                )
                            context_parts.append("  修复后:")
                            context_parts.append(f"    {change['code'][:500]}...")

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
                    "c.description IS NOT NULL",
                    "c.description != ''",
                ]
                params = []

                if severity_filter:
                    conditions.append("c.severity = ?")
                    params.append(severity_filter)

                if language_filter:
                    conditions.append("r.repo_language = ?")
                    params.append(language_filter)

                where_clause = " AND ".join(conditions)

                # 查询CVE数据 - 根据实际的CVEfixes数据库表结构
                query = f"""
                SELECT DISTINCT
                    c.cve_id, 
                    c.severity, 
                    c.description, 
                    cwe.cwe_id,
                    c.cvss2_base_score as cvss_score,
                    r.repo_language as programming_language,
                    '' as vulnerability_pattern,
                    '' as fix_pattern
                FROM cve c
                LEFT JOIN cwe_classification cc ON c.cve_id = cc.cve_id
                LEFT JOIN cwe ON cc.cwe_id = cwe.cwe_id  
                LEFT JOIN fixes f ON c.cve_id = f.cve_id
                LEFT JOIN repository r ON f.repo_url = r.repo_url
                WHERE {where_clause}
                ORDER BY 
                    CASE c.severity 
                        WHEN 'CRITICAL' THEN 1 
                        WHEN 'HIGH' THEN 2 
                        WHEN 'MEDIUM' THEN 3 
                        WHEN 'LOW' THEN 4
                        ELSE 5 
                    END,
                    c.cvss2_base_score DESC
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
                            severity=record["severity"] or "UNKNOWN",
                            description=record["description"] or "",
                            cwe_id=record["cwe_id"],
                            cvss_score=record["cvss_score"],
                            fix_hash="",  # 这些字段不是必须的，但需要为空字符串
                            repo_url="",
                            repo_name="",
                            programming_language=record["programming_language"] or "unknown",
                            repository_stars=0,
                            vulnerability_pattern="",  # CVEfixes原始数据库中没有这个字段
                            fix_pattern="",  # CVEfixes原始数据库中没有这个字段
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
