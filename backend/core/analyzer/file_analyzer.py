"""
文件分析模块
负责对文件进行AST分析、安全扫描、Git历史分析等
"""

import ast
import os
import subprocess
import json
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
from utils.logger import get_logger
from core.security_rules import get_security_rule_engine

logger = get_logger(__name__)


@dataclass
class SecurityIssue:
    """安全问题"""

    severity: str  # high, medium, low
    rule_id: str
    message: str
    file_path: str
    line_number: int
    column: int
    code_snippet: str
    cwe_id: Optional[str] = None


@dataclass
class FileAnalysisResult:
    """文件分析结果"""

    file_path: str
    language: str
    lines_of_code: int
    complexity_score: float
    security_issues: List[SecurityIssue]
    git_changes: int
    fix_commits: int
    ast_features: Dict[str, Any]
    risk_score: float
    last_modified: str


class FileAnalyzer:
    """文件分析器"""

    def __init__(self):
        self.supported_languages = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".cpp": "cpp",
            ".c": "c",
            ".cs": "csharp",
            ".go": "go",
            ".php": "php",
            ".rb": "ruby",
        }

        # 风险评分权重
        self.risk_weights = {
            "security_issues": 0.4,
            "complexity": 0.2,
            "git_changes": 0.2,
            "fix_commits": 0.2,
        }

    async def analyze_files_batch(
        self,
        repo_path: str,
        file_paths: List[str],
        git_history: Dict[str, List[Dict]] = None,
    ) -> List[FileAnalysisResult]:
        """
        批量分析文件

        Args:
            repo_path: 仓库路径
            file_paths: 文件路径列表
            git_history: Git历史记录（可选）

        Returns:
            List[FileAnalysisResult]: 分析结果列表
        """
        results = []

        # 使用线程池并行分析
        with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            future_to_file = {
                executor.submit(
                    self._analyze_single_file,
                    repo_path,
                    file_path,
                    git_history.get(file_path, []) if git_history else [],
                ): file_path
                for file_path in file_paths
            }

            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.error(f"分析文件失败 {file_path}: {e}")

        logger.info(f"批量分析完成，共分析 {len(results)} 个文件")
        return results

    def _analyze_single_file(
        self, repo_path: str, file_path: str, git_commits: List[Dict]
    ) -> Optional[FileAnalysisResult]:
        """分析单个文件"""
        try:
            full_path = Path(repo_path) / file_path
            if not full_path.exists():
                return None

            # 读取文件内容
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # 确定语言
            language = self._detect_language(file_path)
            if not language:
                return None

            # 基础指标
            lines_of_code = len([line for line in content.split("\n") if line.strip()])

            # AST分析
            ast_features = self._analyze_ast(content, language)

            # 复杂度评分
            complexity_score = self._calculate_complexity(ast_features)

            # 安全扫描
            security_issues = self._scan_security_issues(
                str(full_path), content, language
            )

            # Git分析
            git_changes = len(git_commits)
            fix_commits = sum(
                1 for commit in git_commits if commit.get("is_fix", False)
            )

            # 风险评分
            risk_score = self._calculate_risk_score(
                security_issues, complexity_score, git_changes, fix_commits
            )

            # 获取最后修改时间
            last_modified = full_path.stat().st_mtime_ns

            return FileAnalysisResult(
                file_path=file_path,
                language=language,
                lines_of_code=lines_of_code,
                complexity_score=complexity_score,
                security_issues=security_issues,
                git_changes=git_changes,
                fix_commits=fix_commits,
                ast_features=ast_features,
                risk_score=risk_score,
                last_modified=str(last_modified),
            )

        except Exception as e:
            logger.error(f"分析文件失败 {file_path}: {e}")
            return None

    def _detect_language(self, file_path: str) -> Optional[str]:
        """检测文件语言"""
        suffix = Path(file_path).suffix.lower()
        return self.supported_languages.get(suffix)

    def _analyze_ast(self, content: str, language: str) -> Dict[str, Any]:
        """AST分析"""
        features = {
            "functions": 0,
            "classes": 0,
            "imports": 0,
            "loops": 0,
            "conditions": 0,
            "try_except": 0,
            "dangerous_functions": 0,
            "max_depth": 0,
        }

        if language == "python":
            features = self._analyze_python_ast(content)
        elif language in ["javascript", "typescript"]:
            features = self._analyze_js_features(content)
        # 可以扩展其他语言的AST分析

        return features

    def _analyze_python_ast(self, content: str) -> Dict[str, Any]:
        """Python AST分析"""
        features = {
            "functions": 0,
            "classes": 0,
            "imports": 0,
            "loops": 0,
            "conditions": 0,
            "try_except": 0,
            "dangerous_functions": 0,
            "max_depth": 0,
        }

        try:
            tree = ast.parse(content)

            class ASTVisitor(ast.NodeVisitor):
                def __init__(self):
                    self.depth = 0
                    self.max_depth = 0

                def visit(self, node):
                    self.depth += 1
                    self.max_depth = max(self.max_depth, self.depth)
                    super().visit(node)
                    self.depth -= 1

                def visit_FunctionDef(self, node):
                    features["functions"] += 1
                    self.generic_visit(node)

                def visit_AsyncFunctionDef(self, node):
                    features["functions"] += 1
                    self.generic_visit(node)

                def visit_ClassDef(self, node):
                    features["classes"] += 1
                    self.generic_visit(node)

                def visit_Import(self, node):
                    features["imports"] += 1
                    self.generic_visit(node)

                def visit_ImportFrom(self, node):
                    features["imports"] += 1
                    self.generic_visit(node)

                def visit_For(self, node):
                    features["loops"] += 1
                    self.generic_visit(node)

                def visit_While(self, node):
                    features["loops"] += 1
                    self.generic_visit(node)

                def visit_If(self, node):
                    features["conditions"] += 1
                    self.generic_visit(node)

                def visit_Try(self, node):
                    features["try_except"] += 1
                    self.generic_visit(node)

                def visit_Call(self, node):
                    # 检查危险函数调用
                    if hasattr(node.func, "id"):
                        func_name = node.func.id
                        dangerous_funcs = [
                            "eval",
                            "exec",
                            "compile",
                            "__import__",
                            "open",
                        ]
                        if func_name in dangerous_funcs:
                            features["dangerous_functions"] += 1
                    self.generic_visit(node)

            visitor = ASTVisitor()
            visitor.visit(tree)
            features["max_depth"] = visitor.max_depth

        except SyntaxError:
            logger.warning("Python语法错误，跳过AST分析")
        except Exception as e:
            logger.warning(f"AST分析失败: {e}")

        return features

    def _analyze_js_features(self, content: str) -> Dict[str, Any]:
        """JavaScript/TypeScript特征分析（简化版）"""
        features = {
            "functions": content.count("function ") + content.count("=> "),
            "classes": content.count("class "),
            "imports": content.count("import ") + content.count("require("),
            "loops": content.count("for ") + content.count("while "),
            "conditions": content.count("if "),
            "try_except": content.count("try "),
            "dangerous_functions": 0,
            "max_depth": 0,
        }

        # 检查危险函数
        dangerous_patterns = ["eval(", "Function(", "setTimeout(", "setInterval("]
        for pattern in dangerous_patterns:
            features["dangerous_functions"] += content.count(pattern)

        return features

    def _calculate_complexity(self, ast_features: Dict[str, Any]) -> float:
        """计算复杂度评分"""
        # 圈复杂度近似计算
        complexity = (
            ast_features.get("functions", 0) * 1
            + ast_features.get("classes", 0) * 2
            + ast_features.get("loops", 0) * 2
            + ast_features.get("conditions", 0) * 1
            + ast_features.get("try_except", 0) * 1
            + ast_features.get("max_depth", 0) * 0.5
        )

        # 标准化到0-100
        return min(complexity / 10.0 * 100, 100)

    def _scan_security_issues(
        self, file_path: str, content: str, language: str
    ) -> List[SecurityIssue]:
        """安全扫描 - 使用规则引擎"""
        security_engine = get_security_rule_engine()
        findings = security_engine.analyze_content(content, file_path)

        # 转换格式
        issues = []
        for finding in findings:
            issue = SecurityIssue(
                severity=finding["severity"],
                rule_id=finding["rule_id"],
                message=finding["description"],
                file_path=finding["file_path"],
                line_number=finding["line_number"],
                column=0,  # 规则引擎暂不提供列信息
                code_snippet=finding["matched_text"],
                cwe_id=finding.get("cwe_id"),
            )
            issues.append(issue)

        # 保留原有的Python和通用扫描作为补充
        if language == "python":
            issues.extend(self._scan_python_security_legacy(file_path, content))

        issues.extend(self._scan_common_patterns_legacy(file_path, content))

        return issues

    def _scan_python_security_legacy(
        self, file_path: str, content: str
    ) -> List[SecurityIssue]:
        """Python安全扫描 - 旧版规则作为补充"""
        issues = []
        lines = content.split("\n")

        # 简化的安全规则
        security_patterns = {
            "eval(": ("high", "B307", "使用eval()可能导致代码注入"),
            "exec(": ("high", "B102", "使用exec()可能导致代码注入"),
            "os.system(": ("high", "B605", "使用os.system()可能导致命令注入"),
            "subprocess.call(shell=True": (
                "medium",
                "B602",
                "subprocess调用使用shell=True存在风险",
            ),
            "pickle.loads(": ("medium", "B301", "使用pickle.loads()可能不安全"),
            "yaml.load(": ("medium", "B506", "使用yaml.load()可能不安全"),
            "input(": ("low", "B322", "使用input()在Python 2中可能不安全"),
        }

        for i, line in enumerate(lines, 1):
            for pattern, (severity, rule_id, message) in security_patterns.items():
                if pattern in line:
                    issues.append(
                        SecurityIssue(
                            severity=severity,
                            rule_id=rule_id,
                            message=message,
                            file_path=file_path,
                            line_number=i,
                            column=line.find(pattern),
                            code_snippet=line.strip(),
                        )
                    )

        return issues

    def _scan_common_patterns_legacy(
        self, file_path: str, content: str
    ) -> List[SecurityIssue]:
        """通用安全模式扫描 - 旧版规则作为补充"""
        """通用安全模式扫描"""
        issues = []
        lines = content.split("\n")

        # 通用危险模式
        patterns = {
            "password": ("low", "HARDCODED_PASSWORD", "可能包含硬编码密码"),
            "secret": ("low", "HARDCODED_SECRET", "可能包含硬编码密钥"),
            "api_key": ("medium", "HARDCODED_API_KEY", "可能包含硬编码API密钥"),
            "token": ("medium", "HARDCODED_TOKEN", "可能包含硬编码令牌"),
        }

        for i, line in enumerate(lines, 1):
            line_lower = line.lower()
            for pattern, (severity, rule_id, message) in patterns.items():
                if pattern in line_lower and "=" in line:
                    issues.append(
                        SecurityIssue(
                            severity=severity,
                            rule_id=rule_id,
                            message=message,
                            file_path=file_path,
                            line_number=i,
                            column=0,
                            code_snippet=line.strip(),
                        )
                    )

        return issues

    def _calculate_risk_score(
        self,
        security_issues: List[SecurityIssue],
        complexity_score: float,
        git_changes: int,
        fix_commits: int,
    ) -> float:
        """计算风险评分"""
        # 安全问题评分
        security_score = 0
        for issue in security_issues:
            if issue.severity == "high":
                security_score += 10
            elif issue.severity == "medium":
                security_score += 5
            elif issue.severity == "low":
                security_score += 2

        # 标准化评分
        security_score = min(security_score, 100)
        complexity_score = min(complexity_score, 100)
        git_score = min(git_changes * 2, 100)
        fix_score = min(fix_commits * 10, 100)

        # 加权计算最终风险评分
        risk_score = (
            security_score * self.risk_weights["security_issues"]
            + complexity_score * self.risk_weights["complexity"]
            + git_score * self.risk_weights["git_changes"]
            + fix_score * self.risk_weights["fix_commits"]
        )

        return round(risk_score, 2)

    def get_top_risk_files(
        self, analysis_results: List[FileAnalysisResult], top_k: int = 20
    ) -> List[FileAnalysisResult]:
        """获取风险评分最高的TOP-K文件"""
        return sorted(analysis_results, key=lambda x: x.risk_score, reverse=True)[
            :top_k
        ]

    def export_analysis_results(
        self, results: List[FileAnalysisResult], output_path: str
    ) -> bool:
        """导出分析结果为JSON"""
        try:
            data = [asdict(result) for result in results]
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"分析结果已导出到: {output_path}")
            return True
        except Exception as e:
            logger.error(f"导出分析结果失败: {e}")
            return False
