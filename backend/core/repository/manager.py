"""
仓库处理模块
负责从GitHub等平台克隆仓库，过滤文件，提取基本信息
"""

import os
import shutil
import tempfile
from typing import List, Dict, Optional, Any
from pathlib import Path
import git
from git import Repo
import fnmatch
from dataclasses import dataclass
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class RepositoryInfo:
    """仓库信息"""

    url: str
    name: str
    local_path: str
    branch: str
    commit_hash: str
    total_files: int
    filtered_files: List[str]
    languages: Dict[str, int]
    size_mb: float


class RepositoryManager:
    """仓库管理器"""

    def __init__(self, temp_dir: str = "./data/temp"):
        self.temp_dir = Path(temp_dir)
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        # 默认过滤规则
        self.ignore_patterns = [
            "*.pyc",
            "*.pyo",
            "*.pyd",
            "__pycache__",
            "*.so",
            "*.dylib",
            "*.dll",
            "*.jpg",
            "*.jpeg",
            "*.png",
            "*.gif",
            "*.ico",
            "*.svg",
            "*.mp4",
            "*.avi",
            "*.mov",
            "*.wmv",
            "*.flv",
            "*.mp3",
            "*.wav",
            "*.flac",
            "*.aac",
            "*.zip",
            "*.tar",
            "*.gz",
            "*.rar",
            "*.7z",
            "*.pdf",
            "*.doc",
            "*.docx",
            "*.xls",
            "*.xlsx",
            "node_modules",
            ".git",
            ".svn",
            ".hg",
            "venv",
            "env",
            ".env",
            "virtualenv",
            "build",
            "dist",
            "target",
            "bin",
            "obj",
            "*.min.js",
            "*.min.css",
            ".DS_Store",
            "Thumbs.db",
            "*.log",
            "*.tmp",
            "*.temp",
        ]

        # 支持的编程语言文件扩展名
        self.language_extensions = {
            "Python": [".py", ".pyw", ".pyx", ".pyz"],
            "JavaScript": [".js", ".jsx", ".mjs"],
            "TypeScript": [".ts", ".tsx"],
            "Java": [".java"],
            "C": [".c", ".h"],
            "C++": [".cpp", ".cxx", ".cc", ".hpp", ".hxx"],
            "C#": [".cs"],
            "Go": [".go"],
            "Rust": [".rs"],
            "PHP": [".php", ".phtml"],
            "Ruby": [".rb"],
            "Swift": [".swift"],
            "Kotlin": [".kt", ".kts"],
            "Shell": [".sh", ".bash", ".zsh"],
            "SQL": [".sql"],
            "HTML": [".html", ".htm"],
            "CSS": [".css", ".scss", ".sass", ".less"],
            "XML": [".xml", ".xsl", ".xsd"],
            "JSON": [".json"],
            "YAML": [".yml", ".yaml"],
            "Dockerfile": ["Dockerfile"],
            "Makefile": ["Makefile", "makefile"],
        }

    async def clone_repository(
        self, repo_url: str, branch: Optional[str] = None, depth: Optional[int] = 100
    ) -> RepositoryInfo:
        """
        克隆Git仓库到临时目录

        Args:
            repo_url: 仓库URL
            branch: 指定分支，默认为主分支
            depth: 克隆深度，默认为1（仅最新提交）

        Returns:
            RepositoryInfo: 仓库信息
        """
        try:
            repo_name = self._extract_repo_name(repo_url)
            local_path = self.temp_dir / f"{repo_name}_{self._generate_temp_id()}"

            logger.info(f"开始克隆仓库: {repo_url} 到 {local_path}")

            # 克隆参数
            clone_kwargs = {"depth": depth, "single_branch": True, "no_checkout": False}

            if branch:
                clone_kwargs["branch"] = branch

            # 执行克隆
            repo = Repo.clone_from(repo_url, local_path, **clone_kwargs)

            # 获取仓库信息
            commit_hash = repo.head.commit.hexsha
            current_branch = repo.active_branch.name

            # 过滤文件
            filtered_files = self._filter_files(local_path)

            # 分析语言分布
            languages = self._analyze_languages(filtered_files)

            # 计算仓库大小
            size_mb = self._calculate_size(local_path)

            repo_info = RepositoryInfo(
                url=repo_url,
                name=repo_name,
                local_path=str(local_path),
                branch=current_branch,
                commit_hash=commit_hash,
                total_files=len(list(local_path.rglob("*"))),
                filtered_files=filtered_files,
                languages=languages,
                size_mb=size_mb,
            )

            logger.info(
                f"仓库克隆完成: {repo_name}, 过滤后文件数: {len(filtered_files)}"
            )
            return repo_info

        except Exception as e:
            logger.error(f"克隆仓库失败: {e}")
            raise

    def _extract_repo_name(self, repo_url: str) -> str:
        """从URL提取仓库名称"""
        return repo_url.rstrip("/").split("/")[-1].replace(".git", "")

    def _generate_temp_id(self) -> str:
        """生成临时目录唯一标识"""
        import time

        return str(int(time.time() * 1000))

    def _filter_files(self, repo_path: Path) -> List[str]:
        """
        根据规则过滤文件

        Args:
            repo_path: 仓库本地路径

        Returns:
            List[str]: 过滤后的文件路径列表
        """
        filtered_files = []

        for file_path in repo_path.rglob("*"):
            if file_path.is_file():
                relative_path = file_path.relative_to(repo_path)

                # 检查是否匹配忽略模式
                if self._should_ignore(str(relative_path)):
                    continue

                # 检查是否为支持的编程语言文件
                if self._is_source_file(file_path):
                    filtered_files.append(str(relative_path))

        return filtered_files

    def _should_ignore(self, file_path: str) -> bool:
        """检查文件是否应该被忽略"""
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(file_path, pattern) or pattern in file_path:
                return True
        return False

    def _is_source_file(self, file_path: Path) -> bool:
        """检查是否为源代码文件"""
        suffix = file_path.suffix.lower()
        name = file_path.name

        # 检查扩展名
        for extensions in self.language_extensions.values():
            if suffix in extensions or name in extensions:
                return True

        return False

    def _analyze_languages(self, file_paths: List[str]) -> Dict[str, int]:
        """分析语言分布"""
        languages = {}

        for file_path in file_paths:
            path = Path(file_path)
            suffix = path.suffix.lower()
            name = path.name

            for lang, extensions in self.language_extensions.items():
                if suffix in extensions or name in extensions:
                    languages[lang] = languages.get(lang, 0) + 1
                    break

        return languages

    def _calculate_size(self, path: Path) -> float:
        """计算目录大小（MB）"""
        total_size = 0
        for file_path in path.rglob("*"):
            if file_path.is_file():
                total_size += file_path.stat().st_size
        return total_size / (1024 * 1024)  # 转换为MB

    def cleanup_repository(self, repo_path: str) -> bool:
        """
        清理临时仓库目录

        Args:
            repo_path: 仓库本地路径

        Returns:
            bool: 清理是否成功
        """
        try:
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
                logger.info(f"已清理仓库目录: {repo_path}")
                return True
            return False
        except Exception as e:
            logger.error(f"清理仓库目录失败: {e}")
            return False

    def get_file_content(self, repo_path: str, file_path: str) -> Optional[str]:
        """
        获取文件内容

        Args:
            repo_path: 仓库本地路径
            file_path: 文件相对路径

        Returns:
            Optional[str]: 文件内容，读取失败返回None
        """
        try:
            full_path = Path(repo_path) / file_path
            if full_path.exists() and full_path.is_file():
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read()
        except Exception as e:
            logger.warning(f"读取文件失败 {file_path}: {e}")
        return None

    def get_git_file_history(self, repo_path: str, file_path: str) -> List[Dict]:
        """
        获取文件的Git历史记录

        Args:
            repo_path: 仓库本地路径
            file_path: 文件相对路径

        Returns:
            List[Dict]: Git提交历史
        """
        try:
            repo = Repo(repo_path)
            commits = list(repo.iter_commits(paths=file_path, max_count=50))

            history = []
            for commit in commits:
                history.append(
                    {
                        "hash": commit.hexsha,
                        "message": commit.message.strip(),
                        "author": str(commit.author),
                        "date": commit.committed_datetime.isoformat(),
                        "is_fix": self._is_fix_commit(commit.message),
                    }
                )

            return history
        except Exception as e:
            logger.warning(f"获取文件Git历史失败 {file_path}: {e}")
            return []

    def extract_file_git_history(
        self, repo_path: str, file_path: str
    ) -> List[Dict[str, Any]]:
        """
        提取文件的Git修改历史，特别关注fix相关的提交

        Args:
            repo_path: 仓库本地路径
            file_path: 相对于仓库根目录的文件路径

        Returns:
            包含提交信息的字典列表，重点标记fix相关提交
        """
        try:
            repo = git.Repo(repo_path)
            commits = list(repo.iter_commits(paths=file_path, max_count=50))

            commit_history = []
            fix_keywords = [
                "fix",
                "patch",
                "security",
                "vuln",
                "bug",
                "issue",
                "cve",
                "vulnerability",
                "exploit",
                "attack",
                "secure",
                "sanitize",
                "validate",
                "escape",
                "修复",
                "漏洞",
                "安全",
            ]

            for commit in commits:
                message = commit.message.lower().strip()

                # 检查是否为fix相关提交
                is_fix = any(keyword in message for keyword in fix_keywords)

                # 获取文件变更统计
                stats = commit.stats.files.get(
                    file_path, {"insertions": 0, "deletions": 0, "lines": 0}
                )

                commit_info = {
                    "hash": commit.hexsha[:8],  # 短hash更易读
                    "full_hash": commit.hexsha,
                    "message": commit.message.strip(),
                    "summary": commit.summary,  # 提交信息第一行
                    "author": str(commit.author.name),
                    "author_email": str(commit.author.email),
                    "date": commit.committed_datetime.isoformat(),
                    "timestamp": commit.committed_date,
                    "is_fix": is_fix,
                    "insertions": stats.get("insertions", 0),
                    "deletions": stats.get("deletions", 0),
                    "total_changes": stats.get("lines", 0),
                    "matched_keywords": [kw for kw in fix_keywords if kw in message]
                    if is_fix
                    else [],
                }

                commit_history.append(commit_info)

            logger.info(
                f"提取文件Git历史: {file_path}, 共{len(commit_history)}个提交, {sum(1 for c in commit_history if c['is_fix'])}个fix提交"
            )
            return commit_history

        except Exception as e:
            logger.warning(f"提取Git历史失败 {file_path}: {e}")
            return []

    def get_repository_git_stats(self, repo_path: str) -> Dict[str, Any]:
        """
        获取整个仓库的Git统计信息

        Args:
            repo_path: 仓库本地路径

        Returns:
            仓库的整体Git统计信息
        """
        try:
            repo = git.Repo(repo_path)

            # 获取最近的提交
            recent_commits = list(repo.iter_commits(max_count=100))

            # 统计fix相关提交
            fix_keywords = ["fix", "patch", "security", "vuln", "bug"]
            fix_commits = [
                c
                for c in recent_commits
                if any(keyword in c.message.lower() for keyword in fix_keywords)
            ]

            # 获取活跃贡献者
            authors = {}
            for commit in recent_commits:
                author = str(commit.author.name)
                authors[author] = authors.get(author, 0) + 1

            # 按月统计提交频率
            from collections import defaultdict
            import datetime

            monthly_commits = defaultdict(int)
            for commit in recent_commits:
                month_key = datetime.datetime.fromtimestamp(
                    commit.committed_date
                ).strftime("%Y-%m")
                monthly_commits[month_key] += 1

            return {
                "total_commits": len(recent_commits),
                "fix_commits": len(fix_commits),
                "fix_ratio": len(fix_commits) / len(recent_commits)
                if recent_commits
                else 0,
                "active_authors": len(authors),
                "top_contributors": sorted(
                    authors.items(), key=lambda x: x[1], reverse=True
                )[:5],
                "monthly_activity": dict(monthly_commits),
                "latest_commit": {
                    "hash": recent_commits[0].hexsha[:8],
                    "message": recent_commits[0].summary,
                    "date": recent_commits[0].committed_datetime.isoformat(),
                    "author": str(recent_commits[0].author.name),
                }
                if recent_commits
                else None,
            }

        except Exception as e:
            logger.error(f"获取仓库Git统计失败: {e}")
            return {
                "total_commits": 0,
                "fix_commits": 0,
                "fix_ratio": 0,
                "active_authors": 0,
                "top_contributors": [],
                "monthly_activity": {},
                "latest_commit": None,
            }
