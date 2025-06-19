"""
请求数据模型
"""

from pydantic import BaseModel, HttpUrl
from typing import Optional, Dict, Any, List


class RepositoryUrl(BaseModel):
    """仓库URL模型"""

    url: HttpUrl
    branch: Optional[str] = None


class AnalysisOptions(BaseModel):
    """分析选项"""

    enable_ai_analysis: bool = True
    max_files_to_analyze: int = 50
    include_low_risk: bool = False
    analysis_depth: str = "normal"  # light, normal, deep


class AnalysisRequest(BaseModel):
    """分析请求模型"""

    repository_url: str
    branch: Optional[str] = None
    analysis_options: Optional[AnalysisOptions] = None


class FileAnalysisRequest(BaseModel):
    """单文件分析请求"""

    file_path: str
    content: str
    language: str
