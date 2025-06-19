"""
响应数据模型
"""

from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime


class AnalysisResponse(BaseModel):
    """分析响应模型"""

    task_id: str
    status: str  # started, running, completed, failed
    message: str
    created_at: Optional[datetime] = None


class ProgressResponse(BaseModel):
    """进度响应模型"""

    task_id: str
    status: str
    progress: int  # 0-100
    current_step: str
    message: str
    eta_minutes: Optional[int] = None


class VulnerabilityResponse(BaseModel):
    """漏洞响应模型"""

    title: str
    severity: str
    cwe_id: Optional[str]
    description: str
    file_path: str
    line_number: int
    confidence: float


class FileRiskResponse(BaseModel):
    """文件风险响应模型"""

    file_path: str
    risk_score: float
    language: str
    vulnerabilities_count: int
    lines_of_code: int


class AnalysisResultResponse(BaseModel):
    """分析结果响应模型"""

    task_id: str
    repository_url: str
    status: str
    summary: Dict[str, Any]
    high_risk_files: List[FileRiskResponse]
    vulnerabilities: List[VulnerabilityResponse]
    created_at: datetime
    completed_at: Optional[datetime] = None
