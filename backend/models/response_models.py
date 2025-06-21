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


class CVEReference(BaseModel):
    """CVE参考信息"""

    cve_id: str
    description: str
    severity: str
    cvss_score: Optional[float] = None
    url: Optional[str] = None
    fix_commit_url: Optional[str] = None


class CodeDiffBlock(BaseModel):
    """代码差异块"""

    description: str
    original_code: str
    fixed_code: str
    start_line: int
    end_line: int
    explanation: str


class VulnerabilityResponse(BaseModel):
    """漏洞响应模型"""

    title: str
    severity: str
    cwe_id: Optional[str]
    description: str
    file_path: str
    line_number: int
    confidence: float
    impact: Optional[str] = None
    remediation: Optional[str] = None
    code_snippet: Optional[str] = None
    cve_references: Optional[List[CVEReference]] = None
    fix_suggestions: Optional[List[CodeDiffBlock]] = None


class FileRiskResponse(BaseModel):
    """文件风险响应模型"""

    file_path: str
    risk_score: float
    language: str
    vulnerabilities_count: int
    lines_of_code: int


class HighRiskFileResponse(BaseModel):
    """高危文件详细响应模型"""

    file_path: str
    risk_score: float
    risk_level: str  # critical, high, medium, low
    language: str
    lines_of_code: int
    vulnerabilities: List[VulnerabilityResponse]
    ai_analysis_summary: Optional[str] = None
    confidence: Optional[float] = None
    analysis_reasoning: Optional[str] = None


class AnalysisResultResponse(BaseModel):
    """分析结果响应模型"""

    task_id: str
    repository_url: str
    status: str
    summary: Dict[str, Any]
    high_risk_files: List[HighRiskFileResponse]
    vulnerabilities: List[VulnerabilityResponse]
    created_at: datetime
    completed_at: Optional[datetime] = None
