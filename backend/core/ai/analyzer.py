"""
AI分析模块
使用大语言模型对高风险文件进行深度安全分析
"""

import os
import json
import asyncio
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
import openai
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class VulnerabilityInfo:
    """漏洞信息"""

    title: str
    severity: str  # critical, high, medium, low
    cwe_id: Optional[str]
    description: str
    location: Dict[str, Any]  # 文件位置信息
    code_snippet: str
    impact: str
    remediation: str
    confidence: float  # 0-1 置信度


@dataclass
class CodeFixSuggestion:
    """代码修复建议"""

    description: str
    original_code: str
    fixed_code: str
    start_line: int
    end_line: int
    explanation: str


@dataclass
class AIAnalysisResult:
    """AI分析结果"""

    file_path: str
    vulnerabilities: List[VulnerabilityInfo]
    fix_suggestions: List[CodeFixSuggestion]
    overall_risk: str
    summary: str
    analysis_time: float


class AIAnalyzer:
    """AI分析器"""

    def __init__(
        self, api_key: str = None, base_url: str = None, model: str = "deepseek-coder"
    ):
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        self.base_url = base_url or os.getenv(
            "DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"
        )
        self.model = model

        if not self.api_key:
            raise ValueError("AI API密钥未配置")

        # 配置OpenAI客户端（兼容DeepSeek API）
        openai.api_key = self.api_key
        openai.api_base = self.base_url

        # 分析提示词模板
        self.vulnerability_analysis_prompt = """
作为一个资深的代码安全专家，请分析以下代码文件中的安全漏洞。

文件路径: {file_path}
编程语言: {language}
代码内容:
```{language}
{code_content}
```

静态分析发现的问题:
{static_issues}

Git历史信息:
- 总修改次数: {git_changes}
- 修复类提交: {fix_commits}

请按照以下JSON格式输出分析结果:
{{
    "vulnerabilities": [
        {{
            "title": "漏洞标题",
            "severity": "critical|high|medium|low",
            "cwe_id": "CWE-XXX",
            "description": "详细描述",
            "location": {{
                "start_line": 行号,
                "end_line": 行号,
                "function": "函数名"
            }},
            "code_snippet": "相关代码片段",
            "impact": "安全影响",
            "remediation": "修复建议",
            "confidence": 0.95
        }}
    ],
    "fix_suggestions": [
        {{
            "description": "修复描述",
            "original_code": "原始代码",
            "fixed_code": "修复后代码",
            "start_line": 行号,
            "end_line": 行号,
            "explanation": "修复说明"
        }}
    ],
    "overall_risk": "critical|high|medium|low",
    "summary": "整体安全评估总结"
}}

注意:
1. 重点关注注入漏洞、权限绕过、敏感信息泄露等安全问题
2. 考虑代码的实际执行上下文
3. 提供具体可行的修复建议
4. 置信度要求准确评估
"""

    async def analyze_high_risk_files(
        self, repo_path: str, file_analysis_results: List[Dict]
    ) -> List[AIAnalysisResult]:
        """
        对高风险文件进行AI分析

        Args:
            repo_path: 仓库路径
            file_analysis_results: 文件分析结果列表

        Returns:
            List[AIAnalysisResult]: AI分析结果列表
        """
        logger.info(f"开始AI分析，共{len(file_analysis_results)}个高风险文件")

        results = []

        # 限制并发数避免API限制
        semaphore = asyncio.Semaphore(3)

        async def analyze_single_file(file_result):
            async with semaphore:
                return await self._analyze_single_file(repo_path, file_result)

        # 并发分析
        tasks = [
            analyze_single_file(file_result) for file_result in file_analysis_results
        ]
        completed_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in completed_results:
            if isinstance(result, AIAnalysisResult):
                results.append(result)
            elif isinstance(result, Exception):
                logger.error(f"AI分析失败: {result}")

        logger.info(f"AI分析完成，成功分析{len(results)}个文件")
        return results

    async def _analyze_single_file(
        self, repo_path: str, file_result: Dict
    ) -> Optional[AIAnalysisResult]:
        """分析单个文件"""
        import time

        start_time = time.time()

        try:
            file_path = file_result["file_path"]
            language = file_result["language"]

            # 读取文件内容
            full_path = os.path.join(repo_path, file_path)
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                code_content = f.read()

            # 准备静态分析问题描述
            static_issues = self._format_static_issues(
                file_result.get("security_issues", [])
            )

            # 构建提示词
            prompt = self.vulnerability_analysis_prompt.format(
                file_path=file_path,
                language=language,
                code_content=code_content,
                static_issues=static_issues,
                git_changes=file_result.get("git_changes", 0),
                fix_commits=file_result.get("fix_commits", 0),
            )

            # 调用AI API
            response = await self._call_ai_api(prompt)

            if response:
                # 解析AI响应
                ai_result = self._parse_ai_response(response, file_path)
                ai_result.analysis_time = time.time() - start_time
                return ai_result

        except Exception as e:
            logger.error(f"分析文件失败 {file_result.get('file_path', 'unknown')}: {e}")

        return None

    def _format_static_issues(self, security_issues: List[Dict]) -> str:
        """格式化静态分析问题"""
        if not security_issues:
            return "无静态分析问题发现"

        formatted_issues = []
        for issue in security_issues:
            formatted_issues.append(
                f"- {issue.get('severity', 'unknown')} 级别: {issue.get('message', '')} "
                f"(行 {issue.get('line_number', 0)})"
            )

        return "\n".join(formatted_issues)

    async def _call_ai_api(self, prompt: str) -> Optional[str]:
        """调用AI API"""
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: openai.ChatCompletion.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": "你是一个专业的代码安全分析专家，专门识别和分析软件安全漏洞。",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.1,
                    max_tokens=4000,
                ),
            )

            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"AI API调用失败: {e}")
            return None

    def _parse_ai_response(self, response: str, file_path: str) -> AIAnalysisResult:
        """解析AI响应"""
        try:
            # 尝试提取JSON部分
            json_start = response.find("{")
            json_end = response.rfind("}") + 1

            if json_start != -1 and json_end > json_start:
                json_str = response[json_start:json_end]
                ai_data = json.loads(json_str)
            else:
                # 如果无法提取JSON，返回空结果
                ai_data = {
                    "vulnerabilities": [],
                    "fix_suggestions": [],
                    "overall_risk": "low",
                    "summary": "AI分析响应格式异常",
                }

            # 转换为数据类
            vulnerabilities = [
                VulnerabilityInfo(**vuln) for vuln in ai_data.get("vulnerabilities", [])
            ]

            fix_suggestions = [
                CodeFixSuggestion(**fix) for fix in ai_data.get("fix_suggestions", [])
            ]

            return AIAnalysisResult(
                file_path=file_path,
                vulnerabilities=vulnerabilities,
                fix_suggestions=fix_suggestions,
                overall_risk=ai_data.get("overall_risk", "unknown"),
                summary=ai_data.get("summary", ""),
                analysis_time=0.0,  # 将在外部设置
            )

        except json.JSONDecodeError as e:
            logger.error(f"解析AI响应JSON失败: {e}")
            return self._create_empty_result(file_path, "JSON解析失败")
        except Exception as e:
            logger.error(f"解析AI响应失败: {e}")
            return self._create_empty_result(file_path, f"解析失败: {str(e)}")

    def _create_empty_result(self, file_path: str, error_msg: str) -> AIAnalysisResult:
        """创建空的分析结果"""
        return AIAnalysisResult(
            file_path=file_path,
            vulnerabilities=[],
            fix_suggestions=[],
            overall_risk="unknown",
            summary=f"AI分析失败: {error_msg}",
            analysis_time=0.0,
        )

    def get_vulnerability_summary(
        self, results: List[AIAnalysisResult]
    ) -> Dict[str, Any]:
        """生成漏洞统计摘要"""
        summary = {
            "total_files": len(results),
            "total_vulnerabilities": 0,
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "cwe_distribution": {},
            "most_common_issues": [],
            "files_by_risk": {"critical": [], "high": [], "medium": [], "low": []},
        }

        all_vulnerabilities = []

        for result in results:
            # 统计文件风险等级
            summary["files_by_risk"][result.overall_risk].append(result.file_path)

            for vuln in result.vulnerabilities:
                all_vulnerabilities.append(vuln)
                summary["total_vulnerabilities"] += 1

                # 严重性统计
                summary["severity_breakdown"][vuln.severity] += 1

                # CWE统计
                if vuln.cwe_id:
                    summary["cwe_distribution"][vuln.cwe_id] = (
                        summary["cwe_distribution"].get(vuln.cwe_id, 0) + 1
                    )

        # 最常见的问题类型
        issue_types = {}
        for vuln in all_vulnerabilities:
            issue_types[vuln.title] = issue_types.get(vuln.title, 0) + 1

        summary["most_common_issues"] = sorted(
            issue_types.items(), key=lambda x: x[1], reverse=True
        )[:10]

        return summary

    def export_results(self, results: List[AIAnalysisResult], output_path: str) -> bool:
        """导出AI分析结果"""
        try:
            data = {
                "analysis_results": [asdict(result) for result in results],
                "summary": self.get_vulnerability_summary(results),
                "metadata": {
                    "analyzer": "CodeVigil AI Analyzer",
                    "model": self.model,
                    "total_files": len(results),
                },
            }

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            logger.info(f"AI分析结果已导出到: {output_path}")
            return True

        except Exception as e:
            logger.error(f"导出AI分析结果失败: {e}")
            return False
