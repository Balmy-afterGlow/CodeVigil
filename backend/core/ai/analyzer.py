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
class FileAnalysisInput:
    """文件分析输入"""

    file_path: str
    content: str
    language: str
    git_commits: List[Dict[str, Any]]  # 包含fix关键字的提交信息
    ast_features: Dict[str, Any]  # AST分析特征
    existing_issues: List[Dict[str, Any]]  # 已发现的静态分析问题


@dataclass
class AIAnalysisResult:
    """AI分析结果"""

    file_path: str
    ai_risk_score: float  # AI评估的风险分数 (0-100)
    vulnerabilities: List[VulnerabilityInfo]
    fix_suggestions: List[CodeFixSuggestion]
    confidence: float  # 整体置信度
    analysis_reasoning: str  # AI分析推理过程
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

    async def analyze_files_batch(
        self, file_inputs: List[FileAnalysisInput], max_batch_size: int = 5
    ) -> List[AIAnalysisResult]:
        """
        批量分析多个文件，最大化token利用率

        Args:
            file_inputs: 文件分析输入列表
            max_batch_size: 单次批量分析的最大文件数

        Returns:
            List[AIAnalysisResult]: AI分析结果列表
        """
        results = []

        # 分批处理，避免单次请求token过多
        for i in range(0, len(file_inputs), max_batch_size):
            batch = file_inputs[i : i + max_batch_size]
            try:
                batch_results = await self._analyze_batch_internal(batch)
                results.extend(batch_results)

                # 添加延迟避免API限流
                if i + max_batch_size < len(file_inputs):
                    await asyncio.sleep(1)

            except Exception as e:
                logger.error(f"批量分析失败 (batch {i // max_batch_size + 1}): {e}")
                # 降级到单文件分析
                for file_input in batch:
                    try:
                        result = await self._analyze_single_file_fallback(file_input)
                        if result:
                            results.append(result)
                    except Exception as e2:
                        logger.error(f"单文件分析失败 {file_input.file_path}: {e2}")

        logger.info(f"AI批量分析完成，共分析 {len(results)} 个文件")
        return results

    async def _analyze_batch_internal(
        self, batch: List[FileAnalysisInput]
    ) -> List[AIAnalysisResult]:
        """内部批量分析方法"""

        # 构建批量分析提示词
        prompt = self._build_batch_analysis_prompt(batch)

        try:
            # 调用AI API
            response = await self._call_ai_api(prompt)

            # 解析批量结果
            return self._parse_batch_response(response, batch)

        except Exception as e:
            logger.error(f"AI API调用失败: {e}")
            raise

    def _build_batch_analysis_prompt(self, batch: List[FileAnalysisInput]) -> str:
        """构建批量分析提示词"""

        prompt = """作为一个资深的代码安全专家，请对以下多个文件进行安全风险评估和漏洞分析。

请综合考虑以下因素：
1. AST静态分析特征
2. Git历史修改情况（特别关注fix相关提交）
3. 代码内容的安全问题

对每个文件输出风险评分(0-100)和详细分析。

"""

        # 添加每个文件的信息
        for i, file_input in enumerate(batch, 1):
            prompt += f"""
=== 文件 {i}: {file_input.file_path} ===
编程语言: {file_input.language}

AST分析特征:
{json.dumps(file_input.ast_features, indent=2, ensure_ascii=False)}

Git历史信息:
- 修改次数: {len(file_input.git_commits)}
- Fix相关提交: {self._extract_fix_commits(file_input.git_commits)}

已发现的静态分析问题:
{json.dumps(file_input.existing_issues, indent=2, ensure_ascii=False)}

代码内容:
```{file_input.language}
{file_input.content[:2000]}{"...(代码过长，已截断)" if len(file_input.content) > 2000 else ""}
```

"""

        prompt += """
请按照以下JSON格式输出所有文件的分析结果:
{
    "files": [
        {
            "file_path": "文件路径",
            "ai_risk_score": 85.5,
            "confidence": 0.9,
            "analysis_reasoning": "基于AST分析发现该文件包含高风险函数调用...",
            "vulnerabilities": [
                {
                    "title": "SQL注入风险",
                    "severity": "high",
                    "cwe_id": "CWE-89",
                    "description": "详细描述",
                    "location": {
                        "start_line": 42,
                        "end_line": 45,
                        "function": "query_user"
                    },
                    "code_snippet": "代码片段",
                    "impact": "影响描述",
                    "remediation": "修复建议",
                    "confidence": 0.8
                }
            ],
            "fix_suggestions": [
                {
                    "description": "使用参数化查询",
                    "original_code": "原代码",
                    "fixed_code": "修复后代码",
                    "start_line": 42,
                    "end_line": 45,
                    "explanation": "详细解释"
                }
            ]
        }
    ]
}

请确保JSON格式正确，并为每个文件提供准确的风险评分。重点关注：
1. 函数复杂度和危险函数调用
2. Git历史中的修复模式
3. 静态分析发现的安全问题
4. 代码的整体质量和安全性
"""

        return prompt

    def _extract_fix_commits(
        self, git_commits: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """提取包含fix关键字的提交"""
        fix_keywords = ["fix", "bug", "patch", "security", "vulnerability", "cve"]
        fix_commits = []

        for commit in git_commits:
            message = commit.get("message", "").lower()
            if any(keyword in message for keyword in fix_keywords):
                fix_commits.append(
                    {
                        "hash": commit.get("hash", ""),
                        "message": commit.get("message", ""),
                        "date": commit.get("date", ""),
                        "author": commit.get("author", ""),
                    }
                )

        return fix_commits

    async def _call_ai_api(self, prompt: str) -> str:
        """调用AI API"""
        try:
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "你是一个专业的代码安全分析专家，擅长识别各种安全漏洞和风险模式。",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,  # 低温度确保结果稳定
                max_tokens=4000,
                timeout=60,
            )

            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"AI API调用失败: {e}")
            raise

    def _parse_batch_response(
        self, response: str, batch: List[FileAnalysisInput]
    ) -> List[AIAnalysisResult]:
        """解析批量响应结果"""
        try:
            # 提取JSON部分
            json_start = response.find("{")
            json_end = response.rfind("}") + 1

            if json_start == -1 or json_end == 0:
                raise ValueError("响应中未找到有效JSON")

            json_str = response[json_start:json_end]
            data = json.loads(json_str)

            results = []
            files_data = data.get("files", [])

            for file_data in files_data:
                # 构建漏洞信息
                vulnerabilities = []
                for vuln_data in file_data.get("vulnerabilities", []):
                    vulnerability = VulnerabilityInfo(
                        title=vuln_data.get("title", ""),
                        severity=vuln_data.get("severity", "medium"),
                        cwe_id=vuln_data.get("cwe_id"),
                        description=vuln_data.get("description", ""),
                        location=vuln_data.get("location", {}),
                        code_snippet=vuln_data.get("code_snippet", ""),
                        impact=vuln_data.get("impact", ""),
                        remediation=vuln_data.get("remediation", ""),
                        confidence=vuln_data.get("confidence", 0.5),
                    )
                    vulnerabilities.append(vulnerability)

                # 构建修复建议
                fix_suggestions = []
                for fix_data in file_data.get("fix_suggestions", []):
                    suggestion = CodeFixSuggestion(
                        description=fix_data.get("description", ""),
                        original_code=fix_data.get("original_code", ""),
                        fixed_code=fix_data.get("fixed_code", ""),
                        start_line=fix_data.get("start_line", 0),
                        end_line=fix_data.get("end_line", 0),
                        explanation=fix_data.get("explanation", ""),
                    )
                    fix_suggestions.append(suggestion)

                # 构建分析结果
                result = AIAnalysisResult(
                    file_path=file_data.get("file_path", ""),
                    ai_risk_score=file_data.get("ai_risk_score", 0.0),
                    vulnerabilities=vulnerabilities,
                    fix_suggestions=fix_suggestions,
                    confidence=file_data.get("confidence", 0.5),
                    analysis_reasoning=file_data.get("analysis_reasoning", ""),
                )
                results.append(result)

            return results

        except json.JSONDecodeError as e:
            logger.error(f"JSON解析失败: {e}")
            logger.error(f"响应内容: {response}")
            raise ValueError(f"AI响应JSON格式错误: {e}")
        except Exception as e:
            logger.error(f"解析批量响应失败: {e}")
            raise

    async def _analyze_single_file_fallback(
        self, file_input: FileAnalysisInput
    ) -> Optional[AIAnalysisResult]:
        """单文件分析降级方案"""
        try:
            # 简化的单文件分析
            simple_prompt = f"""
分析文件: {file_input.file_path}
语言: {file_input.language}

请给出0-100的风险评分和简要分析。

代码片段:
```{file_input.language}
{file_input.content[:1000]}
```

JSON格式输出:
{{
    "ai_risk_score": 分数,
    "confidence": 置信度,
    "analysis_reasoning": "分析原因"
}}
"""

            response = await self._call_ai_api(simple_prompt)

            # 简单解析
            json_start = response.find("{")
            json_end = response.rfind("}") + 1

            if json_start != -1 and json_end > json_start:
                data = json.loads(response[json_start:json_end])
                return AIAnalysisResult(
                    file_path=file_input.file_path,
                    ai_risk_score=data.get("ai_risk_score", 50.0),
                    vulnerabilities=[],
                    fix_suggestions=[],
                    confidence=data.get("confidence", 0.3),
                    analysis_reasoning=data.get("analysis_reasoning", "降级分析"),
                )

        except Exception as e:
            logger.error(f"单文件降级分析失败: {e}")

        return None

    # 向后兼容的旧接口
    async def analyze_high_risk_files(
        self, repo_path: str, file_analysis_results: List[Dict]
    ) -> List[AIAnalysisResult]:
        """
        向后兼容接口：使用新的批量分析方法
        """
        # 转换为新的输入格式
        file_inputs = []
        for file_result in file_analysis_results:
            try:
                # 读取文件内容
                full_path = os.path.join(repo_path, file_result["file_path"])
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                file_input = FileAnalysisInput(
                    file_path=file_result["file_path"],
                    content=content,
                    language=file_result.get("language", "unknown"),
                    git_commits=file_result.get("git_commits", []),
                    ast_features=file_result.get("ast_features", {}),
                    existing_issues=[
                        {
                            "severity": issue.severity,
                            "rule_id": issue.rule_id,
                            "message": issue.message,
                            "line_number": issue.line_number,
                        }
                        for issue in file_result.get("security_issues", [])
                    ],
                )
                file_inputs.append(file_input)
            except Exception as e:
                logger.error(
                    f"转换文件输入失败 {file_result.get('file_path', 'unknown')}: {e}"
                )

        # 使用新的批量分析方法
        return await self.analyze_files_batch(file_inputs)
