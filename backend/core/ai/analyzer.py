"""
AI分析模块
使用大语言模型对高风险文件进行深度安全分析
支持与CVE知识库联动，自动生成diff和CVE关联
"""

import os
import json
import asyncio
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import openai
from core.rag.cve_knowledge_base import CVEfixesKnowledgeBase

logger = logging.getLogger(__name__)


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
    """AI分析器，支持CVE知识库增强"""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = "deepseek-coder",
    ):
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        self.base_url = base_url or os.getenv(
            "DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"
        )
        self.model = model

        if not self.api_key:
            raise ValueError("AI API密钥未配置")

        # 配置OpenAI客户端（兼容DeepSeek API）
        self.client = openai.OpenAI(api_key=self.api_key, base_url=self.base_url)

        # 初始化CVE知识库
        self.cve_kb = CVEfixesKnowledgeBase()

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

        # CVE增强分析：对发现的漏洞进行CVE关联和diff生成
        enhanced_results = await self._enhance_with_cve_knowledge(results)

        return enhanced_results

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
            response = self.client.chat.completions.create(
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

            return response.choices[0].message.content or ""

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
                    overall_risk=file_data.get("overall_risk", "medium"),
                    summary=file_data.get("summary", ""),
                    analysis_time=0.0,  # 这里可以计算实际分析时间
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
                    overall_risk=data.get("overall_risk", "medium"),
                    summary=data.get("summary", "降级分析结果"),
                    analysis_time=0.0,
                )

        except Exception as e:
            logger.error(f"单文件降级分析失败: {e}")

        return None

    async def _enhance_with_cve_knowledge(
        self, analysis_results: List[AIAnalysisResult]
    ) -> List[AIAnalysisResult]:
        """
        使用CVE知识库增强分析结果
        自动为发现的漏洞关联CVE和生成修复diff
        """
        enhanced_results = []

        for result in analysis_results:
            enhanced_result = result

            # 对每个漏洞进行CVE知识库检索
            if result.vulnerabilities:
                enhanced_vulnerabilities = []

                for vuln in result.vulnerabilities:
                    try:
                        # 检索相似的CVE修复案例
                        similar_cves = self.cve_kb.search_similar_vulnerabilities(
                            vulnerability_description=vuln.description,
                            code_snippet=vuln.code_snippet,
                            language=self._extract_language_from_path(result.file_path),
                            severity=vuln.severity,
                            limit=3,
                        )

                        # 创建增强后的漏洞对象（保持原有字段不变）
                        enhanced_vuln = VulnerabilityInfo(
                            title=vuln.title,
                            severity=vuln.severity,
                            cwe_id=vuln.cwe_id,
                            description=vuln.description,
                            location=vuln.location,
                            code_snippet=vuln.code_snippet,
                            impact=vuln.impact,
                            remediation=vuln.remediation,
                            confidence=vuln.confidence,
                        )

                        # 如果找到相关CVE，生成增强的修复建议
                        if similar_cves:
                            enhanced_remediation = (
                                await self._generate_enhanced_remediation(
                                    vuln.__dict__, similar_cves, result.file_path
                                )
                            )
                            # 更新修复建议（确保类型一致）
                            if isinstance(enhanced_remediation, str):
                                enhanced_vuln.remediation = enhanced_remediation

                        enhanced_vulnerabilities.append(enhanced_vuln)

                    except Exception as e:
                        logger.warning(f"CVE增强分析失败 {result.file_path}: {e}")
                        enhanced_vulnerabilities.append(vuln)

                enhanced_result.vulnerabilities = enhanced_vulnerabilities

            enhanced_results.append(enhanced_result)

        return enhanced_results

    async def _generate_enhanced_remediation(
        self,
        vulnerability: Dict[str, Any],
        similar_cves: List[Dict[str, Any]],
        file_path: str,
    ) -> Dict[str, Any]:
        """
        基于CVE知识库生成增强的修复建议
        包含diff和CVE链接
        """
        try:
            # 构建CVE上下文信息
            cve_context = self._build_cve_context(similar_cves)

            # 生成增强修复提示词
            prompt = f"""
作为一个资深的代码安全专家，基于以下CVE修复案例和当前发现的漏洞，生成具体的修复建议。

当前漏洞信息:
- 类型: {vulnerability.get("title", "")}
- 严重程度: {vulnerability.get("severity", "")}
- CWE: {vulnerability.get("cwe_id", "")}
- 描述: {vulnerability.get("description", "")}
- 代码片段:
```
{vulnerability.get("code_snippet", "")}
```

相关CVE修复案例:
{cve_context}

请基于这些CVE修复模式，生成以下内容:

1. 具体的修复diff（展示修改前后的代码）
2. 修复步骤说明
3. 最相关的CVE链接
4. 修复验证方法

请按照以下JSON格式输出:
{{
    "fix_diff": {{
        "before": "修改前的代码",
        "after": "修改后的代码", 
        "explanation": "修改说明"
    }},
    "fix_steps": [
        "步骤1: ...",
        "步骤2: ..."
    ],
    "most_relevant_cve": "CVE-XXXX-XXXX",
    "cve_link": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-XXXX-XXXX",
    "verification_method": "验证修复的方法"
}}
"""

            # 调用AI生成增强修复建议
            response = await self._call_ai_api(prompt)

            # 解析响应
            json_start = response.find("{")
            json_end = response.rfind("}") + 1

            if json_start != -1 and json_end > json_start:
                json_str = response[json_start:json_end]
                enhanced_remediation = json.loads(json_str)
                return enhanced_remediation
            else:
                logger.warning(f"CVE增强修复建议解析失败: {file_path}")
                return {"error": "解析失败"}

        except Exception as e:
            logger.error(f"生成CVE增强修复建议失败: {e}")
            return {"error": str(e)}

    def _build_cve_context(self, similar_cves: List[Dict[str, Any]]) -> str:
        """构建CVE上下文信息"""
        context_parts = []

        for i, cve in enumerate(similar_cves[:3], 1):  # 只使用前3个最相关的CVE
            context_parts.append(f"""
CVE案例 {i}: {cve.get("cve_id", "Unknown")}
- 严重程度: {cve.get("severity", "Unknown")}  
- CWE: {cve.get("cwe_id", "Unknown")}
- 修复模式: {cve.get("fix_pattern", "No pattern available")}
- 修复示例:
  修改前: {cve.get("vulnerability_pattern", "No example available")}
  修改后: {cve.get("fix_pattern", "No fix available")}
""")

        return "\n".join(context_parts)

    def _extract_language_from_path(self, file_path: str) -> str:
        """从文件路径提取编程语言"""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".java": "java",
            ".c": "c",
            ".cpp": "cpp",
            ".php": "php",
            ".go": "go",
            ".rs": "rust",
        }

        ext = os.path.splitext(file_path)[1].lower()
        return ext_map.get(ext, "unknown")

    # === 三阶段AI分析核心方法 ===

    async def analyze_files_three_stage(
        self, file_inputs: List[FileAnalysisInput], risk_threshold: float = 70.0
    ) -> Dict[str, Any]:
        """
        严格的三阶段AI分析流程：
        1. 批量AI分析所有文件，打分筛选高危文件
        2. 对高危文件进行AI详细分析，输出漏洞和修复描述
        3. 用CVEfixes知识库检索相关修复案例，结合AI生成最终diff和CVE关联

        Args:
            file_inputs: 文件分析输入列表
            risk_threshold: 高危文件阈值分数 (0-100)

        Returns:
            Dict包含各阶段分析结果
        """
        analysis_start_time = asyncio.get_event_loop().time()

        logger.info(f"开始三阶段AI分析，共{len(file_inputs)}个文件")

        # === 第一阶段：批量风险评估 ===
        logger.info("第一阶段：批量风险评估")
        stage1_results = await self._stage1_batch_risk_assessment(file_inputs)

        # 筛选高危文件
        high_risk_files = [
            result
            for result in stage1_results
            if result.ai_risk_score >= risk_threshold
        ]

        logger.info(f"第一阶段完成，发现{len(high_risk_files)}个高危文件")

        # === 第二阶段：高危文件详细分析 ===
        logger.info("第二阶段：高危文件详细分析")
        stage2_results = []
        if high_risk_files:
            stage2_results = await self._stage2_detailed_vulnerability_analysis(
                [
                    fi
                    for fi in file_inputs
                    if any(hr.file_path == fi.file_path for hr in high_risk_files)
                ]
            )

        logger.info(f"第二阶段完成，详细分析了{len(stage2_results)}个高危文件")

        # === 第三阶段：CVE知识库增强和diff生成 ===
        logger.info("第三阶段：CVE知识库增强和diff生成")
        stage3_results = []
        if stage2_results:
            stage3_results = await self._stage3_cve_enhanced_diff_generation(
                stage2_results
            )

        logger.info(f"第三阶段完成，生成了{len(stage3_results)}个CVE增强结果")

        analysis_end_time = asyncio.get_event_loop().time()
        total_analysis_time = analysis_end_time - analysis_start_time

        return {
            "stage1_risk_assessment": stage1_results,
            "stage2_detailed_analysis": stage2_results,
            "stage3_cve_enhanced": stage3_results,
            "high_risk_files_count": len(high_risk_files),
            "total_files_count": len(file_inputs),
            "risk_threshold": risk_threshold,
            "total_analysis_time": total_analysis_time,
            "summary": {
                "total_files": len(file_inputs),
                "high_risk_files": len(high_risk_files),
                "vulnerabilities_found": sum(
                    len(r.vulnerabilities) for r in stage3_results
                ),
                "cve_references": sum(1 for r in stage3_results if r.vulnerabilities),
                "analysis_time": total_analysis_time,
            },
        }

    async def _stage1_batch_risk_assessment(
        self, file_inputs: List[FileAnalysisInput]
    ) -> List[AIAnalysisResult]:
        """第一阶段：批量风险评估，快速打分筛选"""

        # 构建专门的风险评估提示词
        risk_assessment_prompt = self._build_risk_assessment_prompt(file_inputs)

        try:
            # 调用AI进行批量风险评估
            response = await self._call_ai_api(risk_assessment_prompt)

            # 解析风险评估结果
            return self._parse_risk_assessment_response(response, file_inputs)

        except Exception as e:
            logger.error(f"第一阶段风险评估失败: {e}")
            # 降级：为所有文件分配默认风险分数
            return [
                AIAnalysisResult(
                    file_path=fi.file_path,
                    ai_risk_score=50.0,  # 默认中等风险
                    vulnerabilities=[],
                    fix_suggestions=[],
                    confidence=0.3,
                    analysis_reasoning="风险评估失败，使用默认分数",
                    overall_risk="medium",
                    summary="风险评估阶段失败",
                    analysis_time=0.0,
                )
                for fi in file_inputs
            ]

    async def _stage2_detailed_vulnerability_analysis(
        self, high_risk_files: List[FileAnalysisInput]
    ) -> List[AIAnalysisResult]:
        """第二阶段：对高危文件进行详细的漏洞分析"""

        detailed_results = []

        # 对每个高危文件进行详细分析
        for file_input in high_risk_files:
            try:
                result = await self._analyze_single_file_detailed(file_input)
                if result:
                    detailed_results.append(result)

                # 添加分析间隔，避免API限流
                await asyncio.sleep(0.5)

            except Exception as e:
                logger.error(f"详细分析文件失败 {file_input.file_path}: {e}")

        return detailed_results

    async def _stage3_cve_enhanced_diff_generation(
        self, detailed_results: List[AIAnalysisResult]
    ) -> List[AIAnalysisResult]:
        """第三阶段：CVE知识库增强和diff生成"""

        enhanced_results = []

        for result in detailed_results:
            try:
                # 对每个发现漏洞的文件进行CVE增强
                if result.vulnerabilities:
                    enhanced_result = await self._enhance_with_cve_and_generate_diff(
                        result
                    )
                    enhanced_results.append(enhanced_result)
                else:
                    enhanced_results.append(result)

            except Exception as e:
                logger.error(f"CVE增强失败 {result.file_path}: {e}")
                enhanced_results.append(result)

        return enhanced_results

    def _build_risk_assessment_prompt(
        self, file_inputs: List[FileAnalysisInput]
    ) -> str:
        """构建第一阶段风险评估提示词"""

        prompt = """作为代码安全专家，请对以下文件进行快速风险评估打分。

重点关注：
1. AST分析发现的复杂度和危险函数调用
2. Git历史中的修复模式和频繁变更
3. 静态分析发现的潜在问题
4. 文件类型和代码特征

为每个文件打分(0-100)，分数越高表示安全风险越大。

"""

        # 添加每个文件的简要信息
        for i, file_input in enumerate(file_inputs[:10], 1):  # 限制数量避免token过多
            prompt += f"""
文件{i}: {file_input.file_path}
- 语言: {file_input.language}
- Git修改次数: {len(file_input.git_commits)}
- Fix相关提交: {len(self._extract_fix_commits(file_input.git_commits))}
- 代码复杂度: {file_input.ast_features.get("complexity", 0)}
- 静态问题数: {len(file_input.existing_issues)}
- 文件大小: {len(file_input.content)} 字符
"""

        prompt += """
请按以下JSON格式输出风险评分：
{
    "risk_scores": [
        {
            "file_path": "文件路径",
            "risk_score": 85.5,
            "confidence": 0.9,
            "risk_reasoning": "发现多个高风险函数调用和频繁的安全修复历史",
            "overall_risk": "high"
        }
    ]
}

请确保风险评分准确，重点识别可能存在安全漏洞的文件。
"""

        return prompt

    def _parse_risk_assessment_response(
        self, response: str, file_inputs: List[FileAnalysisInput]
    ) -> List[AIAnalysisResult]:
        """解析风险评估响应"""

        try:
            # 提取JSON部分
            json_start = response.find("{")
            json_end = response.rfind("}") + 1

            if json_start != -1 and json_end > json_start:
                data = json.loads(response[json_start:json_end])
                risk_scores = data.get("risk_scores", [])

                results = []
                file_path_map = {fi.file_path: fi for fi in file_inputs}

                for score_data in risk_scores:
                    file_path = score_data.get("file_path", "")
                    if file_path in file_path_map:
                        result = AIAnalysisResult(
                            file_path=file_path,
                            ai_risk_score=float(score_data.get("risk_score", 50.0)),
                            vulnerabilities=[],
                            fix_suggestions=[],
                            confidence=float(score_data.get("confidence", 0.5)),
                            analysis_reasoning=score_data.get("risk_reasoning", ""),
                            overall_risk=score_data.get("overall_risk", "medium"),
                            summary="风险评估阶段",
                            analysis_time=0.0,
                        )
                        results.append(result)

                # 为未包含在响应中的文件添加默认分数
                responded_paths = {r.file_path for r in results}
                for file_input in file_inputs:
                    if file_input.file_path not in responded_paths:
                        results.append(
                            AIAnalysisResult(
                                file_path=file_input.file_path,
                                ai_risk_score=30.0,  # 默认低风险
                                vulnerabilities=[],
                                fix_suggestions=[],
                                confidence=0.3,
                                analysis_reasoning="未在AI响应中包含",
                                overall_risk="low",
                                summary="默认风险评估",
                                analysis_time=0.0,
                            )
                        )

                return results

        except json.JSONDecodeError as e:
            logger.error(f"风险评估响应JSON解析失败: {e}")

        # 降级处理：返回默认分数
        return [
            AIAnalysisResult(
                file_path=fi.file_path,
                ai_risk_score=40.0,
                vulnerabilities=[],
                fix_suggestions=[],
                confidence=0.2,
                analysis_reasoning="风险评估解析失败",
                overall_risk="medium",
                summary="解析失败的默认评估",
                analysis_time=0.0,
            )
            for fi in file_inputs
        ]

    async def _analyze_single_file_detailed(
        self, file_input: FileAnalysisInput
    ) -> Optional[AIAnalysisResult]:
        """对单个文件进行详细的漏洞分析"""

        # 构建详细分析提示词
        detailed_prompt = self._build_detailed_analysis_prompt(file_input)

        try:
            response = await self._call_ai_api(detailed_prompt)
            return self._parse_detailed_analysis_response(response, file_input)

        except Exception as e:
            logger.error(f"详细分析失败 {file_input.file_path}: {e}")
            return None

    def _build_detailed_analysis_prompt(self, file_input: FileAnalysisInput) -> str:
        """构建详细漏洞分析提示词"""

        fix_commits = self._extract_fix_commits(file_input.git_commits)

        prompt = f"""作为资深代码安全专家，请深入分析以下高风险文件的安全漏洞。

文件路径: {file_input.file_path}
编程语言: {file_input.language}

代码内容:
```{file_input.language}
{file_input.content}
```

AST分析特征:
{json.dumps(file_input.ast_features, indent=2, ensure_ascii=False)}

静态分析问题:
{json.dumps(file_input.existing_issues, indent=2, ensure_ascii=False)}

Git修复历史:
{json.dumps(fix_commits, indent=2, ensure_ascii=False)}

请深入分析以下安全问题：
1. 注入漏洞（SQL注入、XSS、命令注入等）
2. 认证和授权缺陷
3. 敏感信息泄露
4. 缓冲区溢出和内存安全
5. 业务逻辑缺陷
6. 加密和随机数使用问题

输出格式要求：
{{
    "vulnerabilities": [
        {{
            "title": "具体漏洞标题",
            "severity": "critical|high|medium|low",
            "cwe_id": "CWE-XXX",
            "description": "详细的漏洞描述和成因分析",
            "location": {{
                "start_line": 行号,
                "end_line": 行号, 
                "function": "函数名"
            }},
            "code_snippet": "存在问题的代码片段",
            "impact": "安全影响和可能的攻击方式",
            "remediation": "具体的修复建议和代码示例",
            "confidence": 0.95
        }}
    ],
    "fix_suggestions": [
        {{
            "description": "修复措施描述",
            "original_code": "原始代码",
            "fixed_code": "修复后的代码",
            "start_line": 行号,
            "end_line": 行号,
            "explanation": "修复原理和实现说明"
        }}
    ],
    "overall_risk": "critical|high|medium|low",
    "summary": "整体安全评估总结"
}}

请确保分析深入准确，提供具体可行的修复方案。
"""

        return prompt

    def _parse_detailed_analysis_response(
        self, response: str, file_input: FileAnalysisInput
    ) -> Optional[AIAnalysisResult]:
        """解析详细分析响应"""

        try:
            # 提取JSON部分
            json_start = response.find("{")
            json_end = response.rfind("}") + 1

            if json_start != -1 and json_end > json_start:
                data = json.loads(response[json_start:json_end])

                # 解析漏洞信息
                vulnerabilities = []
                for vuln_data in data.get("vulnerabilities", []):
                    vuln = VulnerabilityInfo(
                        title=vuln_data.get("title", ""),
                        severity=vuln_data.get("severity", "medium"),
                        cwe_id=vuln_data.get("cwe_id"),
                        description=vuln_data.get("description", ""),
                        location=vuln_data.get("location", {}),
                        code_snippet=vuln_data.get("code_snippet", ""),
                        impact=vuln_data.get("impact", ""),
                        remediation=vuln_data.get("remediation", ""),
                        confidence=float(vuln_data.get("confidence", 0.5)),
                    )
                    vulnerabilities.append(vuln)

                # 解析修复建议
                fix_suggestions = []
                for fix_data in data.get("fix_suggestions", []):
                    fix = CodeFixSuggestion(
                        description=fix_data.get("description", ""),
                        original_code=fix_data.get("original_code", ""),
                        fixed_code=fix_data.get("fixed_code", ""),
                        start_line=int(fix_data.get("start_line", 0)),
                        end_line=int(fix_data.get("end_line", 0)),
                        explanation=fix_data.get("explanation", ""),
                    )
                    fix_suggestions.append(fix)

                return AIAnalysisResult(
                    file_path=file_input.file_path,
                    ai_risk_score=85.0,  # 高危文件的默认分数
                    vulnerabilities=vulnerabilities,
                    fix_suggestions=fix_suggestions,
                    confidence=0.8,
                    analysis_reasoning="详细漏洞分析",
                    overall_risk=data.get("overall_risk", "high"),
                    summary=data.get("summary", ""),
                    analysis_time=0.0,
                )

        except json.JSONDecodeError as e:
            logger.error(f"详细分析响应JSON解析失败: {e}")

        return None

    async def _enhance_with_cve_and_generate_diff(
        self, analysis_result: AIAnalysisResult
    ) -> AIAnalysisResult:
        """CVE知识库增强和diff生成"""

        enhanced_vulnerabilities = []

        for vuln in analysis_result.vulnerabilities:
            try:
                # 使用CVE知识库检索相关修复案例
                cve_context = self.cve_kb.generate_diff_context_for_ai(
                    vulnerability_description=vuln.description,
                    code_snippet=vuln.code_snippet,
                    language=self._extract_language_from_path(
                        analysis_result.file_path
                    ),
                )

                # 生成CVE增强的修复建议
                enhanced_remediation = await self._generate_cve_enhanced_remediation(
                    vuln, cve_context, analysis_result.file_path
                )

                # 创建增强后的漏洞信息
                enhanced_vuln = VulnerabilityInfo(
                    title=vuln.title,
                    severity=vuln.severity,
                    cwe_id=vuln.cwe_id,
                    description=vuln.description,
                    location=vuln.location,
                    code_snippet=vuln.code_snippet,
                    impact=vuln.impact,
                    remediation=enhanced_remediation,
                    confidence=vuln.confidence,
                )

                enhanced_vulnerabilities.append(enhanced_vuln)

            except Exception as e:
                logger.warning(f"CVE增强失败: {e}")
                enhanced_vulnerabilities.append(vuln)

        # 返回增强后的分析结果
        return AIAnalysisResult(
            file_path=analysis_result.file_path,
            ai_risk_score=analysis_result.ai_risk_score,
            vulnerabilities=enhanced_vulnerabilities,
            fix_suggestions=analysis_result.fix_suggestions,
            confidence=analysis_result.confidence,
            analysis_reasoning=analysis_result.analysis_reasoning + " [CVE增强]",
            overall_risk=analysis_result.overall_risk,
            summary=analysis_result.summary + " (已结合CVE知识库增强)",
            analysis_time=analysis_result.analysis_time,
        )

    async def _generate_cve_enhanced_remediation(
        self, vulnerability: VulnerabilityInfo, cve_context: str, file_path: str
    ) -> str:
        """生成CVE增强的修复建议"""

        prompt = f"""基于CVE修复案例知识库，为以下漏洞生成增强的修复建议和代码diff。

== 漏洞信息 ==
标题: {vulnerability.title}
类型: {vulnerability.cwe_id}
严重程度: {vulnerability.severity}
描述: {vulnerability.description}
问题代码:
```
{vulnerability.code_snippet}
```

== CVE知识库参考 ==
{cve_context}

== 文件信息 ==
文件路径: {file_path}
编程语言: {self._extract_language_from_path(file_path)}

请结合CVE修复案例，生成以下内容：
1. 详细的修复步骤和原理说明
2. 具体的代码修改diff
3. 相关的最佳实践建议
4. 如何验证修复效果

输出要求简洁实用，重点突出具体的代码修改。
"""

        try:
            response = await self._call_ai_api(prompt)
            return response
        except Exception as e:
            logger.error(f"生成CVE增强修复建议失败: {e}")
            return vulnerability.remediation  # 回退到原始修复建议

    # === 严格三阶段AI分析方法（按照用户需求重构）===

    async def analyze_files_strict_three_stage(
        self,
        file_inputs: List[FileAnalysisInput],
        stage1_batch_size: int = 10,
        risk_threshold: float = 70.0,
    ) -> Dict[str, Any]:
        """
        严格按照用户需求的三阶段AI分析：

        阶段1: 批量输入全部匹配文件 → AI风险打分 → 筛选高危文件
        阶段2: 对高危文件逐个进行AI详细分析 → 输出漏洞+修复描述+代码片段行号
        阶段3: 漏洞信息 + CVE知识库检索 → AI生成具体diff + CVE关联

        Args:
            file_inputs: 所有匹配到的文件列表
            stage1_batch_size: 第一阶段批量分析的每批文件数量
            risk_threshold: 高危文件风险阈值

        Returns:
            包含三个阶段完整结果的字典
        """
        logger.info(f"开始严格三阶段AI分析，共{len(file_inputs)}个文件")
        analysis_start_time = asyncio.get_event_loop().time()

        # === 第一阶段：批量风险评估打分 ===
        logger.info("=== 第一阶段：批量AI风险评估 ===")
        stage1_results = await self._stage1_batch_risk_scoring(
            file_inputs, stage1_batch_size
        )

        # 筛选高危文件（按风险分数排序）
        high_risk_files = [
            result
            for result in stage1_results
            if result.ai_risk_score >= risk_threshold
        ]
        high_risk_files.sort(key=lambda x: x.ai_risk_score, reverse=True)

        logger.info(
            f"第一阶段完成：{len(file_inputs)}个文件 → {len(high_risk_files)}个高危文件"
        )

        # === 第二阶段：高危文件详细漏洞分析 ===
        logger.info("=== 第二阶段：高危文件详细漏洞分析 ===")
        stage2_results = []

        if high_risk_files:
            # 获取高危文件的完整输入信息
            high_risk_inputs = [
                fi
                for fi in file_inputs
                if any(hr.file_path == fi.file_path for hr in high_risk_files)
            ]

            stage2_results = await self._stage2_detailed_vulnerability_analysis(
                high_risk_inputs
            )

        logger.info(f"第二阶段完成：详细分析了{len(stage2_results)}个高危文件")

        # === 第三阶段：CVE知识库增强 + diff生成 ===
        logger.info("=== 第三阶段：CVE知识库增强和diff生成 ===")
        stage3_results = []

        if stage2_results:
            stage3_results = await self._stage3_cve_enhanced_diff_generation(
                stage2_results
            )

        logger.info(f"第三阶段完成：生成了{len(stage3_results)}个CVE增强结果")

        # 计算总耗时
        analysis_end_time = asyncio.get_event_loop().time()
        total_time = analysis_end_time - analysis_start_time

        # 统计结果
        total_vulnerabilities = sum(len(r.vulnerabilities) for r in stage3_results)
        total_cve_links = sum(
            1
            for r in stage3_results
            for v in r.vulnerabilities
            if hasattr(v, "cve_id") and v.cve_id
        )

        return {
            "analysis_type": "strict_three_stage",
            "stage1_batch_risk_assessment": {
                "total_files": len(file_inputs),
                "high_risk_files": len(high_risk_files),
                "risk_threshold": risk_threshold,
                "results": stage1_results,
            },
            "stage2_detailed_vulnerability_analysis": {
                "analyzed_files": len(stage2_results),
                "results": stage2_results,
            },
            "stage3_cve_enhanced_diff_generation": {
                "enhanced_files": len(stage3_results),
                "results": stage3_results,
            },
            "summary": {
                "total_files_analyzed": len(file_inputs),
                "high_risk_files_found": len(high_risk_files),
                "vulnerabilities_discovered": total_vulnerabilities,
                "cve_references_generated": total_cve_links,
                "total_analysis_time": total_time,
                "average_time_per_file": total_time / len(file_inputs)
                if file_inputs
                else 0,
            },
        }

    async def _stage1_batch_risk_scoring(
        self, file_inputs: List[FileAnalysisInput], batch_size: int = 10
    ) -> List[AIAnalysisResult]:
        """
        第一阶段：批量风险评估打分

        将所有文件分批次输入AI，每批次包含多个文件的完整信息
        AI需要对每个文件给出0-100的风险评分
        """
        logger.info(f"第一阶段开始：批量风险评估，批次大小={batch_size}")

        all_results = []

        # 分批处理所有文件
        for i in range(0, len(file_inputs), batch_size):
            batch = file_inputs[i : i + batch_size]
            batch_num = i // batch_size + 1

            logger.info(f"处理第{batch_num}批次，包含{len(batch)}个文件")

            try:
                # 构建专门的第一阶段批量评分提示词
                prompt = self._build_stage1_batch_scoring_prompt(batch)

                # 调用AI进行批量风险评分
                response = await self._call_ai_api(prompt)

                # 解析批量评分结果
                batch_results = self._parse_stage1_scoring_response(response, batch)
                all_results.extend(batch_results)

                # 避免API限流
                if i + batch_size < len(file_inputs):
                    await asyncio.sleep(1)

            except Exception as e:
                logger.error(f"第一阶段批次{batch_num}失败: {e}")
                # 降级处理：给予默认分数
                for file_input in batch:
                    all_results.append(
                        AIAnalysisResult(
                            file_path=file_input.file_path,
                            ai_risk_score=50.0,  # 默认中等风险
                            vulnerabilities=[],
                            fix_suggestions=[],
                            confidence=0.3,
                            analysis_reasoning="第一阶段批量评分失败，使用默认分数",
                            overall_risk="medium",
                            summary="风险评分阶段异常",
                            analysis_time=0.0,
                        )
                    )

        logger.info(f"第一阶段完成：成功评估{len(all_results)}个文件")
        return all_results

    def _build_stage1_batch_scoring_prompt(self, batch: List[FileAnalysisInput]) -> str:
        """构建第一阶段专用的批量风险评分提示词"""

        prompt = """作为资深代码安全专家，请对以下文件进行快速风险评估打分。

你的任务是根据提供的信息为每个文件打0-100分的安全风险评分：
- 90-100分: 极高风险（存在明显的严重安全漏洞）
- 70-89分: 高风险（可能存在重要安全问题）  
- 50-69分: 中等风险（有一定安全隐患）
- 30-49分: 低风险（安全问题较少）
- 0-29分: 极低风险（基本无安全问题）

评分依据：
1. AST静态分析特征（复杂度、危险函数调用等）
2. Git历史修改模式（特别是fix类型的提交）
3. 已发现的静态分析安全问题
4. 代码内容的安全风险模式

"""

        # 添加每个文件的信息
        for i, file_input in enumerate(batch, 1):
            fix_commits = self._extract_fix_commits(file_input.git_commits)

            prompt += f"""
=== 文件{i}: {file_input.file_path} ===
编程语言: {file_input.language}
文件大小: {len(file_input.content)} 字符

AST分析特征:
{json.dumps(file_input.ast_features, indent=2, ensure_ascii=False)}

Git修改历史:
- 总修改次数: {len(file_input.git_commits)}
- Fix相关提交: {len(fix_commits)}
- Fix提交详情: {json.dumps(fix_commits[:3], indent=2, ensure_ascii=False)}

已发现的静态分析问题:
{json.dumps(file_input.existing_issues, indent=2, ensure_ascii=False)}

代码片段（前1000字符）:
```{file_input.language}
{file_input.content[:1000]}{"...(代码过长已截断)" if len(file_input.content) > 1000 else ""}
```

"""

        prompt += f"""
请按以下JSON格式输出所有{len(batch)}个文件的风险评分：

{{
    "batch_risk_scores": [
        {{
            "file_path": "文件路径",
            "risk_score": 85,
            "confidence": 0.9,
            "risk_reasoning": "发现SQL注入漏洞模式，且有多次安全修复历史",
            "risk_level": "high|medium|low"
        }}
    ]
}}

请确保为每个文件提供准确的风险评分和详细的评分理由。"""

        return prompt

    def _parse_stage1_scoring_response(
        self, response: str, batch: List[FileAnalysisInput]
    ) -> List[AIAnalysisResult]:
        """解析第一阶段评分响应"""

        try:
            # 提取JSON
            json_start = response.find("{")
            json_end = response.rfind("}") + 1

            if json_start != -1 and json_end > json_start:
                data = json.loads(response[json_start:json_end])
                scores = data.get("batch_risk_scores", [])

                results = []
                file_path_map = {fi.file_path: fi for fi in batch}

                for score_data in scores:
                    file_path = score_data.get("file_path", "")
                    if file_path in file_path_map:
                        result = AIAnalysisResult(
                            file_path=file_path,
                            ai_risk_score=float(score_data.get("risk_score", 50.0)),
                            vulnerabilities=[],  # 第一阶段不输出具体漏洞
                            fix_suggestions=[],  # 第一阶段不输出修复建议
                            confidence=float(score_data.get("confidence", 0.5)),
                            analysis_reasoning=score_data.get("risk_reasoning", ""),
                            overall_risk=score_data.get("risk_level", "medium"),
                            summary="第一阶段风险评分",
                            analysis_time=0.0,
                        )
                        results.append(result)

                # 为没有评分的文件添加默认结果
                scored_paths = {r.file_path for r in results}
                for file_input in batch:
                    if file_input.file_path not in scored_paths:
                        results.append(
                            AIAnalysisResult(
                                file_path=file_input.file_path,
                                ai_risk_score=40.0,
                                vulnerabilities=[],
                                fix_suggestions=[],
                                confidence=0.3,
                                analysis_reasoning="未在AI响应中找到评分",
                                overall_risk="medium",
                                summary="默认风险评分",
                                analysis_time=0.0,
                            )
                        )

                return results

        except Exception as e:
            logger.error(f"解析第一阶段评分响应失败: {e}")

        # 降级处理
        return [
            AIAnalysisResult(
                file_path=fi.file_path,
                ai_risk_score=45.0,
                vulnerabilities=[],
                fix_suggestions=[],
                confidence=0.2,
                analysis_reasoning="第一阶段响应解析失败",
                overall_risk="medium",
                summary="解析失败的默认评分",
                analysis_time=0.0,
            )
            for fi in batch
        ]

    # 保持现有的第二、三阶段方法，但确保它们的职责更清晰
