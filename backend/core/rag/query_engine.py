"""
RAG查询器 - 基于检索增强生成的安全分析
"""

from typing import List, Dict, Any, Optional
import re
from core.rag.knowledge_base import KnowledgeBaseManager, VulnerabilityKnowledge


class SecurityRAGQueryEngine:
    """安全RAG查询引擎"""

    def __init__(self, knowledge_base: KnowledgeBaseManager):
        self.kb = knowledge_base

    def analyze_code_pattern(
        self, code: str, language: str, file_path: str
    ) -> Dict[str, Any]:
        """分析代码模式并提供安全建议"""
        results = {
            "vulnerabilities": [],
            "recommendations": [],
            "risk_score": 0.0,
            "confidence": 0.0,
        }

        # 检测各种安全模式
        detected_patterns = self._detect_security_patterns(code, language)

        if not detected_patterns:
            return results

        total_risk = 0.0
        total_confidence = 0.0
        all_recommendations = []

        for pattern in detected_patterns:
            # 在知识库中搜索相关漏洞
            vulns = self.kb.search_vulnerabilities(
                query=pattern["type"], language=language, limit=3
            )

            if vulns:
                # 选择最匹配的漏洞
                best_match = self._find_best_match(pattern, vulns)

                if best_match:
                    vuln_info = {
                        "id": best_match.id,
                        "title": best_match.title,
                        "description": best_match.description,
                        "severity": best_match.severity,
                        "cwe_id": best_match.cwe_id,
                        "cvss_score": best_match.cvss_score,
                        "location": pattern["location"],
                        "code_snippet": pattern["code"],
                        "pattern_confidence": pattern["confidence"],
                    }

                    results["vulnerabilities"].append(vuln_info)

                    # 获取修复建议
                    recommendations = self.kb.get_recommendations(
                        pattern["type"],
                        language,
                        {"file_path": file_path, "code_context": pattern["code"]},
                    )

                    all_recommendations.extend(recommendations["recommendations"])

                    # 计算风险分数
                    severity_scores = {
                        "critical": 10.0,
                        "high": 7.5,
                        "medium": 5.0,
                        "low": 2.5,
                    }

                    risk_impact = severity_scores.get(best_match.severity, 2.5)
                    pattern_risk = risk_impact * pattern["confidence"]
                    total_risk += pattern_risk
                    total_confidence += pattern["confidence"]

        # 去重建议
        results["recommendations"] = list(set(all_recommendations))

        # 计算总体风险分数和置信度
        if detected_patterns:
            results["risk_score"] = min(10.0, total_risk / len(detected_patterns))
            results["confidence"] = total_confidence / len(detected_patterns)

        return results

    def _detect_security_patterns(
        self, code: str, language: str
    ) -> List[Dict[str, Any]]:
        """检测代码中的安全模式"""
        patterns = []

        # 定义安全模式规则
        security_rules = self._get_security_rules(language)

        lines = code.split("\n")

        for line_num, line in enumerate(lines, 1):
            for rule in security_rules:
                if re.search(rule["pattern"], line, re.IGNORECASE):
                    patterns.append(
                        {
                            "type": rule["type"],
                            "location": {"line": line_num, "column": 1},
                            "code": line.strip(),
                            "confidence": rule["confidence"],
                            "description": rule["description"],
                        }
                    )

        return patterns

    def _get_security_rules(self, language: str) -> List[Dict[str, Any]]:
        """获取针对特定语言的安全规则"""
        common_rules = [
            {
                "type": "硬编码敏感信息",
                "pattern": r"(password|pwd|secret|key|token|api_key)\s*=\s*[\"'][^\"']{8,}[\"']",
                "confidence": 0.8,
                "description": "检测到硬编码的敏感信息",
            },
            {
                "type": "弱密码策略",
                "pattern": r"password\s*=\s*[\"'](123|password|admin|root)[\"']",
                "confidence": 0.9,
                "description": "检测到弱密码",
            },
        ]

        language_rules = {
            "python": [
                {
                    "type": "SQL注入",
                    "pattern": r"(execute|cursor\.execute|query)\s*\(\s*[\"'].*%[s|d].*[\"']\s*%",
                    "confidence": 0.9,
                    "description": "可能存在SQL注入漏洞",
                },
                {
                    "type": "命令注入",
                    "pattern": r"(os\.system|subprocess\.call|exec|eval)\s*\(",
                    "confidence": 0.8,
                    "description": "可能存在命令注入漏洞",
                },
                {
                    "type": "反序列化漏洞",
                    "pattern": r"pickle\.loads?\s*\(",
                    "confidence": 0.7,
                    "description": "不安全的反序列化操作",
                },
            ],
            "javascript": [
                {
                    "type": "XSS跨站脚本",
                    "pattern": r"(innerHTML|outerHTML|document\.write)\s*=",
                    "confidence": 0.8,
                    "description": "可能存在XSS漏洞",
                },
                {
                    "type": "eval注入",
                    "pattern": r"eval\s*\(",
                    "confidence": 0.9,
                    "description": "危险的eval使用",
                },
            ],
            "java": [
                {
                    "type": "SQL注入",
                    "pattern": r"Statement.*executeQuery.*\+",
                    "confidence": 0.8,
                    "description": "可能存在SQL注入漏洞",
                },
                {
                    "type": "XXE漏洞",
                    "pattern": r"DocumentBuilderFactory|SAXParserFactory",
                    "confidence": 0.6,
                    "description": "可能存在XXE漏洞",
                },
            ],
            "php": [
                {
                    "type": "SQL注入",
                    "pattern": r"mysql_query.*\$_",
                    "confidence": 0.8,
                    "description": "可能存在SQL注入漏洞",
                },
                {
                    "type": "文件包含漏洞",
                    "pattern": r"(include|require).*\$_",
                    "confidence": 0.9,
                    "description": "可能存在文件包含漏洞",
                },
            ],
        }

        rules = common_rules.copy()
        if language.lower() in language_rules:
            rules.extend(language_rules[language.lower()])

        return rules

    def _find_best_match(
        self, pattern: Dict[str, Any], vulns: List[VulnerabilityKnowledge]
    ) -> Optional[VulnerabilityKnowledge]:
        """找到最匹配的漏洞知识"""
        if not vulns:
            return None

        # 简单的匹配算法：优先考虑严重性和标题相似度
        best_match = None
        best_score = 0.0

        for vuln in vulns:
            score = 0.0

            # 严重性权重
            severity_weights = {"critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.4}
            score += severity_weights.get(vuln.severity, 0.2)

            # 标题相似度（简单的关键词匹配）
            pattern_keywords = set(pattern["type"].lower().split())
            title_keywords = set(vuln.title.lower().split())

            if pattern_keywords & title_keywords:
                score += 0.5

            # 描述相似度
            if pattern["type"].lower() in vuln.description.lower():
                score += 0.3

            if score > best_score:
                best_score = score
                best_match = vuln

        return best_match

    def get_security_recommendations(
        self, analysis_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """基于分析结果获取综合安全建议"""
        all_vulns = []
        all_recommendations = set()
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        # 收集所有漏洞信息
        for result in analysis_results:
            all_vulns.extend(result.get("vulnerabilities", []))
            all_recommendations.update(result.get("recommendations", []))

        # 统计严重性分布
        for vuln in all_vulns:
            severity = vuln.get("severity", "low")
            if severity in severity_counts:
                severity_counts[severity] += 1

        # 计算总体风险分数
        total_risk = sum(
            result.get("risk_score", 0) * len(result.get("vulnerabilities", []))
            for result in analysis_results
        )

        total_vulns = sum(
            len(result.get("vulnerabilities", [])) for result in analysis_results
        )
        overall_risk = total_risk / total_vulns if total_vulns > 0 else 0

        # 生成优先修复建议
        priority_recommendations = self._generate_priority_recommendations(all_vulns)

        return {
            "overall_risk_score": round(overall_risk, 2),
            "vulnerability_count": total_vulns,
            "severity_distribution": severity_counts,
            "recommendations": list(all_recommendations),
            "priority_fixes": priority_recommendations,
            "security_score": max(0, 100 - (overall_risk * 10)),  # 安全评分
        }

    def _generate_priority_recommendations(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """生成优先修复建议"""
        priority_fixes = []

        # 按严重性分组
        critical_vulns = [v for v in vulnerabilities if v.get("severity") == "critical"]
        high_vulns = [v for v in vulnerabilities if v.get("severity") == "high"]

        if critical_vulns:
            priority_fixes.append(
                {
                    "priority": "极高",
                    "description": f"立即修复 {len(critical_vulns)} 个严重漏洞",
                    "actions": [
                        "停止部署到生产环境",
                        "立即修复SQL注入和命令注入漏洞",
                        "进行安全测试验证",
                    ],
                }
            )

        if high_vulns:
            priority_fixes.append(
                {
                    "priority": "高",
                    "description": f"在下个版本修复 {len(high_vulns)} 个高危漏洞",
                    "actions": ["制定修复计划", "进行代码审查", "增加安全测试用例"],
                }
            )

        return priority_fixes
