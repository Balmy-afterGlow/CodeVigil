"""
安全规则库 - 定义各种安全检查规则
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class SeverityLevel(Enum):
    """严重性级别"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityRule:
    """安全规则"""

    rule_id: str
    name: str
    description: str
    severity: SeverityLevel
    pattern: str
    language: Optional[str] = None
    file_types: Optional[List[str]] = None
    category: str = "general"
    cwe_id: Optional[str] = None
    fix_suggestion: str = ""


class SecurityRuleEngine:
    """安全规则引擎"""

    def __init__(self):
        self.rules: List[SecurityRule] = []
        self._load_default_rules()

    def _load_default_rules(self):
        """加载默认安全规则"""
        # SQL注入规则
        self.rules.extend(
            [
                SecurityRule(
                    rule_id="SQL_INJECTION_001",
                    name="SQL注入风险",
                    description="检测可能的SQL注入漏洞",
                    severity=SeverityLevel.HIGH,
                    pattern=r"(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE).*\+.*['\"]",
                    language="python",
                    file_types=[".py"],
                    category="injection",
                    cwe_id="CWE-89",
                    fix_suggestion="使用参数化查询或ORM来避免SQL注入",
                ),
                SecurityRule(
                    rule_id="SQL_INJECTION_002",
                    name="字符串拼接SQL",
                    description="检测直接字符串拼接构造SQL的情况",
                    severity=SeverityLevel.CRITICAL,
                    pattern=r"['\"].*SELECT.*['\"].*\+.*['\"].*['\"]",
                    language="python",
                    file_types=[".py"],
                    category="injection",
                    cwe_id="CWE-89",
                    fix_suggestion="使用参数化查询替代字符串拼接",
                ),
            ]
        )

        # XSS规则
        self.rules.extend(
            [
                SecurityRule(
                    rule_id="XSS_001",
                    name="跨站脚本攻击风险",
                    description="检测可能的XSS漏洞",
                    severity=SeverityLevel.HIGH,
                    pattern=r"innerHTML\s*=\s*.*\+",
                    language="javascript",
                    file_types=[".js", ".jsx", ".ts", ".tsx"],
                    category="xss",
                    cwe_id="CWE-79",
                    fix_suggestion="使用textContent或安全的DOM操作方法",
                ),
                SecurityRule(
                    rule_id="XSS_002",
                    name="危险的HTML渲染",
                    description="检测直接渲染用户输入到HTML的情况",
                    severity=SeverityLevel.CRITICAL,
                    pattern=r"dangerouslySetInnerHTML|v-html",
                    language="javascript",
                    file_types=[".js", ".jsx", ".ts", ".tsx", ".vue"],
                    category="xss",
                    cwe_id="CWE-79",
                    fix_suggestion="对用户输入进行适当的转义和验证",
                ),
            ]
        )

        # 身份验证和授权规则
        self.rules.extend(
            [
                SecurityRule(
                    rule_id="AUTH_001",
                    name="硬编码密码",
                    description="检测硬编码在代码中的密码",
                    severity=SeverityLevel.CRITICAL,
                    pattern=r"(password|passwd|pwd)\s*=\s*['\"][^'\"]{3,}['\"]",
                    category="authentication",
                    cwe_id="CWE-798",
                    fix_suggestion="使用环境变量或安全配置文件存储敏感信息",
                ),
                SecurityRule(
                    rule_id="AUTH_002",
                    name="硬编码API密钥",
                    description="检测硬编码的API密钥",
                    severity=SeverityLevel.CRITICAL,
                    pattern=r"(api_key|apikey|secret_key|access_token)\s*=\s*['\"][A-Za-z0-9_-]{20,}['\"]",
                    category="authentication",
                    cwe_id="CWE-798",
                    fix_suggestion="使用环境变量管理API密钥",
                ),
            ]
        )

        # 文件操作规则
        self.rules.extend(
            [
                SecurityRule(
                    rule_id="FILE_001",
                    name="路径遍历漏洞",
                    description="检测可能的路径遍历攻击",
                    severity=SeverityLevel.HIGH,
                    pattern=r"(open|file|read).*\.\./",
                    category="file_operation",
                    cwe_id="CWE-22",
                    fix_suggestion="验证和规范化文件路径，限制访问范围",
                ),
                SecurityRule(
                    rule_id="FILE_002",
                    name="不安全的文件上传",
                    description="检测缺乏验证的文件上传功能",
                    severity=SeverityLevel.MEDIUM,
                    pattern=r"\.save\(.*\)|upload.*\(.*\)",
                    category="file_operation",
                    cwe_id="CWE-434",
                    fix_suggestion="验证文件类型、大小和内容",
                ),
            ]
        )

        # 加密相关规则
        self.rules.extend(
            [
                SecurityRule(
                    rule_id="CRYPTO_001",
                    name="弱加密算法",
                    description="检测使用弱加密算法",
                    severity=SeverityLevel.MEDIUM,
                    pattern=r"(MD5|SHA1|DES|RC4)",
                    category="cryptography",
                    cwe_id="CWE-327",
                    fix_suggestion="使用更强的加密算法如AES、SHA-256等",
                ),
                SecurityRule(
                    rule_id="CRYPTO_002",
                    name="硬编码加密密钥",
                    description="检测硬编码的加密密钥",
                    severity=SeverityLevel.CRITICAL,
                    pattern=r"(key|secret)\s*=\s*['\"][A-Fa-f0-9]{16,}['\"]",
                    category="cryptography",
                    cwe_id="CWE-321",
                    fix_suggestion="从安全的密钥管理系统获取密钥",
                ),
            ]
        )

    def analyze_content(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """分析文件内容，返回发现的安全问题"""
        findings = []
        file_ext = self._get_file_extension(file_path)

        for rule in self.rules:
            # 检查文件类型是否匹配
            if rule.file_types and file_ext not in rule.file_types:
                continue

            # 执行正则匹配
            matches = re.finditer(rule.pattern, content, re.IGNORECASE | re.MULTILINE)

            for match in matches:
                line_number = content[: match.start()].count("\n") + 1
                finding = {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "description": rule.description,
                    "severity": rule.severity.value,
                    "category": rule.category,
                    "cwe_id": rule.cwe_id,
                    "fix_suggestion": rule.fix_suggestion,
                    "file_path": file_path,
                    "line_number": line_number,
                    "matched_text": match.group(),
                    "context": self._get_context(content, match.start(), match.end()),
                }
                findings.append(finding)

        return findings

    def _get_file_extension(self, file_path: str) -> str:
        """获取文件扩展名"""
        import os

        return os.path.splitext(file_path)[1].lower()

    def _get_context(
        self, content: str, start: int, end: int, context_lines: int = 2
    ) -> Dict[str, Any]:
        """获取匹配内容的上下文"""
        lines = content.split("\n")
        match_line = content[:start].count("\n")

        start_line = max(0, match_line - context_lines)
        end_line = min(len(lines), match_line + context_lines + 1)

        return {
            "start_line": start_line + 1,
            "end_line": end_line,
            "lines": lines[start_line:end_line],
            "match_line": match_line + 1,
        }

    def get_rules_by_category(self, category: str) -> List[SecurityRule]:
        """按类别获取规则"""
        return [rule for rule in self.rules if rule.category == category]

    def get_rules_by_severity(self, severity: SeverityLevel) -> List[SecurityRule]:
        """按严重性级别获取规则"""
        return [rule for rule in self.rules if rule.severity == severity]

    def add_custom_rule(self, rule: SecurityRule):
        """添加自定义规则"""
        self.rules.append(rule)

    def get_statistics(self) -> Dict[str, Any]:
        """获取规则统计信息"""
        stats = {
            "total_rules": len(self.rules),
            "by_category": {},
            "by_severity": {},
            "by_language": {},
        }

        for rule in self.rules:
            # 按类别统计
            stats["by_category"][rule.category] = (
                stats["by_category"].get(rule.category, 0) + 1
            )

            # 按严重性统计
            severity = rule.severity.value
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1

            # 按语言统计
            if rule.language:
                stats["by_language"][rule.language] = (
                    stats["by_language"].get(rule.language, 0) + 1
                )

        return stats


# 全局规则引擎实例
security_rule_engine = SecurityRuleEngine()


def get_security_rule_engine() -> SecurityRuleEngine:
    """获取安全规则引擎实例"""
    return security_rule_engine
