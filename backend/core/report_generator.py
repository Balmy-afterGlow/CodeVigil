"""
报告生成器 - 生成多种格式的安全分析报告
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import jinja2


@dataclass
class ReportConfig:
    """报告配置"""

    include_summary: bool = True
    include_file_details: bool = True
    include_vulnerability_details: bool = True
    include_recommendations: bool = True
    include_charts: bool = True
    severity_filter: Optional[List[str]] = None


class ReportGenerator:
    """报告生成器"""

    def __init__(self, templates_dir: str = "./templates"):
        self.templates_dir = templates_dir
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(templates_dir),
            autoescape=jinja2.select_autoescape(["html", "xml"]),
        )
        self._ensure_templates()

    def _ensure_templates(self):
        """确保模板目录和模板文件存在"""
        os.makedirs(self.templates_dir, exist_ok=True)

        # 创建基础模板
        self._create_html_template()
        self._create_markdown_template()

    def generate_report(
        self,
        analysis_data: Dict[str, Any],
        format_type: str = "html",
        config: Optional[ReportConfig] = None,
    ) -> str:
        """生成报告"""
        if config is None:
            config = ReportConfig()

        # 处理数据
        processed_data = self._process_analysis_data(analysis_data, config)

        # 根据格式生成报告
        if format_type.lower() == "html":
            return self._generate_html_report(processed_data)
        elif format_type.lower() == "markdown":
            return self._generate_markdown_report(processed_data)
        elif format_type.lower() == "json":
            return self._generate_json_report(processed_data)
        elif format_type.lower() == "csv":
            return self._generate_csv_report(processed_data)
        else:
            raise ValueError(f"不支持的报告格式: {format_type}")

    def _process_analysis_data(
        self, data: Dict[str, Any], config: ReportConfig
    ) -> Dict[str, Any]:
        """处理分析数据"""
        processed = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "task_id": data.get("task_id", "unknown"),
                "repository_url": data.get("repository_info", {}).get("url", ""),
                "branch": data.get("repository_info", {}).get("branch", "main"),
            },
            "summary": self._generate_summary(data),
            "vulnerabilities": [],
            "files": [],
            "statistics": data.get("summary", {}),
            "recommendations": [],
        }

        # 处理漏洞数据
        if config.include_vulnerability_details:
            vulnerabilities = []
            for ai_result in data.get("ai_analysis", []):
                for vuln in ai_result.get("vulnerabilities", []):
                    if (
                        not config.severity_filter
                        or vuln.get("severity") in config.severity_filter
                    ):
                        vulnerabilities.append(vuln)
            processed["vulnerabilities"] = vulnerabilities

        # 处理文件数据
        if config.include_file_details:
            processed["files"] = data.get("file_analysis", [])

        # 生成建议
        if config.include_recommendations:
            processed["recommendations"] = self._generate_recommendations(data)

        return processed

    def _generate_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """生成摘要信息"""
        summary = data.get("summary", {})

        # 计算风险分布
        risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for ai_result in data.get("ai_analysis", []):
            for vuln in ai_result.get("vulnerabilities", []):
                severity = vuln.get("severity", "low")
                if severity in risk_distribution:
                    risk_distribution[severity] += 1

        # 计算总体风险评分
        total_score = (
            risk_distribution["critical"] * 10
            + risk_distribution["high"] * 7
            + risk_distribution["medium"] * 4
            + risk_distribution["low"] * 1
        )

        max_possible_score = sum(risk_distribution.values()) * 10
        risk_score = (
            (total_score / max_possible_score * 100) if max_possible_score > 0 else 0
        )

        return {
            **summary,
            "risk_distribution": risk_distribution,
            "total_vulnerabilities": sum(risk_distribution.values()),
            "risk_score": round(risk_score, 2),
            "security_grade": self._calculate_security_grade(risk_score),
        }

    def _calculate_security_grade(self, risk_score: float) -> str:
        """计算安全等级"""
        if risk_score >= 80:
            return "D (高风险)"
        elif risk_score >= 60:
            return "C (中高风险)"
        elif risk_score >= 40:
            return "B (中等风险)"
        elif risk_score >= 20:
            return "A- (较低风险)"
        else:
            return "A (低风险)"

    def _generate_recommendations(self, data: Dict[str, Any]) -> List[str]:
        """生成修复建议"""
        recommendations = set()

        # 基于漏洞类型生成建议
        vuln_types = set()
        for ai_result in data.get("ai_analysis", []):
            for vuln in ai_result.get("vulnerabilities", []):
                vuln_types.add(vuln.get("type", ""))

        # 通用建议
        recommendations.add("定期进行代码安全审查")
        recommendations.add("使用静态代码分析工具")
        recommendations.add("实施安全编码标准")

        # 基于漏洞类型的具体建议
        if "SQL注入" in vuln_types:
            recommendations.add("使用参数化查询防止SQL注入")
            recommendations.add("对用户输入进行严格验证和过滤")

        if "XSS" in vuln_types or "跨站脚本" in vuln_types:
            recommendations.add("对输出内容进行HTML编码")
            recommendations.add("实施内容安全策略(CSP)")

        if "硬编码" in str(vuln_types):
            recommendations.add("使用环境变量存储敏感信息")
            recommendations.add("实施密钥管理最佳实践")

        return sorted(list(recommendations))

    def _generate_html_report(self, data: Dict[str, Any]) -> str:
        """生成HTML报告"""
        template = self.env.get_template("report.html")
        return template.render(**data)

    def _generate_markdown_report(self, data: Dict[str, Any]) -> str:
        """生成Markdown报告"""
        template = self.env.get_template("report.md")
        return template.render(**data)

    def _generate_json_report(self, data: Dict[str, Any]) -> str:
        """生成JSON报告"""
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    def _generate_csv_report(self, data: Dict[str, Any]) -> str:
        """生成CSV报告"""
        import io
        import csv

        output = io.StringIO()
        writer = csv.writer(output)

        # 写入头部
        writer.writerow(
            ["文件路径", "漏洞类型", "严重程度", "行号", "描述", "修复建议"]
        )

        # 写入漏洞数据
        for vuln in data["vulnerabilities"]:
            writer.writerow(
                [
                    vuln.get("file", ""),
                    vuln.get("type", ""),
                    vuln.get("severity", ""),
                    vuln.get("line", ""),
                    vuln.get("description", ""),
                    vuln.get("solution", ""),
                ]
            )

        return output.getvalue()

    def _create_html_template(self):
        """创建HTML模板"""
        template_content = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeVigil 安全分析报告</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #e0e0e0; }
        .logo { font-size: 28px; font-weight: bold; color: #2563eb; margin-bottom: 10px; }
        .subtitle { color: #6b7280; font-size: 16px; }
        .metadata { background: #f8fafc; padding: 15px; border-radius: 6px; margin-bottom: 25px; }
        .metadata-item { margin: 5px 0; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .summary-card.risk { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
        .summary-card.files { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }
        .summary-card.grade { background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%); color: #2d3748; }
        .card-title { font-size: 14px; opacity: 0.9; margin-bottom: 8px; }
        .card-value { font-size: 28px; font-weight: bold; }
        .section { margin: 30px 0; }
        .section-title { font-size: 20px; font-weight: bold; color: #2d3748; margin-bottom: 15px; border-left: 4px solid #2563eb; padding-left: 12px; }
        .vulnerability { background: #fef2f2; border: 1px solid #fecaca; border-radius: 6px; padding: 15px; margin: 10px 0; }
        .vulnerability.critical { border-color: #dc2626; }
        .vulnerability.high { border-color: #ea580c; }
        .vulnerability.medium { border-color: #ca8a04; }
        .vulnerability.low { border-color: #2563eb; }
        .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .vuln-title { font-weight: bold; color: #2d3748; }
        .severity-badge { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; text-transform: uppercase; }
        .severity-critical { background: #dc2626; color: white; }
        .severity-high { background: #ea580c; color: white; }
        .severity-medium { background: #ca8a04; color: white; }
        .severity-low { background: #2563eb; color: white; }
        .vuln-details { font-size: 14px; color: #4b5563; line-height: 1.6; }
        .recommendation-list { list-style: none; padding: 0; }
        .recommendation-list li { background: #f0f9ff; border-left: 4px solid #2563eb; padding: 12px; margin: 8px 0; border-radius: 4px; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #6b7280; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️ CodeVigil</div>
            <div class="subtitle">代码安全分析报告</div>
        </div>
        
        <div class="metadata">
            <div class="metadata-item"><strong>仓库:</strong> {{ metadata.repository_url }}</div>
            <div class="metadata-item"><strong>分支:</strong> {{ metadata.branch }}</div>
            <div class="metadata-item"><strong>生成时间:</strong> {{ metadata.generated_at }}</div>
            <div class="metadata-item"><strong>任务ID:</strong> {{ metadata.task_id }}</div>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <div class="card-title">发现漏洞</div>
                <div class="card-value">{{ summary.total_vulnerabilities }}</div>
            </div>
            <div class="summary-card risk">
                <div class="card-title">风险评分</div>
                <div class="card-value">{{ summary.risk_score }}%</div>
            </div>
            <div class="summary-card files">
                <div class="card-title">扫描文件</div>
                <div class="card-value">{{ summary.total_files }}</div>
            </div>
            <div class="summary-card grade">
                <div class="card-title">安全等级</div>
                <div class="card-value" style="font-size: 18px;">{{ summary.security_grade }}</div>
            </div>
        </div>
        
        {% if vulnerabilities %}
        <div class="section">
            <div class="section-title">🔍 发现的漏洞</div>
            {% for vuln in vulnerabilities %}
            <div class="vulnerability {{ vuln.severity }}">
                <div class="vuln-header">
                    <div class="vuln-title">{{ vuln.type }} - {{ vuln.file }}:{{ vuln.line }}</div>
                    <span class="severity-badge severity-{{ vuln.severity }}">{{ vuln.severity }}</span>
                </div>
                <div class="vuln-details">
                    <p><strong>描述:</strong> {{ vuln.description }}</p>
                    {% if vuln.solution %}
                    <p><strong>修复建议:</strong> {{ vuln.solution }}</p>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        {% if recommendations %}
        <div class="section">
            <div class="section-title">💡 修复建议</div>
            <ul class="recommendation-list">
                {% for recommendation in recommendations %}
                <li>{{ recommendation }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        <div class="footer">
            <p>报告由 CodeVigil 自动生成 | 如需帮助请访问项目文档</p>
        </div>
    </div>
</body>
</html>"""

        template_path = os.path.join(self.templates_dir, "report.html")
        with open(template_path, "w", encoding="utf-8") as f:
            f.write(template_content)

    def _create_markdown_template(self):
        """创建Markdown模板"""
        template_content = """# 🛡️ CodeVigil 代码安全分析报告

## 📋 基本信息

- **仓库地址**: {{ metadata.repository_url }}
- **分析分支**: {{ metadata.branch }}
- **生成时间**: {{ metadata.generated_at }}
- **任务ID**: {{ metadata.task_id }}

## 📊 分析摘要

| 指标 | 数值 |
|------|------|
| 发现漏洞 | {{ summary.total_vulnerabilities }} |
| 风险评分 | {{ summary.risk_score }}% |
| 扫描文件 | {{ summary.total_files }} |
| 安全等级 | {{ summary.security_grade }} |

### 漏洞分布

- 🔴 严重: {{ summary.risk_distribution.critical }}
- 🟠 高危: {{ summary.risk_distribution.high }}
- 🟡 中等: {{ summary.risk_distribution.medium }}
- 🔵 较低: {{ summary.risk_distribution.low }}

{% if vulnerabilities %}
## 🔍 漏洞详情

{% for vuln in vulnerabilities %}
### {{ loop.index }}. {{ vuln.type }}

- **文件**: `{{ vuln.file }}`
- **行号**: {{ vuln.line }}
- **严重程度**: {{ vuln.severity.upper() }}
- **描述**: {{ vuln.description }}
{% if vuln.solution %}
- **修复建议**: {{ vuln.solution }}
{% endif %}

---
{% endfor %}
{% endif %}

{% if recommendations %}
## 💡 修复建议

{% for recommendation in recommendations %}
{{ loop.index }}. {{ recommendation }}
{% endfor %}
{% endif %}

## 📝 说明

本报告由 CodeVigil 自动生成，建议结合人工审查进行安全评估。

---
*生成时间: {{ metadata.generated_at }}*
"""

        template_path = os.path.join(self.templates_dir, "report.md")
        with open(template_path, "w", encoding="utf-8") as f:
            f.write(template_content)


# 全局报告生成器实例
report_generator = ReportGenerator()
