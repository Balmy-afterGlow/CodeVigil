# 🛡️ CodeVigil 代码安全分析报告

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
