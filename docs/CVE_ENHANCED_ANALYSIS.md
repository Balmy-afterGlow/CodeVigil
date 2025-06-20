# CodeVigil CVE增强分析使用指南

## 概述

CodeVigil现在支持基于CVEfixes数据集的增强分析功能，可以在AI分析后自动关联相关CVE，生成精确的修复diff和CVE链接。

## 核心流程

### 1. 高危文件分析（默认20个文件）
- 系统首先分析仓库中的高危文件（当前默认配置为20个）
- 使用增强型AST分析器进行深度语义分析
- 结合Git历史修改情况进行风险评估

### 2. AI批量分析
- 将文件内容、AST特征、Git fix提交、静态分析结果一并送入AI
- AI返回JSON格式的评分与漏洞详情，包括：
  - 漏洞标题、严重程度、CWE分类
  - 代码位置和片段
  - 影响描述和修复建议

### 3. CVE知识库增强（新增功能）
- 自动使用漏洞描述和代码片段检索CVEfixes知识库
- 查找相似的CVE修复案例
- 提取修复模式和代码变更示例

### 4. AI二次分析
- 将CVE上下文和修复案例合入prompt
- AI基于历史修复模式生成最终的diff
- 自动关联相关CVE链接

## API端点

### 主要分析接口
```
POST /api/analyze-repository
```
- 完整的仓库安全分析流程
- 自动集成CVE增强分析

### CVE增强分析接口
```
POST /api/ai-enhanced-analysis
```
- 对初次AI分析结果进行CVE增强
- 输入：漏洞信息和文件路径
- 输出：增强的修复建议和CVE关联

### CVE上下文生成接口  
```
POST /api/generate-cve-enhanced-diff
```
- 基于漏洞信息生成CVE修复上下文
- 专门用于diff生成的辅助接口

## 配置说明

### 高危文件数量配置
当前默认分析20个高危文件，在以下位置配置：
```python
# backend/api/routes.py:427
top_risk_files = file_analyzer.get_top_risk_files(file_results, 20)
```

### CVE知识库配置
- 数据库位置: `data/knowledge_base/cvefixes_kb.db`
- 支持全文搜索和语义检索
- 包含CVE基础信息、文件变更、代码变更详情

## 初始化CVE知识库

运行初始化脚本：
```bash
cd /home/moyu/Code/Project/CodeVigil
python scripts/init_cve_kb.py
```

这会加载示例CVE数据，包括：
- CVE-2021-44228 (Log4j)
- CVE-2022-22965 (Spring4Shell)  
- CVE-2021-3129 (Laravel)

## 数据流程图

```
仓库代码 
    ↓
文件分析器 (获取20个高危文件)
    ↓
AI批量分析 (漏洞识别)
    ↓
CVE知识库检索 (相似案例)
    ↓
AI二次分析 (diff生成 + CVE关联)
    ↓
最终报告
```

## 增强功能特性

### CVE关联
- 基于漏洞描述自动匹配相关CVE
- 提供CVE链接和详细信息
- 支持CWE分类关联

### 智能diff生成
- 基于历史修复模式生成代码修改建议
- 提供修改前后的代码对比
- 包含修复步骤和验证方法

### 修复模式学习
- 从CVE修复案例中提取通用模式
- 支持多种编程语言的修复建议
- 自动分析修复关键词和方法

## 性能优化

### 批量处理
- 最大批量大小：5个文件/批次
- 支持API限流控制
- 异常降级到单文件分析

### 缓存机制
- CVE搜索结果缓存
- 全文搜索索引优化
- 数据库连接池管理

## 扩展说明

### 集成真实CVEfixes数据集
如需使用完整的CVEfixes数据集：

1. 下载CVEfixes数据库
2. 修改`load_from_cvefixes_db`方法的数据库路径
3. 运行数据导入脚本

### 自定义修复模式
可以通过修改`_extract_common_fix_patterns`方法来添加新的修复模式识别逻辑。

### API集成
前端可以通过新增的API端点获取CVE增强分析结果，实现实时的修复建议和CVE关联展示。
