# CodeVigil - 开源仓库代码审计系统

一个基于AI驱动的开源仓库代码安全审计系统，能够自动识别代码中的安全漏洞并提供修复建议。

## ✨ 功能特性

- 🔍 **智能代码分析**: 结合AST静态分析、Git历史分析和AI审计
- 🎯 **风险评估**: 多维度评分算法识别高危文件
- 🤖 **AI增强分析**: 基于大语言模型的漏洞检测和修复建议
- 📚 **知识库RAG**: 集成CVE/CWE数据库提供精准修复方案
- 📊 **可视化展示**: 风险热力图和进度追踪
- 📋 **多格式报告**: 支持MD、PDF、JSON格式导出

## 🏗️ 系统架构

```
CodeVigil/
├── backend/                 # 后端服务
│   ├── core/               # 核心模块
│   │   ├── repository/     # 仓库处理模块
│   │   ├── analyzer/       # 文件分析模块
│   │   ├── ai/            # AI分析模块
│   │   └── rag/           # RAG知识库模块
│   ├── api/               # API接口
│   ├── models/            # 数据模型
│   └── utils/             # 工具函数
├── frontend/              # 前端界面
│   ├── src/
│   │   ├── components/    # React组件
│   │   ├── pages/         # 页面组件
│   │   ├── hooks/         # 自定义钩子
│   │   └── utils/         # 工具函数
│   └── public/            # 静态资源
├── data/                  # 数据存储
│   ├── knowledge_base/    # RAG知识库
│   ├── temp/             # 临时文件
│   └── reports/          # 生成报告
└── docs/                 # 项目文档
```

## 🚀 快速开始

### 环境要求

- Python 3.8+
- Node.js 16+
- Git

### 安装依赖

#### 后端
```bash
cd backend
pip install -r requirements.txt
```

#### 前端
```bash
cd frontend
npm install
```

### 运行项目

#### 启动后端服务
```bash
cd backend
python app.py
```

#### 启动前端服务
```bash
cd frontend
npm start
```

## 📝 技术栈

### 后端
- **框架**: Flask/FastAPI
- **代码分析**: ast, bandit, semgrep
- **版本控制**: gitpython
- **AI模型**: DeepSeek API
- **向量检索**: FAISS
- **报告生成**: WeasyPrint, pdfkit

### 前端
- **框架**: React 18
- **样式**: Tailwind CSS
- **图表**: Chart.js
- **状态管理**: React Context/Redux

## 🔧 配置说明

详细配置请参考 [配置文档](docs/configuration.md)

## 📖 API文档

API文档请参考 [API说明](docs/api.md)

## 🤝 贡献指南

欢迎提交Issue和Pull Request！

## 📄 许可证

MIT License