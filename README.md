# CodeVigil - 基于AI的代码安全审计系统

一个集成了CVE历史数据库的AI驱动代码安全审计系统，采用严格三阶段分析流水线，提供精准的漏洞检测和修复建议。

> 数据集获取：https://zenodo.org/records/13118970
> 
> CVEfixes托管仓库：https://github.com/secureIT-project/CVEfixes

## 🌟 2025-06-21 重大更新

### 🎯 核心改进
- ✅ **重构三阶段AI分析流水线** - 批量风险评分 → 详细分析 → CVE关联增强
- ✅ **集成50GB CVEfixes真实数据库** - 基于历史漏洞修复案例的智能建议
- ✅ **完整本地开发支持** - 详细的非Docker本地运行指南 ([LOCAL_SETUP.md](LOCAL_SETUP.md))
- ✅ **高效知识库管理工具** - 智能从大型数据库提取适量样本数据
- ✅ **代码清理和重构** - 移除过时功能，优化API结构

## ✨ 核心功能特性

### 🤖 AI分析引擎
- **三阶段严格分析**: 批量风险评分 → 详细漏洞分析 → CVE关联增强
- **智能自适应**: 根据项目规模自动选择最优分析策略
- **上下文感知**: 结合项目结构和依赖关系进行深度分析
- **多语言支持**: Python、JavaScript、Java、C/C++、PHP、Go等

### 🛡️ CVE知识库集成
- **50GB真实数据**: 集成CVEfixes v1.0.8数据库，包含11,873个真实CVE案例
- **智能修复建议**: 基于相似历史漏洞的修复模式生成具体建议
- **模式匹配**: 根据漏洞类型和代码特征匹配相似修复案例
- **Diff生成增强**: AI结合历史案例生成精准的修复代码diff

### 📊 分析和可视化
- **风险热力图**: 文件级别的安全风险可视化
- **实时进度追踪**: WebSocket实时更新分析进度
- **多维度评分**: CVSS、业务影响、修复难度综合评估
- **趋势分析**: 项目安全状况历史趋势

### 📋 报告和导出
- **多格式导出**: PDF、HTML、JSON、CSV格式支持
- **管理层报告**: 高级决策者友好的摘要报告
- **技术详细报告**: 开发人员详细技术报告
- **修复优先级**: 基于风险评分的智能排序

## 🏗️ 系统架构

```
CodeVigil/
├── 📄 LOCAL_SETUP.md           # 📖 本地开发完整指南 (新增)
├── 📄 start_local.sh          # 🚀 本地环境一键启动 (新增)
├── backend/                    # 🔧 后端服务 (FastAPI + Python)
│   ├── core/ai/analyzer.py     #    三阶段AI分析引擎 (重构)
│   ├── core/rag/               #    CVE知识库系统 (重写)
│   ├── api/routes.py           #    清理后的API端点 (优化)
│   └── requirements.txt        #    Python依赖
├── frontend/                   # 🎨 前端界面 (React + TypeScript)
│   ├── src/components/         #    可复用组件
│   ├── src/pages/             #    主要页面
│   └── package.json           #    Node.js依赖
├── scripts/                    # 🛠️ 管理工具 (新增)
│   ├── manage_cve_kb.py        #    CVE知识库管理工具
│   ├── simple_kb_init.py       #    简化知识库初始化
│   └── test_cve_db.py          #    数据库测试工具
├── data/                       # 💾 数据存储
│   ├── CVEfixes_v1.0.8/        #    50GB CVE历史数据库
│   └── knowledge_base/         #    提取的知识库样本
└── docs/                       # 📚 技术文档
```

## 🚀 快速开始

### 🏠 本地开发 (推荐新手)

📖 **完整指南**: [LOCAL_SETUP.md](LOCAL_SETUP.md) - 详细的本地开发环境设置指南

```bash
# 1. 查看本地设置指南
cat LOCAL_SETUP.md

# 2. 一键启动本地环境
./start_local.sh

# 3. 手动启动 (如需自定义)
cd backend && python app.py
cd frontend && npm start
```

### 🐳 容器化部署

```bash
# 开发环境
./start.sh dev

# 生产环境  
./start.sh prod
```

### 🛠️ CVE知识库初始化 (可选但推荐)

```bash
# 快速初始化 500 条样本数据 (推荐)
python scripts/simple_kb_init.py --limit 500

# 高级管理工具 (从50GB数据库提取)
python scripts/manage_cve_kb.py --action all --limit 1000
```

## 📋 系统要求

### 基础要求
- **Python**: 3.8+
- **Node.js**: 16+ 
- **内存**: 4GB+ (8GB推荐)
- **磁盘**: 2GB+ (不含CVE数据库)

### CVE知识库 (可选)
- **磁盘空间**: 50GB+ (完整CVEfixes数据库)
- **推荐配置**: SSD + 16GB RAM (获得最佳性能)

## 🌐 访问地址

启动成功后访问：
- **前端应用**: http://localhost:3000
- **后端API**: http://localhost:8000
- **API文档**: http://localhost:8000/docs

## 💡 使用示例

### 分析GitHub仓库
1. 在前端界面输入仓库URL: `https://github.com/username/repository`
2. 选择分析模式 (快速/详细/增强)
3. 观察实时分析进度
4. 查看结果和修复建议
5. 导出报告 (PDF/HTML/JSON)

### 命令行使用

# 或启动生产环境
./start.sh prod
```

访问地址：
- 前端应用: http://localhost:3000
- 后端API: http://localhost:8000
- API文档: http://localhost:8000/docs

### 方式二：手动安装

#### 后端安装

```bash
cd backend

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 安装依赖
pip install -r requirements.txt

# 配置环境变量
cp .env.example .env
# 编辑 .env 文件

# 启动服务
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

#### 前端安装

```bash
cd frontend

# 安装依赖
npm install

# 配置环境变量
cp .env.example .env
# 编辑 .env 文件

# 启动开发服务器
npm start
```

### 环境要求

- Python 3.8+
- Node.js 16+
- Git
- Docker & Docker Compose (可选)
- PostgreSQL (生产环境)
- Redis (可选，用于缓存)

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