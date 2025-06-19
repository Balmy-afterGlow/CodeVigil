#!/bin/bash

# CodeVigil 项目启动脚本

set -e

echo "🚀 开始启动 CodeVigil 项目..."

# 检查 Python 版本
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 未安装，请先安装 Python 3.8+"
    exit 1
fi

# 检查 Node.js 版本
if ! command -v node &> /dev/null; then
    echo "❌ Node.js 未安装，请先安装 Node.js 16+"
    exit 1
fi

# 创建必要的目录
echo "📁 创建数据目录..."
mkdir -p data/temp data/reports data/knowledge_base logs

# 后端环境配置
echo "🔧 配置后端环境..."
cd backend

# 检查虚拟环境
if [ ! -d "venv" ]; then
    echo "📦 创建虚拟环境..."
    python3 -m venv venv
fi

# 激活虚拟环境
source venv/bin/activate

# 安装依赖
echo "📦 安装后端依赖..."
pip install -r requirements.txt

# 复制环境配置
if [ ! -f ".env" ]; then
    echo "⚙️ 创建环境配置文件..."
    cp .env.example .env
    echo "请编辑 backend/.env 文件配置 API 密钥等信息"
fi

# 初始化数据库
echo "🗄️ 初始化数据库..."
python -c "
import asyncio
from core.database import init_db
asyncio.run(init_db())
"

cd ..

# 前端环境配置
echo "🎨 配置前端环境..."
cd frontend

# 安装前端依赖
echo "📦 安装前端依赖..."
npm install

# 复制环境配置
if [ ! -f ".env" ]; then
    echo "⚙️ 创建前端环境配置..."
    cp .env.example .env
fi

cd ..

echo "✅ 项目初始化完成！"
echo ""
echo "🔗 快速启动："
echo "  后端服务: cd backend && source venv/bin/activate && python app.py"
echo "  前端服务: cd frontend && npm start"
echo ""
echo "📖 更多信息请查看:"
echo "  - README.md"
echo "  - docs/analysis.md"
echo "  - docs/configuration.md"
