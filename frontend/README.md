# CodeVigil Frontend

CodeVigil 是一个开源仓库代码安全审计系统的前端应用，基于 React + TypeScript + Tailwind CSS 构建。

## 功能特性

- 🔍 **代码分析**: 支持多种编程语言的代码安全分析
- 📊 **可视化报告**: 直观的漏洞统计和风险热力图
- 🚀 **实时进度**: 实时显示分析进度和状态
- 📥 **多格式导出**: 支持 PDF、HTML、JSON、CSV 等格式导出
- 📱 **响应式设计**: 适配桌面和移动设备
- 🎨 **现代界面**: 基于 Tailwind CSS 的现代化 UI

## 技术栈

- **框架**: React 18
- **语言**: TypeScript
- **样式**: Tailwind CSS
- **路由**: React Router v6
- **图表**: Chart.js / Recharts
- **构建工具**: Create React App
- **包管理**: npm/yarn

## 项目结构

```
src/
├── components/          # 可复用组件
│   ├── Badge.tsx           # 徽章组件
│   ├── Button.tsx          # 按钮组件
│   ├── Card.tsx            # 卡片组件
│   ├── EmptyState.tsx      # 空状态组件
│   ├── ExportButtons.tsx   # 导出按钮组件
│   ├── Header.tsx          # 头部导航组件
│   ├── Input.tsx           # 输入框组件
│   ├── LoadingSpinner.tsx  # 加载动画组件
│   ├── NotificationContainer.tsx # 通知容器
│   ├── ProgressTracker.tsx # 进度追踪组件
│   ├── RiskHeatmap.tsx     # 风险热力图组件
│   └── VulnerabilityList.tsx # 漏洞列表组件
├── hooks/               # 自定义 Hooks
│   ├── useAnalysis.ts      # 分析数据 Hook
│   ├── useAnalysisHistory.ts # 分析历史 Hook
│   ├── useLocalStorage.ts  # 本地存储 Hook
│   └── useNotification.ts  # 通知 Hook
├── pages/               # 页面组件
│   ├── AnalysisPage.tsx    # 分析页面
│   ├── Dashboard.tsx       # 仪表盘页面
│   ├── HistoryPage.tsx     # 历史记录页面
│   └── ResultsPage.tsx     # 结果页面
├── routes/              # 路由配置
│   └── AppRoutes.tsx       # 应用路由
├── types/               # TypeScript 类型定义
│   └── index.ts            # 全局类型
├── utils/               # 工具函数
│   ├── api.ts              # API 服务
│   ├── constants.ts        # 常量定义
│   └── helpers.ts          # 辅助函数
├── App.tsx              # 应用入口组件
├── App.css              # 全局样式
├── index.tsx            # React 入口文件
└── index.css            # 基础样式
```

## 快速开始

### 环境要求

- Node.js >= 16.0.0
- npm >= 8.0.0 或 yarn >= 1.22.0

### 安装依赖

```bash
npm install
# 或
yarn install
```

### 环境配置

复制环境变量示例文件并配置：

```bash
cp .env.example .env
```

编辑 `.env` 文件：

```env
REACT_APP_API_URL=http://localhost:8000
REACT_APP_VERSION=1.0.0
```

### 启动开发服务器

```bash
npm start
# 或
yarn start
```

访问 http://localhost:3000 查看应用。

### 构建生产版本

```bash
npm run build
# 或
yarn build
```

构建文件将生成在 `build/` 目录。

## 主要组件说明

### 页面组件

- **Dashboard**: 仪表盘，显示分析统计和最近分析记录
- **AnalysisPage**: 分析配置页面，用于创建新的分析任务
- **ResultsPage**: 分析结果页面，显示详细的分析结果和漏洞信息
- **HistoryPage**: 历史记录页面，查看所有分析历史

### 核心组件

- **Header**: 顶部导航栏，包含页面导航和状态信息
- **ProgressTracker**: 分析进度显示组件
- **VulnerabilityList**: 漏洞列表展示组件
- **RiskHeatmap**: 风险热力图可视化组件
- **ExportButtons**: 报告导出功能组件

### 工具 Hooks

- **useAnalysis**: 管理单个分析任务的状态和数据
- **useAnalysisHistory**: 管理分析历史记录
- **useNotification**: 管理应用通知系统
- **useLocalStorage**: 管理本地存储数据

## API 集成

前端通过 `src/utils/api.ts` 中的 `ApiService` 类与后端进行通信：

```typescript
// 开始分析
const response = await apiService.startAnalysis({
  repoUrl: 'https://github.com/user/repo',
  branch: 'main',
  analysisConfig: {
    enableAiAnalysis: true,
    languages: ['javascript', 'python'],
    excludePatterns: ['node_modules/', '*.min.js']
  }
});

// 获取分析状态
const analysis = await apiService.getAnalysisStatus(analysisId);

// 导出报告
const exportResult = await apiService.exportReport(analysisId, 'pdf');
```

## 样式系统

使用 Tailwind CSS 进行样式管理，主要特点：

- **响应式设计**: 使用 Tailwind 的响应式断点
- **主题系统**: 统一的颜色和间距规范
- **组件化**: 可复用的样式组件
- **暗色模式**: 支持暗色主题切换（可扩展）

## 部署

### 构建 Docker 镜像

```bash
# 在前端目录下
docker build -t codevigil-frontend .
docker run -p 3000:80 codevigil-frontend
```

### Nginx 配置示例

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        root /usr/share/nginx/html;
        index index.html index.htm;
        try_files $uri $uri/ /index.html;
    }
    
    location /api {
        proxy_pass http://backend:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 开发指南

### 代码规范

- 使用 TypeScript 进行类型检查
- 遵循 ESLint 和 Prettier 配置
- 组件命名使用 PascalCase
- 文件名使用 PascalCase（组件）或 camelCase（工具）

### 组件开发

```typescript
// 组件模板
import React from 'react';

interface ComponentProps {
  title: string;
  children?: React.ReactNode;
  className?: string;
}

const Component: React.FC<ComponentProps> = ({
  title,
  children,
  className = ''
}) => {
  return (
    <div className={`component-base ${className}`}>
      <h2>{title}</h2>
      {children}
    </div>
  );
};

export default Component;
```

### 添加新页面

1. 在 `src/pages/` 创建页面组件
2. 在 `src/routes/AppRoutes.tsx` 添加路由
3. 更新导航菜单（如需要）

### 状态管理

使用 React Hooks 进行状态管理：

- `useState`: 本地组件状态
- `useContext`: 全局状态共享
- 自定义 Hooks: 封装复杂逻辑

## 测试

```bash
# 运行测试
npm test

# 生成测试覆盖率报告
npm run test:coverage
```

## 贡献指南

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 联系方式

- 项目主页: https://github.com/user/codevigil
- 问题反馈: https://github.com/user/codevigil/issues
- 文档: https://codevigil.docs.com
