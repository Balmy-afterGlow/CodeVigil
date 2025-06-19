# API接口文档

## 基础信息

- **Base URL**: `http://localhost:8000/api`
- **认证方式**: Bearer Token (JWT)
- **请求格式**: JSON
- **响应格式**: JSON

## 接口列表

### 1. 健康检查

**GET** `/health`

检查API服务状态。

**响应示例**:
```json
{
  "status": "healthy",
  "message": "CodeVigil API正在运行",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### 2. 启动仓库分析

**POST** `/analyze/repository`

启动新的仓库安全分析任务。

**请求参数**:
```json
{
  "repository_url": "https://github.com/user/repo.git",
  "branch": "main",
  "analysis_options": {
    "enable_ai_analysis": true,
    "max_files_to_analyze": 50,
    "include_low_risk": false,
    "analysis_depth": "normal"
  }
}
```

**响应示例**:
```json
{
  "task_id": "analysis_12345_1640995200",
  "status": "started",
  "message": "分析任务已启动",
  "created_at": "2024-01-01T12:00:00Z"
}
```

### 3. 获取分析进度

**GET** `/analysis/{task_id}/progress`

获取指定任务的分析进度。

**路径参数**:
- `task_id`: 任务ID

**响应示例**:
```json
{
  "task_id": "analysis_12345_1640995200",
  "status": "running",
  "progress": 65,
  "current_step": "AI深度分析中",
  "message": "正在分析第15/20个高风险文件...",
  "eta_minutes": 5
}
```

**状态说明**:
- `started`: 任务已启动
- `running`: 正在执行
- `completed`: 已完成
- `failed`: 执行失败

### 4. 获取分析结果

**GET** `/analysis/{task_id}/results`

获取完整的分析结果。

**路径参数**:
- `task_id`: 任务ID

**响应示例**:
```json
{
  "task_id": "analysis_12345_1640995200",
  "repository_info": {
    "url": "https://github.com/user/repo.git",
    "name": "repo",
    "branch": "main",
    "commit_hash": "abc123...",
    "total_files": 150,
    "filtered_files": 45,
    "languages": {
      "Python": 30,
      "JavaScript": 10,
      "HTML": 5
    },
    "size_mb": 15.6
  },
  "summary": {
    "total_files_analyzed": 45,
    "high_risk_files": 8,
    "vulnerabilities_found": 12,
    "critical_issues": 2,
    "high_issues": 4,
    "medium_issues": 4,
    "low_issues": 2
  },
  "high_risk_files": [
    {
      "file_path": "src/auth/login.py",
      "risk_score": 85.5,
      "language": "python",
      "vulnerabilities_count": 3,
      "lines_of_code": 156
    }
  ],
  "vulnerabilities": [
    {
      "title": "SQL注入漏洞",
      "severity": "high",
      "cwe_id": "CWE-89",
      "description": "在用户输入处理中发现潜在的SQL注入漏洞",
      "file_path": "src/auth/login.py",
      "line_number": 45,
      "confidence": 0.9
    }
  ],
  "created_at": "2024-01-01T12:00:00Z",
  "completed_at": "2024-01-01T12:15:00Z"
}
```

### 5. 导出分析报告

**POST** `/export/{task_id}/{format}`

导出指定格式的分析报告。

**路径参数**:
- `task_id`: 任务ID
- `format`: 导出格式 (`json` | `pdf` | `markdown`)

**响应示例**:
```json
{
  "export_path": "./data/reports/analysis_12345_1640995200_report.pdf",
  "download_url": "/download/analysis_12345_1640995200_report.pdf",
  "file_size": "2.5MB",
  "created_at": "2024-01-01T12:30:00Z"
}
```

### 6. 下载报告文件

**GET** `/download/{filename}`

下载生成的报告文件。

**路径参数**:
- `filename`: 文件名

**响应**: 文件流下载

### 7. 获取任务列表

**GET** `/analysis/tasks`

获取用户的分析任务列表。

**查询参数**:
- `page`: 页码 (默认: 1)
- `limit`: 每页数量 (默认: 20)
- `status`: 过滤状态 (可选)

**响应示例**:
```json
{
  "tasks": [
    {
      "task_id": "analysis_12345_1640995200",
      "repository_url": "https://github.com/user/repo.git",
      "status": "completed",
      "created_at": "2024-01-01T12:00:00Z",
      "completed_at": "2024-01-01T12:15:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 5,
    "total_pages": 1
  }
}
```

### 8. 删除分析任务

**DELETE** `/analysis/{task_id}`

删除指定的分析任务及其结果。

**路径参数**:
- `task_id`: 任务ID

**响应示例**:
```json
{
  "message": "任务已删除",
  "task_id": "analysis_12345_1640995200"
}
```

## WebSocket 接口

### 实时进度推送

**WebSocket** `/ws/{client_id}`

建立WebSocket连接，接收实时的分析进度更新。

**连接参数**:
- `client_id`: 客户端唯一标识

**消息格式**:
```json
{
  "type": "progress_update",
  "task_id": "analysis_12345_1640995200",
  "progress": 75,
  "message": "正在进行AI分析...",
  "timestamp": "2024-01-01T12:10:00Z"
}
```

## 错误码说明

| 状态码 | 说明 | 示例 |
|--------|------|------|
| 200 | 请求成功 | 正常响应 |
| 400 | 请求参数错误 | 无效的仓库URL |
| 401 | 未授权 | Token无效或过期 |
| 404 | 资源不存在 | 任务ID不存在 |
| 429 | 请求过于频繁 | API限流 |
| 500 | 服务器内部错误 | 分析引擎异常 |

**错误响应格式**:
```json
{
  "error": "INVALID_REPOSITORY_URL",
  "message": "提供的仓库URL格式不正确",
  "details": {
    "url": "invalid-url",
    "expected_format": "https://github.com/user/repo.git"
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## 使用示例

### cURL示例

```bash
# 启动分析
curl -X POST "http://localhost:8000/api/analyze/repository" \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "https://github.com/user/repo.git",
    "branch": "main",
    "analysis_options": {
      "enable_ai_analysis": true,
      "max_files_to_analyze": 50
    }
  }'

# 获取进度
curl "http://localhost:8000/api/analysis/analysis_12345_1640995200/progress"

# 获取结果
curl "http://localhost:8000/api/analysis/analysis_12345_1640995200/results"
```

### JavaScript示例

```javascript
// 启动分析
const response = await fetch('/api/analyze/repository', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    repository_url: 'https://github.com/user/repo.git',
    branch: 'main',
    analysis_options: {
      enable_ai_analysis: true,
      max_files_to_analyze: 50
    }
  })
});

const { task_id } = await response.json();

// 轮询进度
const pollProgress = async () => {
  const response = await fetch(`/api/analysis/${task_id}/progress`);
  const progress = await response.json();
  
  if (progress.status === 'completed') {
    // 获取结果
    const resultsResponse = await fetch(`/api/analysis/${task_id}/results`);
    const results = await resultsResponse.json();
    console.log('分析完成:', results);
  } else {
    console.log('进度:', progress.progress + '%');
    setTimeout(pollProgress, 2000);
  }
};

pollProgress();
```

### Python示例

```python
import requests
import time

# 启动分析
response = requests.post('http://localhost:8000/api/analyze/repository', json={
    'repository_url': 'https://github.com/user/repo.git',
    'branch': 'main',
    'analysis_options': {
        'enable_ai_analysis': True,
        'max_files_to_analyze': 50
    }
})

task_id = response.json()['task_id']

# 等待完成
while True:
    progress_response = requests.get(f'http://localhost:8000/api/analysis/{task_id}/progress')
    progress = progress_response.json()
    
    print(f"进度: {progress['progress']}% - {progress['message']}")
    
    if progress['status'] == 'completed':
        # 获取结果
        results_response = requests.get(f'http://localhost:8000/api/analysis/{task_id}/results')
        results = results_response.json()
        print('分析完成:', results['summary'])
        break
    elif progress['status'] == 'failed':
        print('分析失败')
        break
    
    time.sleep(2)
```

## API限制

- **请求频率**: 每分钟最多100次请求
- **并发分析**: 每用户最多3个并发分析任务
- **文件大小**: 单个仓库最大1GB
- **超时时间**: 分析任务最长运行30分钟

## 版本说明

当前API版本: `v1`

版本更新策略:
- 向下兼容的更改会在当前版本中发布
- 破坏性更改会发布新的版本号
- 旧版本会保持6个月的支持期

---

如有API相关问题，请查看 [GitHub Issues](https://github.com/your-repo/codevigil/issues) 或提交新的问题。
