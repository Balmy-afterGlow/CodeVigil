# 配置说明文档

## 环境变量配置

### 后端配置 (backend/.env)

```bash
# 应用基础配置
APP_NAME=CodeVigil
APP_VERSION=1.0.0
DEBUG=True
SECRET_KEY=your-secret-key-here

# 数据库配置
DATABASE_URL=postgresql://username:password@localhost:5432/codevigil
# 或使用 SQLite (开发环境)
# DATABASE_URL=sqlite:///./data/codevigil.db

# Redis配置
REDIS_URL=redis://localhost:6379/0

# AI API配置
DEEPSEEK_API_KEY=your-deepseek-api-key
DEEPSEEK_BASE_URL=https://api.deepseek.com/v1
DEFAULT_MODEL=deepseek-coder

# 文件存储配置
TEMP_DIR=./data/temp
REPORTS_DIR=./data/reports
KNOWLEDGE_BASE_DIR=./data/knowledge_base
MAX_REPO_SIZE=1GB
MAX_FILE_SIZE=10MB

# 分析配置
MAX_FILES_PER_BATCH=50
AI_TIMEOUT=300
SEMGREP_TIMEOUT=180
BANDIT_TIMEOUT=120

# Celery配置
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/2

# 日志配置
LOG_LEVEL=INFO
LOG_FILE=./logs/app.log

# RAG配置
FAISS_INDEX_PATH=./data/knowledge_base/faiss_index
EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2
CHUNK_SIZE=512
CHUNK_OVERLAP=50
```

### 前端配置 (frontend/.env)

```bash
# 环境配置
NODE_ENV=development
REACT_APP_API_BASE_URL=http://localhost:8000/api

# API配置
REACT_APP_WS_URL=ws://localhost:8000/ws
REACT_APP_UPLOAD_MAX_SIZE=100MB

# 功能开关
REACT_APP_ENABLE_DEMO=true
REACT_APP_ENABLE_ANALYTICS=false
```

## API密钥获取

### DeepSeek API
1. 访问 [DeepSeek平台](https://platform.deepseek.com/)
2. 注册并登录账户
3. 在API管理页面创建新的API密钥
4. 将密钥填入 `DEEPSEEK_API_KEY` 配置项

### 其他AI平台 (可选)
- **OpenAI**: 修改 `DEEPSEEK_BASE_URL` 为 `https://api.openai.com/v1`
- **Claude**: 使用相应的API配置
- **本地模型**: 部署Ollama等本地推理服务

## 数据库配置

### SQLite (开发环境推荐)
```bash
DATABASE_URL=sqlite:///./data/codevigil.db
```

### PostgreSQL (生产环境推荐)
```bash
# 安装PostgreSQL
sudo apt-get install postgresql postgresql-contrib

# 创建数据库和用户
sudo -u postgres psql
CREATE DATABASE codevigil;
CREATE USER codevigil_user WITH ENCRYPTED PASSWORD 'password';
GRANT ALL PRIVILEGES ON DATABASE codevigil TO codevigil_user;

# 配置连接
DATABASE_URL=postgresql://codevigil_user:password@localhost:5432/codevigil
```

### MySQL (备选方案)
```bash
DATABASE_URL=mysql://username:password@localhost:3306/codevigil
```

## Redis配置

### 本地安装
```bash
# Ubuntu/Debian
sudo apt-get install redis-server

# CentOS/RHEL
sudo yum install redis

# macOS
brew install redis

# 启动服务
sudo systemctl start redis-server
```

### Docker部署
```bash
docker run -d --name redis -p 6379:6379 redis:alpine
```

## 性能调优配置

### 文件分析优化
```bash
# 并发线程数 (建议为CPU核心数)
MAX_WORKER_THREADS=4

# 批处理大小
BATCH_SIZE=20

# 超时配置
ANALYSIS_TIMEOUT=600
```

### AI分析优化
```bash
# 并发请求数 (避免API限制)
AI_CONCURRENT_REQUESTS=3

# 重试配置
AI_MAX_RETRIES=3
AI_RETRY_DELAY=1

# 缓存配置
AI_CACHE_TTL=3600
```

### 前端性能
```bash
# 启用Service Worker
REACT_APP_ENABLE_SW=true

# API请求缓存
REACT_APP_CACHE_DURATION=300

# 懒加载配置
REACT_APP_LAZY_LOAD=true
```

## 安全配置

### HTTPS配置
```bash
# 启用HTTPS
ENABLE_HTTPS=true
SSL_CERT_PATH=/path/to/cert.pem
SSL_KEY_PATH=/path/to/key.pem
```

### CORS配置
```bash
# 允许的域名
CORS_ORIGINS=http://localhost:3000,https://yourdomain.com

# 是否允许凭证
CORS_ALLOW_CREDENTIALS=true
```

### API安全
```bash
# JWT密钥
JWT_SECRET_KEY=your-jwt-secret-key
JWT_ALGORITHM=HS256
JWT_EXPIRATION=3600

# API速率限制
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
```

## 监控配置

### 日志配置
```bash
# 日志级别
LOG_LEVEL=INFO

# 日志文件
LOG_FILE=./logs/app.log
LOG_MAX_SIZE=10MB
LOG_BACKUP_COUNT=5

# Sentry (可选)
SENTRY_DSN=your-sentry-dsn
```

### 指标监控
```bash
# Prometheus (可选)
ENABLE_METRICS=true
METRICS_PORT=9090

# 健康检查
HEALTH_CHECK_INTERVAL=30
```

## 部署配置

### Docker配置
```dockerfile
# Dockerfile配置示例
FROM python:3.9-slim

ENV PYTHONPATH=/app
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Kubernetes配置
```yaml
# ConfigMap示例
apiVersion: v1
kind: ConfigMap
metadata:
  name: codevigil-config
data:
  DATABASE_URL: "postgresql://..."
  REDIS_URL: "redis://redis:6379"
  LOG_LEVEL: "INFO"
```

## 故障排除

### 常见问题

1. **数据库连接失败**
   - 检查数据库服务状态
   - 验证连接字符串格式
   - 确认防火墙设置

2. **AI API调用失败**
   - 验证API密钥有效性
   - 检查网络连接
   - 确认API配额

3. **前端无法连接后端**
   - 检查CORS配置
   - 验证API地址配置
   - 确认防火墙设置

4. **内存不足**
   - 增加系统内存
   - 调整批处理大小
   - 启用交换文件

### 性能问题

1. **分析速度慢**
   - 增加并发线程数
   - 使用SSD存储
   - 优化网络带宽

2. **数据库查询慢**
   - 添加数据库索引
   - 使用连接池
   - 考虑读写分离

3. **前端加载慢**
   - 启用压缩
   - 使用CDN
   - 实现代码分割

---

如有其他配置问题，请参考 [GitHub Issues](https://github.com/your-repo/codevigil/issues) 或提交新的问题。
