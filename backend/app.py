"""
CodeVigil主应用入口
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
import uvicorn
import os
import logging
import json
from dotenv import load_dotenv

from api.routes import api_router
from api.middleware import setup_middleware
from core.database import init_db
from core.config import get_settings
from core.task_manager import get_task_manager
from core.rag.cve_knowledge_base import CVEfixesKnowledgeBase
from core.notification import get_notification_manager

# 加载环境变量
load_dotenv()

# 获取配置
settings = get_settings()

# 配置日志
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动时初始化
    logger.info("启动CodeVigil应用...")

    # 初始化数据库
    # await init_db()

    # 初始化CVE知识库
    try:
        cve_knowledge_base = CVEfixesKnowledgeBase()

        # 检查向量数据库是否存在，如果不存在则构建
        if not os.path.exists(cve_knowledge_base.vector_index_path):
            logger.info("向量数据库不存在，开始构建...")
            success = cve_knowledge_base.build_vector_knowledge_base(limit=1000)
            if success:
                logger.info("CVE向量知识库构建完成")
            else:
                logger.warning("CVE向量知识库构建失败，将使用文本搜索")
        else:
            logger.info("CVE向量知识库已存在，跳过构建")

        # 将知识库实例存储到应用状态中
        app.state.cve_knowledge_base = cve_knowledge_base
        logger.info("CVE知识库初始化完成")

    except Exception as e:
        logger.error(f"CVE知识库初始化失败: {e}")
        # 创建一个默认实例，即使向量搜索不可用
        app.state.cve_knowledge_base = CVEfixesKnowledgeBase()
        logger.warning("将使用基础的CVE知识库功能")

    # 初始化任务管理器
    task_manager = get_task_manager(settings)
    notification_manager = get_notification_manager()
    logger.info("任务管理器初始化完成")

    yield

    # 关闭时清理
    logger.info("正在关闭CodeVigil应用...")

    # 清理旧任务
    try:
        cleaned = task_manager.cleanup_old_tasks(days=7)
        logger.info(f"清理了 {cleaned} 个旧任务")
    except Exception as e:
        logger.error(f"清理任务失败: {e}")
    logger.info("关闭CodeVigil应用...")


# 创建FastAPI应用
app = FastAPI(
    title="CodeVigil API",
    description="开源仓库代码审计系统",
    version="1.0.0",
    lifespan=lifespan,
)

# 设置中间件
setup_middleware(app)

# 注册路由
app.include_router(api_router, prefix="/api")

# 静态文件服务（用于前端构建文件）
if os.path.exists("../frontend/build"):
    app.mount("/", StaticFiles(directory="../frontend/build", html=True), name="static")


@app.get("/download/{filename}")
async def download_file(filename: str):
    """
    下载生成的报告文件
    """
    try:
        # 检查文件是否存在于报告目录
        file_path = os.path.join("./data/reports", filename)
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="文件不存在")

        # 检查文件扩展名是否安全
        allowed_extensions = [".json", ".html", ".md", ".csv", ".pdf"]
        if not any(filename.endswith(ext) for ext in allowed_extensions):
            raise HTTPException(status_code=400, detail="不支持的文件类型")

        return FileResponse(
            path=file_path, filename=filename, media_type="application/octet-stream"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"下载文件失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# WebSocket连接管理
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, task_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[task_id] = websocket
        logger.info(f"WebSocket连接建立: {task_id}")

    def disconnect(self, task_id: str):
        if task_id in self.active_connections:
            del self.active_connections[task_id]
            logger.info(f"WebSocket连接断开: {task_id}")

    async def send_progress_update(self, task_id: str, progress_data: dict):
        """发送进度更新"""
        if task_id in self.active_connections:
            try:
                await self.active_connections[task_id].send_text(
                    json.dumps(progress_data, ensure_ascii=False)
                )
            except Exception as e:
                logger.error(f"发送进度更新失败 {task_id}: {e}")
                self.disconnect(task_id)

    async def broadcast_system_message(self, message: dict):
        """广播系统消息"""
        disconnected = []
        for task_id, connection in self.active_connections.items():
            try:
                await connection.send_text(json.dumps(message, ensure_ascii=False))
            except Exception as e:
                logger.error(f"广播消息失败 {task_id}: {e}")
                disconnected.append(task_id)

        # 清理断开的连接
        for task_id in disconnected:
            self.disconnect(task_id)


manager = ConnectionManager()


# 在应用启动时设置通知管理器
def setup_notification_system():
    """设置通知系统"""
    notification_manager = get_notification_manager()
    notification_manager.set_websocket_manager(manager)
    return notification_manager


# 在lifespan中调用
notification_manager = setup_notification_system()


@app.websocket("/ws/progress/{task_id}")
async def websocket_progress_endpoint(websocket: WebSocket, task_id: str):
    """WebSocket端点，用于实时进度更新"""
    await manager.connect(task_id, websocket)
    try:
        # 发送当前任务状态
        task_mgr = get_task_manager(settings)
        task = task_mgr.get_task(task_id)
        if task:
            await manager.send_progress_update(
                task_id,
                {
                    "type": "progress",
                    "task_id": task_id,
                    "status": task.status,
                    "progress": task.progress,
                    "current_step": task.current_step,
                    "message": task.message,
                },
            )

        # 保持连接
        while True:
            data = await websocket.receive_text()
            # 处理客户端消息（如心跳包）
            try:
                message = json.loads(data)
                if message.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except json.JSONDecodeError:
                pass

    except WebSocketDisconnect:
        manager.disconnect(task_id)


@app.get("/health")
async def health_check():
    """健康检查端点"""
    return {"status": "healthy", "message": "CodeVigil is running"}


if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=os.getenv("DEBUG", "False").lower() == "true",
    )
