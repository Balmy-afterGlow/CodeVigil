"""
通知系统 - 用于发送实时进度更新
"""

from typing import Dict, Any, Optional

logger = None  # 简化版本，避免导入问题


class NotificationManager:
    """通知管理器"""

    def __init__(self):
        self.websocket_manager = None

    def set_websocket_manager(self, manager):
        """设置WebSocket管理器"""
        self.websocket_manager = manager

    async def send_progress_update(self, task_id: str, progress_data: Dict[str, Any]):
        """发送进度更新通知"""
        if self.websocket_manager:
            try:
                await self.websocket_manager.send_progress_update(
                    task_id, progress_data
                )
            except Exception as e:
                if logger:
                    logger.error(f"发送进度通知失败: {e}")

    async def send_task_completed(self, task_id: str, result: Dict[str, Any]):
        """发送任务完成通知"""
        notification = {
            "type": "task_completed",
            "task_id": task_id,
            "message": "分析任务已完成",
            "result": result,
        }
        await self.send_progress_update(task_id, notification)

    async def send_task_failed(self, task_id: str, error: str):
        """发送任务失败通知"""
        notification = {
            "type": "task_failed",
            "task_id": task_id,
            "message": "分析任务失败",
            "error": error,
        }
        await self.send_progress_update(task_id, notification)

    async def send_progress(
        self, task_id: str, progress: int, step: str, message: Optional[str] = None
    ):
        """发送进度通知"""
        notification = {
            "type": "progress_update",
            "task_id": task_id,
            "progress": progress,
            "current_step": step,
            "message": message or step,
        }
        await self.send_progress_update(task_id, notification)


# 全局通知管理器实例
notification_manager = NotificationManager()


def get_notification_manager() -> NotificationManager:
    """获取通知管理器实例"""
    return notification_manager
