"""
任务管理器 - 管理分析任务的生命周期
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from core.config import Settings

# 避免循环导入，使用TYPE_CHECKING
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.notification import NotificationManager


@dataclass
class TaskInfo:
    """任务信息"""

    task_id: str
    task_type: str
    status: str
    progress: int = 0
    current_step: str = ""
    message: str = ""
    created_at: Optional[float] = None
    updated_at: Optional[float] = None
    result: Optional[Dict] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now().timestamp()
        if self.updated_at is None:
            self.updated_at = self.created_at


class TaskManager:
    """任务管理器"""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.tasks: Dict[str, TaskInfo] = {}
        self.notification_manager: Optional["NotificationManager"] = None

    def set_notification_manager(self, notification_manager: "NotificationManager"):
        """设置通知管理器"""
        self.notification_manager = notification_manager

    def create_task(self, task_id: str, task_type: str) -> TaskInfo:
        """创建新任务"""
        task = TaskInfo(
            task_id=task_id,
            task_type=task_type,
            status="pending",
            progress=0,
            current_step="初始化任务",
            message="任务已创建",
        )
        self.tasks[task_id] = task
        return task

    def get_task(self, task_id: str) -> Optional[TaskInfo]:
        """获取任务信息"""
        return self.tasks.get(task_id)

    async def update_task_progress(
        self, task_id: str, progress: int, step: str, message: Optional[str] = None
    ):
        """更新任务进度"""
        if task_id in self.tasks:
            task = self.tasks[task_id]
            task.progress = progress
            task.current_step = step
            task.message = message or step
            task.updated_at = datetime.now().timestamp()

            # 发送进度通知
            if self.notification_manager:
                await self.notification_manager.send_progress(
                    task_id, progress, step, message
                )

    def complete_task(self, task_id: str, result: Dict):
        """完成任务"""
        if task_id in self.tasks:
            task = self.tasks[task_id]
            task.status = "completed"
            task.progress = 100
            task.current_step = "任务完成"
            task.message = "分析任务已完成"
            task.result = result
            task.updated_at = datetime.now().timestamp()

    def fail_task(self, task_id: str, error: str):
        """任务失败"""
        if task_id in self.tasks:
            task = self.tasks[task_id]
            task.status = "failed"
            task.current_step = "任务失败"
            task.message = f"任务失败: {error}"
            task.error = error
            task.updated_at = datetime.now().timestamp()

    def list_tasks(
        self, status: Optional[str] = None, limit: int = 50
    ) -> List[TaskInfo]:
        """列出任务"""
        tasks = list(self.tasks.values())
        if status:
            tasks = [t for t in tasks if t.status == status]
        return sorted(tasks, key=lambda x: x.created_at or 0, reverse=True)[:limit]

    def delete_task(self, task_id: str) -> bool:
        """删除任务"""
        if task_id in self.tasks:
            del self.tasks[task_id]
            return True
        return False

    def cleanup_old_tasks(self, days: int = 7) -> int:
        """清理旧任务"""
        cutoff_time = datetime.now().timestamp() - (days * 24 * 3600)
        old_tasks = [
            task_id
            for task_id, task in self.tasks.items()
            if (task.created_at or 0) < cutoff_time
            and task.status in ["completed", "failed"]
        ]
        for task_id in old_tasks:
            del self.tasks[task_id]
        return len(old_tasks)

    def get_system_stats(self) -> Dict[str, Any]:
        """获取系统统计"""
        total = len(self.tasks)
        by_status: Dict[str, int] = {}
        for task in self.tasks.values():
            by_status[task.status] = by_status.get(task.status, 0) + 1

        return {
            "total_tasks": total,
            "by_status": by_status,
            "active_tasks": by_status.get("running", 0) + by_status.get("pending", 0),
        }


# 全局任务管理器实例
_task_manager: Optional[TaskManager] = None


def get_task_manager(settings: Settings) -> TaskManager:
    """获取任务管理器实例"""
    global _task_manager
    if _task_manager is None:
        _task_manager = TaskManager(settings)
    return _task_manager
