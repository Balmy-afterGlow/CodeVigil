"""
API路由配置
"""

import time
import os
from dataclasses import asdict
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import List
import json

from models.request_models import AnalysisRequest, RepositoryUrl
from models.response_models import AnalysisResponse, ProgressResponse
from core.repository.manager import RepositoryManager
from core.analyzer.file_analyzer import FileAnalyzer
from core.ai.analyzer import AIAnalyzer
from utils.logger import get_logger

logger = get_logger(__name__)

# 创建API路由器
api_router = APIRouter()

# 创建核心服务实例
repo_manager = RepositoryManager()
file_analyzer = FileAnalyzer()
ai_analyzer = AIAnalyzer()


@api_router.get("/health")
async def health_check():
    """健康检查"""
    return {"status": "healthy", "message": "CodeVigil API正在运行"}


@api_router.post("/analyze/repository", response_model=AnalysisResponse)
async def analyze_repository(
    request: AnalysisRequest, background_tasks: BackgroundTasks
):
    """
    启动仓库分析任务
    """
    try:
        logger.info(f"收到仓库分析请求: {request.repository_url}")

        # 启动后台分析任务
        task_id = f"analysis_{hash(request.repository_url)}_{int(time.time())}"
        background_tasks.add_task(
            run_analysis_pipeline,
            task_id,
            request.repository_url,
            request.branch,
            request.analysis_options,
        )

        return AnalysisResponse(
            task_id=task_id, status="started", message="分析任务已启动"
        )

    except Exception as e:
        logger.error(f"启动分析任务失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/analysis/{task_id}/progress", response_model=ProgressResponse)
async def get_analysis_progress(task_id: str):
    """
    获取分析进度
    """
    # 这里应该从Redis或数据库获取进度信息
    # 暂时返回模拟数据
    return ProgressResponse(
        task_id=task_id,
        status="running",
        progress=50,
        current_step="文件分析中",
        message="正在分析高风险文件...",
    )


@api_router.get("/analysis/{task_id}/results")
async def get_analysis_results(task_id: str):
    """
    获取分析结果
    """
    try:
        # 从存储中获取结果
        results_file = f"./data/reports/{task_id}_results.json"
        if os.path.exists(results_file):
            with open(results_file, "r", encoding="utf-8") as f:
                results = json.load(f)
            return results
        else:
            raise HTTPException(status_code=404, detail="分析结果不存在")

    except Exception as e:
        logger.error(f"获取分析结果失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post("/export/{task_id}/{format}")
async def export_results(task_id: str, format: str):
    """
    导出分析结果

    Args:
        task_id: 任务ID
        format: 导出格式 (json, pdf, markdown)
    """
    try:
        if format not in ["json", "pdf", "markdown"]:
            raise HTTPException(status_code=400, detail="不支持的导出格式")

        # 实现导出逻辑
        export_path = f"./data/reports/{task_id}_report.{format}"

        # 这里应该实现实际的导出功能
        return {
            "export_path": export_path,
            "download_url": f"/download/{task_id}_report.{format}",
        }

    except Exception as e:
        logger.error(f"导出结果失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def run_analysis_pipeline(
    task_id: str, repo_url: str, branch: str = None, options: dict = None
):
    """
    运行完整的分析流水线
    """
    try:
        logger.info(f"开始执行分析任务: {task_id}")

        # 1. 克隆仓库
        repo_info = await repo_manager.clone_repository(repo_url, branch)

        # 2. 文件分析
        file_results = await file_analyzer.analyze_files_batch(
            repo_info.local_path, repo_info.filtered_files
        )

        # 3. 获取高风险文件
        top_risk_files = file_analyzer.get_top_risk_files(file_results, 20)

        # 4. AI深度分析
        ai_results = await ai_analyzer.analyze_high_risk_files(
            repo_info.local_path, [asdict(result) for result in top_risk_files]
        )

        # 5. 保存结果
        final_results = {
            "task_id": task_id,
            "repository_info": asdict(repo_info),
            "file_analysis": [asdict(result) for result in file_results],
            "ai_analysis": [asdict(result) for result in ai_results],
            "summary": {
                "total_files": len(file_results),
                "high_risk_files": len(top_risk_files),
                "vulnerabilities_found": sum(
                    len(r.vulnerabilities) for r in ai_results
                ),
            },
        }

        # 保存到文件
        results_file = f"./data/reports/{task_id}_results.json"
        os.makedirs(os.path.dirname(results_file), exist_ok=True)

        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(final_results, f, indent=2, ensure_ascii=False)

        # 清理临时仓库
        repo_manager.cleanup_repository(repo_info.local_path)

        logger.info(f"分析任务完成: {task_id}")

    except Exception as e:
        logger.error(f"分析任务失败 {task_id}: {e}")
        # 这里应该更新任务状态为失败
