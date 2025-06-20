"""
API路由配置
"""

import time
import os
from dataclasses import asdict
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import List, Optional, Dict, Any
import json

from models.request_models import AnalysisRequest, RepositoryUrl
from models.response_models import AnalysisResponse, ProgressResponse
from core.repository.manager import RepositoryManager
from core.analyzer.file_analyzer import FileAnalyzer
from core.ai.analyzer import AIAnalyzer
from core.task_manager import get_task_manager
from core.rag.knowledge_base import knowledge_base
from core.rag.query_engine import rag_query_engine
from core.report_generator import ReportGenerator
from core.config import get_settings
from utils.logger import get_logger
from core.security_rules import get_security_rule_engine

logger = get_logger(__name__)
settings = get_settings()

# 创建API路由器
api_router = APIRouter()

# 创建核心服务实例
repo_manager = RepositoryManager()
file_analyzer = FileAnalyzer()
ai_analyzer = AIAnalyzer()
task_manager = get_task_manager(settings)
report_generator = ReportGenerator()


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
    try:
        task = task_manager.get_task(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")

        return ProgressResponse(
            task_id=task_id,
            status=task.status,
            progress=task.progress,
            current_step=task.current_step,
            message=task.message,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取任务进度失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/analysis/{task_id}/results")
async def get_analysis_results(task_id: str):
    """
    获取分析结果
    """
    try:
        task = task_manager.get_task(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="任务不存在")

        if task.status != "completed":
            raise HTTPException(status_code=400, detail="任务尚未完成")

        return task.result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取分析结果失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post("/export/{task_id}/{format}")
async def export_results(task_id: str, format: str):
    """
    导出分析结果

    Args:
        task_id: 任务ID
        format: 导出格式 (json, pdf, markdown, html, csv)
    """
    try:
        if format not in ["json", "pdf", "markdown", "html", "csv"]:
            raise HTTPException(status_code=400, detail="不支持的导出格式")

        # 获取任务结果
        task = task_manager.get_task(task_id)
        if not task or task.status != "completed":
            raise HTTPException(status_code=404, detail="任务结果不存在或未完成")

        # 使用报告生成器生成报告
        export_path = await report_generator.generate_report(
            task.result, format, f"{task_id}_report"
        )

        return {
            "export_path": export_path,
            "download_url": f"/download/{os.path.basename(export_path)}",
            "format": format,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"导出结果失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post("/knowledge/query")
async def query_knowledge_base(query: str):
    """
    查询RAG知识库
    """
    try:
        if not query.strip():
            raise HTTPException(status_code=400, detail="查询内容不能为空")

        try:
            results = rag_query_engine.query(query)
        except Exception as e:
            logger.warning(f"RAG查询失败: {e}")
            results = "查询服务暂不可用"

        return {"query": query, "results": results, "timestamp": time.time()}
    except Exception as e:
        logger.error(f"知识库查询失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/tasks")
async def list_tasks(status: Optional[str] = None, limit: int = 50):
    """
    获取任务列表
    """
    try:
        tasks = task_manager.list_tasks(status=status, limit=limit)
        return {
            "tasks": [
                {
                    "task_id": task.task_id,
                    "status": task.status,
                    "progress": task.progress,
                    "created_at": task.created_at,
                    "updated_at": task.updated_at,
                    "task_type": task.task_type,
                }
                for task in tasks
            ],
            "total": len(tasks),
        }
    except Exception as e:
        logger.error(f"获取任务列表失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.delete("/tasks/{task_id}")
async def delete_task(task_id: str):
    """
    删除任务
    """
    try:
        success = task_manager.delete_task(task_id)
        if not success:
            raise HTTPException(status_code=404, detail="任务不存在")

        return {"message": "任务删除成功"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"删除任务失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/system/stats")
async def get_system_stats():
    """
    获取系统统计信息
    """
    try:
        stats = task_manager.get_system_stats()
        return {
            "task_stats": stats,
            "knowledge_base_loaded": knowledge_base.is_loaded(),
            "system_status": "healthy",
        }
    except Exception as e:
        logger.error(f"获取系统统计失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/security/rules")
async def get_security_rules():
    """
    获取安全规则列表
    """
    try:
        security_engine = get_security_rule_engine()
        stats = security_engine.get_statistics()
        return {
            "rules": [
                {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "description": rule.description,
                    "severity": rule.severity.value,
                    "category": rule.category,
                    "language": rule.language,
                    "cwe_id": rule.cwe_id,
                }
                for rule in security_engine.rules
            ],
            "statistics": stats,
        }
    except Exception as e:
        logger.error(f"获取安全规则失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/security/rules/{category}")
async def get_security_rules_by_category(category: str):
    """
    按类别获取安全规则
    """
    try:
        security_engine = get_security_rule_engine()
        rules = security_engine.get_rules_by_category(category)
        return {
            "category": category,
            "rules": [
                {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "description": rule.description,
                    "severity": rule.severity.value,
                    "fix_suggestion": rule.fix_suggestion,
                }
                for rule in rules
            ],
        }
    except Exception as e:
        logger.error(f"获取安全规则失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/docs/capabilities")
async def get_system_capabilities():
    """
    获取系统能力描述
    """
    return {
        "analysis_capabilities": {
            "supported_languages": [
                "Python",
                "JavaScript",
                "TypeScript",
                "Java",
                "C/C++",
                "Go",
                "Rust",
                "PHP",
                "Ruby",
                "Shell",
            ],
            "security_checks": [
                "SQL注入检测",
                "XSS漏洞检测",
                "身份验证问题",
                "硬编码密码检测",
                "文件操作安全",
                "加密算法检查",
                "命令注入检测",
                "路径遍历检测",
            ],
            "analysis_types": [
                "静态代码分析",
                "AST语法分析",
                "Git历史分析",
                "AI增强分析",
                "RAG安全建议",
            ],
        },
        "export_formats": ["HTML", "Markdown", "JSON", "CSV", "PDF"],
        "real_time_features": ["WebSocket进度推送", "任务状态跟踪", "实时分析结果"],
        "ai_features": {
            "enabled": True,
            "rag_knowledge_base": True,
            "security_recommendations": True,
            "code_review_suggestions": True,
        },
    }


@api_router.get("/health/detailed")
async def detailed_health_check():
    """
    详细健康检查
    """
    try:
        # 检查各个组件状态
        health_status = {
            "status": "healthy",
            "timestamp": time.time(),
            "components": {},
        }

        # 检查任务管理器
        try:
            task_stats = task_manager.get_system_stats()
            health_status["components"]["task_manager"] = {
                "status": "healthy",
                "stats": task_stats,
            }
        except Exception as e:
            health_status["components"]["task_manager"] = {
                "status": "unhealthy",
                "error": str(e),
            }
            health_status["status"] = "degraded"

        # 检查知识库
        try:
            kb_loaded = knowledge_base.is_loaded()
            health_status["components"]["knowledge_base"] = {
                "status": "healthy" if kb_loaded else "not_loaded",
                "loaded": kb_loaded,
            }
        except Exception as e:
            health_status["components"]["knowledge_base"] = {
                "status": "unhealthy",
                "error": str(e),
            }

        # 检查安全规则引擎
        try:
            security_engine = get_security_rule_engine()
            stats = security_engine.get_statistics()
            health_status["components"]["security_engine"] = {
                "status": "healthy",
                "stats": stats,
            }
        except Exception as e:
            health_status["components"]["security_engine"] = {
                "status": "unhealthy",
                "error": str(e),
            }

        return health_status

    except Exception as e:
        logger.error(f"健康检查失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def run_analysis_pipeline(
    task_id: str,
    repo_url: str,
    branch: Optional[str] = None,
    options: Optional[dict] = None,
):
    """
    运行完整的分析流水线
    """
    try:
        logger.info(f"开始执行分析任务: {task_id}")

        # 创建任务
        task_manager.create_task(task_id, "repository_analysis")
        task_manager.update_task_progress(task_id, 10, "正在克隆仓库...")

        # 1. 克隆仓库
        repo_info = await repo_manager.clone_repository(repo_url, branch)
        task_manager.update_task_progress(task_id, 30, "正在分析文件...")

        # 2. 文件分析
        file_results = await file_analyzer.analyze_files_batch(
            repo_info.local_path, repo_info.filtered_files
        )
        task_manager.update_task_progress(task_id, 50, "正在筛选高风险文件...")

        # 3. 获取高风险文件
        top_risk_files = file_analyzer.get_top_risk_files(file_results, 20)
        task_manager.update_task_progress(task_id, 70, "正在进行AI深度分析...")

        # 4. AI深度分析 - 使用新的批量分析
        task_manager.update_task_progress(task_id, 70, "正在进行AI深度分析...")

        # 准备AI分析输入 - 包含完整的Git历史分析
        from core.ai.analyzer import FileAnalysisInput

        ai_inputs = []

        for file_result in top_risk_files:
            try:
                # 读取文件内容
                full_path = os.path.join(repo_info.local_path, file_result.file_path)
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                # 获取该文件的Git历史分析
                git_history = repo_manager.extract_file_git_history(
                    repo_info.local_path, file_result.file_path
                )

                ai_input = FileAnalysisInput(
                    file_path=file_result.file_path,
                    content=content,
                    language=file_result.language,
                    git_commits=git_history,  # 使用真实的Git历史数据
                    ast_features=file_result.ast_features,
                    existing_issues=[
                        {
                            "severity": issue.severity,
                            "rule_id": issue.rule_id,
                            "message": issue.message,
                            "line_number": issue.line_number,
                        }
                        for issue in file_result.security_issues
                    ],
                )
                ai_inputs.append(ai_input)

            except Exception as e:
                logger.warning(f"准备AI输入失败 {file_result.file_path}: {e}")

        # 使用严格的三阶段AI分析
        three_stage_results = await ai_analyzer.analyze_files_strict_three_stage(
            ai_inputs,
            stage1_batch_size=10,  # 第一阶段每批处理10个文件
            risk_threshold=70.0,  # 风险阈值70分以上为高危
        )

        # 提取最终的AI分析结果（第三阶段结果）
        ai_results = three_stage_results.get(
            "stage3_cve_enhanced_diff_generation", {}
        ).get("results", [])

        # 如果第三阶段结果为空，使用第二阶段结果作为备用
        if not ai_results:
            ai_results = three_stage_results.get(
                "stage2_detailed_vulnerability_analysis", {}
            ).get("results", [])

        # 5. RAG增强分析 - 获取相关安全建议
        task_manager.update_task_progress(task_id, 85, "正在生成安全建议...")

        # 对每个AI分析结果添加RAG建议
        for ai_result in ai_results:
            if ai_result.vulnerabilities:
                for vuln in ai_result.vulnerabilities:
                    # 查询相关的安全知识
                    try:
                        rag_suggestions = rag_query_engine.query(
                            f"如何修复 {vuln.get('type', '')} 类型的安全漏洞: {vuln.get('description', '')}"
                        )
                        vuln["rag_suggestions"] = rag_suggestions
                    except Exception as e:
                        logger.warning(f"RAG查询失败: {e}")
                        vuln["rag_suggestions"] = "暂无相关建议"

        task_manager.update_task_progress(task_id, 95, "正在保存结果...")

        # 6. 保存结果 - 包含完整的三阶段分析信息
        final_results = {
            "task_id": task_id,
            "repository_info": asdict(repo_info),
            "file_analysis": [asdict(result) for result in file_results],
            "three_stage_ai_analysis": three_stage_results,  # 完整的三阶段结果
            "final_ai_results": [
                asdict(result) for result in ai_results
            ],  # 最终AI分析结果
            "summary": {
                "total_files": len(file_results),
                "high_risk_files": len(top_risk_files),
                "stage1_files_scored": three_stage_results.get(
                    "stage1_batch_risk_assessment", {}
                ).get("total_files", 0),
                "stage2_files_analyzed": three_stage_results.get(
                    "stage2_detailed_vulnerability_analysis", {}
                ).get("analyzed_files", 0),
                "stage3_files_enhanced": three_stage_results.get(
                    "stage3_cve_enhanced_diff_generation", {}
                ).get("enhanced_files", 0),
                "vulnerabilities_found": sum(
                    len(r.vulnerabilities)
                    for r in ai_results
                    if hasattr(r, "vulnerabilities") and r.vulnerabilities
                ),
                "cve_references": three_stage_results.get("summary", {}).get(
                    "cve_references_generated", 0
                ),
                "total_analysis_time": three_stage_results.get("summary", {}).get(
                    "total_analysis_time", 0
                ),
                "analysis_timestamp": time.time(),
                "repository_url": repo_url,
                "branch": branch or "main",
            },
        }

        # 完成任务
        task_manager.complete_task(task_id, final_results)

        # 清理临时仓库
        repo_manager.cleanup_repository(repo_info.local_path)

        logger.info(f"分析任务完成: {task_id}")

    except Exception as e:
        logger.error(f"分析任务失败 {task_id}: {e}")
        task_manager.fail_task(task_id, str(e))


@api_router.post("/generate-cve-enhanced-diff")
async def generate_cve_enhanced_diff(vulnerability_info: Dict[str, Any]):
    """
    基于漏洞信息和CVE知识库生成增强的修复diff
    """
    try:
        # 初始化CVE知识库
        from ..core.cve_knowledge_base import CVEFixesKnowledgeBase

        cve_kb = CVEFixesKnowledgeBase()

        # 提取漏洞信息
        vuln_description = vulnerability_info.get("description", "")
        code_snippet = vulnerability_info.get("code_snippet", "")
        file_path = vulnerability_info.get("file_path", "")
        language = vulnerability_info.get("language", "")

        # 生成CVE上下文
        cve_context = cve_kb.generate_diff_context_for_ai(
            vulnerability_description=vuln_description,
            code_snippet=code_snippet,
            language=language,
            limit=3,
        )

        # 搜索相关CVE
        similar_cves = cve_kb.search_similar_vulnerabilities(
            vulnerability_description=vuln_description,
            code_snippet=code_snippet,
            language=language,
            limit=5,
        )

        return {
            "status": "success",
            "cve_context": cve_context,
            "similar_cves": similar_cves,
            "file_path": file_path,
            "recommendations": "基于CVE知识库的修复建议已生成",
        }

    except Exception as e:
        logger.error(f"生成CVE增强diff失败: {e}")
        return {"status": "error", "message": str(e)}


@api_router.post("/ai-enhanced-analysis")
async def ai_enhanced_analysis(analysis_request: Dict[str, Any]):
    """
    AI增强分析：在初次AI分析后，结合CVE知识库进行二次分析
    用于生成更精确的diff和CVE关联
    """
    try:
        # 获取初次分析结果
        vulnerabilities = analysis_request.get("vulnerabilities", [])
        file_path = analysis_request.get("file_path", "")

        if not vulnerabilities:
            return {"status": "error", "message": "未提供漏洞信息"}

        # 初始化AI分析器和CVE知识库
        from ..core.ai.analyzer import AIAnalyzer
        from ..core.cve_knowledge_base import CVEFixesKnowledgeBase

        ai_analyzer = AIAnalyzer()
        cve_kb = CVEFixesKnowledgeBase()

        enhanced_results = []

        for vuln in vulnerabilities:
            try:
                # 为每个漏洞生成CVE上下文
                cve_context = cve_kb.generate_diff_context_for_ai(
                    vulnerability_description=vuln.get("description", ""),
                    code_snippet=vuln.get("code_snippet", ""),
                    language=ai_analyzer._extract_language_from_path(file_path),
                )

                # 搜索相关CVE
                similar_cves = cve_kb.search_similar_vulnerabilities(
                    vulnerability_description=vuln.get("description", ""),
                    code_snippet=vuln.get("code_snippet", ""),
                    language=ai_analyzer._extract_language_from_path(file_path),
                    limit=3,
                )

                # 使用AI生成增强的修复建议
                enhanced_remediation = await ai_analyzer._generate_enhanced_remediation(
                    vuln, similar_cves, file_path
                )

                enhanced_vuln = vuln.copy()
                enhanced_vuln.update(
                    {
                        "cve_context": cve_context,
                        "related_cves": similar_cves,
                        "enhanced_remediation": enhanced_remediation,
                    }
                )

                enhanced_results.append(enhanced_vuln)

            except Exception as e:
                logger.warning(f"增强分析失败 {vuln.get('title', 'Unknown')}: {e}")
                enhanced_results.append(vuln)

        return {
            "status": "success",
            "file_path": file_path,
            "enhanced_vulnerabilities": enhanced_results,
            "summary": f"成功增强分析了 {len(enhanced_results)} 个漏洞",
        }

    except Exception as e:
        logger.error(f"AI增强分析失败: {e}")
        return {"status": "error", "message": str(e)}
