// API服务
import { apiClient } from './apiClient';
import { AnalysisResults, ProgressResponse } from '../types';

// 为了兼容现有代码，创建扩展的AnalysisResult类型
export interface AnalysisResult extends AnalysisResults {
    // 添加前端组件所需的其他字段
    id: string; // 使用task_id作为id
    repository: {
        name: string;
        url: string;
    };
    createdAt: string; // 使用created_at
    completedAt?: string; // 使用completed_at
    progress: number;
    statistics: {
        totalFiles: number;
        scannedFiles: number;
        vulnerabilities: number;
        criticalIssues: number;
    };
}

interface ApiResponse<T> {
    success: boolean;
    data?: T;
    error?: string;
}

class ApiService {
    // 将原始结果转换为前端所需的AnalysisResult格式
    private convertToAnalysisResult(result: AnalysisResults): AnalysisResult {
        // 提取仓库名称（从URL中获取）
        const repoName = result.repository_url.split('/').slice(-1)[0].replace('.git', '') || '未知仓库';

        return {
            ...result,
            id: result.task_id,
            repository: {
                name: repoName,
                url: result.repository_url
            },
            createdAt: result.created_at,
            completedAt: result.completed_at,
            progress: result.status === 'completed' ? 100 : 0,
            statistics: {
                totalFiles: result.summary?.total_files_analyzed || 0,
                scannedFiles: result.summary?.total_files_analyzed || 0,
                vulnerabilities: result.summary?.total_vulnerabilities || 0,
                criticalIssues: result.summary?.critical_count || 0
            }
        };
    }

    // 分析相关API
    async getAnalysisStatus(taskId: string): Promise<ApiResponse<AnalysisResult>> {
        try {
            const progress = await apiClient.getAnalysisProgress(taskId);

            if (progress.status === 'completed') {
                const results = await apiClient.getAnalysisResults(taskId);
                return {
                    success: true,
                    data: this.convertToAnalysisResult(results)
                };
            }

            // 创建一个临时的分析结果对象
            const tempResult: AnalysisResults = {
                task_id: progress.task_id,
                repository_url: '',
                status: progress.status,
                summary: {
                    total_files_analyzed: 0,
                    total_vulnerabilities: 0,
                    risk_level: '',
                    critical_count: 0,
                    high_count: 0,
                    medium_count: 0,
                    low_count: 0,
                    analysis_duration_seconds: 0
                },
                high_risk_files: [],
                vulnerabilities: [],
                created_at: new Date().toISOString(),
                completed_at: undefined
            };

            return {
                success: true,
                data: this.convertToAnalysisResult({
                    ...tempResult,
                    // 使用progress对象中的数据更新临时结果
                    status: progress.status,
                    progress: progress.progress
                } as AnalysisResults)
            };
        } catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : '获取分析状态失败'
            };
        }
    }

    // 获取历史分析记录
    async getAnalysisHistory(): Promise<ApiResponse<AnalysisResult[]>> {
        try {
            const { tasks } = await apiClient.getTasks('completed');

            // 只获取已完成的分析任务
            const completedTasks = tasks.filter(task => task.status === 'completed');

            // 获取每个任务的详细结果
            const analysisResults: AnalysisResult[] = [];

            for (const task of completedTasks.slice(0, 5)) { // 限制为最近5条记录
                try {
                    const result = await apiClient.getAnalysisResults(task.task_id);
                    // 转换为前端需要的格式
                    analysisResults.push(this.convertToAnalysisResult(result));
                } catch (err) {
                    console.error(`获取任务 ${task.task_id} 详细信息失败:`, err);
                }
            }

            return {
                success: true,
                data: analysisResults
            };
        } catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : '获取分析历史失败'
            };
        }
    }

    // 删除分析记录
    async deleteAnalysis(taskId: string): Promise<ApiResponse<void>> {
        try {
            await apiClient.deleteTask(taskId);
            return {
                success: true
            };
        } catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : '删除分析记录失败'
            };
        }
    }

    // 导出分析报告
    async exportAnalysis(taskId: string, format: string): Promise<ApiResponse<string>> {
        try {
            const result = await apiClient.exportResults(taskId, format);
            return {
                success: true,
                data: result.download_url
            };
        } catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : '导出分析报告失败'
            };
        }
    }
}

export const apiService = new ApiService();
