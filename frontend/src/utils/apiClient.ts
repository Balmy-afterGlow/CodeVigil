// API 客户端工具
import type {
    AnalysisRequest,
    AnalysisResponse,
    ProgressResponse,
    AnalysisResults,
    ExportResult,
    TaskInfo,
    SystemStats,
    SecurityRule,
    SystemCapabilities
} from '../types';
import { API_CONFIG } from './constants';

const API_BASE_URL = API_CONFIG.baseURL;

class ApiClient {
    private baseURL: string;

    constructor(baseURL = API_BASE_URL) {
        this.baseURL = baseURL;
    }

    private async request<T>(
        endpoint: string,
        options: RequestInit = {}
    ): Promise<T> {
        const url = `${this.baseURL}${endpoint}`;

        const config: RequestInit = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers,
            },
            ...options,
        };

        const response = await fetch(url, config);

        if (!response.ok) {
            throw new Error(`API Error: ${response.status} ${response.statusText}`);
        }

        return response.json();
    }

    // 分析相关 API
    async startAnalysis(request: AnalysisRequest): Promise<AnalysisResponse> {
        return this.request<AnalysisResponse>('/analyze/repository', {
            method: 'POST',
            body: JSON.stringify(request),
        });
    }

    async getAnalysisProgress(taskId: string): Promise<ProgressResponse> {
        return this.request<ProgressResponse>(`/analysis/${taskId}/progress`);
    }

    async getAnalysisResults(taskId: string): Promise<AnalysisResults> {
        return this.request<AnalysisResults>(`/analysis/${taskId}/results`);
    }

    async exportResults(taskId: string, format: string): Promise<ExportResult> {
        return this.request<ExportResult>(`/export/${taskId}/${format}`, {
            method: 'POST',
        });
    }

    // 任务管理 API
    async getTasks(status?: string, limit = 50): Promise<{ tasks: TaskInfo[]; total: number }> {
        const params = new URLSearchParams();
        if (status) params.append('status', status);
        params.append('limit', limit.toString());

        return this.request<{ tasks: TaskInfo[]; total: number }>(`/tasks?${params.toString()}`);
    }

    async deleteTask(taskId: string): Promise<{ message: string }> {
        return this.request<{ message: string }>(`/tasks/${taskId}`, {
            method: 'DELETE',
        });
    }

    // 系统信息 API
    async getSystemStats(): Promise<SystemStats> {
        return this.request<SystemStats>('/system/stats');
    }

    async getSecurityRules(): Promise<{ rules: SecurityRule[]; statistics: any }> {
        return this.request<{ rules: SecurityRule[]; statistics: any }>('/security/rules');
    }

    async getSecurityRulesByCategory(category: string): Promise<{ category: string; rules: SecurityRule[] }> {
        return this.request<{ category: string; rules: SecurityRule[] }>(`/security/rules/${category}`);
    }

    async getSystemCapabilities(): Promise<SystemCapabilities> {
        return this.request<SystemCapabilities>('/docs/capabilities');
    }

    // 健康检查 API
    async healthCheck(): Promise<{ status: string; message: string }> {
        return this.request<{ status: string; message: string }>('/health');
    }

    async detailedHealthCheck(): Promise<any> {
        return this.request<any>('/health/detailed');
    }

    // 下载文件工具
    getDownloadUrl(path: string): string {
        return `${this.baseURL}${path}`;
    }
}

// 导出单例实例
export const apiClient = new ApiClient();
export default ApiClient;
