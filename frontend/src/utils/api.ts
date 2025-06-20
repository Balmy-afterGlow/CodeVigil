// API服务工具函数
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export interface ApiResponse<T = any> {
    success: boolean;
    data?: T;
    message?: string;
    error?: string;
}

export interface AnalysisRequest {
    repoUrl: string;
    branch?: string;
    analysisConfig?: {
        enableAiAnalysis: boolean;
        languages: string[];
        excludePatterns: string[];
    };
}

export interface AnalysisResult {
    id: string;
    status: 'pending' | 'running' | 'completed' | 'failed';
    progress: number;
    createdAt: string;
    completedAt?: string;
    repository: {
        url: string;
        branch: string;
        name: string;
    };
    statistics: {
        totalFiles: number;
        scannedFiles: number;
        vulnerabilities: number;
        criticalIssues: number;
        highRiskFiles: number;
    };
    vulnerabilities: Vulnerability[];
    files: FileAnalysis[];
}

export interface Vulnerability {
    id: string;
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    description: string;
    file: string;
    line: number;
    column?: number;
    code: string;
    solution?: string;
    cwe?: string;
    cvss?: number;
}

export interface FileAnalysis {
    path: string;
    language: string;
    size: number;
    complexity: number;
    riskScore: number;
    vulnerabilities: number;
    lastModified: string;
}

class ApiService {
    private async request<T>(
        endpoint: string,
        options: RequestInit = {}
    ): Promise<ApiResponse<T>> {
        const url = `${API_BASE_URL}${endpoint}`;

        try {
            const response = await fetch(url, {
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers,
                },
                ...options,
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            return data;
        } catch (error) {
            console.error('API request failed:', error);
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error',
            };
        }
    }

    // 开始分析
    async startAnalysis(request: AnalysisRequest): Promise<ApiResponse<{ analysisId: string }>> {
        return this.request('/api/analyze', {
            method: 'POST',
            body: JSON.stringify(request),
        });
    }

    // 获取分析状态
    async getAnalysisStatus(analysisId: string): Promise<ApiResponse<AnalysisResult>> {
        return this.request(`/api/analysis/${analysisId}`);
    }

    // 获取分析历史
    async getAnalysisHistory(): Promise<ApiResponse<AnalysisResult[]>> {
        return this.request('/api/analysis/history');
    }

    // 导出报告
    async exportReport(
        analysisId: string,
        format: 'pdf' | 'html' | 'json' | 'csv'
    ): Promise<ApiResponse<{ downloadUrl: string }>> {
        return this.request(`/api/analysis/${analysisId}/export?format=${format}`, {
            method: 'POST',
        });
    }

    // 获取统计数据
    async getStatistics(): Promise<ApiResponse<{
        totalAnalyses: number;
        totalVulnerabilities: number;
        recentAnalyses: AnalysisResult[];
    }>> {
        return this.request('/api/statistics');
    }
}

export const apiService = new ApiService();
