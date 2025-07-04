// 类型定义
export interface AnalysisOptions {
    enable_ai_analysis: boolean;
    max_files_to_analyze: number;
    include_low_risk: boolean;
    analysis_depth: 'light' | 'normal' | 'deep';
}

// 请求模型
export interface AnalysisRequest {
    repository_url: string;
    branch?: string;
    analysis_options?: AnalysisOptions;
}

// 响应模型
export interface AnalysisResponse {
    task_id: string;
    status: string;
    message: string;
    created_at?: string;
}

export interface ProgressResponse {
    task_id: string;
    status: string;
    progress: number;
    current_step: string;
    message: string;
    eta_minutes?: number;
}

// CVE参考信息
export interface CVEReference {
    cve_id: string;
    description: string;
    severity: string;
    cvss_score?: number;
    url?: string;
    fix_commit_url?: string;
}

// 代码差异块
export interface CodeDiffBlock {
    description: string;
    original_code: string;
    fixed_code: string;
    start_line: number;
    end_line: number;
    explanation: string;
}

export interface VulnerabilityInfo {
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    cwe_id?: string;
    description: string;
    file_path: string;
    line_number: number;
    confidence: number;
    impact?: string;
    remediation?: string;
    code_snippet?: string;
    cve_references?: CVEReference[];
    fix_suggestions?: CodeDiffBlock[];
}

export interface FileRiskInfo {
    file_path: string;
    risk_score: number;
    language: string;
    vulnerabilities_count: number;
    lines_of_code: number;
}

// 高危文件详细信息
export interface HighRiskFileInfo {
    file_path: string;
    risk_score: number;
    risk_level: 'critical' | 'high' | 'medium' | 'low';
    language: string;
    lines_of_code: number;
    vulnerabilities: VulnerabilityInfo[];
    ai_analysis_summary?: string;
    confidence?: number;
    analysis_reasoning?: string;
}

export interface AnalysisResults {
    task_id: string;
    repository_url: string;
    status: string;
    summary: {
        total_files_analyzed: number;
        total_vulnerabilities: number;
        high_risk_files_count: number;
        risk_level: string;
        critical_count: number;
        high_count: number;
        medium_count: number;
        low_count: number;
        analysis_duration_seconds: number;
        ai_stage1_files?: number;
        ai_stage2_files?: number;
        ai_stage3_files?: number;
        cve_references_count?: number;
    };
    high_risk_files: HighRiskFileInfo[];
    vulnerabilities: VulnerabilityInfo[];
    created_at: string;
    completed_at?: string;
}

export interface ProgressMessage {
    task_id: string;
    status: string;
    progress: number;
    current_step: string;
    message: string;
}

export interface ExportResult {
    export_path: string;
    download_url: string;
    format: string;
}

export interface TaskInfo {
    task_id: string;
    status: string;
    progress: number;
    created_at: string;
    updated_at: string;
    task_type: string;
}

export interface SystemStats {
    active_tasks: number;
    completed_tasks: number;
    failed_tasks: number;
    total_repositories_analyzed: number;
    total_vulnerabilities_found: number;
    system_uptime_hours: number;
}

export interface SecurityRule {
    id: string;
    name: string;
    category: string;
    severity: string;
    description: string;
    enabled: boolean;
}

export interface SystemCapabilities {
    supported_languages: string[];
    supported_export_formats: string[];
    max_repository_size_mb: number;
    enable_ai_analysis: boolean;
}

// 莫兰迪配色方案
export const morandiColors = {
    primary: '#94a3b8',
    secondary: '#cbd5e1',
    accent: '#64748b',
    background: '#f8fafc',
    surface: '#f1f5f9',
    text: '#334155',
    error: '#ef4444',
    warning: '#f97316',
    success: '#22c55e',
    muted: '#94a3b8',

    // 扩展颜色
    gray: {
        50: '#f8fafc',
        100: '#f1f5f9',
        200: '#e2e8f0',
        300: '#cbd5e1',
        400: '#94a3b8',
        500: '#64748b',
        600: '#475569',
        700: '#334155',
        800: '#1e293b',
        900: '#0f172a',
    },

    // 风险等级颜色
    risk: {
        critical: '#ef4444',
        high: '#f97316',
        medium: '#f59e0b',
        low: '#10b981',
        info: '#3b82f6',
    }
};