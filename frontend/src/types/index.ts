// 全局类型定义

export type AnalysisStatus = 'pending' | 'running' | 'completed' | 'failed';
export type VulnerabilitySeverity = 'critical' | 'high' | 'medium' | 'low';
export type ExportFormat = 'pdf' | 'html' | 'json' | 'csv';

export interface Repository {
    url: string;
    branch: string;
    name: string;
    owner?: string;
    description?: string;
    stars?: number;
    forks?: number;
    lastUpdated?: string;
}

export interface AnalysisConfig {
    enableAiAnalysis: boolean;
    languages: string[];
    excludePatterns: string[];
    maxFileSize?: number;
    timeout?: number;
}

export interface AnalysisRequest {
    repoUrl: string;
    branch?: string;
    analysisConfig?: AnalysisConfig;
}

export interface AnalysisStatistics {
    totalFiles: number;
    scannedFiles: number;
    skippedFiles: number;
    vulnerabilities: number;
    criticalIssues: number;
    highRiskFiles: number;
    mediumRiskFiles: number;
    lowRiskFiles: number;
    duplicateIssues: number;
    codeLines: number;
    commentLines: number;
    blankLines: number;
}

export interface Vulnerability {
    id: string;
    type: string;
    severity: VulnerabilitySeverity;
    title: string;
    description: string;
    file: string;
    line: number;
    column?: number;
    code: string;
    solution?: string;
    cwe?: string;
    cvss?: number;
    references?: string[];
    confidence: number;
    category: string;
    tags: string[];
    firstSeen: string;
    lastSeen: string;
}

export interface FileAnalysis {
    path: string;
    name: string;
    extension: string;
    language: string;
    size: number;
    lines: number;
    complexity: number;
    riskScore: number;
    vulnerabilities: number;
    issues: VulnerabilityBrief[];
    lastModified: string;
    author?: string;
    dependencies?: string[];
    imports?: string[];
    functions?: FunctionInfo[];
    classes?: ClassInfo[];
}

export interface VulnerabilityBrief {
    id: string;
    type: string;
    severity: VulnerabilitySeverity;
    line: number;
    confidence: number;
}

export interface FunctionInfo {
    name: string;
    line: number;
    complexity: number;
    parameters: number;
    riskScore: number;
}

export interface ClassInfo {
    name: string;
    line: number;
    methods: number;
    complexity: number;
    riskScore: number;
}

export interface AnalysisResult {
    id: string;
    status: AnalysisStatus;
    progress: number;
    createdAt: string;
    completedAt?: string;
    duration?: number;
    repository: Repository;
    statistics: AnalysisStatistics;
    vulnerabilities: Vulnerability[];
    files: FileAnalysis[];
    aiAnalysis?: AiAnalysisResult;
    metadata: AnalysisMetadata;
}

export interface AiAnalysisResult {
    summary: string;
    recommendations: string[];
    riskAssessment: {
        overall: number;
        categories: Record<string, number>;
    };
    patterns: SecurityPattern[];
    prioritizedIssues: string[];
}

export interface SecurityPattern {
    id: string;
    name: string;
    description: string;
    occurrences: number;
    severity: VulnerabilitySeverity;
    files: string[];
}

export interface AnalysisMetadata {
    version: string;
    toolVersion: string;
    environment: string;
    configuration: AnalysisConfig;
    scanDuration: number;
    resourceUsage: {
        memory: number;
        cpu: number;
    };
}

export interface ExportOptions {
    format: ExportFormat;
    includeSource: boolean;
    includeMetadata: boolean;
    severityFilter?: VulnerabilitySeverity[];
    fileFilter?: string[];
}

export interface ApiResponse<T = any> {
    success: boolean;
    data?: T;
    message?: string;
    error?: string;
    timestamp: string;
}

export interface PaginatedResponse<T> {
    items: T[];
    total: number;
    page: number;
    pageSize: number;
    totalPages: number;
}

export interface ChartData {
    labels: string[];
    datasets: {
        label: string;
        data: number[];
        backgroundColor?: string[];
        borderColor?: string[];
        borderWidth?: number;
    }[];
}

export interface HeatmapData {
    file: string;
    line: number;
    column: number;
    severity: VulnerabilitySeverity;
    count: number;
    riskScore: number;
}

export interface UserPreferences {
    theme: 'light' | 'dark' | 'system';
    language: 'zh-CN' | 'en-US';
    pageSize: number;
    autoRefresh: boolean;
    notificationSettings: {
        browser: boolean;
        email: boolean;
        sound: boolean;
    };
    dashboardLayout: string[];
}

export interface Notification {
    id: string;
    type: 'success' | 'error' | 'warning' | 'info';
    title: string;
    message: string;
    timestamp: string;
    read: boolean;
    actions?: NotificationAction[];
}

export interface NotificationAction {
    label: string;
    action: () => void;
    variant?: 'primary' | 'secondary';
}
