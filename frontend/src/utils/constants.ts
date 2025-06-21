// 全局常量配置
export const API_CONFIG = {
    baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000/api',
    timeout: 30000,
};

// 莫兰迪色彩配置
export const MORANDI_COLORS = {
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
};

// 风险等级定义
export const RISK_LEVELS = {
    critical: { name: '严重', color: '#ef4444' },
    high: { name: '高危', color: '#f97316' },
    medium: { name: '中危', color: '#f59e0b' },
    low: { name: '低危', color: '#10b981' },
};

// 漏洞严重性定义
export const VULNERABILITY_SEVERITY = {
    CRITICAL: { value: 'critical', label: '严重', color: '#ef4444' },
    HIGH: { value: 'high', label: '高危', color: '#f97316' },
    MEDIUM: { value: 'medium', label: '中危', color: '#f59e0b' },
    LOW: { value: 'low', label: '低危', color: '#10b981' },
    INFO: { value: 'info', label: '信息', color: '#3b82f6' },
};

// 分析步骤
export const ANALYSIS_STEPS = [
    { key: 'init', label: '初始化' },
    { key: 'clone', label: '克隆仓库' },
    { key: 'scan', label: '代码扫描' },
    { key: 'analyze', label: '分析漏洞' },
    { key: 'generate', label: '生成报告' },
];

// 导出格式
export const EXPORT_FORMATS = [
    { key: 'html', label: 'HTML报告' },
    { key: 'markdown', label: 'Markdown报告' },
    { key: 'pdf', label: 'PDF报告' },
    { key: 'json', label: 'JSON数据' },
];
