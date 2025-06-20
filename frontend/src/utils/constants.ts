// 应用常量定义

export const APP_CONFIG = {
    name: 'CodeVigil',
    version: '1.0.0',
    description: '开源仓库代码安全审计系统',
};

export const API_CONFIG = {
    baseUrl: process.env.REACT_APP_API_URL || 'http://localhost:8000',
    timeout: 30000,
    retryAttempts: 3,
};

export const ANALYSIS_STATUS = {
    PENDING: 'pending',
    RUNNING: 'running',
    COMPLETED: 'completed',
    FAILED: 'failed',
} as const;

export const VULNERABILITY_SEVERITY = {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
} as const;

export const SUPPORTED_LANGUAGES = [
    'javascript',
    'typescript',
    'python',
    'java',
    'c++',
    'c',
    'c#',
    'php',
    'ruby',
    'go',
    'rust',
    'swift',
    'kotlin',
    'scala',
    'sql',
    'html',
    'css',
    'shell',
    'yaml',
    'json',
    'xml',
];

export const EXPORT_FORMATS = [
    { value: 'pdf', label: 'PDF报告', description: '适合打印和分享的完整报告' },
    { value: 'html', label: 'HTML报告', description: '可在浏览器中查看的交互式报告' },
    { value: 'json', label: 'JSON数据', description: '结构化数据，便于程序处理' },
    { value: 'csv', label: 'CSV表格', description: '可在Excel中打开的数据表格' },
];

export const PAGINATION = {
    defaultPageSize: 20,
    pageSizes: [10, 20, 50, 100],
};

export const THEME_CONFIG = {
    colors: {
        primary: '#3b82f6',
        secondary: '#6b7280',
        success: '#10b981',
        warning: '#f59e0b',
        error: '#ef4444',
        info: '#3b82f6',
    },
    breakpoints: {
        sm: '640px',
        md: '768px',
        lg: '1024px',
        xl: '1280px',
        '2xl': '1536px',
    },
};

export const ROUTES = {
    HOME: '/',
    DASHBOARD: '/dashboard',
    ANALYSIS: '/analysis',
    RESULTS: '/results',
    HISTORY: '/history',
};

export const LOCAL_STORAGE_KEYS = {
    ANALYSIS_HISTORY: 'codevigil_analysis_history',
    USER_PREFERENCES: 'codevigil_user_preferences',
    RECENT_REPOSITORIES: 'codevigil_recent_repositories',
};

export const DEFAULT_ANALYSIS_CONFIG = {
    enableAiAnalysis: true,
    languages: [],
    excludePatterns: [
        'node_modules/',
        '.git/',
        'dist/',
        'build/',
        '*.min.js',
        '*.min.css',
    ],
};

export const VULNERABILITY_TYPES = [
    'SQL注入',
    'XSS跨站脚本',
    'CSRF跨站请求伪造',
    '代码注入',
    '路径遍历',
    '敏感信息泄露',
    '弱密码策略',
    '不安全的加密',
    '权限控制缺陷',
    '输入验证不足',
    '会话管理漏洞',
    '业务逻辑缺陷',
];

export const RISK_SCORE_RANGES = {
    CRITICAL: { min: 9, max: 10, color: '#dc2626' },
    HIGH: { min: 7, max: 8.9, color: '#ea580c' },
    MEDIUM: { min: 4, max: 6.9, color: '#ca8a04' },
    LOW: { min: 0, max: 3.9, color: '#2563eb' },
};

export const NOTIFICATION_DURATION = {
    SUCCESS: 3000,
    INFO: 4000,
    WARNING: 5000,
    ERROR: 6000,
};
