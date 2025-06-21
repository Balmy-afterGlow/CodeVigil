// 通用工具函数
import { MORANDI_COLORS, VULNERABILITY_SEVERITY } from './constants';

export const formatDate = (dateString: string): string => {
    const date = new Date(dateString);
    return date.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
    });
};

export const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 B';

    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

export const formatDuration = (milliseconds: number): string => {
    const seconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (hours > 0) {
        return `${hours}小时${minutes % 60}分钟`;
    }
    if (minutes > 0) {
        return `${minutes}分钟${seconds % 60}秒`;
    }
    return `${seconds}秒`;
};

export const getSeverityColor = (severity: string): string => {
    switch (severity) {
        case VULNERABILITY_SEVERITY.CRITICAL.value:
            return 'morandi-badge-critical';
        case VULNERABILITY_SEVERITY.HIGH.value:
            return 'morandi-badge-high';
        case VULNERABILITY_SEVERITY.MEDIUM.value:
            return 'morandi-badge-medium';
        case VULNERABILITY_SEVERITY.LOW.value:
            return 'morandi-badge-low';
        default:
            return 'morandi-badge-medium';
    }
};

export const getSeverityBadgeColor = (severity: string): string => {
    switch (severity) {
        case 'critical':
            return 'bg-red-100 text-red-800';
        case 'high':
            return 'bg-orange-100 text-orange-800';
        case 'medium':
            return 'bg-yellow-100 text-yellow-800';
        case 'low':
            return 'bg-blue-100 text-blue-800';
        default:
            return 'bg-gray-100 text-gray-800';
    }
};

export const getRiskScoreColor = (score: number): string => {
    if (score >= 8) return 'text-red-600';
    if (score >= 6) return 'text-orange-600';
    if (score >= 4) return 'text-yellow-600';
    return 'text-green-600';
};

export const truncateText = (text: string, maxLength: number): string => {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
};

export const getLanguageIcon = (language: string): string => {
    const icons: Record<string, string> = {
        javascript: '🟨',
        typescript: '🔷',
        python: '🐍',
        java: '☕',
        'c++': '⚙️',
        c: '⚙️',
        'c#': '🔷',
        php: '🐘',
        ruby: '💎',
        go: '🐹',
        rust: '🦀',
        swift: '🦉',
        kotlin: '🎯',
        scala: '🏗️',
        sql: '🗃️',
        html: '🌐',
        css: '🎨',
        shell: '🐚',
        yaml: '📄',
        json: '📋',
        xml: '📄',
    };

    return icons[language.toLowerCase()] || '📄';
};

export const downloadFile = (blob: Blob, filename: string): void => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
};

export const copyToClipboard = async (text: string): Promise<boolean> => {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (error) {
        console.error('Failed to copy to clipboard:', error);
        return false;
    }
};

export const debounce = <T extends (...args: any[]) => any>(
    func: T,
    wait: number
): ((...args: Parameters<T>) => void) => {
    let timeout: NodeJS.Timeout;

    return (...args: Parameters<T>) => {
        clearTimeout(timeout);
        timeout = setTimeout(() => func(...args), wait);
    };
};

export const validateUrl = (url: string): boolean => {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
};

export const validateGitUrl = (url: string): boolean => {
    const gitUrlPattern = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
    const gitSshPattern = /^git@[\da-z\.-]+\.[\da-z\.]{2,6}:[\/\w \.-]*\.git$/;

    return gitUrlPattern.test(url) || gitSshPattern.test(url);
};
