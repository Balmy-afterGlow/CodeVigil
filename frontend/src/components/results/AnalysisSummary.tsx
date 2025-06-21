import React from 'react';
import Button from '../common/Button';
import type { AnalysisResults } from '../../types';

interface AnalysisSummaryProps {
    results: AnalysisResults;
    onExport: (format: string) => void;
    isExporting: boolean;
}

const AnalysisSummary: React.FC<AnalysisSummaryProps> = ({
    results,
    onExport,
    isExporting
}) => {
    const formatDateTime = (dateString: string) => {
        const date = new Date(dateString);
        return date.toLocaleString('zh-CN');
    };

    return (
        <div className="bg-white rounded-lg shadow-sm p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-medium text-gray-700">分析摘要</h2>
                <div className="flex space-x-2">
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => onExport('html')}
                        disabled={isExporting}
                        isLoading={isExporting}
                    >
                        导出HTML
                    </Button>
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => onExport('markdown')}
                        disabled={isExporting}
                        isLoading={isExporting}
                    >
                        导出MD
                    </Button>
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => onExport('pdf')}
                        disabled={isExporting}
                        isLoading={isExporting}
                    >
                        导出PDF
                    </Button>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                <div className="bg-gray-50 rounded-md p-4">
                    <p className="text-sm text-gray-500">仓库 URL</p>
                    <p className="text-gray-700 truncate" title={results.repository_url}>
                        {results.repository_url}
                    </p>
                </div>
                <div className="bg-gray-50 rounded-md p-4">
                    <p className="text-sm text-gray-500">分析时间</p>
                    <p className="text-gray-700">
                        {results.created_at && formatDateTime(results.created_at)}
                    </p>
                </div>
                <div className="bg-gray-50 rounded-md p-4">
                    <p className="text-sm text-gray-500">分析持续时间</p>
                    <p className="text-gray-700">
                        {results.summary.analysis_duration_seconds
                            ? `${Math.floor(results.summary.analysis_duration_seconds / 60)} 分 ${results.summary.analysis_duration_seconds % 60} 秒`
                            : '未知'}
                    </p>
                </div>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-gray-50 rounded-md p-4 text-center">
                    <p className="text-xs text-gray-500">分析文件数</p>
                    <p className="text-2xl font-semibold text-gray-700">
                        {results.summary.total_files_analyzed}
                    </p>
                </div>
                <div className="bg-gray-50 rounded-md p-4 text-center">
                    <p className="text-xs text-gray-500">总漏洞数</p>
                    <p className="text-2xl font-semibold text-gray-700">
                        {results.summary.total_vulnerabilities}
                    </p>
                </div>
                <div className="bg-red-50 rounded-md p-4 text-center">
                    <p className="text-xs text-red-500">严重/高危漏洞</p>
                    <p className="text-2xl font-semibold text-red-600">
                        {results.summary.critical_count + results.summary.high_count}
                    </p>
                </div>
                <div className="bg-yellow-50 rounded-md p-4 text-center">
                    <p className="text-xs text-yellow-600">中低危漏洞</p>
                    <p className="text-2xl font-semibold text-yellow-700">
                        {results.summary.medium_count + results.summary.low_count}
                    </p>
                </div>
            </div>
        </div>
    );
};

export default AnalysisSummary;
