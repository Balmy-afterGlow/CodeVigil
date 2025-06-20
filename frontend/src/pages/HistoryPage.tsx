import React from 'react';
import { useNavigate } from 'react-router-dom';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import LoadingSpinner from '../components/LoadingSpinner';
import EmptyState from '../components/EmptyState';
import { useAnalysisHistory } from '../hooks/useAnalysisHistory';
import { formatDate, truncateText } from '../utils/helpers';

const HistoryPage: React.FC = () => {
    const navigate = useNavigate();
    const { history, loading, error, refresh } = useAnalysisHistory();

    if (loading) {
        return (
            <div className="flex justify-center items-center h-64">
                <LoadingSpinner text="加载历史记录..." />
            </div>
        );
    }

    if (error) {
        return (
            <Card title="错误" className="text-center">
                <div className="text-red-600 mb-4">{error}</div>
                <Button onClick={refresh} variant="primary">
                    重新加载
                </Button>
            </Card>
        );
    }

    if (history.length === 0) {
        return (
            <Card>
                <EmptyState
                    title="暂无分析记录"
                    description="还没有进行过任何代码分析，开始您的第一次安全审计吧！"
                    action={
                        <Button
                            onClick={() => navigate('/analysis')}
                            variant="primary"
                        >
                            开始新分析
                        </Button>
                    }
                />
            </Card>
        );
    }

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <h1 className="text-2xl font-bold text-gray-900">分析历史</h1>
                <div className="flex space-x-4">
                    <Button onClick={refresh} variant="outline">
                        刷新
                    </Button>
                    <Button onClick={() => navigate('/analysis')} variant="primary">
                        新建分析
                    </Button>
                </div>
            </div>

            <div className="grid gap-6">
                {history.map((analysis) => (
                    <Card key={analysis.id} className="hover:shadow-md transition-shadow">
                        <div className="flex items-start justify-between">
                            <div className="flex-1">
                                <div className="flex items-center space-x-3 mb-2">
                                    <h3 className="text-lg font-semibold text-gray-900">
                                        {analysis.repository.name}
                                    </h3>
                                    <Badge variant="status" color={analysis.status}>
                                        {getStatusText(analysis.status)}
                                    </Badge>
                                </div>

                                <p className="text-sm text-gray-600 mb-2">
                                    {truncateText(analysis.repository.url, 60)}
                                </p>

                                <div className="flex items-center space-x-6 text-sm text-gray-500 mb-4">
                                    <span>创建时间: {formatDate(analysis.createdAt)}</span>
                                    {analysis.completedAt && (
                                        <span>完成时间: {formatDate(analysis.completedAt)}</span>
                                    )}
                                </div>

                                {analysis.status === 'completed' && (
                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                                        <div className="flex flex-col">
                                            <span className="text-gray-500">总文件数</span>
                                            <span className="font-semibold">{analysis.statistics.totalFiles}</span>
                                        </div>
                                        <div className="flex flex-col">
                                            <span className="text-gray-500">扫描文件</span>
                                            <span className="font-semibold">{analysis.statistics.scannedFiles}</span>
                                        </div>
                                        <div className="flex flex-col">
                                            <span className="text-gray-500">漏洞数量</span>
                                            <span className="font-semibold text-red-600">
                                                {analysis.statistics.vulnerabilities}
                                            </span>
                                        </div>
                                        <div className="flex flex-col">
                                            <span className="text-gray-500">严重问题</span>
                                            <span className="font-semibold text-orange-600">
                                                {analysis.statistics.criticalIssues}
                                            </span>
                                        </div>
                                    </div>
                                )}

                                {analysis.status === 'running' && (
                                    <div className="flex items-center space-x-2">
                                        <div className="w-full bg-gray-200 rounded-full h-2">
                                            <div
                                                className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                                                style={{ width: `${analysis.progress}%` }}
                                            />
                                        </div>
                                        <span className="text-sm text-gray-600 whitespace-nowrap">
                                            {analysis.progress}%
                                        </span>
                                    </div>
                                )}
                            </div>

                            <div className="flex flex-col space-y-2 ml-6">
                                {analysis.status === 'completed' && (
                                    <Button
                                        size="sm"
                                        onClick={() => navigate(`/results/${analysis.id}`)}
                                        variant="primary"
                                    >
                                        查看结果
                                    </Button>
                                )}

                                {analysis.status === 'running' && (
                                    <Button
                                        size="sm"
                                        onClick={() => navigate(`/results/${analysis.id}`)}
                                        variant="outline"
                                    >
                                        查看进度
                                    </Button>
                                )}

                                {analysis.status === 'failed' && (
                                    <Button
                                        size="sm"
                                        onClick={() => navigate('/analysis')}
                                        variant="outline"
                                    >
                                        重新分析
                                    </Button>
                                )}
                            </div>
                        </div>
                    </Card>
                ))}
            </div>
        </div>
    );
};

const getStatusText = (status: string): string => {
    switch (status) {
        case 'pending':
            return '等待中';
        case 'running':
            return '分析中';
        case 'completed':
            return '已完成';
        case 'failed':
            return '已失败';
        default:
            return '未知';
    }
};

export default HistoryPage;
