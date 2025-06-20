import React from 'react';
import { Link } from 'react-router-dom';

interface RecentAnalysis {
    id: string;
    repository: string;
    status: 'completed' | 'running' | 'failed';
    vulnerabilities: number;
    riskScore: number;
    createdAt: string;
}

const Dashboard: React.FC = () => {
    // 模拟数据，实际应用中从API获取
    const recentAnalyses: RecentAnalysis[] = [
        {
            id: '1',
            repository: 'user/vulnerable-app',
            status: 'completed',
            vulnerabilities: 12,
            riskScore: 85,
            createdAt: '2024-01-15T10:30:00Z'
        },
        {
            id: '2',
            repository: 'org/secure-project',
            status: 'completed',
            vulnerabilities: 3,
            riskScore: 25,
            createdAt: '2024-01-14T15:20:00Z'
        },
        {
            id: '3',
            repository: 'team/legacy-code',
            status: 'running',
            vulnerabilities: 0,
            riskScore: 0,
            createdAt: '2024-01-14T09:15:00Z'
        }
    ];

    const stats = {
        totalAnalyses: 156,
        vulnerabilitiesFound: 1247,
        criticalIssues: 89,
        averageRiskScore: 42
    };

    const getStatusColor = (status: string) => {
        switch (status) {
            case 'completed':
                return 'text-green-600 bg-green-100';
            case 'running':
                return 'text-blue-600 bg-blue-100';
            case 'failed':
                return 'text-red-600 bg-red-100';
            default:
                return 'text-gray-600 bg-gray-100';
        }
    };

    const getRiskColor = (score: number) => {
        if (score >= 80) return 'text-red-600';
        if (score >= 60) return 'text-orange-600';
        if (score >= 40) return 'text-yellow-600';
        return 'text-green-600';
    };

    const formatDate = (dateString: string) => {
        return new Date(dateString).toLocaleDateString('zh-CN', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    };

    return (
        <div className="space-y-8">
            {/* 页面标题 */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold text-gray-900">仪表板</h1>
                    <p className="text-gray-600 mt-1">代码安全分析概览</p>
                </div>
                <Link
                    to="/analysis"
                    className="bg-indigo-600 text-white px-6 py-3 rounded-lg hover:bg-indigo-700 transition-colors font-medium"
                >
                    开始新分析
                </Link>
            </div>

            {/* 统计卡片 */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <div className="bg-white p-6 rounded-lg shadow border">
                    <div className="flex items-center">
                        <div className="p-2 bg-blue-100 rounded-lg">
                            <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                            </svg>
                        </div>
                        <div className="ml-4">
                            <p className="text-sm font-medium text-gray-600">总分析次数</p>
                            <p className="text-2xl font-bold text-gray-900">{stats.totalAnalyses}</p>
                        </div>
                    </div>
                </div>

                <div className="bg-white p-6 rounded-lg shadow border">
                    <div className="flex items-center">
                        <div className="p-2 bg-red-100 rounded-lg">
                            <svg className="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                            </svg>
                        </div>
                        <div className="ml-4">
                            <p className="text-sm font-medium text-gray-600">发现漏洞</p>
                            <p className="text-2xl font-bold text-gray-900">{stats.vulnerabilitiesFound}</p>
                        </div>
                    </div>
                </div>

                <div className="bg-white p-6 rounded-lg shadow border">
                    <div className="flex items-center">
                        <div className="p-2 bg-orange-100 rounded-lg">
                            <svg className="w-6 h-6 text-orange-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                            </svg>
                        </div>
                        <div className="ml-4">
                            <p className="text-sm font-medium text-gray-600">严重问题</p>
                            <p className="text-2xl font-bold text-gray-900">{stats.criticalIssues}</p>
                        </div>
                    </div>
                </div>

                <div className="bg-white p-6 rounded-lg shadow border">
                    <div className="flex items-center">
                        <div className="p-2 bg-green-100 rounded-lg">
                            <svg className="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                        </div>
                        <div className="ml-4">
                            <p className="text-sm font-medium text-gray-600">平均风险评分</p>
                            <p className="text-2xl font-bold text-gray-900">{stats.averageRiskScore}</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* 最近分析 */}
            <div className="bg-white rounded-lg shadow border">
                <div className="px-6 py-4 border-b border-gray-200">
                    <h2 className="text-lg font-semibold text-gray-900">最近分析</h2>
                </div>
                <div className="divide-y divide-gray-200">
                    {recentAnalyses.map((analysis) => (
                        <div key={analysis.id} className="px-6 py-4 hover:bg-gray-50 transition-colors">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center space-x-4">
                                    <div className="flex-shrink-0">
                                        <div className="w-10 h-10 bg-gray-100 rounded-lg flex items-center justify-center">
                                            <svg className="w-5 h-5 text-gray-600" fill="currentColor" viewBox="0 0 20 20">
                                                <path fillRule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z" clipRule="evenodd" />
                                            </svg>
                                        </div>
                                    </div>
                                    <div>
                                        <h3 className="text-sm font-medium text-gray-900">{analysis.repository}</h3>
                                        <p className="text-sm text-gray-500">{formatDate(analysis.createdAt)}</p>
                                    </div>
                                </div>
                                <div className="flex items-center space-x-4">
                                    <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${getStatusColor(analysis.status)}`}>
                                        {analysis.status === 'completed' ? '已完成' :
                                            analysis.status === 'running' ? '进行中' : '失败'}
                                    </span>
                                    {analysis.status === 'completed' && (
                                        <>
                                            <span className="text-sm text-gray-600">
                                                {analysis.vulnerabilities} 个漏洞
                                            </span>
                                            <span className={`text-sm font-medium ${getRiskColor(analysis.riskScore)}`}>
                                                风险: {analysis.riskScore}
                                            </span>
                                            <Link
                                                to={`/results/${analysis.id}`}
                                                className="text-indigo-600 hover:text-indigo-700 text-sm font-medium"
                                            >
                                                查看详情
                                            </Link>
                                        </>
                                    )}
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
                <div className="px-6 py-4 bg-gray-50 border-t border-gray-200">
                    <Link
                        to="/history"
                        className="text-indigo-600 hover:text-indigo-700 text-sm font-medium"
                    >
                        查看所有分析历史 →
                    </Link>
                </div>
            </div>
        </div>
    );
};

export default Dashboard;
