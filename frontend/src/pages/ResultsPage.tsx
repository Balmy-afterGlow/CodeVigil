import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import toast from 'react-hot-toast';
import { AnalysisResults, ProgressResponse } from '../types';
import ProgressTracker from '../components/ProgressTracker';
import VulnerabilityList from '../components/VulnerabilityList';
import RiskHeatmap from '../components/RiskHeatmap';
import ExportButtons from '../components/ExportButtons';
import HighRiskFileList from '../components/results/HighRiskFileList';

const ResultsPage: React.FC = () => {
    const { taskId } = useParams<{ taskId: string }>();
    const [results, setResults] = useState<AnalysisResults | null>(null);
    const [progress, setProgress] = useState<ProgressResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState<'overview' | 'files' | 'vulnerabilities' | 'heatmap'>('overview');

    useEffect(() => {
        if (!taskId) return;

        const checkProgress = async () => {
            try {
                const response = await fetch(`/api/analysis/${taskId}/progress`);
                if (!response.ok) throw new Error('获取进度失败');

                const progressData = await response.json();
                setProgress(progressData);

                if (progressData.status === 'completed') {
                    // 获取完整结果
                    const resultsResponse = await fetch(`/api/analysis/${taskId}/results`);
                    if (resultsResponse.ok) {
                        const resultsData = await resultsResponse.json();
                        setResults(resultsData);
                        setLoading(false);
                    }
                } else if (progressData.status === 'failed') {
                    setError('分析失败');
                    setLoading(false);
                }
            } catch (err) {
                setError('获取分析状态失败');
                setLoading(false);
            }
        };

        // 立即检查一次
        checkProgress();

        // 如果还在进行中，定期轮询
        const interval = setInterval(checkProgress, 2000);

        return () => clearInterval(interval);
    }, [taskId]);

    const getSeverityColor = (severity: string) => {
        switch (severity.toLowerCase()) {
            case 'critical':
                return 'text-red-600 bg-red-100';
            case 'high':
                return 'text-orange-600 bg-orange-100';
            case 'medium':
                return 'text-yellow-600 bg-yellow-100';
            case 'low':
                return 'text-green-600 bg-green-100';
            default:
                return 'text-gray-600 bg-gray-100';
        }
    };

    const formatDate = (dateString: string) => {
        return new Date(dateString).toLocaleString('zh-CN');
    };

    if (loading) {
        return (
            <div className="max-w-6xl mx-auto space-y-8">
                <div className="text-center">
                    <h1 className="text-3xl font-bold text-gray-900">分析进行中</h1>
                    <p className="text-gray-600 mt-2">任务ID: {taskId}</p>
                </div>

                {progress && <ProgressTracker progress={progress} />}
            </div>
        );
    }

    if (error) {
        return (
            <div className="max-w-6xl mx-auto text-center">
                <div className="bg-red-50 border border-red-200 rounded-lg p-8">
                    <svg className="mx-auto h-12 w-12 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                    </svg>
                    <h2 className="mt-4 text-xl font-semibold text-red-800">分析失败</h2>
                    <p className="mt-2 text-red-600">{error}</p>
                </div>
            </div>
        );
    }

    if (!results) {
        return <div className="text-center">未找到分析结果</div>;
    }

    return (
        <div className="max-w-7xl mx-auto space-y-8">
            {/* 页面头部 */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold text-gray-900">分析结果</h1>
                    <p className="text-gray-600 mt-1">
                        {results.repository_url}
                    </p>
                    <p className="text-sm text-gray-500">
                        完成时间: {formatDate(results.completed_at || results.created_at)}
                    </p>
                </div>
                <ExportButtons taskId={taskId!} />
            </div>

            {/* 概览统计 */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <div className="bg-white p-6 rounded-lg shadow border">
                    <div className="flex items-center">
                        <div className="p-2 bg-blue-100 rounded-lg">
                            <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                            </svg>
                        </div>
                        <div className="ml-4">
                            <p className="text-sm font-medium text-gray-600">分析文件</p>
                            <p className="text-2xl font-bold text-gray-900">{results.summary.total_files_analyzed}</p>
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
                            <p className="text-sm font-medium text-gray-600">高风险文件</p>
                            <p className="text-2xl font-bold text-gray-900">{results.summary.high_risk_files_count || results.high_risk_files.length}</p>
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
                            <p className="text-sm font-medium text-gray-600">发现漏洞</p>
                            <p className="text-2xl font-bold text-gray-900">{results.summary.total_vulnerabilities}</p>
                        </div>
                    </div>
                </div>

                <div className="bg-white p-6 rounded-lg shadow border">
                    <div className="flex items-center">
                        <div className="p-2 bg-yellow-100 rounded-lg">
                            <svg className="w-6 h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                            </svg>
                        </div>
                        <div className="ml-4">
                            <p className="text-sm font-medium text-gray-600">严重问题</p>
                            <p className="text-2xl font-bold text-gray-900">{results.summary.critical_count}</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* 标签页导航 */}
            <div className="border-b border-gray-200">
                <nav className="-mb-px flex space-x-8">
                    {[
                        { key: 'overview', label: '概览', icon: '📊' },
                        { key: 'files', label: '高风险文件', icon: '📁' },
                        { key: 'vulnerabilities', label: '漏洞详情', icon: '🔍' },
                        { key: 'heatmap', label: '风险热力图', icon: '🔥' }
                    ].map((tab) => (
                        <button
                            key={tab.key}
                            onClick={() => setActiveTab(tab.key as any)}
                            className={`py-2 px-1 border-b-2 font-medium text-sm ${activeTab === tab.key
                                ? 'border-indigo-500 text-indigo-600'
                                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                                }`}
                        >
                            {tab.icon} {tab.label}
                        </button>
                    ))}
                </nav>
            </div>

            {/* 标签页内容 */}
            <div className="min-h-96">
                {activeTab === 'overview' && (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                        {/* 严重性分布 */}
                        <div className="bg-white p-6 rounded-lg shadow border">
                            <h3 className="text-lg font-semibold text-gray-900 mb-4">漏洞严重性分布</h3>
                            <div className="space-y-3">
                                {[
                                    { level: 'critical', count: results.summary.critical_count, label: '严重' },
                                    { level: 'high', count: results.summary.high_count, label: '高危' },
                                    { level: 'medium', count: results.summary.medium_count, label: '中危' },
                                    { level: 'low', count: results.summary.low_count, label: '低危' }
                                ].map((item) => (
                                    <div key={item.level} className="flex items-center justify-between">
                                        <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(item.level)}`}>
                                            {item.label}
                                        </span>
                                        <span className="text-sm font-medium text-gray-900">{item.count}</span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* AI分析统计 */}
                        {results.summary.ai_stage1_files && (
                            <div className="bg-white p-6 rounded-lg shadow border">
                                <h3 className="text-lg font-semibold text-gray-900 mb-4">AI分析统计</h3>
                                <div className="space-y-3">
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm text-gray-700">第一阶段评分文件</span>
                                        <span className="text-sm font-medium text-gray-900">{results.summary.ai_stage1_files}</span>
                                    </div>
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm text-gray-700">第二阶段分析文件</span>
                                        <span className="text-sm font-medium text-gray-900">{results.summary.ai_stage2_files || 0}</span>
                                    </div>
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm text-gray-700">第三阶段增强文件</span>
                                        <span className="text-sm font-medium text-gray-900">{results.summary.ai_stage3_files || 0}</span>
                                    </div>
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm text-gray-700">CVE参考数量</span>
                                        <span className="text-sm font-medium text-gray-900">{results.summary.cve_references_count || 0}</span>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                )}

                {activeTab === 'files' && (
                    <HighRiskFileList files={results.high_risk_files} />
                )}

                {activeTab === 'vulnerabilities' && (
                    <VulnerabilityList vulnerabilities={results.vulnerabilities} />
                )}

                {activeTab === 'heatmap' && (
                    <RiskHeatmap files={results.high_risk_files.map(file => ({
                        file_path: file.file_path,
                        risk_score: file.risk_score,
                        language: file.language,
                        vulnerabilities_count: file.vulnerabilities.length,
                        lines_of_code: file.lines_of_code
                    }))} />
                )}
            </div>
        </div>
    );
};

export default ResultsPage;
