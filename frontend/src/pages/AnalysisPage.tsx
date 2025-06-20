import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';

interface AnalysisOptions {
    enableAiAnalysis: boolean;
    maxFilesToAnalyze: number;
    includeLowRisk: boolean;
    analysisDepth: 'light' | 'normal' | 'deep';
}

const AnalysisPage: React.FC = () => {
    const navigate = useNavigate();
    const [repositoryUrl, setRepositoryUrl] = useState('');
    const [branch, setBranch] = useState('');
    const [options, setOptions] = useState<AnalysisOptions>({
        enableAiAnalysis: true,
        maxFilesToAnalyze: 50,
        includeLowRisk: false,
        analysisDepth: 'normal'
    });
    const [isSubmitting, setIsSubmitting] = useState(false);

    const validateUrl = (url: string): boolean => {
        const githubRegex = /^https:\/\/github\.com\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+(?:\.git)?$/;
        const gitlabRegex = /^https:\/\/gitlab\.com\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+(?:\.git)?$/;
        return githubRegex.test(url) || gitlabRegex.test(url);
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!repositoryUrl.trim()) {
            toast.error('请输入仓库URL');
            return;
        }

        if (!validateUrl(repositoryUrl)) {
            toast.error('请输入有效的GitHub或GitLab仓库URL');
            return;
        }

        setIsSubmitting(true);

        try {
            const response = await fetch('/api/analyze/repository', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    repository_url: repositoryUrl,
                    branch: branch || undefined,
                    analysis_options: {
                        enable_ai_analysis: options.enableAiAnalysis,
                        max_files_to_analyze: options.maxFilesToAnalyze,
                        include_low_risk: options.includeLowRisk,
                        analysis_depth: options.analysisDepth
                    }
                })
            });

            if (!response.ok) {
                throw new Error('启动分析失败');
            }

            const result = await response.json();
            toast.success('分析任务已启动');
            navigate(`/results/${result.task_id}`);
        } catch (error) {
            toast.error('启动分析失败，请重试');
            console.error('Analysis error:', error);
        } finally {
            setIsSubmitting(false);
        }
    };

    const examples = [
        'https://github.com/user/vulnerable-app.git',
        'https://github.com/organization/legacy-project.git',
        'https://gitlab.com/team/security-demo.git'
    ];

    return (
        <div className="max-w-4xl mx-auto space-y-8">
            {/* 页面标题 */}
            <div className="text-center">
                <h1 className="text-3xl font-bold text-gray-900">开始代码安全分析</h1>
                <p className="text-gray-600 mt-2">输入Git仓库URL，我们将为您进行全面的安全审计</p>
            </div>

            {/* 分析表单 */}
            <div className="bg-white rounded-lg shadow-lg border p-8">
                <form onSubmit={handleSubmit} className="space-y-6">
                    {/* 仓库URL */}
                    <div>
                        <label htmlFor="repository-url" className="block text-sm font-medium text-gray-700 mb-2">
                            仓库URL *
                        </label>
                        <input
                            type="url"
                            id="repository-url"
                            value={repositoryUrl}
                            onChange={(e) => setRepositoryUrl(e.target.value)}
                            placeholder="https://github.com/user/repo.git"
                            className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                            required
                        />
                        <p className="text-sm text-gray-500 mt-1">
                            支持 GitHub 和 GitLab 公开仓库
                        </p>
                    </div>

                    {/* 分支 */}
                    <div>
                        <label htmlFor="branch" className="block text-sm font-medium text-gray-700 mb-2">
                            分支名称
                        </label>
                        <input
                            type="text"
                            id="branch"
                            value={branch}
                            onChange={(e) => setBranch(e.target.value)}
                            placeholder="main (默认分支)"
                            className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                        />
                    </div>

                    {/* 分析选项 */}
                    <div className="border-t pt-6">
                        <h3 className="text-lg font-medium text-gray-900 mb-4">分析选项</h3>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            {/* AI分析开关 */}
                            <div className="flex items-center justify-between p-4 border rounded-lg">
                                <div>
                                    <h4 className="text-sm font-medium text-gray-900">AI深度分析</h4>
                                    <p className="text-sm text-gray-500">使用大语言模型进行深度安全分析</p>
                                </div>
                                <label className="relative inline-flex items-center cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked={options.enableAiAnalysis}
                                        onChange={(e) => setOptions({ ...options, enableAiAnalysis: e.target.checked })}
                                        className="sr-only peer"
                                    />
                                    <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-indigo-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600"></div>
                                </label>
                            </div>

                            {/* 低风险包含开关 */}
                            <div className="flex items-center justify-between p-4 border rounded-lg">
                                <div>
                                    <h4 className="text-sm font-medium text-gray-900">包含低风险问题</h4>
                                    <p className="text-sm text-gray-500">是否包含低严重性的安全问题</p>
                                </div>
                                <label className="relative inline-flex items-center cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked={options.includeLowRisk}
                                        onChange={(e) => setOptions({ ...options, includeLowRisk: e.target.checked })}
                                        className="sr-only peer"
                                    />
                                    <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-indigo-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600"></div>
                                </label>
                            </div>
                        </div>

                        {/* 最大文件数 */}
                        <div className="mt-6">
                            <label htmlFor="max-files" className="block text-sm font-medium text-gray-700 mb-2">
                                最大分析文件数: {options.maxFilesToAnalyze}
                            </label>
                            <input
                                type="range"
                                id="max-files"
                                min="10"
                                max="200"
                                step="10"
                                value={options.maxFilesToAnalyze}
                                onChange={(e) => setOptions({ ...options, maxFilesToAnalyze: parseInt(e.target.value) })}
                                className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer slider"
                            />
                            <div className="flex justify-between text-sm text-gray-500 mt-1">
                                <span>10</span>
                                <span>200</span>
                            </div>
                        </div>

                        {/* 分析深度 */}
                        <div className="mt-6">
                            <label className="block text-sm font-medium text-gray-700 mb-3">分析深度</label>
                            <div className="grid grid-cols-3 gap-3">
                                {(['light', 'normal', 'deep'] as const).map((depth) => (
                                    <button
                                        key={depth}
                                        type="button"
                                        onClick={() => setOptions({ ...options, analysisDepth: depth })}
                                        className={`p-3 text-sm font-medium rounded-lg border transition-colors ${options.analysisDepth === depth
                                                ? 'bg-indigo-50 border-indigo-200 text-indigo-700'
                                                : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                                            }`}
                                    >
                                        {depth === 'light' ? '轻量级' : depth === 'normal' ? '标准' : '深度'}
                                    </button>
                                ))}
                            </div>
                            <p className="text-sm text-gray-500 mt-2">
                                {options.analysisDepth === 'light' && '快速扫描，基础安全检查'}
                                {options.analysisDepth === 'normal' && '标准分析，平衡速度和准确性'}
                                {options.analysisDepth === 'deep' && '深度分析，最全面的安全检查'}
                            </p>
                        </div>
                    </div>

                    {/* 提交按钮 */}
                    <div className="flex justify-end pt-6 border-t">
                        <button
                            type="submit"
                            disabled={isSubmitting}
                            className="bg-indigo-600 text-white px-8 py-3 rounded-lg hover:bg-indigo-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors font-medium flex items-center space-x-2"
                        >
                            {isSubmitting ? (
                                <>
                                    <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                    </svg>
                                    <span>启动分析中...</span>
                                </>
                            ) : (
                                <span>开始分析</span>
                            )}
                        </button>
                    </div>
                </form>
            </div>

            {/* 示例URL */}
            <div className="bg-gray-50 rounded-lg p-6">
                <h3 className="text-sm font-medium text-gray-900 mb-3">示例仓库URL:</h3>
                <div className="space-y-2">
                    {examples.map((example, index) => (
                        <button
                            key={index}
                            onClick={() => setRepositoryUrl(example)}
                            className="block w-full text-left text-sm text-indigo-600 hover:text-indigo-800 hover:bg-white px-3 py-2 rounded transition-colors"
                        >
                            {example}
                        </button>
                    ))}
                </div>
            </div>

            {/* 说明 */}
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
                <div className="flex">
                    <div className="flex-shrink-0">
                        <svg className="h-5 w-5 text-blue-400" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                        </svg>
                    </div>
                    <div className="ml-3">
                        <h3 className="text-sm font-medium text-blue-800">分析说明</h3>
                        <div className="mt-2 text-sm text-blue-700">
                            <ul className="list-disc list-inside space-y-1">
                                <li>分析过程通常需要 5-15 分钟，具体时间取决于仓库大小和分析深度</li>
                                <li>我们会克隆仓库到临时目录，分析完成后自动清理</li>
                                <li>支持 Python、JavaScript、Java、Go 等主流编程语言</li>
                                <li>AI 分析需要消耗一定的计算资源，建议选择重要项目进行深度分析</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default AnalysisPage;
