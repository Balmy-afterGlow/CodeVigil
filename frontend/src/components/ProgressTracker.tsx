import React from 'react';

interface Progress {
    task_id: string;
    status: string;
    progress: number;
    current_step: string;
    message: string;
    eta_minutes?: number;
}

interface ProgressTrackerProps {
    progress: Progress;
}

const ProgressTracker: React.FC<ProgressTrackerProps> = ({ progress }) => {
    const getStepIcon = (step: string, isActive: boolean, isCompleted: boolean) => {
        if (isCompleted) {
            return (
                <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center">
                    <svg className="w-4 h-4 text-white" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                    </svg>
                </div>
            );
        }

        if (isActive) {
            return (
                <div className="w-8 h-8 bg-indigo-500 rounded-full flex items-center justify-center">
                    <div className="w-3 h-3 bg-white rounded-full animate-pulse"></div>
                </div>
            );
        }

        return (
            <div className="w-8 h-8 bg-gray-300 rounded-full flex items-center justify-center">
                <div className="w-3 h-3 bg-white rounded-full"></div>
            </div>
        );
    };

    const steps = [
        { key: 'clone', label: '克隆仓库', description: '下载代码仓库' },
        { key: 'analyze', label: '文件分析', description: '静态代码分析' },
        { key: 'ai', label: 'AI深度分析', description: '智能漏洞检测' },
        { key: 'generate', label: '生成报告', description: '汇总分析结果' }
    ];

    const getCurrentStepIndex = () => {
        const step = progress.current_step.toLowerCase();
        if (step.includes('克隆') || step.includes('clone')) return 0;
        if (step.includes('分析') && !step.includes('ai')) return 1;
        if (step.includes('ai') || step.includes('深度')) return 2;
        if (step.includes('报告') || step.includes('生成')) return 3;
        return 0;
    };

    const currentStepIndex = getCurrentStepIndex();

    return (
        <div className="bg-white rounded-lg shadow-lg border p-8">
            <div className="text-center mb-8">
                <h2 className="text-2xl font-bold text-gray-900 mb-2">分析进度</h2>
                <p className="text-gray-600">{progress.message}</p>
            </div>

            {/* 进度条 */}
            <div className="mb-8">
                <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-indigo-600">进度</span>
                    <span className="text-sm font-medium text-indigo-600">{progress.progress}%</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                    <div
                        className="bg-indigo-600 h-2 rounded-full transition-all duration-500 ease-out"
                        style={{ width: `${progress.progress}%` }}
                    ></div>
                </div>
                {progress.eta_minutes && (
                    <p className="text-sm text-gray-500 mt-2">
                        预计剩余时间: {progress.eta_minutes} 分钟
                    </p>
                )}
            </div>

            {/* 步骤指示器 */}
            <div className="relative">
                {/* 连接线 */}
                <div className="absolute top-4 left-4 right-4 h-0.5 bg-gray-200">
                    <div
                        className="h-full bg-indigo-500 transition-all duration-500"
                        style={{ width: `${(currentStepIndex / (steps.length - 1)) * 100}%` }}
                    ></div>
                </div>

                {/* 步骤 */}
                <div className="relative flex justify-between">
                    {steps.map((step, index) => {
                        const isCompleted = index < currentStepIndex;
                        const isActive = index === currentStepIndex;

                        return (
                            <div key={step.key} className="flex flex-col items-center">
                                {getStepIcon(step.key, isActive, isCompleted)}
                                <div className="mt-3 text-center">
                                    <p className={`text-sm font-medium ${isActive ? 'text-indigo-600' :
                                            isCompleted ? 'text-green-600' : 'text-gray-500'
                                        }`}>
                                        {step.label}
                                    </p>
                                    <p className="text-xs text-gray-500 mt-1">{step.description}</p>
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* 当前状态 */}
            <div className="mt-8 p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-3">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-indigo-600"></div>
                    <span className="text-sm text-gray-700">{progress.current_step}</span>
                </div>
            </div>
        </div>
    );
};

export default ProgressTracker;
