import React from 'react';
import ProgressBar from '../common/ProgressBar';

interface AnalysisProgressProps {
    progress: number;
    currentStep: string;
    message: string;
    isAnalyzing: boolean;
}

const AnalysisProgress: React.FC<AnalysisProgressProps> = ({
    progress,
    currentStep,
    message,
    isAnalyzing
}) => {
    if (!isAnalyzing) {
        return null;
    }

    return (
        <div className="bg-white rounded-lg shadow-sm p-6 mb-8">
            <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-medium text-gray-700">分析进度</h2>
                <span className="text-2xl font-semibold text-accent">{progress}%</span>
            </div>

            <ProgressBar progress={progress} className="mb-4" />

            <div className="flex flex-col">
                <div className="flex justify-between text-sm text-gray-500 mb-1">
                    <span>当前步骤：</span>
                    <span className="font-medium text-accent">{currentStep}</span>
                </div>

                <div className="flex justify-between text-sm text-gray-500">
                    <span>状态：</span>
                    <span className="text-gray-700">{message}</span>
                </div>
            </div>

            {progress === 100 && (
                <div className="mt-4 p-3 bg-green-50 text-green-700 rounded-md text-sm flex items-center">
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-2" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                    </svg>
                    分析完成！结果将在下方显示
                </div>
            )}
        </div>
    );
};

export default AnalysisProgress;
