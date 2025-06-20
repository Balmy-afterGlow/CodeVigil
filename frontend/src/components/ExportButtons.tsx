import React, { useState } from 'react';
import toast from 'react-hot-toast';

interface ExportButtonsProps {
    taskId: string;
}

const ExportButtons: React.FC<ExportButtonsProps> = ({ taskId }) => {
    const [isExporting, setIsExporting] = useState<string | null>(null);

    const handleExport = async (format: 'json' | 'pdf' | 'markdown') => {
        setIsExporting(format);

        try {
            const response = await fetch(`/api/export/${taskId}/${format}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
            });

            if (!response.ok) {
                throw new Error('导出失败');
            }

            const result = await response.json();

            // 下载文件
            const downloadUrl = result.download_url;
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.download = `analysis_report_${taskId}.${format}`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);

            toast.success(`${format.toUpperCase()} 报告已生成并下载`);
        } catch (error) {
            toast.error(`导出 ${format.toUpperCase()} 报告失败`);
            console.error('Export error:', error);
        } finally {
            setIsExporting(null);
        }
    };

    const exportOptions = [
        {
            format: 'json' as const,
            label: 'JSON',
            description: '机器可读的结构化数据',
            icon: (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                </svg>
            ),
            color: 'bg-blue-500 hover:bg-blue-600'
        },
        {
            format: 'pdf' as const,
            label: 'PDF',
            description: '专业格式的分析报告',
            icon: (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
            ),
            color: 'bg-red-500 hover:bg-red-600'
        },
        {
            format: 'markdown' as const,
            label: 'Markdown',
            description: '易读的文档格式',
            icon: (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                </svg>
            ),
            color: 'bg-green-500 hover:bg-green-600'
        }
    ];

    return (
        <div className="flex items-center space-x-3">
            <span className="text-sm font-medium text-gray-700">导出报告:</span>

            {exportOptions.map((option) => (
                <button
                    key={option.format}
                    onClick={() => handleExport(option.format)}
                    disabled={isExporting !== null}
                    className={`
            ${option.color} text-white px-4 py-2 rounded-lg font-medium text-sm
            disabled:bg-gray-400 disabled:cursor-not-allowed
            transition-colors flex items-center space-x-2
            hover:shadow-md transform hover:scale-105 transition-transform
          `}
                    title={option.description}
                >
                    {isExporting === option.format ? (
                        <>
                            <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                            <span>导出中...</span>
                        </>
                    ) : (
                        <>
                            {option.icon}
                            <span>{option.label}</span>
                        </>
                    )}
                </button>
            ))}
        </div>
    );
};

export default ExportButtons;
