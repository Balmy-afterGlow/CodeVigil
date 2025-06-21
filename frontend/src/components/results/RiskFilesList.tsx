import React from 'react';
import RiskBadge from '../common/RiskBadge';
import type { FileRiskInfo } from '../../types';

interface RiskFilesListProps {
    files: FileRiskInfo[];
    onFileSelect: (file: FileRiskInfo) => void;
    selectedFile: FileRiskInfo | null;
}

const RiskFilesList: React.FC<RiskFilesListProps> = ({
    files,
    onFileSelect,
    selectedFile
}) => {
    const getRiskLevel = (score: number): 'critical' | 'high' | 'medium' | 'low' => {
        if (score >= 8.0) return 'critical';
        if (score >= 6.0) return 'high';
        if (score >= 3.0) return 'medium';
        return 'low';
    };

    return (
        <div className="bg-white rounded-lg shadow-sm overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-700">高风险文件列表</h3>
            </div>

            {files.length === 0 ? (
                <div className="p-6 text-center text-gray-500">
                    没有发现高风险文件
                </div>
            ) : (
                <ul className="divide-y divide-gray-200 max-h-[400px] overflow-y-auto">
                    {files.map((file, index) => {
                        const riskLevel = getRiskLevel(file.risk_score);
                        const isSelected = selectedFile?.file_path === file.file_path;

                        return (
                            <li
                                key={index}
                                className={`px-6 py-4 hover:bg-gray-50 cursor-pointer transition-colors ${isSelected ? 'bg-gray-50 border-l-4 border-accent' : ''
                                    }`}
                                onClick={() => onFileSelect(file)}
                            >
                                <div className="flex items-center justify-between mb-2">
                                    <div className="flex items-center">
                                        <span className={`w-2 h-2 rounded-full mr-2 ${riskLevel === 'critical' ? 'bg-risk-critical' :
                                                riskLevel === 'high' ? 'bg-risk-high' :
                                                    riskLevel === 'medium' ? 'bg-risk-medium' : 'bg-risk-low'
                                            }`}></span>
                                        <RiskBadge level={riskLevel} />
                                    </div>
                                    <span className="text-sm text-gray-500">{file.language}</span>
                                </div>

                                <div className="flex justify-between items-baseline">
                                    <p className="font-mono text-sm truncate" title={file.file_path}>
                                        {file.file_path.split('/').pop()}
                                    </p>
                                    <span className="text-xs text-gray-500">
                                        {file.vulnerabilities_count} 个问题
                                    </span>
                                </div>

                                <p className="text-xs text-gray-500 mt-1 truncate" title={file.file_path}>
                                    {file.file_path}
                                </p>
                            </li>
                        );
                    })}
                </ul>
            )}
        </div>
    );
};

export default RiskFilesList;
