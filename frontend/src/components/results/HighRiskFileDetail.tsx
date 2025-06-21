import React, { useState } from 'react';
import { HighRiskFileInfo, CVEReference, CodeDiffBlock } from '../../types';
import { morandiColors } from '../../types';
import SimpleCodeBlock from '../common/SimpleCodeBlock';
import './HighRiskFileDetail.css';
import {
    ChevronDownIcon,
    ChevronRightIcon,
    ExclamationTriangleIcon,
    ShieldExclamationIcon,
    CodeBracketIcon,
    LinkIcon,
    ClipboardDocumentIcon
} from '@heroicons/react/24/outline';

interface HighRiskFileDetailProps {
    file: HighRiskFileInfo;
    className?: string;
}

const HighRiskFileDetail: React.FC<HighRiskFileDetailProps> = ({ file, className = '' }) => {
    const [isExpanded, setIsExpanded] = useState(false);
    const [expandedVulns, setExpandedVulns] = useState<Set<number>>(new Set());
    const [expandedDiffs, setExpandedDiffs] = useState<Set<string>>(new Set());

    const getRiskColor = (riskLevel: string) => {
        switch (riskLevel) {
            case 'critical':
                return morandiColors.risk.critical;
            case 'high':
                return morandiColors.risk.high;
            case 'medium':
                return morandiColors.risk.medium;
            case 'low':
                return morandiColors.risk.low;
            default:
                return morandiColors.gray[400];
        }
    };

    const getRiskBadgeClass = (riskLevel: string) => {
        switch (riskLevel) {
            case 'critical':
                return 'bg-red-100 text-red-800 border-red-200';
            case 'high':
                return 'bg-orange-100 text-orange-800 border-orange-200';
            case 'medium':
                return 'bg-yellow-100 text-yellow-800 border-yellow-200';
            case 'low':
                return 'bg-green-100 text-green-800 border-green-200';
            default:
                return 'bg-gray-100 text-gray-800 border-gray-200';
        }
    };

    const getSeverityIcon = (severity: string) => {
        switch (severity) {
            case 'critical':
            case 'high':
                return <ExclamationTriangleIcon className="w-4 h-4" />;
            case 'medium':
                return <ShieldExclamationIcon className="w-4 h-4" />;
            default:
                return <ShieldExclamationIcon className="w-4 h-4" />;
        }
    };

    const toggleVulnExpanded = (index: number) => {
        const newExpanded = new Set(expandedVulns);
        if (newExpanded.has(index)) {
            newExpanded.delete(index);
        } else {
            newExpanded.add(index);
        }
        setExpandedVulns(newExpanded);
    };

    const toggleDiffExpanded = (diffId: string) => {
        const newExpanded = new Set(expandedDiffs);
        if (newExpanded.has(diffId)) {
            newExpanded.delete(diffId);
        } else {
            newExpanded.add(diffId);
        }
        setExpandedDiffs(newExpanded);
    };

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
    };

    const renderCVEReferences = (cveRefs: CVEReference[]) => {
        if (!cveRefs || cveRefs.length === 0) return null;

        return (
            <div className="mt-3">
                <h5 className="text-sm font-medium text-gray-700 mb-2 flex items-center">
                    <LinkIcon className="w-4 h-4 mr-1" />
                    关联CVE参考
                </h5>
                <div className="flex flex-wrap gap-2">
                    {cveRefs.map((cve, index) => (
                        <div
                            key={index}
                            className="inline-flex items-center px-3 py-1 rounded-full text-xs bg-blue-50 border border-blue-200 text-blue-700"
                        >
                            <span className="font-medium">{cve.cve_id}</span>
                            {cve.cvss_score && (
                                <span className="ml-2 px-1.5 py-0.5 bg-blue-100 rounded text-xs">
                                    CVSS: {cve.cvss_score}
                                </span>
                            )}
                            {cve.url && (
                                <a
                                    href={cve.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="ml-2 text-blue-600 hover:text-blue-800"
                                >
                                    <LinkIcon className="w-3 h-3" />
                                </a>
                            )}
                        </div>
                    ))}
                </div>
            </div>
        );
    };

    const renderCodeDiff = (diff: CodeDiffBlock, diffIndex: number) => {
        const diffId = `${file.file_path}-${diffIndex}`;
        const isExpanded = expandedDiffs.has(diffId);

        return (
            <div key={diffIndex} className="mt-4 border border-gray-200 rounded-lg overflow-hidden">
                <div
                    className="bg-gray-50 px-4 py-3 cursor-pointer hover:bg-gray-100 transition-colors"
                    onClick={() => toggleDiffExpanded(diffId)}
                >
                    <div className="flex items-center justify-between">
                        <div className="flex items-center">
                            <CodeBracketIcon className="w-4 h-4 mr-2 text-gray-500" />
                            <span className="font-medium text-sm text-gray-700">
                                {diff.description}
                            </span>
                            <span className="ml-2 text-xs text-gray-500">
                                (行 {diff.start_line}-{diff.end_line})
                            </span>
                        </div>
                        {isExpanded ?
                            <ChevronDownIcon className="w-4 h-4 text-gray-500" /> :
                            <ChevronRightIcon className="w-4 h-4 text-gray-500" />
                        }
                    </div>
                </div>

                {isExpanded && (
                    <div className="p-4 bg-white">
                        <div className="mb-3">
                            <div className="text-sm text-gray-600 prose prose-sm max-w-none">
                                {diff.explanation}
                            </div>
                        </div>

                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                            {/* 原始代码 */}
                            <div className="bg-red-50 border border-red-200 rounded-lg overflow-hidden">
                                <div className="bg-red-100 px-3 py-2 flex items-center justify-between">
                                    <span className="text-xs font-medium text-red-700">修改前</span>
                                    <button
                                        onClick={() => copyToClipboard(diff.original_code)}
                                        className="text-red-600 hover:text-red-800"
                                    >
                                        <ClipboardDocumentIcon className="w-4 h-4" />
                                    </button>
                                </div>
                                <SimpleCodeBlock
                                    code={diff.original_code}
                                    language={file.language}
                                    startingLineNumber={diff.start_line}
                                    className="bg-red-50"
                                />
                            </div>

                            {/* 修复后代码 */}
                            <div className="bg-green-50 border border-green-200 rounded-lg overflow-hidden">
                                <div className="bg-green-100 px-3 py-2 flex items-center justify-between">
                                    <span className="text-xs font-medium text-green-700">修改后</span>
                                    <button
                                        onClick={() => copyToClipboard(diff.fixed_code)}
                                        className="text-green-600 hover:text-green-800"
                                    >
                                        <ClipboardDocumentIcon className="w-4 h-4" />
                                    </button>
                                </div>
                                <SimpleCodeBlock
                                    code={diff.fixed_code}
                                    language={file.language}
                                    startingLineNumber={diff.start_line}
                                    className="bg-green-50"
                                />
                            </div>
                        </div>
                    </div>
                )}
            </div>
        );
    };

    return (
        <div className={`bg-white border border-gray-200 rounded-lg shadow-sm ${className}`}>
            {/* 文件头部信息 */}
            <div
                className="p-4 cursor-pointer hover:bg-gray-50 transition-colors"
                onClick={() => setIsExpanded(!isExpanded)}
            >
                <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                        {isExpanded ?
                            <ChevronDownIcon className="w-5 h-5 text-gray-500" /> :
                            <ChevronRightIcon className="w-5 h-5 text-gray-500" />
                        }
                        <div>
                            <div className="flex items-center space-x-2">
                                <h3 className="font-medium text-gray-900 truncate max-w-md">
                                    {file.file_path}
                                </h3>
                                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getRiskBadgeClass(file.risk_level)}`}>
                                    {file.risk_level.toUpperCase()}
                                </span>
                                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-600">
                                    {file.language}
                                </span>
                            </div>
                            <div className="flex items-center space-x-4 mt-1 text-sm text-gray-500">
                                <span>风险分数: {file.risk_score.toFixed(1)}</span>
                                <span>代码行数: {file.lines_of_code.toLocaleString()}</span>
                                <span>漏洞数量: {file.vulnerabilities.length}</span>
                                {file.confidence && (
                                    <span>置信度: {(file.confidence * 100).toFixed(1)}%</span>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* 风险分数可视化 */}
                    <div className="flex items-center space-x-2">
                        <div className="w-20 h-2 bg-gray-200 rounded-full overflow-hidden">
                            <div
                                className="h-full transition-all duration-300"
                                style={{
                                    width: `${Math.min(file.risk_score, 100)}%`,
                                    backgroundColor: getRiskColor(file.risk_level)
                                }}
                            />
                        </div>
                        <span className="text-sm font-medium" style={{ color: getRiskColor(file.risk_level) }}>
                            {file.risk_score.toFixed(1)}
                        </span>
                    </div>
                </div>
            </div>

            {/* 展开的详细内容 */}
            {isExpanded && (
                <div className="border-t border-gray-200">
                    {/* AI分析摘要 */}
                    {file.ai_analysis_summary && (
                        <div className="p-4 bg-blue-50 border-b border-gray-200">
                            <h4 className="font-medium text-blue-900 mb-2">AI分析摘要</h4>
                            <p className="text-sm text-blue-800">{file.ai_analysis_summary}</p>
                            {file.analysis_reasoning && (
                                <details className="mt-2">
                                    <summary className="text-xs text-blue-600 cursor-pointer hover:text-blue-800">
                                        查看分析推理过程
                                    </summary>
                                    <p className="text-xs text-blue-700 mt-1 pl-4">{file.analysis_reasoning}</p>
                                </details>
                            )}
                        </div>
                    )}

                    {/* 漏洞列表 */}
                    <div className="p-4">
                        <h4 className="font-medium text-gray-900 mb-3 flex items-center">
                            <ExclamationTriangleIcon className="w-4 h-4 mr-2" />
                            发现的安全漏洞 ({file.vulnerabilities.length})
                        </h4>

                        <div className="space-y-3">
                            {file.vulnerabilities.map((vuln, index) => (
                                <div key={index} className="border border-gray-200 rounded-lg overflow-hidden">
                                    <div
                                        className="p-3 bg-gray-50 cursor-pointer hover:bg-gray-100 transition-colors"
                                        onClick={() => toggleVulnExpanded(index)}
                                    >
                                        <div className="flex items-center justify-between">
                                            <div className="flex items-center space-x-2">
                                                {getSeverityIcon(vuln.severity)}
                                                <span className="font-medium text-sm">{vuln.title}</span>
                                                <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${getRiskBadgeClass(vuln.severity)}`}>
                                                    {vuln.severity.toUpperCase()}
                                                </span>
                                                {vuln.cwe_id && (
                                                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-purple-100 text-purple-700">
                                                        {vuln.cwe_id}
                                                    </span>
                                                )}
                                            </div>
                                            {expandedVulns.has(index) ?
                                                <ChevronDownIcon className="w-4 h-4 text-gray-500" /> :
                                                <ChevronRightIcon className="w-4 h-4 text-gray-500" />
                                            }
                                        </div>
                                        <div className="mt-1 text-xs text-gray-500">
                                            行 {vuln.line_number} · 置信度 {(vuln.confidence * 100).toFixed(1)}%
                                        </div>
                                    </div>

                                    {expandedVulns.has(index) && (
                                        <div className="p-4 bg-white border-t border-gray-200">
                                            <div className="space-y-4">
                                                {/* 漏洞描述 */}
                                                <div>
                                                    <h5 className="text-sm font-medium text-gray-700 mb-2">漏洞描述</h5>
                                                    <p className="text-sm text-gray-600">{vuln.description}</p>
                                                </div>

                                                {/* 影响和修复建议 */}
                                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                    {vuln.impact && (
                                                        <div>
                                                            <h5 className="text-sm font-medium text-gray-700 mb-2">安全影响</h5>
                                                            <p className="text-sm text-gray-600">{vuln.impact}</p>
                                                        </div>
                                                    )}
                                                    {vuln.remediation && (
                                                        <div>
                                                            <h5 className="text-sm font-medium text-gray-700 mb-2">修复建议</h5>
                                                            <p className="text-sm text-gray-600">{vuln.remediation}</p>
                                                        </div>
                                                    )}
                                                </div>

                                                {/* 代码片段 */}
                                                {vuln.code_snippet && (
                                                    <div>
                                                        <h5 className="text-sm font-medium text-gray-700 mb-2">问题代码</h5>
                                                        <SimpleCodeBlock
                                                            code={vuln.code_snippet}
                                                            language={file.language}
                                                            startingLineNumber={vuln.line_number}
                                                        />
                                                    </div>
                                                )}

                                                {/* CVE参考 */}
                                                {renderCVEReferences(vuln.cve_references || [])}

                                                {/* 修复差异 */}
                                                {vuln.fix_suggestions && vuln.fix_suggestions.length > 0 && (
                                                    <div>
                                                        <h5 className="text-sm font-medium text-gray-700 mb-2">修复代码差异</h5>
                                                        {vuln.fix_suggestions.map((diff, diffIndex) =>
                                                            renderCodeDiff(diff, diffIndex)
                                                        )}
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default HighRiskFileDetail;
