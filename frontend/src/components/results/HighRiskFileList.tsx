import React, { useState } from 'react';
import { HighRiskFileInfo } from '../../types';
import { morandiColors } from '../../types';
import HighRiskFileDetail from './HighRiskFileDetail';
import {
    AdjustmentsHorizontalIcon,
    FunnelIcon,
    MagnifyingGlassIcon
} from '@heroicons/react/24/outline';

interface HighRiskFileListProps {
    files: HighRiskFileInfo[];
    className?: string;
}

const HighRiskFileList: React.FC<HighRiskFileListProps> = ({ files, className = '' }) => {
    const [searchTerm, setSearchTerm] = useState('');
    const [riskFilter, setRiskFilter] = useState<string>('all');
    const [languageFilter, setLanguageFilter] = useState<string>('all');
    const [sortBy, setSortBy] = useState<'risk_score' | 'vulnerabilities_count' | 'file_path'>('risk_score');
    const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

    // 获取所有的编程语言
    const languages = Array.from(new Set(files.map(f => f.language))).sort();

    // 过滤和排序文件
    const filteredAndSortedFiles = files
        .filter(file => {
            // 搜索过滤
            const matchesSearch = file.file_path.toLowerCase().includes(searchTerm.toLowerCase()) ||
                file.vulnerabilities.some(v =>
                    v.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                    v.description.toLowerCase().includes(searchTerm.toLowerCase())
                );

            // 风险等级过滤
            const matchesRisk = riskFilter === 'all' || file.risk_level === riskFilter;

            // 编程语言过滤
            const matchesLanguage = languageFilter === 'all' || file.language === languageFilter;

            return matchesSearch && matchesRisk && matchesLanguage;
        })
        .sort((a, b) => {
            let comparison = 0;

            switch (sortBy) {
                case 'risk_score':
                    comparison = a.risk_score - b.risk_score;
                    break;
                case 'vulnerabilities_count':
                    comparison = a.vulnerabilities.length - b.vulnerabilities.length;
                    break;
                case 'file_path':
                    comparison = a.file_path.localeCompare(b.file_path);
                    break;
                default:
                    comparison = 0;
            }

            return sortOrder === 'asc' ? comparison : -comparison;
        });

    const totalVulnerabilities = filteredAndSortedFiles.reduce((sum, file) => sum + file.vulnerabilities.length, 0);

    return (
        <div className={`bg-white ${className}`}>
            {/* 标题和统计 */}
            <div className="border-b border-gray-200 p-6">
                <div className="flex items-center justify-between">
                    <div>
                        <h2 className="text-xl font-semibold text-gray-900">高危文件详情</h2>
                        <p className="mt-1 text-sm text-gray-600">
                            显示 {filteredAndSortedFiles.length} 个高危文件，共发现 {totalVulnerabilities} 个安全漏洞
                        </p>
                    </div>

                    {/* 快速统计 */}
                    <div className="flex items-center space-x-4">
                        {['critical', 'high', 'medium', 'low'].map(level => {
                            const count = filteredAndSortedFiles.filter(f => f.risk_level === level).length;
                            if (count === 0) return null;

                            return (
                                <div key={level} className="text-center">
                                    <div className={`text-lg font-semibold ${level === 'critical' ? 'text-red-600' :
                                            level === 'high' ? 'text-orange-600' :
                                                level === 'medium' ? 'text-yellow-600' : 'text-green-600'
                                        }`}>
                                        {count}
                                    </div>
                                    <div className="text-xs text-gray-500 capitalize">{level}</div>
                                </div>
                            );
                        })}
                    </div>
                </div>
            </div>

            {/* 过滤和搜索工具栏 */}
            <div className="p-4 bg-gray-50 border-b border-gray-200">
                <div className="flex flex-wrap items-center gap-4">
                    {/* 搜索框 */}
                    <div className="flex-1 min-w-64">
                        <div className="relative">
                            <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                            <input
                                type="text"
                                placeholder="搜索文件路径或漏洞描述..."
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            />
                        </div>
                    </div>

                    {/* 风险等级过滤 */}
                    <div className="flex items-center space-x-2">
                        <FunnelIcon className="w-4 h-4 text-gray-500" />
                        <select
                            value={riskFilter}
                            onChange={(e) => setRiskFilter(e.target.value)}
                            className="border border-gray-300 rounded-md px-3 py-2 text-sm"
                        >
                            <option value="all">所有风险等级</option>
                            <option value="critical">严重</option>
                            <option value="high">高危</option>
                            <option value="medium">中危</option>
                            <option value="low">低危</option>
                        </select>
                    </div>

                    {/* 编程语言过滤 */}
                    <div className="flex items-center space-x-2">
                        <select
                            value={languageFilter}
                            onChange={(e) => setLanguageFilter(e.target.value)}
                            className="border border-gray-300 rounded-md px-3 py-2 text-sm"
                        >
                            <option value="all">所有语言</option>
                            {languages.map(lang => (
                                <option key={lang} value={lang}>{lang}</option>
                            ))}
                        </select>
                    </div>

                    {/* 排序选项 */}
                    <div className="flex items-center space-x-2">
                        <AdjustmentsHorizontalIcon className="w-4 h-4 text-gray-500" />
                        <select
                            value={`${sortBy}-${sortOrder}`}
                            onChange={(e) => {
                                const [field, order] = e.target.value.split('-');
                                setSortBy(field as any);
                                setSortOrder(order as any);
                            }}
                            className="border border-gray-300 rounded-md px-3 py-2 text-sm"
                        >
                            <option value="risk_score-desc">风险分数 (高到低)</option>
                            <option value="risk_score-asc">风险分数 (低到高)</option>
                            <option value="vulnerabilities_count-desc">漏洞数量 (多到少)</option>
                            <option value="vulnerabilities_count-asc">漏洞数量 (少到多)</option>
                            <option value="file_path-asc">文件路径 (A-Z)</option>
                            <option value="file_path-desc">文件路径 (Z-A)</option>
                        </select>
                    </div>
                </div>
            </div>

            {/* 文件列表 */}
            <div className="p-6">
                {filteredAndSortedFiles.length === 0 ? (
                    <div className="text-center py-12">
                        <div className="text-gray-500 text-lg">没有找到匹配的高危文件</div>
                        <p className="text-gray-400 text-sm mt-2">
                            尝试调整搜索条件或过滤器
                        </p>
                    </div>
                ) : (
                    <div className="space-y-6">
                        {filteredAndSortedFiles.map((file, index) => (
                            <HighRiskFileDetail
                                key={`${file.file_path}-${index}`}
                                file={file}
                                className="transition-all duration-200 hover:shadow-md"
                            />
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
};

export default HighRiskFileList;
