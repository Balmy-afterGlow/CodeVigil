import React, { useState, useEffect, useRef } from 'react';

interface FileRisk {
    file_path: string;
    risk_score: number;
    language: string;
    vulnerabilities_count: number;
    lines_of_code: number;
}

interface RiskHeatmapProps {
    files: FileRisk[];
}

const RiskHeatmap: React.FC<RiskHeatmapProps> = ({ files }) => {
    const [selectedFile, setSelectedFile] = useState<FileRisk | null>(null);
    const [viewMode, setViewMode] = useState<'grid' | 'tree'>('grid');
    const canvasRef = useRef<HTMLCanvasElement>(null);

    // 按目录结构组织文件
    const organizeFilesByDirectory = (files: FileRisk[]) => {
        const tree: any = {};

        files.forEach(file => {
            const parts = file.file_path.split('/');
            let current = tree;

            parts.forEach((part, index) => {
                if (index === parts.length - 1) {
                    // 叶子节点 (文件)
                    current[part] = { ...file, type: 'file' };
                } else {
                    // 目录节点
                    if (!current[part]) {
                        current[part] = { type: 'directory', children: {} };
                    }
                    current = current[part].children || current[part];
                }
            });
        });

        return tree;
    };

    const getRiskColor = (riskScore: number) => {
        if (riskScore >= 80) return '#ef4444'; // red-500
        if (riskScore >= 60) return '#f97316'; // orange-500
        if (riskScore >= 40) return '#eab308'; // yellow-500
        if (riskScore >= 20) return '#84cc16'; // lime-500
        return '#22c55e'; // green-500
    };

    const getRiskOpacity = (riskScore: number) => {
        return Math.max(0.3, riskScore / 100);
    };

    const drawGridHeatmap = () => {
        const canvas = canvasRef.current;
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        // 设置画布大小
        const containerWidth = canvas.parentElement?.clientWidth || 800;
        canvas.width = containerWidth;
        canvas.height = Math.ceil(files.length / 10) * 60 + 40;

        // 清除画布
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        // 绘制网格
        const cellWidth = (canvas.width - 40) / 10;
        const cellHeight = 50;

        files.forEach((file, index) => {
            const row = Math.floor(index / 10);
            const col = index % 10;
            const x = 20 + col * cellWidth;
            const y = 20 + row * cellHeight;

            // 绘制文件块
            ctx.fillStyle = getRiskColor(file.risk_score);
            ctx.globalAlpha = getRiskOpacity(file.risk_score);
            ctx.fillRect(x, y, cellWidth - 2, cellHeight - 2);

            // 绘制边框
            ctx.globalAlpha = 1;
            ctx.strokeStyle = '#e5e7eb';
            ctx.lineWidth = 1;
            ctx.strokeRect(x, y, cellWidth - 2, cellHeight - 2);

            // 添加文件名 (缩短)
            ctx.fillStyle = '#374151';
            ctx.font = '10px Arial';
            ctx.textAlign = 'center';
            const fileName = file.file_path.split('/').pop() || '';
            const truncatedName = fileName.length > 8 ? fileName.substring(0, 8) + '...' : fileName;
            ctx.fillText(truncatedName, x + cellWidth / 2, y + cellHeight / 2);
        });
    };

    useEffect(() => {
        if (viewMode === 'grid') {
            drawGridHeatmap();
        }
    }, [files, viewMode]);

    const renderTreeNode = (node: any, path: string = '', level: number = 0): React.ReactNode => {
        return Object.entries(node).map(([name, item]: [string, any]) => {
            const currentPath = path ? `${path}/${name}` : name;
            const indent = level * 20;

            if (item.type === 'file') {
                const file = item as FileRisk;
                return (
                    <div
                        key={currentPath}
                        className="flex items-center py-2 px-3 hover:bg-gray-50 cursor-pointer transition-colors"
                        style={{ paddingLeft: `${indent + 12}px` }}
                        onClick={() => setSelectedFile(file)}
                    >
                        <div className="flex items-center space-x-3 flex-1">
                            <div
                                className="w-4 h-4 rounded border border-gray-300"
                                style={{
                                    backgroundColor: getRiskColor(file.risk_score),
                                    opacity: getRiskOpacity(file.risk_score)
                                }}
                            ></div>
                            <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                            </svg>
                            <span className="text-sm text-gray-900">{name}</span>
                        </div>
                        <div className="flex items-center space-x-2 text-xs text-gray-500">
                            <span>{file.vulnerabilities_count} 漏洞</span>
                            <span className={`font-medium ${file.risk_score >= 80 ? 'text-red-600' :
                                    file.risk_score >= 60 ? 'text-orange-600' :
                                        file.risk_score >= 40 ? 'text-yellow-600' : 'text-green-600'
                                }`}>
                                {file.risk_score.toFixed(1)}
                            </span>
                        </div>
                    </div>
                );
            } else {
                return (
                    <div key={currentPath}>
                        <div
                            className="flex items-center py-2 px-3 text-sm font-medium text-gray-700"
                            style={{ paddingLeft: `${indent + 12}px` }}
                        >
                            <svg className="w-4 h-4 mr-2 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-5L12 5H5a2 2 0 00-2 2z" />
                            </svg>
                            {name}/
                        </div>
                        {renderTreeNode(item.children || item, currentPath, level + 1)}
                    </div>
                );
            }
        });
    };

    const fileTree = organizeFilesByDirectory(files);

    return (
        <div className="space-y-6">
            {/* 控制面板 */}
            <div className="bg-white p-6 rounded-lg shadow border">
                <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-gray-900">风险热力图</h3>
                    <div className="flex items-center space-x-2">
                        <button
                            onClick={() => setViewMode('grid')}
                            className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${viewMode === 'grid'
                                    ? 'bg-indigo-100 text-indigo-700'
                                    : 'text-gray-500 hover:text-gray-700'
                                }`}
                        >
                            网格视图
                        </button>
                        <button
                            onClick={() => setViewMode('tree')}
                            className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${viewMode === 'tree'
                                    ? 'bg-indigo-100 text-indigo-700'
                                    : 'text-gray-500 hover:text-gray-700'
                                }`}
                        >
                            树形视图
                        </button>
                    </div>
                </div>

                {/* 风险等级说明 */}
                <div className="flex items-center space-x-6 text-sm">
                    <span className="text-gray-600">风险等级:</span>
                    {[
                        { label: '低风险', color: '#22c55e', range: '0-40' },
                        { label: '中等风险', color: '#eab308', range: '40-60' },
                        { label: '高风险', color: '#f97316', range: '60-80' },
                        { label: '极高风险', color: '#ef4444', range: '80-100' }
                    ].map((item) => (
                        <div key={item.label} className="flex items-center space-x-2">
                            <div
                                className="w-4 h-4 rounded border border-gray-300"
                                style={{ backgroundColor: item.color }}
                            ></div>
                            <span className="text-gray-700">{item.label} ({item.range})</span>
                        </div>
                    ))}
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* 热力图主视图 */}
                <div className="lg:col-span-2">
                    <div className="bg-white rounded-lg shadow border overflow-hidden">
                        <div className="p-4 border-b border-gray-200">
                            <h4 className="text-sm font-semibold text-gray-900">
                                {viewMode === 'grid' ? '文件风险网格' : '目录结构视图'}
                            </h4>
                        </div>

                        <div className="p-4">
                            {viewMode === 'grid' ? (
                                <div className="relative">
                                    <canvas
                                        ref={canvasRef}
                                        className="border border-gray-200 rounded cursor-pointer"
                                        onClick={(e) => {
                                            const canvas = canvasRef.current;
                                            if (!canvas) return;

                                            const rect = canvas.getBoundingClientRect();
                                            const x = e.clientX - rect.left;
                                            const y = e.clientY - rect.top;

                                            // 计算点击的文件
                                            const cellWidth = (canvas.width - 40) / 10;
                                            const cellHeight = 50;
                                            const col = Math.floor((x - 20) / cellWidth);
                                            const row = Math.floor((y - 20) / cellHeight);
                                            const index = row * 10 + col;

                                            if (index >= 0 && index < files.length) {
                                                setSelectedFile(files[index]);
                                            }
                                        }}
                                    />
                                    {files.length === 0 && (
                                        <div className="text-center py-8 text-gray-500">
                                            暂无数据
                                        </div>
                                    )}
                                </div>
                            ) : (
                                <div className="max-h-96 overflow-y-auto">
                                    {Object.keys(fileTree).length === 0 ? (
                                        <div className="text-center py-8 text-gray-500">
                                            暂无数据
                                        </div>
                                    ) : (
                                        renderTreeNode(fileTree)
                                    )}
                                </div>
                            )}
                        </div>
                    </div>
                </div>

                {/* 文件详情面板 */}
                <div className="lg:col-span-1">
                    <div className="bg-white rounded-lg shadow border">
                        <div className="p-4 border-b border-gray-200">
                            <h4 className="text-sm font-semibold text-gray-900">文件详情</h4>
                        </div>

                        <div className="p-4">
                            {selectedFile ? (
                                <div className="space-y-4">
                                    <div>
                                        <h5 className="text-sm font-medium text-gray-900 mb-2">文件路径</h5>
                                        <p className="text-sm text-gray-600 font-mono bg-gray-50 p-2 rounded">
                                            {selectedFile.file_path}
                                        </p>
                                    </div>

                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <h5 className="text-sm font-medium text-gray-900 mb-1">编程语言</h5>
                                            <p className="text-sm text-gray-600">{selectedFile.language}</p>
                                        </div>
                                        <div>
                                            <h5 className="text-sm font-medium text-gray-900 mb-1">代码行数</h5>
                                            <p className="text-sm text-gray-600">{selectedFile.lines_of_code}</p>
                                        </div>
                                    </div>

                                    <div>
                                        <h5 className="text-sm font-medium text-gray-900 mb-1">漏洞数量</h5>
                                        <p className="text-sm text-gray-600">{selectedFile.vulnerabilities_count} 个</p>
                                    </div>

                                    <div>
                                        <h5 className="text-sm font-medium text-gray-900 mb-1">风险评分</h5>
                                        <div className="flex items-center space-x-2">
                                            <div
                                                className="w-6 h-6 rounded border border-gray-300"
                                                style={{
                                                    backgroundColor: getRiskColor(selectedFile.risk_score),
                                                    opacity: getRiskOpacity(selectedFile.risk_score)
                                                }}
                                            ></div>
                                            <span className={`text-lg font-bold ${selectedFile.risk_score >= 80 ? 'text-red-600' :
                                                    selectedFile.risk_score >= 60 ? 'text-orange-600' :
                                                        selectedFile.risk_score >= 40 ? 'text-yellow-600' : 'text-green-600'
                                                }`}>
                                                {selectedFile.risk_score.toFixed(1)}
                                            </span>
                                        </div>
                                    </div>

                                    <div className="pt-2 border-t border-gray-200">
                                        <h5 className="text-sm font-medium text-gray-900 mb-2">风险评估</h5>
                                        <p className="text-sm text-gray-600">
                                            {selectedFile.risk_score >= 80 && '该文件存在极高安全风险，建议立即处理'}
                                            {selectedFile.risk_score >= 60 && selectedFile.risk_score < 80 && '该文件存在高安全风险，建议优先处理'}
                                            {selectedFile.risk_score >= 40 && selectedFile.risk_score < 60 && '该文件存在中等安全风险，建议及时关注'}
                                            {selectedFile.risk_score < 40 && '该文件风险相对较低，可定期检查'}
                                        </p>
                                    </div>
                                </div>
                            ) : (
                                <div className="text-center py-8">
                                    <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                    </svg>
                                    <h3 className="mt-4 text-sm font-medium text-gray-900">选择文件</h3>
                                    <p className="mt-2 text-sm text-gray-500">点击热力图中的文件查看详细信息</p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default RiskHeatmap;
