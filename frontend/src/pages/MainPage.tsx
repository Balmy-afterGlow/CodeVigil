import React, { useState, useEffect } from 'react';
import Header from '../components/common/Header';
import RepositoryForm from '../components/analysis/RepositoryForm';
import AnalysisProgress from '../components/analysis/AnalysisProgress';
import AnalysisSummary from '../components/results/AnalysisSummary';
import RiskFilesList from '../components/results/RiskFilesList';
import VulnerabilityList from '../components/results/VulnerabilityList';
import VulnerabilityDetail from '../components/results/VulnerabilityDetail';
import { apiClient } from '../utils/apiClient';
import type {
    AnalysisResults,
    FileRiskInfo,
    VulnerabilityInfo
} from '../types';

const MainPage: React.FC = () => {
    const [repositoryUrl, setRepositoryUrl] = useState('');
    const [branch, setBranch] = useState('');
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const [isExporting, setIsExporting] = useState(false);

    // 分析状态
    const [analysisState, setAnalysisState] = useState({
        taskId: '',
        status: 'idle',
        progress: 0,
        currentStep: '',
        message: '',
    });

    // 分析结果
    const [results, setResults] = useState<AnalysisResults | null>(null);

    // 选中的文件和漏洞
    const [selectedFile, setSelectedFile] = useState<FileRiskInfo | null>(null);
    const [selectedVulnerability, setSelectedVulnerability] = useState<VulnerabilityInfo | null>(null);
    const [fileVulnerabilities, setFileVulnerabilities] = useState<VulnerabilityInfo[]>([]);

    // 定期轮询进度
    useEffect(() => {
        let interval: NodeJS.Timeout | null = null;

        if (isAnalyzing && analysisState.taskId) {
            interval = setInterval(async () => {
                try {
                    const progress = await apiClient.getAnalysisProgress(analysisState.taskId);

                    setAnalysisState(prev => ({
                        ...prev,
                        status: progress.status,
                        progress: progress.progress,
                        currentStep: progress.current_step,
                        message: progress.message,
                    }));

                    if (progress.status === 'completed') {
                        setIsAnalyzing(false);
                        fetchResults(analysisState.taskId);
                        if (interval) clearInterval(interval);
                    } else if (progress.status === 'failed') {
                        setIsAnalyzing(false);
                        if (interval) clearInterval(interval);
                    }
                } catch (error) {
                    console.error('获取进度失败:', error);
                }
            }, 2000);
        }

        return () => {
            if (interval) clearInterval(interval);
        };
    }, [isAnalyzing, analysisState.taskId]);

    // 当选中文件变化时，过滤该文件的漏洞
    useEffect(() => {
        if (selectedFile && results) {
            const fileVulns = results.vulnerabilities.filter(
                v => v.file_path === selectedFile.file_path
            );

            setFileVulnerabilities(fileVulns);
            setSelectedVulnerability(fileVulns.length > 0 ? fileVulns[0] : null);
        } else {
            setFileVulnerabilities([]);
            setSelectedVulnerability(null);
        }
    }, [selectedFile, results]);

    // 启动分析
    const startAnalysis = async (url: string, branch: string) => {
        setRepositoryUrl(url);
        setBranch(branch);
        setIsAnalyzing(true);
        setAnalysisState({
            taskId: '',
            status: 'analyzing',
            progress: 0,
            currentStep: '启动分析...',
            message: '正在初始化分析任务',
        });

        try {
            const response = await apiClient.startAnalysis({
                repository_url: url,
                branch: branch || undefined,
                analysis_options: {
                    enable_ai_analysis: true,
                    max_files_to_analyze: 50,
                    include_low_risk: false,
                    analysis_depth: 'normal'
                }
            });

            setAnalysisState(prev => ({
                ...prev,
                taskId: response.task_id,
                message: '分析任务已启动',
            }));
        } catch (error) {
            console.error('启动分析失败:', error);
            setIsAnalyzing(false);
            setAnalysisState(prev => ({
                ...prev,
                status: 'failed',
                message: '启动分析任务失败',
            }));
        }
    };

    // 获取分析结果
    const fetchResults = async (taskId: string) => {
        try {
            const result = await apiClient.getAnalysisResults(taskId);
            setResults(result);

            if (result.high_risk_files.length > 0) {
                setSelectedFile(result.high_risk_files[0]);
            }
        } catch (error) {
            console.error('获取结果失败:', error);
        }
    };

    // 导出报告
    const handleExport = async (format: string) => {
        if (!results || !analysisState.taskId) return;

        setIsExporting(true);
        try {
            const exportResult = await apiClient.exportResults(analysisState.taskId, format);

            // 创建下载链接
            const link = document.createElement('a');
            link.href = exportResult.download_url;
            link.download = `report.${format}`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        } catch (error) {
            console.error('导出失败:', error);
        } finally {
            setIsExporting(false);
        }
    };

    // 重新分析
    const resetAnalysis = () => {
        setIsAnalyzing(false);
        setResults(null);
        setSelectedFile(null);
        setSelectedVulnerability(null);
        setFileVulnerabilities([]);
        setAnalysisState({
            taskId: '',
            status: 'idle',
            progress: 0,
            currentStep: '',
            message: '',
        });
    };

    return (
        <div className="min-h-screen bg-background">
            <Header />

            <div className="container mx-auto px-4 py-6">
                {!results && (
                    <RepositoryForm
                        onSubmit={startAnalysis}
                        isLoading={isAnalyzing}
                    />
                )}

                <AnalysisProgress
                    progress={analysisState.progress}
                    currentStep={analysisState.currentStep}
                    message={analysisState.message}
                    isAnalyzing={isAnalyzing}
                />

                {results && (
                    <div className="mb-6 flex justify-between items-center">
                        <h1 className="text-2xl font-bold text-gray-700">分析结果</h1>
                        <button
                            onClick={resetAnalysis}
                            className="text-accent hover:text-gray-700 flex items-center"
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-1" viewBox="0 0 20 20" fill="currentColor">
                                <path fillRule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z" clipRule="evenodd" />
                            </svg>
                            重新分析
                        </button>
                    </div>
                )}

                {results && (
                    <AnalysisSummary
                        results={results}
                        onExport={handleExport}
                        isExporting={isExporting}
                    />
                )}

                {results && (
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div>
                            <RiskFilesList
                                files={results.high_risk_files}
                                onFileSelect={setSelectedFile}
                                selectedFile={selectedFile}
                            />
                        </div>
                        <div className="md:col-span-2">
                            {selectedFile && (
                                <>
                                    <VulnerabilityList
                                        vulnerabilities={fileVulnerabilities}
                                        onSelect={setSelectedVulnerability}
                                        selectedVulnerability={selectedVulnerability}
                                    />

                                    {selectedVulnerability && (
                                        <VulnerabilityDetail vulnerability={selectedVulnerability} />
                                    )}
                                </>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default MainPage;
