import { useState, useEffect } from 'react';
import { apiService, AnalysisResult } from '../utils/api';

export const useAnalysis = (analysisId?: string) => {
    const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        if (!analysisId) return;

        const fetchAnalysis = async () => {
            setLoading(true);
            setError(null);

            try {
                const response = await apiService.getAnalysisStatus(analysisId);
                if (response.success && response.data) {
                    setAnalysis(response.data);
                } else {
                    setError(response.error || '获取分析数据失败');
                }
            } catch (err) {
                setError(err instanceof Error ? err.message : '未知错误');
            } finally {
                setLoading(false);
            }
        };

        fetchAnalysis();

        // 如果分析正在进行中，定期轮询状态
        let interval: NodeJS.Timeout;
        if (analysis?.status === 'running' || analysis?.status === 'pending') {
            interval = setInterval(fetchAnalysis, 2000);
        }

        return () => {
            if (interval) clearInterval(interval);
        };
    }, [analysisId, analysis?.status]);

    const refresh = async () => {
        if (!analysisId) return;

        setLoading(true);
        try {
            const response = await apiService.getAnalysisStatus(analysisId);
            if (response.success && response.data) {
                setAnalysis(response.data);
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : '刷新失败');
        } finally {
            setLoading(false);
        }
    };

    return {
        analysis,
        loading,
        error,
        refresh,
    };
};
