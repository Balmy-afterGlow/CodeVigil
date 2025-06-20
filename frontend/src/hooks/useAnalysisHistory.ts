import { useState, useEffect } from 'react';
import { apiService, AnalysisResult } from '../utils/api';

export const useAnalysisHistory = () => {
    const [history, setHistory] = useState<AnalysisResult[]>([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const fetchHistory = async () => {
        setLoading(true);
        setError(null);

        try {
            const response = await apiService.getAnalysisHistory();
            if (response.success && response.data) {
                setHistory(response.data);
            } else {
                setError(response.error || '获取历史记录失败');
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : '未知错误');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchHistory();
    }, []);

    const refresh = () => {
        fetchHistory();
    };

    const addAnalysis = (analysis: AnalysisResult) => {
        setHistory(prev => [analysis, ...prev]);
    };

    const updateAnalysis = (updatedAnalysis: AnalysisResult) => {
        setHistory(prev =>
            prev.map(item =>
                item.id === updatedAnalysis.id ? updatedAnalysis : item
            )
        );
    };

    return {
        history,
        loading,
        error,
        refresh,
        addAnalysis,
        updateAnalysis,
    };
};
