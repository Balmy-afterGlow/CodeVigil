import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Header from '../components/Header';
import Dashboard from '../pages/Dashboard';
import AnalysisPage from '../pages/AnalysisPage';
import ResultsPage from '../pages/ResultsPage';
import HistoryPage from '../pages/HistoryPage';
import NotificationContainer from '../components/NotificationContainer';

const AppRoutes: React.FC = () => {
    return (
        <Router>
            <div className="min-h-screen bg-gray-50">
                <Header />
                <main className="container mx-auto px-4 py-8">
                    <Routes>
                        <Route path="/" element={<Navigate to="/dashboard" replace />} />
                        <Route path="/dashboard" element={<Dashboard />} />
                        <Route path="/analysis" element={<AnalysisPage />} />
                        <Route path="/results/:analysisId" element={<ResultsPage />} />
                        <Route path="/history" element={<HistoryPage />} />
                        <Route path="*" element={<Navigate to="/dashboard" replace />} />
                    </Routes>
                </main>
                <NotificationContainer />
            </div>
        </Router>
    );
};

export default AppRoutes;
