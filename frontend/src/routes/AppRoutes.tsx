import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import MainPage from '../pages/MainPage';

const AppRoutes: React.FC = () => {
    return (
        <Router>
            <div className="min-h-screen">
                <Routes>
                    <Route path="/" element={<MainPage />} />
                    <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
            </div>
        </Router>
    );
};

export default AppRoutes;
