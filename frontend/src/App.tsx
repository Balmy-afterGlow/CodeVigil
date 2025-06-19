import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import Header from './components/Header';
import Dashboard from './pages/Dashboard';
import AnalysisPage from './pages/AnalysisPage';
import ResultsPage from './pages/ResultsPage';
import './App.css';

function App() {
    return (
        <Router>
            <div className="min-h-screen bg-gray-50">
                <Header />
                <main className="container mx-auto px-4 py-8">
                    <Routes>
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/analysis" element={<AnalysisPage />} />
                        <Route path="/results/:taskId" element={<ResultsPage />} />
                    </Routes>
                </main>
                <Toaster position="top-right" />
            </div>
        </Router>
    );
}

export default App;
