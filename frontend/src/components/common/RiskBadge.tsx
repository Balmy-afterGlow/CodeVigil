import React from 'react';

interface RiskBadgeProps {
    level: 'critical' | 'high' | 'medium' | 'low';
    className?: string;
}

const RiskBadge: React.FC<RiskBadgeProps> = ({ level, className = '' }) => {
    const levelText = {
        critical: '严重',
        high: '高危',
        medium: '中危',
        low: '低危',
    };

    return (
        <span className={`risk-badge ${level} ${className}`}>
            {levelText[level]}
        </span>
    );
};

export default RiskBadge;
