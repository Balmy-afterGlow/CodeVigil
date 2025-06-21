import React from 'react';

interface ProgressBarProps {
    progress: number;
    className?: string;
}

const ProgressBar: React.FC<ProgressBarProps> = ({ progress, className = '' }) => {
    return (
        <div className={`progress-bar ${className}`}>
            <div
                className="progress"
                style={{ width: `${Math.max(0, Math.min(100, progress))}%` }}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={progress}
                role="progressbar"
            />
        </div>
    );
};

export default ProgressBar;
