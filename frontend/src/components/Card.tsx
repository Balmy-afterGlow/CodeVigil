import React from 'react';

interface CardProps {
    title?: string;
    subtitle?: string;
    children: React.ReactNode;
    className?: string;
    headerAction?: React.ReactNode;
    padding?: 'none' | 'sm' | 'md' | 'lg';
}

const Card: React.FC<CardProps> = ({
    title,
    subtitle,
    children,
    className = '',
    headerAction,
    padding = 'md',
}) => {
    const paddingClasses = {
        none: '',
        sm: 'p-4',
        md: 'p-6',
        lg: 'p-8',
    };

    return (
        <div className={`bg-white rounded-lg border border-gray-200 shadow-sm ${className}`}>
            {(title || subtitle || headerAction) && (
                <div className="px-6 py-4 border-b border-gray-200">
                    <div className="flex items-center justify-between">
                        <div>
                            {title && (
                                <h3 className="text-lg font-semibold text-gray-900">{title}</h3>
                            )}
                            {subtitle && (
                                <p className="text-sm text-gray-500 mt-1">{subtitle}</p>
                            )}
                        </div>
                        {headerAction && (
                            <div className="flex-shrink-0">{headerAction}</div>
                        )}
                    </div>
                </div>
            )}

            <div className={paddingClasses[padding]}>
                {children}
            </div>
        </div>
    );
};

export default Card;
