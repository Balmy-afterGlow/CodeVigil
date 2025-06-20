import React from 'react';
import { getSeverityBadgeColor } from '../utils/helpers';

interface BadgeProps {
    variant?: 'default' | 'severity' | 'status' | 'custom';
    color?: string;
    size?: 'sm' | 'md' | 'lg';
    children: React.ReactNode;
    className?: string;
}

const Badge: React.FC<BadgeProps> = ({
    variant = 'default',
    color,
    size = 'md',
    children,
    className = '',
}) => {
    const baseClasses = 'inline-flex items-center font-medium rounded-full border';

    const sizeClasses = {
        sm: 'px-2 py-0.5 text-xs',
        md: 'px-2.5 py-1 text-sm',
        lg: 'px-3 py-1.5 text-base',
    };

    const variantClasses = {
        default: 'bg-gray-100 text-gray-800 border-gray-200',
        severity: color ? getSeverityBadgeColor(color) : 'bg-gray-100 text-gray-800 border-gray-200',
        status: getStatusColor(color || ''),
        custom: color || 'bg-gray-100 text-gray-800 border-gray-200',
    };

    function getStatusColor(status: string): string {
        switch (status) {
            case 'completed':
                return 'bg-green-100 text-green-800 border-green-200';
            case 'running':
                return 'bg-blue-100 text-blue-800 border-blue-200';
            case 'pending':
                return 'bg-yellow-100 text-yellow-800 border-yellow-200';
            case 'failed':
                return 'bg-red-100 text-red-800 border-red-200';
            default:
                return 'bg-gray-100 text-gray-800 border-gray-200';
        }
    }

    return (
        <span
            className={`
        ${baseClasses}
        ${sizeClasses[size]}
        ${variantClasses[variant]}
        ${className}
      `}
        >
            {children}
        </span>
    );
};

export default Badge;
