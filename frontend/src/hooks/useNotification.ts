import { useState, useEffect } from 'react';

interface NotificationOptions {
    type: 'success' | 'error' | 'warning' | 'info';
    message: string;
    duration?: number;
}

interface Notification extends NotificationOptions {
    id: string;
    timestamp: number;
}

export const useNotification = () => {
    const [notifications, setNotifications] = useState<Notification[]>([]);

    const addNotification = ({ type, message, duration = 5000 }: NotificationOptions) => {
        const id = Math.random().toString(36).substr(2, 9);
        const notification: Notification = {
            id,
            type,
            message,
            duration,
            timestamp: Date.now(),
        };

        setNotifications(prev => [...prev, notification]);

        // 自动移除通知
        if (duration > 0) {
            setTimeout(() => {
                removeNotification(id);
            }, duration);
        }

        return id;
    };

    const removeNotification = (id: string) => {
        setNotifications(prev => prev.filter(notification => notification.id !== id));
    };

    const clearAll = () => {
        setNotifications([]);
    };

    // 便捷方法
    const showSuccess = (message: string, duration?: number) =>
        addNotification({ type: 'success', message, duration });

    const showError = (message: string, duration?: number) =>
        addNotification({ type: 'error', message, duration });

    const showWarning = (message: string, duration?: number) =>
        addNotification({ type: 'warning', message, duration });

    const showInfo = (message: string, duration?: number) =>
        addNotification({ type: 'info', message, duration });

    return {
        notifications,
        addNotification,
        removeNotification,
        clearAll,
        showSuccess,
        showError,
        showWarning,
        showInfo,
    };
};
