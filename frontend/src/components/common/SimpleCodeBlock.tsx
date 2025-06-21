import React from 'react';

interface SimpleCodeBlockProps {
    code: string;
    language: string;
    startingLineNumber?: number;
    className?: string;
}

const SimpleCodeBlock: React.FC<SimpleCodeBlockProps> = ({
    code,
    language,
    startingLineNumber = 1,
    className = ''
}) => {
    const lines = code.split('\n');

    return (
        <div className={`bg-gray-50 border border-gray-200 rounded-lg overflow-hidden ${className}`}>
            <div className="bg-gray-100 px-3 py-1 text-xs text-gray-600 border-b">
                {language}
            </div>
            <pre className="p-3 text-sm overflow-x-auto">
                <code>
                    {lines.map((line, index) => (
                        <div key={index} className="flex">
                            <span className="text-gray-400 select-none mr-3 text-right w-8">
                                {startingLineNumber + index}
                            </span>
                            <span className="flex-1">{line || ' '}</span>
                        </div>
                    ))}
                </code>
            </pre>
        </div>
    );
};

export default SimpleCodeBlock;
