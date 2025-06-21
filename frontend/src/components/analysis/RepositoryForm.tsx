import React, { useState } from 'react';
import Button from '../common/Button';

interface RepositoryFormProps {
    onSubmit: (url: string, branch: string) => void;
    isLoading: boolean;
}

const RepositoryForm: React.FC<RepositoryFormProps> = ({ onSubmit, isLoading }) => {
    const [repositoryUrl, setRepositoryUrl] = useState('');
    const [branch, setBranch] = useState('');
    const [error, setError] = useState<string | null>(null);

    const validateGitHubUrl = (url: string): boolean => {
        const githubRegex = /^https:\/\/github\.com\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+(?:\.git)?$/;
        return githubRegex.test(url);
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();

        if (!repositoryUrl.trim()) {
            setError('请输入GitHub仓库URL');
            return;
        }

        if (!validateGitHubUrl(repositoryUrl)) {
            setError('请输入有效的GitHub仓库URL');
            return;
        }

        setError(null);
        onSubmit(repositoryUrl, branch);
    };

    return (
        <div className="bg-white rounded-lg shadow-sm p-6 mb-8">
            <h2 className="text-lg font-medium text-gray-700 mb-4">仓库分析</h2>

            <form onSubmit={handleSubmit}>
                <div className="mb-4">
                    <label htmlFor="repository-url" className="block text-sm font-medium text-gray-600 mb-1">
                        GitHub 仓库 URL
                    </label>
                    <input
                        id="repository-url"
                        type="text"
                        value={repositoryUrl}
                        onChange={(e) => setRepositoryUrl(e.target.value)}
                        placeholder="https://github.com/username/repository"
                        className="input"
                        disabled={isLoading}
                    />
                    {error && (
                        <p className="text-error text-sm mt-1">{error}</p>
                    )}
                </div>

                <div className="mb-6">
                    <label htmlFor="branch" className="block text-sm font-medium text-gray-600 mb-1">
                        分支 <span className="text-gray-400 font-normal">(可选，默认为主分支)</span>
                    </label>
                    <input
                        id="branch"
                        type="text"
                        value={branch}
                        onChange={(e) => setBranch(e.target.value)}
                        placeholder="main"
                        className="input"
                        disabled={isLoading}
                    />
                </div>

                <div className="flex justify-end">
                    <Button
                        type="submit"
                        isLoading={isLoading}
                        disabled={isLoading}
                        icon={
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-11a1 1 0 10-2 0v2H7a1 1 0 100 2h2v2a1 1 0 102 0v-2h2a1 1 0 100-2h-2V7z" clipRule="evenodd" />
                            </svg>
                        }
                    >
                        开始分析
                    </Button>
                </div>
            </form>
        </div>
    );
};

export default RepositoryForm;
