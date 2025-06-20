"""
RAG (Retrieval Augmented Generation) 模块
用于基于知识库的安全分析和建议生成
"""

from .knowledge_base import KnowledgeBaseManager, VulnerabilityKnowledge
from .query_engine import SecurityRAGQueryEngine

__all__ = ["KnowledgeBaseManager", "VulnerabilityKnowledge", "SecurityRAGQueryEngine"]
