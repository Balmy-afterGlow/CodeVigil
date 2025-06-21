"""
RAG (Retrieval Augmented Generation) 模块
用于基于知识库的安全分析和建议生成
"""

from .cve_knowledge_base import CVEfixesKnowledgeBase, CVEFixKnowledge

__all__ = ["CVEfixesKnowledgeBase", "CVEFixKnowledge"]
