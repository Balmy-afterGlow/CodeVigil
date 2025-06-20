"""
增强型AST分析器 - 深度语义分析和风险评估
"""

import ast
import os
from typing import Dict, List, Any, Set, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import re


class RiskLevel(Enum):
    """风险级别"""

    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


@dataclass
class SecurityPattern:
    """安全模式"""

    pattern_id: str
    name: str
    risk_level: RiskLevel
    description: str
    context_sensitive: bool = True


@dataclass
class ASTSecurityFinding:
    """AST安全发现"""

    pattern_id: str
    name: str
    risk_level: RiskLevel
    line_number: int
    column: int
    function_name: Optional[str]
    code_snippet: str
    context: Dict[str, Any]
    confidence: float


class EnhancedASTAnalyzer:
    """增强型AST分析器"""

    def __init__(self):
        self.security_patterns = self._load_security_patterns()
        self.current_function = None
        self.current_class = None
        self.call_graph = {}
        self.data_flow = {}

    def _load_security_patterns(self) -> Dict[str, SecurityPattern]:
        """加载安全模式"""
        patterns = {}

        # 代码注入模式
        patterns["EVAL_INJECTION"] = SecurityPattern(
            "EVAL_INJECTION",
            "eval()代码注入",
            RiskLevel.CRITICAL,
            "eval()函数可能导致任意代码执行",
        )

        patterns["EXEC_INJECTION"] = SecurityPattern(
            "EXEC_INJECTION",
            "exec()代码注入",
            RiskLevel.CRITICAL,
            "exec()函数可能导致任意代码执行",
        )

        # 命令注入模式
        patterns["OS_SYSTEM"] = SecurityPattern(
            "OS_SYSTEM", "系统命令执行", RiskLevel.HIGH, "os.system()可能导致命令注入"
        )

        patterns["SUBPROCESS_SHELL"] = SecurityPattern(
            "SUBPROCESS_SHELL",
            "Shell命令执行",
            RiskLevel.HIGH,
            "subprocess使用shell=True可能导致命令注入",
        )

        # 文件操作模式
        patterns["FILE_INCLUSION"] = SecurityPattern(
            "FILE_INCLUSION",
            "文件包含漏洞",
            RiskLevel.MEDIUM,
            "动态文件路径可能导致路径遍历",
        )

        # 序列化安全
        patterns["PICKLE_LOADS"] = SecurityPattern(
            "PICKLE_LOADS",
            "不安全反序列化",
            RiskLevel.HIGH,
            "pickle.loads()可能导致任意代码执行",
        )

        # SQL注入模式
        patterns["SQL_CONCATENATION"] = SecurityPattern(
            "SQL_CONCATENATION",
            "SQL字符串拼接",
            RiskLevel.HIGH,
            "字符串拼接构造SQL可能导致注入",
        )

        # 密码学问题
        patterns["WEAK_RANDOM"] = SecurityPattern(
            "WEAK_RANDOM",
            "弱随机数生成",
            RiskLevel.MEDIUM,
            "使用random模块生成安全敏感的随机数",
        )

        patterns["HARDCODED_SECRET"] = SecurityPattern(
            "HARDCODED_SECRET",
            "硬编码密钥",
            RiskLevel.HIGH,
            "代码中硬编码密钥、密码等敏感信息",
        )

        return patterns

    def analyze_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """深度分析Python文件"""
        try:
            tree = ast.parse(content)

            # 重置分析状态
            self.current_function = None
            self.current_class = None
            self.call_graph = {}
            self.data_flow = {}

            # 多轮分析
            analyzer = SecurityASTVisitor(self, file_path)
            analyzer.visit(tree)

            # 计算综合风险评分
            risk_score = self._calculate_comprehensive_risk(
                analyzer.findings, analyzer.metrics
            )

            return {
                "file_path": file_path,
                "risk_score": risk_score,
                "security_findings": [
                    {
                        "pattern_id": f.pattern_id,
                        "name": f.name,
                        "risk_level": f.risk_level.name,
                        "line_number": f.line_number,
                        "function_name": f.function_name,
                        "code_snippet": f.code_snippet,
                        "context": f.context,
                        "confidence": f.confidence,
                    }
                    for f in analyzer.findings
                ],
                "complexity_metrics": analyzer.metrics,
                "call_graph": self.call_graph,
                "data_flow_issues": self._analyze_data_flow_issues(analyzer.data_flows),
            }

        except SyntaxError as e:
            return {
                "file_path": file_path,
                "error": f"语法错误: {e}",
                "risk_score": 0.0,
                "security_findings": [],
                "complexity_metrics": {},
            }
        except Exception as e:
            return {
                "file_path": file_path,
                "error": f"分析失败: {e}",
                "risk_score": 0.0,
                "security_findings": [],
                "complexity_metrics": {},
            }

    def _calculate_comprehensive_risk(
        self, findings: List[ASTSecurityFinding], metrics: Dict
    ) -> float:
        """计算综合风险评分"""

        # 基础风险分数（基于发现的安全问题）
        base_risk = 0.0
        for finding in findings:
            risk_weight = {
                RiskLevel.CRITICAL: 25,
                RiskLevel.HIGH: 15,
                RiskLevel.MEDIUM: 8,
                RiskLevel.LOW: 3,
                RiskLevel.INFO: 1,
            }
            base_risk += risk_weight[finding.risk_level] * finding.confidence

        # 复杂度风险加成
        complexity_risk = 0.0

        # 圈复杂度风险
        cyclomatic = metrics.get("cyclomatic_complexity", 0)
        if cyclomatic > 20:
            complexity_risk += 15
        elif cyclomatic > 10:
            complexity_risk += 8
        elif cyclomatic > 5:
            complexity_risk += 3

        # 嵌套深度风险
        max_depth = metrics.get("max_nesting_depth", 0)
        if max_depth > 6:
            complexity_risk += 10
        elif max_depth > 4:
            complexity_risk += 5

        # 函数长度风险
        max_func_length = metrics.get("max_function_length", 0)
        if max_func_length > 100:
            complexity_risk += 8
        elif max_func_length > 50:
            complexity_risk += 4

        # 危险函数调用密度
        dangerous_calls = metrics.get("dangerous_function_calls", 0)
        total_calls = metrics.get("total_function_calls", 1)
        danger_ratio = dangerous_calls / total_calls

        if danger_ratio > 0.1:
            complexity_risk += 12
        elif danger_ratio > 0.05:
            complexity_risk += 6

        # 数据流风险
        data_flow_risk = 0.0
        untrusted_inputs = metrics.get("untrusted_input_sources", 0)
        sensitive_sinks = metrics.get("sensitive_output_sinks", 0)

        if untrusted_inputs > 0 and sensitive_sinks > 0:
            data_flow_risk += 10  # 存在从不可信输入到敏感输出的路径

        # 综合评分
        total_risk = base_risk + complexity_risk + data_flow_risk

        # 标准化到0-100
        normalized_risk = min(total_risk, 100.0)

        return round(normalized_risk, 2)

    def _analyze_data_flow_issues(self, data_flows: List[Dict]) -> List[Dict]:
        """分析数据流安全问题"""
        issues = []

        # 检查不可信输入到敏感输出的路径
        untrusted_sources = {
            "input",
            "raw_input",
            "sys.argv",
            "request.form",
            "request.args",
        }
        sensitive_sinks = {"eval", "exec", "os.system", "subprocess.call"}

        for flow in data_flows:
            source = flow.get("source")
            sink = flow.get("sink")

            if source in untrusted_sources and sink in sensitive_sinks:
                issues.append(
                    {
                        "type": "untrusted_input_to_sensitive_sink",
                        "source": source,
                        "sink": sink,
                        "path": flow.get("path", []),
                        "risk_level": "HIGH",
                    }
                )

        return issues


class SecurityASTVisitor(ast.NodeVisitor):
    """安全导向的AST访问器"""

    def __init__(self, analyzer: EnhancedASTAnalyzer, file_path: str):
        self.analyzer = analyzer
        self.file_path = file_path
        self.findings: List[ASTSecurityFinding] = []
        self.metrics = {
            "functions": 0,
            "classes": 0,
            "total_function_calls": 0,
            "dangerous_function_calls": 0,
            "max_function_length": 0,
            "max_nesting_depth": 0,
            "cyclomatic_complexity": 0,
            "untrusted_input_sources": 0,
            "sensitive_output_sinks": 0,
        }

        self.current_function = None
        self.current_class = None
        self.nesting_depth = 0
        self.max_depth = 0
        self.data_flows: List[Dict] = []

        # 不可信输入源
        self.untrusted_sources = {
            "input",
            "raw_input",
            "sys.argv",
            "request.form",
            "request.args",
            "request.json",
            "request.data",
        }

        # 敏感输出接收器
        self.sensitive_sinks = {
            "eval",
            "exec",
            "os.system",
            "subprocess.call",
            "subprocess.run",
            "subprocess.Popen",
        }

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """访问函数定义"""
        self.metrics["functions"] += 1

        old_function = self.current_function
        self.current_function = node.name

        # 计算函数长度
        func_length = (
            node.end_lineno - node.lineno if hasattr(node, "end_lineno") else 0
        )
        self.metrics["max_function_length"] = max(
            self.metrics["max_function_length"], func_length
        )

        # 计算函数的圈复杂度
        complexity = self._calculate_function_complexity(node)
        self.metrics["cyclomatic_complexity"] += complexity

        self.generic_visit(node)
        self.current_function = old_function

    def visit_ClassDef(self, node: ast.ClassDef):
        """访问类定义"""
        self.metrics["classes"] += 1

        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class

    def visit_Call(self, node: ast.Call):
        """访问函数调用"""
        self.metrics["total_function_calls"] += 1

        # 获取函数名
        func_name = self._get_function_name(node.func)

        if func_name:
            # 检查安全模式
            self._check_security_patterns(node, func_name)

            # 检查数据流
            self._track_data_flow(node, func_name)

        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        """访问if语句"""
        self._enter_nesting()
        self.generic_visit(node)
        self._exit_nesting()

    def visit_For(self, node: ast.For):
        """访问for循环"""
        self._enter_nesting()
        self.generic_visit(node)
        self._exit_nesting()

    def visit_While(self, node: ast.While):
        """访问while循环"""
        self._enter_nesting()
        self.generic_visit(node)
        self._exit_nesting()

    def visit_Try(self, node: ast.Try):
        """访问try语句"""
        self._enter_nesting()
        self.generic_visit(node)
        self._exit_nesting()

    def _enter_nesting(self):
        """进入嵌套"""
        self.nesting_depth += 1
        self.max_depth = max(self.max_depth, self.nesting_depth)
        self.metrics["max_nesting_depth"] = self.max_depth

    def _exit_nesting(self):
        """退出嵌套"""
        self.nesting_depth -= 1

    def _get_function_name(self, func_node) -> Optional[str]:
        """获取函数名"""
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            # 处理 module.function 形式
            value = func_node.value
            if isinstance(value, ast.Name):
                return f"{value.id}.{func_node.attr}"
            elif isinstance(value, ast.Attribute):
                # 递归处理嵌套属性
                parent = self._get_function_name(value)
                return f"{parent}.{func_node.attr}" if parent else func_node.attr

        return None

    def _check_security_patterns(self, node: ast.Call, func_name: str):
        """检查安全模式"""

        # eval/exec检查
        if func_name in ["eval", "exec"]:
            self._add_finding(
                "EVAL_INJECTION" if func_name == "eval" else "EXEC_INJECTION",
                node,
                func_name,
                self._analyze_call_context(node),
            )

        # os.system检查
        elif func_name == "os.system":
            self._add_finding(
                "OS_SYSTEM", node, func_name, self._analyze_call_context(node)
            )

        # subprocess shell检查
        elif "subprocess" in func_name:
            shell_risk = self._check_subprocess_shell(node)
            if shell_risk:
                self._add_finding("SUBPROCESS_SHELL", node, func_name, shell_risk)

        # pickle.loads检查
        elif func_name == "pickle.loads":
            self._add_finding(
                "PICKLE_LOADS", node, func_name, self._analyze_call_context(node)
            )

        # 文件操作检查
        elif func_name in ["open", "__builtins__.open"] and self._has_dynamic_path(
            node
        ):
            self._add_finding(
                "FILE_INCLUSION", node, func_name, self._analyze_file_path_context(node)
            )

        # SQL拼接检查
        elif self._is_potential_sql_injection(node, func_name):
            self._add_finding(
                "SQL_CONCATENATION", node, func_name, self._analyze_sql_context(node)
            )

        # 弱随机数检查
        elif func_name.startswith("random.") and self._in_security_context():
            self._add_finding(
                "WEAK_RANDOM", node, func_name, {"context": "security_sensitive"}
            )

        # 标记危险函数
        if func_name in self.sensitive_sinks:
            self.metrics["dangerous_function_calls"] += 1

        # 标记不可信输入
        if func_name in self.untrusted_sources:
            self.metrics["untrusted_input_sources"] += 1

    def _add_finding(
        self, pattern_id: str, node: ast.Call, func_name: str, context: Dict
    ):
        """添加安全发现"""
        pattern = self.analyzer.security_patterns.get(pattern_id)
        if not pattern:
            return

        # 获取代码片段
        code_snippet = self._get_code_snippet(node)

        # 计算置信度
        confidence = self._calculate_confidence(pattern, context)

        finding = ASTSecurityFinding(
            pattern_id=pattern_id,
            name=pattern.name,
            risk_level=pattern.risk_level,
            line_number=getattr(node, "lineno", 0),
            column=getattr(node, "col_offset", 0),
            function_name=self.current_function,
            code_snippet=code_snippet,
            context=context,
            confidence=confidence,
        )

        self.findings.append(finding)

    def _analyze_call_context(self, node: ast.Call) -> Dict[str, Any]:
        """分析函数调用上下文"""
        context = {
            "args_count": len(node.args),
            "has_keywords": len(node.keywords) > 0,
            "dynamic_args": False,
            "user_controlled": False,
        }

        # 检查参数是否动态生成
        for arg in node.args:
            if isinstance(arg, (ast.BinOp, ast.Call, ast.Name)):
                context["dynamic_args"] = True

            # 检查是否可能来自用户输入
            if self._is_user_controlled(arg):
                context["user_controlled"] = True

        return context

    def _check_subprocess_shell(self, node: ast.Call) -> Optional[Dict]:
        """检查subprocess的shell参数"""
        for keyword in node.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                if keyword.value.value is True:
                    return {
                        "shell_enabled": True,
                        "command_dynamic": self._has_dynamic_command(node),
                    }
        return None

    def _has_dynamic_path(self, node: ast.Call) -> bool:
        """检查文件路径是否动态"""
        if node.args:
            arg = node.args[0]
            return isinstance(arg, (ast.BinOp, ast.Call, ast.Name))
        return False

    def _is_potential_sql_injection(self, node: ast.Call, func_name: str) -> bool:
        """检查潜在的SQL注入"""
        # 简化版：检查是否有字符串拼接的SQL关键字
        for arg in node.args:
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                # 检查是否包含SQL关键字
                if self._contains_sql_keywords(arg):
                    return True
        return False

    def _contains_sql_keywords(self, node: ast.BinOp) -> bool:
        """检查是否包含SQL关键字"""
        sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"]

        def check_string_node(n):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                return any(kw in n.value.upper() for kw in sql_keywords)
            return False

        return check_string_node(node.left) or check_string_node(node.right)

    def _in_security_context(self) -> bool:
        """检查是否在安全敏感上下文中"""
        # 简化版：检查函数名是否包含安全相关关键字
        if self.current_function:
            security_keywords = ["password", "token", "key", "secret", "auth", "login"]
            func_lower = self.current_function.lower()
            return any(kw in func_lower for kw in security_keywords)
        return False

    def _is_user_controlled(self, node) -> bool:
        """检查节点是否可能受用户控制"""
        if isinstance(node, ast.Name):
            # 简化版：检查变量名是否暗示用户输入
            user_vars = ["input", "user_input", "request", "params", "args"]
            return node.id.lower() in user_vars
        return False

    def _has_dynamic_command(self, node: ast.Call) -> bool:
        """检查命令是否动态生成"""
        if node.args:
            return isinstance(node.args[0], (ast.BinOp, ast.Call, ast.Name))
        return False

    def _get_code_snippet(self, node) -> str:
        """获取代码片段（简化版）"""
        return f"Line {getattr(node, 'lineno', 0)}"

    def _calculate_confidence(self, pattern: SecurityPattern, context: Dict) -> float:
        """计算置信度"""
        base_confidence = 0.7

        # 根据上下文调整置信度
        if context.get("user_controlled"):
            base_confidence += 0.2

        if context.get("dynamic_args"):
            base_confidence += 0.1

        if pattern.context_sensitive and not context:
            base_confidence -= 0.3

        return min(max(base_confidence, 0.1), 1.0)

    def _calculate_function_complexity(self, node: ast.FunctionDef) -> int:
        """计算函数圈复杂度"""
        complexity = 1  # 基础复杂度

        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, ast.Lambda):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1

        return complexity

    def _track_data_flow(self, node: ast.Call, func_name: str):
        """跟踪数据流"""
        # 简化版数据流跟踪
        if func_name in self.untrusted_sources:
            self.data_flows.append(
                {
                    "type": "source",
                    "source": func_name,
                    "line": getattr(node, "lineno", 0),
                }
            )

        if func_name in self.sensitive_sinks:
            self.data_flows.append(
                {"type": "sink", "sink": func_name, "line": getattr(node, "lineno", 0)}
            )


def get_enhanced_ast_analyzer() -> EnhancedASTAnalyzer:
    """获取增强型AST分析器实例"""
    return EnhancedASTAnalyzer()
