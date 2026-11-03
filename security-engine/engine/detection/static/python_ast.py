"""
Module C (Python) — Static Python AST Security Analyzer
Safely traverses Python AST using standard library ast module without executing code.
"""

import ast
import re
from typing import List, Dict, Any, Optional

from engine.schemas.finding import SecurityFinding, Severity, FindingCategory

SENSITIVE_FILE_PATTERNS = re.compile(r"(\.ssh/|\.aws/|/etc/shadow|/etc/passwd|\.bash_history|\.npmrc)", re.IGNORECASE)
SENSITIVE_ENV_KEYS = re.compile(r"(AWS_SECRET|AWS_ACCESS|GITHUB_TOKEN|DISCORD_WEBHOOK|SLACK_TOKEN|API_KEY|PASSWORD)", re.IGNORECASE)


class PythonASTVisitor(ast.NodeVisitor):
    """
    AST visitor inspecting function calls, imports, attribute lookups, and string constants.
    """

    def __init__(self, rel_path: str):
        self.rel_path = rel_path
        self.findings: List[SecurityFinding] = []

    def visit_Call(self, node: ast.Call):
        func_name = self._resolve_call_name(node.func)

        # 1. Dynamic Code Execution: eval(), exec(), compile()
        if func_name in ("eval", "exec", "compile"):
            self.findings.append(SecurityFinding(
                module="PYTHON_AST_ANALYZER",
                rule_id="PY_DYNAMIC_EXECUTION",
                category=FindingCategory.STATIC_CODE,
                severity=Severity.HIGH,
                confidence=0.85,
                title=f"Dynamic Execution via {func_name}()",
                description=f"Invocation of dynamic code execution function '{func_name}()'.",
                affected_file=self.rel_path,
                affected_line=getattr(node, "lineno", None),
                evidence={"function": func_name},
                detection_method="PYTHON_AST_TRAVERSAL",
            ))

        # 2. Subprocess & Shell Spawning: os.system, subprocess.Popen, etc.
        elif func_name in (
            "os.system", "os.popen", "subprocess.Popen", "subprocess.run",
            "subprocess.call", "subprocess.check_call", "subprocess.check_output"
        ):
            self.findings.append(SecurityFinding(
                module="PYTHON_AST_ANALYZER",
                rule_id="PY_SUBPROCESS_SPAWN",
                category=FindingCategory.STATIC_CODE,
                severity=Severity.HIGH,
                confidence=0.85,
                title=f"Child Process Execution via {func_name}()",
                description=f"Execution of external shell command using '{func_name}()'.",
                affected_file=self.rel_path,
                affected_line=getattr(node, "lineno", None),
                evidence={"function": func_name},
                detection_method="PYTHON_AST_TRAVERSAL",
            ))

        # 3. Dynamic Imports: __import__, importlib.import_module
        elif func_name in ("__import__", "importlib.import_module"):
            self.findings.append(SecurityFinding(
                module="PYTHON_AST_ANALYZER",
                rule_id="PY_DYNAMIC_IMPORT",
                category=FindingCategory.STATIC_CODE,
                severity=Severity.MEDIUM,
                confidence=0.75,
                title=f"Dynamic Module Import via {func_name}()",
                description="Dynamic runtime module loading often used to evade static import tracking.",
                affected_file=self.rel_path,
                affected_line=getattr(node, "lineno", None),
                evidence={"function": func_name},
                detection_method="PYTHON_AST_TRAVERSAL",
            ))

        # 4. Encoded Payload Decoding: base64.b64decode, binascii.unhexlify, zlib.decompress
        elif func_name in ("base64.b64decode", "binascii.unhexlify", "codecs.decode", "zlib.decompress"):
            self.findings.append(SecurityFinding(
                module="PYTHON_AST_ANALYZER",
                rule_id="PY_PAYLOAD_DECODING",
                category=FindingCategory.OBFUSCATION,
                severity=Severity.MEDIUM,
                confidence=0.80,
                title=f"Runtime Payload Decoding via {func_name}()",
                description="Invocation of decoding routines often chained into hidden payload execution.",
                affected_file=self.rel_path,
                affected_line=getattr(node, "lineno", None),
                evidence={"function": func_name},
                detection_method="PYTHON_AST_TRAVERSAL",
            ))

        # 5. Network Sockets & Low-level Transport
        elif func_name in ("socket.socket", "urllib.request.urlopen"):
            self.findings.append(SecurityFinding(
                module="PYTHON_AST_ANALYZER",
                rule_id="PY_NETWORK_SOCKET_ACCESS",
                category=FindingCategory.STATIC_CODE,
                severity=Severity.MEDIUM,
                confidence=0.70,
                title=f"Direct Network Connection via {func_name}()",
                description="Direct outbound socket creation or URL retrieval from library source.",
                affected_file=self.rel_path,
                affected_line=getattr(node, "lineno", None),
                evidence={"function": func_name},
                detection_method="PYTHON_AST_TRAVERSAL",
            ))

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        # Inspect string constants for sensitive files or secret tokens
        if isinstance(node.value, str):
            val = node.value

            # Sensitive files
            if SENSITIVE_FILE_PATTERNS.search(val):
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_SENSITIVE_FILE_TARGETING",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.HIGH,
                    confidence=0.90,
                    title="Targeting Sensitive System Credentials",
                    description=f"Source references credential path pattern: '{val}'.",
                    affected_file=self.rel_path,
                    affected_line=getattr(node, "lineno", None),
                    evidence={"targeted_path": val},
                    detection_method="PYTHON_AST_STRING_INSPECTION",
                ))

            # Sensitive env keys in string literals
            if SENSITIVE_ENV_KEYS.search(val) and len(val) < 60:
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_SECRET_ENV_HARVESTING",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.HIGH,
                    confidence=0.80,
                    title="Harvesting Cloud/Environment Secrets",
                    description=f"String literal targets sensitive secret token: '{val}'.",
                    affected_file=self.rel_path,
                    affected_line=getattr(node, "lineno", None),
                    evidence={"env_key": val},
                    detection_method="PYTHON_AST_STRING_INSPECTION",
                ))

        self.generic_visit(node)

    def _resolve_call_name(self, node: ast.AST) -> str:
        """Helper to resolve Call node function target (e.g. os.system)."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val_name = self._resolve_call_name(node.value)
            return f"{val_name}.{node.attr}" if val_name else node.attr
        return ""


class PythonASTAnalyzer:
    """
    Parses and scans Python source files using Python standard ast.
    """

    def analyze_source(self, source_code: str, rel_path: str) -> List[SecurityFinding]:
        try:
            tree = ast.parse(source_code, filename=rel_path)
        except SyntaxError:
            # Syntax errors are common in non-standard scripts or Python 2 remnants; fail gracefully
            return []

        visitor = PythonASTVisitor(rel_path)
        visitor.visit(tree)
        return visitor.findings

