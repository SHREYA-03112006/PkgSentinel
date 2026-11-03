"""
Module C (Python) — Static Python AST Security Analyzer
Safely traverses Python AST using standard library ast module without executing code.
"""

import ast
import re
from typing import List, Dict, Any, Optional, Set

from engine.schemas.finding import SecurityFinding, Severity, FindingCategory

SENSITIVE_FILE_PATTERNS = re.compile(r"(\.ssh/|\.aws/|/etc/shadow|/etc/passwd|\.bash_history|\.npmrc)", re.IGNORECASE)
SENSITIVE_ENV_KEYS = re.compile(r"(AWS_SECRET|AWS_ACCESS|GITHUB_TOKEN|DISCORD_WEBHOOK|SLACK_TOKEN|API_KEY|PASSWORD)", re.IGNORECASE)

SENSITIVE_IMPORT_TARGETS = {"os", "subprocess", "socket", "pty", "ctypes", "winreg", "shutil"}

SUBPROCESS_FUNCS = {
    "os.system", "os.popen",
    "subprocess.Popen", "subprocess.run", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output",
}

DECODING_CALLS = {
    "base64.b64decode", "base64.decode", "b64decode",
    "binascii.unhexlify", "unhexlify", "codecs.decode",
    "zlib.decompress", "gzip.decompress", "bz2.decompress",
    "bytes.fromhex", "urllib.request.urlopen", "requests.get", "requests.post",
}

ENV_LOOKUP_CALLS = {
    "os.getenv", "os.environ.get", "environ.get",
}

CONFIG_OR_SHELL_PATH_PATTERN = re.compile(
    r"(config|settings|cli|shell|console|interact|startup|conf\.py)",
    re.IGNORECASE,
)

CONFIG_OR_SHELL_FUNC_PATTERN = re.compile(
    r"(config|setting|pyfile|shell|cli|interact|console|setup|startup)",
    re.IGNORECASE,
)

PLUGIN_OR_HELPER_PATH_PATTERN = re.compile(
    r"(helper|compat|plugin|loader|discovery|entrypoint|registry)",
    re.IGNORECASE,
)

PLUGIN_OR_HELPER_FUNC_PATTERN = re.compile(
    r"(find_package|import_string|load_plugin|import_module|resolve_module|load_entry_point|get_module|find_module|_import|import_name)",
    re.IGNORECASE,
)

TEST_OR_DOCS_PATH_PATTERN = re.compile(
    r"(^|[/\\])(tests?|fixtures?|examples?|samples?|demos?|benchmarks?|docs?)[/\\]|(^|[/\\])test_[^/\\]+\.py$|(^|[/\\])[^/\\]+_test\.py$|(^|[/\\])conftest\.py$",
    re.IGNORECASE,
)

SUSPICIOUS_CMD_PATTERNS = re.compile(
    r"(\bcurl\b.*(\|\s*(bash|sh|python)|>|-o\s+)|"
    r"\bwget\b.*(\|\s*(bash|sh|python)|>|-o\s+)|"
    r"\bpowershell\b.*(-enc|-encodedcommand|-c\b|downloadstring)|"
    r"\b(nc|ncat|netcat)\b.*-e\b|"
    r"/dev/tcp/\d+|"
    r"\bchmod\s+(\+x|777|755)\b|"
    r"\b(whoami|id|cat\s+/etc/shadow|net\s+user|certutil\s+-urlcache)\b|"
    r"\b(rm\s+-rf\s+/\b|mkfifo\b))",
    re.IGNORECASE,
)


class PythonASTVisitor(ast.NodeVisitor):
    """
    AST visitor inspecting function calls, imports, attribute lookups, and string constants.
    """

    def __init__(self, rel_path: str):
        self.rel_path = rel_path
        self.findings: List[SecurityFinding] = []
        self.function_stack: List[str] = []
        self.class_stack: List[str] = []
        self.imported_symbols: Dict[str, str] = {}
        self.in_try_import_block: bool = False
        self._ignored_compile_nodes: Set[int] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname or alias.name
            self.imported_symbols[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        for alias in node.names:
            name = alias.asname or alias.name
            self.imported_symbols[name] = f"{mod}.{alias.name}" if mod else alias.name
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef):
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_Try(self, node: ast.Try):
        catches_import = any(
            self._is_import_exception(h.type) for h in node.handlers if h.type is not None
        )
        prev = self.in_try_import_block
        if catches_import:
            self.in_try_import_block = True
        self.generic_visit(node)
        self.in_try_import_block = prev

    def _is_import_exception(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name) and node.id in ("ImportError", "ModuleNotFoundError"):
            return True
        if isinstance(node, ast.Tuple):
            return any(
                isinstance(elt, ast.Name) and elt.id in ("ImportError", "ModuleNotFoundError")
                for elt in node.elts
            )
        return False

    def _is_test_or_docs_context(self) -> bool:
        return bool(TEST_OR_DOCS_PATH_PATTERN.search(self.rel_path))

    def _is_config_or_shell_context(self) -> bool:
        if CONFIG_OR_SHELL_PATH_PATTERN.search(self.rel_path):
            return True
        for fn in self.function_stack:
            if CONFIG_OR_SHELL_FUNC_PATTERN.search(fn):
                return True
        return False

    def _is_plugin_or_helper_context(self) -> bool:
        if self.in_try_import_block:
            return True
        if PLUGIN_OR_HELPER_PATH_PATTERN.search(self.rel_path):
            return True
        for fn in self.function_stack:
            if PLUGIN_OR_HELPER_FUNC_PATTERN.search(fn):
                return True
        return False

    def _is_obfuscated_expression(self, node: Optional[ast.AST]) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Call):
            func_name = self._resolve_call_name(node.func)
            if func_name in DECODING_CALLS or any(func_name.endswith("." + d) for d in ("b64decode", "unhexlify", "decompress", "decode")):
                return True
            if func_name == "compile" and node.args:
                return self._is_obfuscated_expression(node.args[0])
        return False

    def _is_env_expression(self, node: Optional[ast.AST]) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Call):
            func_name = self._resolve_call_name(node.func)
            if func_name in ENV_LOOKUP_CALLS:
                return True
            if func_name == "compile" and node.args:
                return self._is_env_expression(node.args[0])
        elif isinstance(node, ast.Subscript):
            val_name = self._resolve_call_name(node.value)
            if val_name in ("os.environ", "environ"):
                return True
        return False

    def _extract_command_strings(self, node: Optional[ast.AST]) -> List[str]:
        if node is None:
            return []
        strings: List[str] = []
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.append(node.value)
        elif isinstance(node, ast.JoinedStr):
            parts = []
            for val in node.values:
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    parts.append(val.value)
                elif isinstance(val, ast.FormattedValue):
                    parts.append("<?>")
            strings.append("".join(parts))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left_s = self._extract_command_strings(node.left)
            right_s = self._extract_command_strings(node.right)
            if left_s and right_s:
                strings.append(left_s[0] + right_s[0])
            elif left_s:
                strings.extend(left_s)
            elif right_s:
                strings.extend(right_s)
        elif isinstance(node, (ast.List, ast.Tuple)):
            for elt in node.elts:
                strings.extend(self._extract_command_strings(elt))
        return strings

    def _is_dynamic_construction(self, node: Optional[ast.AST]) -> bool:
        if node is None:
            return False
        if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.FormattedValue, ast.Name)):
            return True
        if isinstance(node, ast.Call):
            return True
        if isinstance(node, (ast.List, ast.Tuple)):
            return any(self._is_dynamic_construction(elt) for elt in node.elts)
        return False

    def visit_Call(self, node: ast.Call):
        func_name = self._resolve_call_name(node.func)

        # 1. Dynamic Code Execution: eval(), exec(), compile()
        # Verify that eval/exec are not shadowed by imported library functions (e.g. pandas.core.computation.eval)
        is_imported_shadow = func_name in self.imported_symbols and not self.imported_symbols[func_name].startswith("builtins.")

        if func_name in ("eval", "exec") and not is_imported_shadow:
            # Suppress child compile nodes from emitting duplicate findings
            for arg in node.args:
                if isinstance(arg, ast.Call) and self._resolve_call_name(arg.func) == "compile":
                    self._ignored_compile_nodes.add(id(arg))

            arg0 = node.args[0] if node.args else None

            if arg0 is not None and self._is_obfuscated_expression(arg0):
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_DYNAMIC_EXECUTION_OBFUSCATED",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    title=f"Obfuscated Dynamic Code Execution via {func_name}()",
                    description=f"Invocation of dynamic execution '{func_name}()' passing decoded/obfuscated payload.",
                    affected_file=self.rel_path,
                    affected_line=getattr(node, "lineno", None),
                    evidence={"function": func_name, "pattern": "OBFUSCATED_PAYLOAD"},
                    detection_method="PYTHON_AST_TRAVERSAL",
                ))
            elif arg0 is not None and self._is_env_expression(arg0):
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_DYNAMIC_EXECUTION_ENV",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title=f"Dynamic Execution from Environment via {func_name}()",
                    description=f"Invocation of dynamic execution '{func_name}()' reading directly from environment variables.",
                    affected_file=self.rel_path,
                    affected_line=getattr(node, "lineno", None),
                    evidence={"function": func_name, "pattern": "ENV_VARIABLE_PAYLOAD"},
                    detection_method="PYTHON_AST_TRAVERSAL",
                ))
            elif self._is_test_or_docs_context():
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_DYNAMIC_EXECUTION",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.LOW,
                    confidence=0.35,
                    title=f"Dynamic Execution via {func_name}() (Test Context)",
                    description=f"Invocation of '{func_name}()' within test suite or development utility.",
                    affected_file=self.rel_path,
                    affected_line=getattr(node, "lineno", None),
                    evidence={"function": func_name, "pattern": "TEST_OR_FIXTURE_EXECUTION"},
                    detection_method="PYTHON_AST_TRAVERSAL",
                ))
            elif self._is_config_or_shell_context() or len(node.args) > 1:
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_DYNAMIC_EXECUTION",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.LOW,
                    confidence=0.40,
                    title=f"Dynamic Execution via {func_name}()",
                    description=f"Dynamic code execution '{func_name}()' within configuration or framework shell context.",
                    affected_file=self.rel_path,
                    affected_line=getattr(node, "lineno", None),
                    evidence={"function": func_name, "pattern": "TRUSTED_CONFIG_OR_SHELL_EXECUTION"},
                    detection_method="PYTHON_AST_TRAVERSAL",
                ))
            else:
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_DYNAMIC_EXECUTION",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.MEDIUM,
                    confidence=0.60,
                    title=f"Dynamic Execution via {func_name}()",
                    description=f"Invocation of dynamic code execution function '{func_name}()'.",
                    affected_file=self.rel_path,
                    affected_line=getattr(node, "lineno", None),
                    evidence={"function": func_name},
                    detection_method="PYTHON_AST_TRAVERSAL",
                ))

        elif func_name == "compile":
            if id(node) in self._ignored_compile_nodes:
                self.generic_visit(node)
                return

            self.findings.append(SecurityFinding(
                module="PYTHON_AST_ANALYZER",
                rule_id="PY_DYNAMIC_COMPILE",
                category=FindingCategory.STATIC_CODE,
                severity=Severity.LOW,
                confidence=0.30,
                title="Bytecode Compilation via compile()",
                description="Invocation of dynamic compilation function 'compile()'.",
                affected_file=self.rel_path,
                affected_line=getattr(node, "lineno", None),
                evidence={"function": func_name},
                detection_method="PYTHON_AST_TRAVERSAL",
            ))

        # 2. Subprocess & Shell Spawning: os.system, os.popen, subprocess.Popen, etc.
        elif func_name in SUBPROCESS_FUNCS:
            is_shell = func_name in ("os.system", "os.popen")
            for kw in node.keywords:
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant):
                        is_shell = bool(kw.value.value)
                    else:
                        is_shell = True

            arg0 = node.args[0] if node.args else None
            cmd_strings = self._extract_command_strings(arg0)
            full_cmd_text = " ".join(cmd_strings)

            matched_suspicious = None
            for s in cmd_strings:
                m = SUSPICIOUS_CMD_PATTERNS.search(s)
                if m:
                    matched_suspicious = m.group(0)
                    break
            if not matched_suspicious and full_cmd_text:
                m = SUSPICIOUS_CMD_PATTERNS.search(full_cmd_text)
                if m:
                    matched_suspicious = m.group(0)

            # Scenario A: Obfuscated command execution (e.g. b64decode)
            if arg0 is not None and self._is_obfuscated_expression(arg0):
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_SUBPROCESS_SPAWN",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    title=f"Obfuscated Child Process Execution via {func_name}()",
                    description=f"Child process spawned with obfuscated or decoded command via '{func_name}()'.",
                    affected_file=self.rel_path,
                    affected_line=getattr(node, "lineno", None),
                    evidence={"function": func_name, "pattern": "OBFUSCATED_PAYLOAD"},
                    detection_method="PYTHON_AST_TRAVERSAL",
                ))

            # Scenario B: Suspicious download-and-execute or attack tools
            elif matched_suspicious:
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_SUBPROCESS_SPAWN",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.HIGH,
                    confidence=0.90,
                    title=f"Suspicious Command Execution via {func_name}()",
                    description=f"Child process invocation '{func_name}()' contains suspicious command signature: '{matched_suspicious}'.",
                    affected_file=self.rel_path,
                    affected_line=getattr(node, "lineno", None),
                    evidence={"function": func_name, "pattern": "SUSPICIOUS_COMMAND_SIGNATURE", "matched": matched_suspicious},
                    detection_method="PYTHON_AST_TRAVERSAL",
                ))

            # Scenario C: Command sourced directly from environment variables
            elif arg0 is not None and self._is_env_expression(arg0):
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_SUBPROCESS_SPAWN",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title=f"Process Execution with Environment Command via {func_name}()",
                    description=f"Child process command sourced directly from environment variables via '{func_name}()'.",
                    affected_file=self.rel_path,
                    affected_line=getattr(node, "lineno", None),
                    evidence={"function": func_name, "pattern": "ENV_VARIABLE_PAYLOAD"},
                    detection_method="PYTHON_AST_TRAVERSAL",
                ))

            # Scenario D: Unsafe dynamic shell construction (shell=True with formatted/concatenated input or variable)
            elif is_shell and self._is_dynamic_construction(arg0):
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_SUBPROCESS_SPAWN",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title=f"Unsafe Dynamic Shell Execution via {func_name}(shell=True)",
                    description=f"Invocation of '{func_name}()' with shell=True and dynamically constructed command arguments.",
                    affected_file=self.rel_path,
                    affected_line=getattr(node, "lineno", None),
                    evidence={"function": func_name, "pattern": "UNSAFE_DYNAMIC_SHELL", "shell": True},
                    detection_method="PYTHON_AST_TRAVERSAL",
                ))

            # Scenario E: Test suite or development utility process execution
            elif self._is_test_or_docs_context():
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_SUBPROCESS_SPAWN",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.LOW,
                    confidence=0.25,
                    title=f"Test Process Execution via {func_name}()",
                    description=f"Child process invocation '{func_name}()' within test suite or development fixture.",
                    affected_file=self.rel_path,
                    affected_line=getattr(node, "lineno", None),
                    evidence={"function": func_name, "pattern": "TEST_OR_FIXTURE_PROCESS", "is_test": True},
                    detection_method="PYTHON_AST_TRAVERSAL",
                ))

            # Scenario F: Production shell=True with static string (e.g. os.system("cls"))
            elif is_shell:
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_SUBPROCESS_SPAWN",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.MEDIUM,
                    confidence=0.60,
                    title=f"Shell Execution via {func_name}()",
                    description=f"Invocation of shell command using '{func_name}()'.",
                    affected_file=self.rel_path,
                    affected_line=getattr(node, "lineno", None),
                    evidence={"function": func_name, "pattern": "STATIC_SHELL_COMMAND", "shell": True},
                    detection_method="PYTHON_AST_TRAVERSAL",
                ))

            # Scenario G: Ordinary system integration (subprocess.run(["locale", "-a"]), clipboard, explicit list)
            else:
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_SUBPROCESS_SPAWN",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.LOW,
                    confidence=0.40,
                    title=f"System Process Execution via {func_name}()",
                    description=f"Execution of external process via '{func_name}()' using explicit argument list for system integration.",
                    affected_file=self.rel_path,
                    affected_line=getattr(node, "lineno", None),
                    evidence={"function": func_name, "pattern": "STANDARD_SYSTEM_PROCESS", "shell": False},
                    detection_method="PYTHON_AST_TRAVERSAL",
                ))

        # 3. Dynamic Imports: __import__, importlib.import_module
        elif func_name in ("__import__", "importlib.import_module"):
            arg0 = node.args[0] if node.args else None

            if arg0 is not None and self._is_obfuscated_expression(arg0):
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_DYNAMIC_IMPORT_OBFUSCATED",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.HIGH,
                    confidence=0.90,
                    title=f"Obfuscated Dynamic Import via {func_name}()",
                    description="Dynamic module loading with obfuscated/decoded module name.",
                    affected_file=self.rel_path,
                    affected_line=getattr(node, "lineno", None),
                    evidence={"function": func_name, "pattern": "OBFUSCATED_IMPORT_TARGET"},
                    detection_method="PYTHON_AST_TRAVERSAL",
                ))
            elif (
                arg0 is not None
                and isinstance(arg0, ast.Constant)
                and isinstance(arg0.value, str)
                and arg0.value in SENSITIVE_IMPORT_TARGETS
            ):
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_DYNAMIC_IMPORT_SUSPICIOUS",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.MEDIUM,
                    confidence=0.80,
                    title=f"Suspicious Dynamic System Import via {func_name}('{arg0.value}')",
                    description=f"Dynamic loading of sensitive system module '{arg0.value}'.",
                    affected_file=self.rel_path,
                    affected_line=getattr(node, "lineno", None),
                    evidence={"function": func_name, "module": arg0.value},
                    detection_method="PYTHON_AST_TRAVERSAL",
                ))
            elif self._is_test_or_docs_context() or self._is_plugin_or_helper_context():
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_DYNAMIC_IMPORT",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.LOW,
                    confidence=0.35,
                    title=f"Dynamic Module Import via {func_name}()",
                    description="Dynamic runtime module loading within plugin discovery or helper utility context.",
                    affected_file=self.rel_path,
                    affected_line=getattr(node, "lineno", None),
                    evidence={"function": func_name, "pattern": "PLUGIN_DISCOVERY_OR_HELPER"},
                    detection_method="PYTHON_AST_TRAVERSAL",
                ))
            else:
                self.findings.append(SecurityFinding(
                    module="PYTHON_AST_ANALYZER",
                    rule_id="PY_DYNAMIC_IMPORT",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.LOW,
                    confidence=0.50,
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
            is_test = self._is_test_or_docs_context()
            self.findings.append(SecurityFinding(
                module="PYTHON_AST_ANALYZER",
                rule_id="PY_NETWORK_SOCKET_ACCESS",
                category=FindingCategory.STATIC_CODE,
                severity=Severity.LOW if is_test else Severity.MEDIUM,
                confidence=0.40 if is_test else 0.70,
                title=f"Direct Network Connection via {func_name}()",
                description="Direct outbound socket creation or URL retrieval from library source.",
                affected_file=self.rel_path,
                affected_line=getattr(node, "lineno", None),
                evidence={"function": func_name, "context": "TEST_OR_FIXTURE" if is_test else "PROD"},
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
                is_test = self._is_test_or_docs_context()
                if is_test:
                    self.findings.append(SecurityFinding(
                        module="PYTHON_AST_ANALYZER",
                        rule_id="PY_SECRET_ENV_HARVESTING",
                        category=FindingCategory.STATIC_CODE,
                        severity=Severity.LOW,
                        confidence=0.30,
                        title="Test Reference to Sensitive Environment Key",
                        description=f"String literal references sensitive environment key '{val}' within test or fixture context.",
                        affected_file=self.rel_path,
                        affected_line=getattr(node, "lineno", None),
                        evidence={"env_key": val, "context": "TEST_OR_FIXTURE"},
                        detection_method="PYTHON_AST_STRING_INSPECTION",
                    ))
                else:
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
