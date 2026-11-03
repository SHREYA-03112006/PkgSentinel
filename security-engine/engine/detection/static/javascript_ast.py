"""
Module C (JavaScript) — Static JavaScript AST Security Analyzer
Uses esprima to traverse JavaScript ESTree AST nodes without executing code.
"""

import re
from typing import List, Dict, Any, Optional
import esprima

from engine.schemas.finding import SecurityFinding, Severity, FindingCategory

SENSITIVE_FILE_PATTERNS = re.compile(r"(\.ssh/|\.aws/|/etc/shadow|/etc/passwd|\.bash_history|\.npmrc)", re.IGNORECASE)
SENSITIVE_ENV_KEYS = re.compile(r"(AWS_SECRET|AWS_ACCESS|GITHUB_TOKEN|DISCORD_WEBHOOK|SLACK_TOKEN|API_KEY|PASSWORD)", re.IGNORECASE)
RAW_IP_REGEX = re.compile(r"^https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/.*)?$")


class JavaScriptASTAnalyzer:
    """
    Parses and scans JavaScript source files using esprima ESTree AST traversal.
    """

    def analyze_source(self, source_code: str, rel_path: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        if not source_code or len(source_code) > 2 * 1024 * 1024:
            # Skip empty or gigantic bundled files (>2MB) to prevent AST recursion depth issues
            return findings

        # Attempt module parsing first, then script parsing with tolerant mode
        tree = None
        try:
            tree = esprima.parseModule(source_code, loc=True, tolerant=True)
        except Exception:
            try:
                tree = esprima.parseScript(source_code, loc=True, tolerant=True)
            except Exception:
                # Syntax error or JSX/TS specific syntax: fail gracefully without crashing
                return findings

        if not tree:
            return findings

        self._traverse_node(tree, rel_path, findings)
        return findings

    def _traverse_node(self, node: Any, rel_path: str, findings: List[SecurityFinding]) -> None:
        if not node or not hasattr(node, "type"):
            return

        node_type = getattr(node, "type", "")
        loc = getattr(node, "loc", None)
        line_no = loc.start.line if loc else None

        # 1. CallExpression: eval(), require(), child_process.exec(), fetch(), etc.
        if node_type == "CallExpression":
            callee_name = self._resolve_callee_name(node.callee)

            # Dynamic code execution via eval()
            if callee_name == "eval":
                findings.append(SecurityFinding(
                    module="JS_AST_ANALYZER",
                    rule_id="JS_DYNAMIC_EVAL",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title="Dynamic Execution via eval()",
                    description="Invocation of eval() to dynamically evaluate arbitrary code strings.",
                    affected_file=rel_path,
                    affected_line=line_no,
                    evidence={"callee": "eval"},
                    detection_method="JS_AST_TRAVERSAL",
                ))

            # Child process execution
            elif (
                callee_name in ("exec", "execSync", "spawn", "spawnSync")
                or callee_name.endswith((".exec", ".execSync", ".spawn", ".spawnSync"))
            ):
                findings.append(SecurityFinding(
                    module="JS_AST_ANALYZER",
                    rule_id="JS_CHILD_PROCESS_SPAWN",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title=f"Child Process Execution via {callee_name}()",
                    description=f"Execution of shell commands using '{callee_name}()'.",
                    affected_file=rel_path,
                    affected_line=line_no,
                    evidence={"callee": callee_name},
                    detection_method="JS_AST_TRAVERSAL",
                ))

            # Dynamic require() with variable/concatenated argument
            elif callee_name == "require":
                if node.arguments and getattr(node.arguments[0], "type", "") != "Literal":
                    findings.append(SecurityFinding(
                        module="JS_AST_ANALYZER",
                        rule_id="JS_DYNAMIC_REQUIRE",
                        category=FindingCategory.STATIC_CODE,
                        severity=Severity.MEDIUM,
                        confidence=0.75,
                        title="Dynamic Computed require()",
                        description="Invocation of require() using non-literal argument to evade static import analysis.",
                        affected_file=rel_path,
                        affected_line=line_no,
                        evidence={"callee": "require"},
                        detection_method="JS_AST_TRAVERSAL",
                    ))

            # Obfuscated Base64 decoding: Buffer.from(..., 'base64')
            elif callee_name == "Buffer.from":
                if len(node.arguments) >= 2:
                    second_arg = getattr(node.arguments[1], "value", "")
                    if second_arg == "base64":
                        findings.append(SecurityFinding(
                            module="JS_AST_ANALYZER",
                            rule_id="JS_BASE64_BUFFER_DECODING",
                            category=FindingCategory.OBFUSCATION,
                            severity=Severity.MEDIUM,
                            confidence=0.80,
                            title="Base64 Buffer Decoding via Buffer.from()",
                            description="Decoding base64 encoded buffer at runtime.",
                            affected_file=rel_path,
                            affected_line=line_no,
                            evidence={"encoding": "base64"},
                            detection_method="JS_AST_TRAVERSAL",
                        ))

            # Network requests: fetch, http.request, https.request, net.connect
            elif callee_name in ("fetch", "http.request", "https.request", "https.get", "net.connect"):
                findings.append(SecurityFinding(
                    module="JS_AST_ANALYZER",
                    rule_id="JS_NETWORK_REQUEST",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.MEDIUM,
                    confidence=0.70,
                    title=f"Outbound Network Invocation via {callee_name}()",
                    description=f"Direct network call initiated using '{callee_name}()'.",
                    affected_file=rel_path,
                    affected_line=line_no,
                    evidence={"callee": callee_name},
                    detection_method="JS_AST_TRAVERSAL",
                ))

        # 2. NewExpression: new Function(...)
        elif node_type == "NewExpression":
            callee_name = self._resolve_callee_name(node.callee)
            if callee_name == "Function":
                findings.append(SecurityFinding(
                    module="JS_AST_ANALYZER",
                    rule_id="JS_FUNCTION_CONSTRUCTOR_EVAL",
                    category=FindingCategory.STATIC_CODE,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title="Dynamic Execution via new Function()",
                    description="Dynamic function compilation via the Function constructor.",
                    affected_file=rel_path,
                    affected_line=line_no,
                    evidence={"callee": "Function"},
                    detection_method="JS_AST_TRAVERSAL",
                ))

        # 3. Literal inspection (Sensitive credentials, files, raw IPs)
        elif node_type == "Literal":
            val = getattr(node, "value", None)
            if isinstance(val, str):
                if SENSITIVE_FILE_PATTERNS.search(val):
                    findings.append(SecurityFinding(
                        module="JS_AST_ANALYZER",
                        rule_id="JS_SENSITIVE_FILE_TARGETING",
                        category=FindingCategory.STATIC_CODE,
                        severity=Severity.HIGH,
                        confidence=0.90,
                        title="Targeting Sensitive System Credentials",
                        description=f"String literal references sensitive system credential path: '{val}'.",
                        affected_file=rel_path,
                        affected_line=line_no,
                        evidence={"targeted_path": val},
                        detection_method="JS_AST_STRING_INSPECTION",
                    ))
                elif SENSITIVE_ENV_KEYS.search(val) and len(val) < 60:
                    findings.append(SecurityFinding(
                        module="JS_AST_ANALYZER",
                        rule_id="JS_SECRET_ENV_HARVESTING",
                        category=FindingCategory.STATIC_CODE,
                        severity=Severity.HIGH,
                        confidence=0.80,
                        title="Harvesting Cloud/Environment Secrets",
                        description=f"String literal references sensitive token name: '{val}'.",
                        affected_file=rel_path,
                        affected_line=line_no,
                        evidence={"env_key": val},
                        detection_method="JS_AST_STRING_INSPECTION",
                    ))
                elif RAW_IP_REGEX.match(val):
                    findings.append(SecurityFinding(
                        module="JS_AST_ANALYZER",
                        rule_id="JS_RAW_IP_ENDPOINT",
                        category=FindingCategory.STATIC_CODE,
                        severity=Severity.HIGH,
                        confidence=0.85,
                        title="Hardcoded Raw IP Endpoint",
                        description=f"Hardcoded direct IP network target without DNS hostname: '{val}'.",
                        affected_file=rel_path,
                        affected_line=line_no,
                        evidence={"endpoint": val},
                        detection_method="JS_AST_STRING_INSPECTION",
                    ))

        # Recurse children
        for key, value in node.__dict__.items():
            if isinstance(value, list):
                for item in value:
                    self._traverse_node(item, rel_path, findings)
            elif hasattr(value, "type"):
                self._traverse_node(value, rel_path, findings)

    def _resolve_callee_name(self, callee: Any) -> str:
        if not callee:
            return ""
        c_type = getattr(callee, "type", "")
        if c_type == "Identifier":
            return getattr(callee, "name", "")
        elif c_type == "MemberExpression":
            obj_name = self._resolve_callee_name(getattr(callee, "object", None))
            prop_name = ""
            prop = getattr(callee, "property", None)
            if prop:
                if getattr(prop, "type", "") == "Identifier":
                    prop_name = getattr(prop, "name", "")
                elif getattr(prop, "type", "") == "Literal":
                    prop_name = str(getattr(prop, "value", ""))
            return f"{obj_name}.{prop_name}" if obj_name else prop_name
        return ""

    def analyze_package_json(self, package_json_data: Dict[str, Any], rel_path: str = "package.json") -> List[SecurityFinding]:
        """
        Inspects package.json for dangerous install lifecycle scripts.
        """
        findings: List[SecurityFinding] = []
        scripts = package_json_data.get("scripts", {})
        if not isinstance(scripts, dict):
            return findings

        for hook in ("preinstall", "install", "postinstall"):
            cmd = scripts.get(hook)
            if cmd:
                findings.append(SecurityFinding(
                    module="JS_AST_ANALYZER",
                    rule_id="JS_LIFECYCLE_INSTALL_HOOK",
                    category=FindingCategory.INSTALL_SCRIPT,
                    severity=Severity.MEDIUM,
                    confidence=0.85,
                    title=f"npm Lifecycle Hook Executed on Install ({hook})",
                    description=(
                        f"Package defines a '{hook}' lifecycle script: '{cmd}'. "
                        "Lifecycle scripts execute automatically when developers install the package."
                    ),
                    affected_file=rel_path,
                    evidence={"hook": hook, "command": cmd},
                    detection_method="PACKAGE_JSON_SCRIPTS_ANALYSIS",
                ))

        return findings
