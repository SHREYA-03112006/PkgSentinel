# PkgSentinel — Core Detection Engine & Explainable Risk Scoring (Phase 1C)

This document specifies the technical design, heuristic rules, unified finding contract, and mathematical scoring rubric implemented in **Phase 1C**.

---

## 1. Unified SecurityFinding Contract

Every detection module emits normalized findings adhering to this contract:

```json
{
  "finding_id": "4b68bb5a-4b95-46c5-8f69-79a0b1234567",
  "module": "JS_AST_ANALYZER",
  "rule_id": "JS_DYNAMIC_EVAL",
  "category": "STATIC_CODE",
  "severity": "HIGH",
  "confidence": 0.85,
  "title": "Dynamic Execution via eval()",
  "description": "Invocation of eval() to dynamically evaluate arbitrary code strings.",
  "affected_file": "package/index.js",
  "affected_line": 14,
  "detection_method": "JS_AST_TRAVERSAL",
  "evidence": { "callee": "eval" },
  "references": []
}
```

---

## 2. Detection Modules Implemented

### Module A: Metadata & Publisher Analysis (`engine/detection/metadata_analyzer.py`)
- **Release Timeline Analysis**: Detects rapid release bursts ($\ge 5$ releases in $<3$ hours) characteristic of automated deployment churn or typosquat flooding (`LOW` severity).
- **Version Number Anomalies**: Flags abnormally elevated major versions ($\ge 99$) commonly used in dependency confusion attacks (`MEDIUM` severity).
- **Repository Consistency**: Compares declared repository URL against the package name. Detects when unverified packages falsely point to high-profile repositories (e.g. `facebook/react`, `vercel/next.js`). Capped at `MEDIUM` severity.
- **Maintainer Email Reputation**: Flags maintainers registered with free/disposable email providers as a weak contextual signal (`LOW` severity).
- **Missing Signal Safety**: Missing registry metadata is never treated as malicious.

### Module B: Typosquatting Detection (`engine/detection/typosquatting.py`)
- **Length-Bounded Damerau-Levenshtein Distance**: Evaluates insertions, deletions, substitutions, and transpositions against curated top npm and PyPI libraries within length difference $\le 2$.
  - Distance 1 $\rightarrow$ `HIGH` severity (confidence 0.85).
  - Distance 2 $\rightarrow$ `MEDIUM` severity (confidence 0.65).
- **Homoglyph & Confusable Mapping**: Uncovers Unicode homoglyph attacks (e.g. Cyrillic `а` (U+0430) vs Latin `a`, Cyrillic `е` (U+0435) vs Latin `e`, lookalike numerals `0`/`o`). Flagged as `HIGH` severity.
- **PyPI PEP 503 Normalization**: Normalizes names (`[-_.]+` collapsed to `-` and lowercase) before proximity matching.
- **Scope-Aware Comparison**: Strips npm scopes (`@scope/pkg`) to evaluate package core names against standard libraries.
- **Combo-Squatting Affixes**: Detects deceptive affixes (`-js`, `-official`, `-cli`, `-core`).

### Module C: Static AST & Shannon Entropy Analysis (`engine/detection/static/`)
- **Python AST Analyzer (`python_ast.py`)**:
  - Traverses AST using Python standard `ast` module without executing code.
  - Detects dynamic execution (`eval`, `exec`, `compile`).
  - Detects child processes (`os.system`, `subprocess.Popen`, `subprocess.run`).
  - Detects dynamic imports (`__import__`, `importlib.import_module`).
  - Detects payload decoding (`base64.b64decode`, `binascii.unhexlify`, `zlib.decompress`).
  - Detects sensitive credential targeting (`.ssh/id_rsa`, `.aws/credentials`, `/etc/shadow`).
  - Detects secret env token harvesting (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`).
  - Detects raw sockets and URL fetchers (`socket.socket`, `urllib.request.urlopen`).
- **JavaScript AST Analyzer (`javascript_ast.py`)**:
  - Traverses ESTree AST using `esprima` parser in tolerant mode without code execution.
  - Detects dynamic execution (`eval()`, `new Function()`).
  - Detects child processes (`child_process.exec`, `execSync`, `spawn`).
  - Detects dynamic computed `require()`.
  - Detects `Buffer.from(..., 'base64')` decoding.
  - Detects hardcoded raw IP endpoints (`http://185.x.x.x`).
  - Detects `package.json` install lifecycle scripts (`preinstall`, `install`, `postinstall`).
- **Shannon Entropy Analyzer (`entropy.py`)**:
  - Calculates information entropy $H = -\sum p_i \log_2 p_i$.
  - Flags files with $H \ge 5.9$ as `OBFUSCATION_HIGH_ENTROPY_FILE` (`MEDIUM` severity).

---

## 3. Module G: Explainable Risk Scoring Engine

### 3.1 Severity Weights
- `CRITICAL`: 50
- `HIGH`: 25
- `MEDIUM`: 10
- `LOW`: 3

### 3.2 Finding Deduplication
Findings are grouped by `(category, affected_file)`. The highest severity finding (with confidence as tie-breaker) is retained, preserving its original evidence record intact.

### 3.3 Asymptotic Scoring Formula
$$S_{\text{raw}} = \sum_{i=1}^{k} \left( W(s_i) \cdot c_i \right)$$

$$S_{\text{norm}} = 100.0 \cdot \left(1.0 - \exp\left(-\frac{S_{\text{raw}}}{45.0}\right)\right)$$

### 3.4 Verdict Decision Rules & Overrides
1. **Critical Finding Override**: Confirmed `CRITICAL` finding with confidence $\ge 0.85 \implies$ `MALICIOUS`.
2. **Multi-Vector Independent High Rule**: $\ge 2$ independent `HIGH` findings from distinct threat categories with confidence $\ge 0.70 \implies$ `MALICIOUS`.
3. **Score $\ge 70$ with Obfuscation-Only Ceiling Guard**: Score $\ge 70 \implies$ `MALICIOUS`, **unless** all findings belong strictly to `OBFUSCATION`. If obfuscation-only, verdict is capped at `SUSPICIOUS`.
4. **Score $\ge 30$ Threshold**: Score $\ge 30 \implies$ `SUSPICIOUS`.
5. **Otherwise**: Verdict is `SAFE`.

### 3.5 Analysis Coverage & Confidence
When no findings are detected, confidence is computed based on analysis coverage:
- $0.85$ if all modules completed cleanly.
- $0.60$ if any module failed or was skipped.

---

## 4. Test Verification Summary

Complete test suite execution (`pytest`):
```
platform win32 -- Python 3.13.2, pytest-9.1.1
rootdir: S:\pro-jects\PKGsentinel\security-engine
testpaths: tests

tests\test_archive_extractor.py ..............                           [ 20%]
tests\test_detection_pipeline.py ..                                      [ 23%]
tests\test_downloader.py ..........                                      [ 38%]
tests\test_health.py ..                                                  [ 41%]
tests\test_inventory.py ...                                              [ 46%]
tests\test_metadata_analyzer.py .....                                    [ 53%]
tests\test_pipeline.py ...                                               [ 58%]
tests\test_schemas.py ..                                                 [ 61%]
tests\test_scoring_engine.py ......                                      [ 70%]
tests\test_static_ast.py ............                                    [ 88%]
tests\test_typosquatting.py ........                                     [100%]

============================= 67 passed in 3.55s ==============================
```
