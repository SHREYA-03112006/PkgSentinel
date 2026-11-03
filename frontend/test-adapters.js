import assert from 'node:assert';
import test from 'node:test';

// Inlined logic to test pure adapter functions directly in ESM
function mapBackendVerdictToUI(verdict, riskScore = 0) {
  if (verdict === 'MALICIOUS' || riskScore >= 70) {
    return { decision: 'BLOCK', classification: 'HIGH' };
  }
  if (verdict === 'SUSPICIOUS' || riskScore >= 30) {
    return { decision: 'WARN', classification: 'MEDIUM' };
  }
  return { decision: 'ALLOW', classification: 'LOW' };
}

function mapBackendFindingToUI(f) {
  let recommendation = 'Review package dependencies and source before approving.';
  if (f.severity === 'CRITICAL') {
    recommendation = 'Quarantine or remove dependency immediately. Do not execute or install.';
  } else if (f.severity === 'HIGH') {
    recommendation = 'Investigate flagged API usage, credential hooks, or network calls.';
  } else if (f.severity === 'MEDIUM') {
    recommendation = 'Audit package provenance, repository links, and maintainer changes.';
  } else {
    recommendation = 'Informational finding. Verify alignment with security policy.';
  }

  return {
    findingId: f.findingId,
    category: f.category || 'Static Analysis',
    severity: f.severity,
    title: f.title,
    detail: f.description,
    recommendation,
    filePath: f.filePath,
    lineNumber: f.lineNumber,
    codeSnippet: f.codeSnippet,
    detectionMethod: f.detectionMethod || 'HEURISTIC',
    confidence: f.confidence ?? 1.0,
    ruleId: f.ruleId
  };
}

function mapBackendReportToUI(r) {
  const risk = r.riskScore !== undefined && r.riskScore !== null ? Number(r.riskScore) : 0;
  const { decision, classification } = mapBackendVerdictToUI(r.verdict, risk);
  const uiFindings = (r.findings || []).map(mapBackendFindingToUI);

  const installScriptDetected = uiFindings.some(f => 
    f.category.toUpperCase().includes('INSTALL') || f.ruleId.includes('INSTALL')
  );
  const obfuscationDetected = uiFindings.some(f => 
    f.category.toUpperCase().includes('OBFUSCATION') || f.ruleId.includes('ENTROPY') || f.ruleId.includes('ENCODED')
  );

  let summaryText = r.summaryNotes || '';
  if (!summaryText && r.verdictReasons && r.verdictReasons.length > 0) {
    summaryText = r.verdictReasons.join(' ');
  }
  if (!summaryText) {
    if (r.verdict === 'MALICIOUS') {
      summaryText = 'Critical zero-day security risks detected in package source or lifecycle hooks.';
    } else if (r.verdict === 'SUSPICIOUS') {
      summaryText = 'Suspicious heuristic anomalies flagged in AST or package metadata requiring review.';
    } else {
      summaryText = 'Clean package profile. No significant zero-day malicious patterns identified.';
    }
  }

  return {
    id: r.jobId,
    name: r.name,
    ecosystem: (r.ecosystem?.toLowerCase() === 'pypi' ? 'pypi' : 'npm'),
    version: r.version || 'latest',
    riskScore: Math.round(risk),
    rawScore: r.rawScore ? Number(r.rawScore) : undefined,
    classification,
    decision,
    verdict: r.verdict || (decision === 'BLOCK' ? 'MALICIOUS' : decision === 'WARN' ? 'SUSPICIOUS' : 'SAFE'),
    status: r.status,
    summary: summaryText,
    verdictReasons: r.verdictReasons || [],
    findings: uiFindings,
    coverage: r.analysisCoverage || {},
    confidence: r.confidenceScore ? Number(r.confidenceScore) : 1.0,
    metadata: {
      publisher: 'Registry Verified',
      publishedDate: r.completedAt ? new Date(r.completedAt).toLocaleDateString() : 'Recent',
      installScriptDetected,
      obfuscationDetected,
      entropyScore: r.analysisCoverage?.['Entropy'] || 'Normal',
      networkActivity: uiFindings.some(f => f.ruleId.includes('NETWORK') || f.ruleId.includes('SOCKET') || f.ruleId.includes('IP')) 
        ? 'Suspicious raw IP / socket APIs detected' 
        : 'None detected'
    },
    timestamp: r.completedAt || r.createdAt || new Date().toISOString(),
    failureReason: r.failureReason || undefined
  };
}

test('mapBackendVerdictToUI maps SAFE to ALLOW', () => {
  const result = mapBackendVerdictToUI('SAFE', 0);
  assert.strictEqual(result.decision, 'ALLOW');
  assert.strictEqual(result.classification, 'LOW');
});

test('mapBackendVerdictToUI maps SUSPICIOUS to WARN', () => {
  const result = mapBackendVerdictToUI('SUSPICIOUS', 45);
  assert.strictEqual(result.decision, 'WARN');
  assert.strictEqual(result.classification, 'MEDIUM');
});

test('mapBackendVerdictToUI maps MALICIOUS to BLOCK', () => {
  const result = mapBackendVerdictToUI('MALICIOUS', 88);
  assert.strictEqual(result.decision, 'BLOCK');
  assert.strictEqual(result.classification, 'HIGH');
});

test('mapBackendFindingToUI formats findings and recommendations', () => {
  const finding = mapBackendFindingToUI({
    findingId: 'f-1',
    ruleId: 'JS_CHILD_PROCESS_SPAWN',
    category: 'INSTALL_SCRIPT',
    severity: 'CRITICAL',
    confidence: 0.95,
    title: 'Command Execution Hook',
    description: 'Executes child_process.exec() in postinstall',
    filePath: 'package.json',
    lineNumber: 14,
    codeSnippet: 'node -e "..."',
    detectionMethod: 'AST_VISITOR'
  });

  assert.strictEqual(finding.findingId, 'f-1');
  assert.strictEqual(finding.severity, 'CRITICAL');
  assert.strictEqual(finding.filePath, 'package.json');
  assert.strictEqual(finding.lineNumber, 14);
  assert.ok(finding.recommendation.includes('Quarantine'));
});

test('mapBackendReportToUI transforms Spring Boot report to UI model', () => {
  const backendReport = {
    jobId: '7f3b8900-3498-4b71-b011-8899aabbccdd',
    ecosystem: 'NPM',
    name: 'chalk-fake',
    version: '5.3.0',
    status: 'COMPLETED',
    verdict: 'MALICIOUS',
    riskScore: 85.5,
    rawScore: 110.0,
    confidenceScore: 0.95,
    summaryNotes: 'Typosquatting and child_process detected.',
    verdictReasons: ['Critical finding: exec() in install hook', 'Typosquat of chalk'],
    analysisCoverage: { AST: 'COMPLETED', Metadata: 'COMPLETED' },
    completedAt: '2026-11-03T10:00:00Z',
    findings: [
      {
        findingId: 'f-1',
        moduleName: 'STATIC_AST',
        ruleId: 'JS_CHILD_PROCESS_SPAWN',
        category: 'INSTALL_SCRIPT',
        severity: 'CRITICAL',
        confidence: 0.95,
        title: 'Child Process Execution',
        description: 'Spawns shell',
        filePath: 'index.js',
        lineNumber: 5,
        codeSnippet: 'exec("calc.exe")',
        detectionMethod: 'AST'
      }
    ]
  };

  const uiResult = mapBackendReportToUI(backendReport);

  assert.strictEqual(uiResult.id, backendReport.jobId);
  assert.strictEqual(uiResult.name, 'chalk-fake');
  assert.strictEqual(uiResult.ecosystem, 'npm');
  assert.strictEqual(uiResult.decision, 'BLOCK');
  assert.strictEqual(uiResult.classification, 'HIGH');
  assert.strictEqual(uiResult.riskScore, 86);
  assert.strictEqual(uiResult.findings.length, 1);
  assert.strictEqual(uiResult.metadata.installScriptDetected, true);
  assert.strictEqual(uiResult.verdictReasons.length, 2);
});
