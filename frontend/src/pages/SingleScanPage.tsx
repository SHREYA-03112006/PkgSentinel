import React, { useState } from 'react';
import { 
  Search, 
  Zap, 
  Layers, 
  ArrowRight, 
  ShieldCheck, 
  AlertTriangle, 
  AlertOctagon, 
  CheckCircle2, 
  FileCode, 
  Activity,
  ChevronDown,
  ChevronUp
} from 'lucide-react';

interface Finding {
  finding_id: string;
  module: string;
  rule_id: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number;
  title: string;
  description: string;
  affected_file?: string;
  affected_line?: number;
  detection_method: string;
  evidence: Record<string, unknown>;
}

interface AnalysisReport {
  job_id: string;
  status: string;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
  risk_score: number;
  raw_score: number;
  confidence_score: number;
  summary_notes: string;
  execution_duration_ms: number;
  verdict_reasons: string[];
  analysis_coverage: Record<string, string>;
  findings: Finding[];
}

export const SingleScanPage: React.FC = () => {
  const [ecosystem, setEcosystem] = useState<'NPM' | 'PYPI'>('NPM');
  const [packageName, setPackageName] = useState('');
  const [version, setVersion] = useState('');
  const [scanDepth, setScanDepth] = useState<'FAST' | 'DEEP'>('FAST');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [expandedEvidence, setExpandedEvidence] = useState<Record<string, boolean>>({});

  const toggleEvidence = (id: string) => {
    setExpandedEvidence(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!packageName.trim() || !version.trim()) return;

    setIsSubmitting(true);
    setErrorMessage(null);
    setReport(null);

    // Call Python Security Engine directly for immediate static analysis report
    fetch('http://localhost:8000/api/v1/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ecosystem,
        name: packageName.trim(),
        version: version.trim()
      })
    })
      .then(async res => {
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || `Server returned HTTP ${res.status}`);
        }
        return res.json();
      })
      .then((data: AnalysisReport) => {
        setReport(data);
      })
      .catch(err => {
        setErrorMessage(`Analysis failed: ${err.message}. Verify that the security-engine service is running on port 8000.`);
      })
      .finally(() => {
        setIsSubmitting(false);
      });
  };

  const severityBadgeClass = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'HIGH':
        return 'bg-rose-500/15 text-rose-300 border-rose-500/30';
      case 'MEDIUM':
        return 'bg-amber-500/15 text-amber-300 border-amber-500/30';
      case 'LOW':
      default:
        return 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30';
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white">Target Package Analysis</h2>
        <p className="text-sm text-slate-400 mt-1">
          Perform zero-day heuristic inspection: metadata, typosquatting proximity, AST hazards, and Shannon entropy.
        </p>
      </div>

      {/* Query Form */}
      <form onSubmit={handleSubmit} className="bg-sentinel-card border border-sentinel-border rounded-xl p-6 space-y-6">
        {/* Ecosystem Selection */}
        <div>
          <label className="block text-xs font-mono uppercase tracking-wider text-slate-300 mb-2">
            Target Ecosystem
          </label>
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => setEcosystem('NPM')}
              className={`flex items-center justify-center gap-2 py-3 px-4 rounded-lg font-medium text-sm border transition-all ${
                ecosystem === 'NPM'
                  ? 'bg-sentinel-accent/20 border-sentinel-cyan text-white shadow-sm shadow-cyan-950'
                  : 'bg-sentinel-surface border-sentinel-border text-slate-400 hover:text-white'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-red-400"></span>
              <span>npm (JavaScript / TypeScript)</span>
            </button>
            <button
              type="button"
              onClick={() => setEcosystem('PYPI')}
              className={`flex items-center justify-center gap-2 py-3 px-4 rounded-lg font-medium text-sm border transition-all ${
                ecosystem === 'PYPI'
                  ? 'bg-sentinel-accent/20 border-sentinel-cyan text-white shadow-sm shadow-cyan-950'
                  : 'bg-sentinel-surface border-sentinel-border text-slate-400 hover:text-white'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-blue-400"></span>
              <span>PyPI (Python Ecosystem)</span>
            </button>
          </div>
        </div>

        {/* Package Coordinates */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="md:col-span-2">
            <label className="block text-xs font-mono uppercase tracking-wider text-slate-300 mb-2">
              Package Name
            </label>
            <input
              type="text"
              value={packageName}
              onChange={(e) => setPackageName(e.target.value)}
              placeholder={ecosystem === 'NPM' ? 'e.g. chalk or @scope/pkg' : 'e.g. requests'}
              required
              className="w-full bg-sentinel-surface border border-sentinel-border rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-sentinel-cyan transition-colors"
            />
          </div>
          <div>
            <label className="block text-xs font-mono uppercase tracking-wider text-slate-300 mb-2">
              Version
            </label>
            <input
              type="text"
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              placeholder="e.g. 1.0.0"
              required
              className="w-full bg-sentinel-surface border border-sentinel-border rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-sentinel-cyan transition-colors font-mono"
            />
          </div>
        </div>

        {/* Scan Depth Selector */}
        <div>
          <label className="block text-xs font-mono uppercase tracking-wider text-slate-300 mb-2">
            Scan Depth Mode
          </label>
          <div className="grid grid-cols-2 gap-3">
            <div
              onClick={() => setScanDepth('FAST')}
              className={`p-4 rounded-lg border cursor-pointer transition-all ${
                scanDepth === 'FAST'
                  ? 'bg-sentinel-accent/10 border-sentinel-cyan text-white'
                  : 'bg-sentinel-surface border-sentinel-border text-slate-400 hover:border-slate-600'
              }`}
            >
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-amber-400" />
                <span className="font-semibold text-sm">Static Heuristic Fast-Path</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Metadata scrutiny, typosquatting proximity, AST analysis, and Shannon entropy estimation.
              </p>
            </div>

            <div
              onClick={() => setScanDepth('DEEP')}
              className={`p-4 rounded-lg border cursor-pointer transition-all opacity-75 ${
                scanDepth === 'DEEP'
                  ? 'bg-sentinel-accent/10 border-sentinel-cyan text-white'
                  : 'bg-sentinel-surface border-sentinel-border text-slate-400 hover:border-slate-600'
              }`}
            >
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-sentinel-cyan" />
                <span className="font-semibold text-sm">Deep Dynamic Sandbox (Phase 2)</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Full Docker canary detonation with network sinkhole egress surveillance.
              </p>
            </div>
          </div>
        </div>

        {/* Submit Button */}
        <div className="pt-2">
          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full py-3 bg-sentinel-accent hover:bg-sentinel-accent-hover disabled:opacity-50 text-slate-950 font-bold rounded-lg text-sm transition-colors flex items-center justify-center gap-2 shadow-sm shadow-cyan-500/20"
          >
            {isSubmitting ? (
              <span className="flex items-center gap-2">
                <Activity className="w-4 h-4 animate-spin text-slate-950" />
                <span>Ingesting & Inspecting Package...</span>
              </span>
            ) : (
              <>
                <Search className="w-4 h-4" />
                <span>Execute Security Analysis</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>

        {errorMessage && (
          <div className="p-4 rounded-lg bg-red-950/40 border border-red-800 text-xs text-red-200">
            {errorMessage}
          </div>
        )}
      </form>

      {/* Actual Live Analysis Report */}
      {report && (
        <div className="space-y-6 animate-in fade-in duration-300">
          {/* Verdict Scorecard Header */}
          <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-6">
            <div className="flex flex-wrap items-center justify-between gap-4 pb-6 border-b border-sentinel-border">
              <div>
                <span className="text-xs font-mono text-sentinel-cyan uppercase tracking-widest">
                  {ecosystem} Security Verdict
                </span>
                <h3 className="text-2xl font-bold font-mono text-white mt-1">
                  {packageName} <span className="text-slate-400 text-lg">@{version}</span>
                </h3>
              </div>

              {/* Verdict Pill */}
              <div className="flex items-center gap-4">
                <div className="text-right">
                  <div className="text-xs font-mono text-slate-400">Risk Score</div>
                  <div className="text-3xl font-bold font-mono text-white">{report.risk_score} <span className="text-sm text-slate-400">/ 100</span></div>
                </div>

                <div className={`px-4 py-2 rounded-xl border flex items-center gap-2 font-bold font-mono text-sm ${
                  report.verdict === 'MALICIOUS'
                    ? 'bg-rose-500/20 text-rose-400 border-rose-500/40'
                    : report.verdict === 'SUSPICIOUS'
                    ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                    : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                }`}>
                  {report.verdict === 'MALICIOUS' ? (
                    <AlertOctagon className="w-5 h-5" />
                  ) : report.verdict === 'SUSPICIOUS' ? (
                    <AlertTriangle className="w-5 h-5" />
                  ) : (
                    <ShieldCheck className="w-5 h-5" />
                  )}
                  <span>{report.verdict}</span>
                </div>
              </div>
            </div>

            {/* Verdict Reasons */}
            <div className="mt-4 space-y-2">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Verdict Attribution:</span>
              <ul className="space-y-1">
                {report.verdict_reasons.map((reason, idx) => (
                  <li key={idx} className="text-sm text-slate-200 flex items-start gap-2">
                    <span className="text-sentinel-cyan mt-1">•</span>
                    <span>{reason}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Coverage Badges */}
            <div className="mt-6 pt-4 border-t border-sentinel-border flex flex-wrap gap-2 text-xs font-mono">
              <span className="text-slate-400 py-1">Analysis Coverage:</span>
              {Object.entries(report.analysis_coverage).map(([mod, status]) => (
                <span
                  key={mod}
                  className={`px-2.5 py-1 rounded-md border ${
                    status === 'COMPLETED'
                      ? 'bg-sentinel-surface text-emerald-400 border-emerald-800/40'
                      : 'bg-red-950/40 text-red-400 border-red-800/40'
                  }`}
                >
                  {mod}: {status}
                </span>
              ))}
              <span className="px-2.5 py-1 rounded-md bg-sentinel-surface text-slate-300 border border-sentinel-border ml-auto">
                Confidence: {Math.round(report.confidence_score * 100)}%
              </span>
            </div>
          </div>

          {/* Findings List */}
          <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-6">
            <div className="flex items-center justify-between pb-4 border-b border-sentinel-border">
              <h4 className="font-bold text-white text-base flex items-center gap-2">
                <FileCode className="w-4 h-4 text-sentinel-cyan" />
                <span>Normalized Security Findings ({report.findings.length})</span>
              </h4>
            </div>

            {report.findings.length === 0 ? (
              <div className="py-10 text-center text-slate-400">
                <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-2" />
                <p className="text-sm text-slate-300">Clean bill of health: 0 security findings detected.</p>
                <p className="text-xs text-slate-500 mt-1">Package source and metadata do not exhibit known malicious patterns.</p>
              </div>
            ) : (
              <div className="divide-y divide-sentinel-border mt-2">
                {report.findings.map((finding) => (
                  <div key={finding.finding_id} className="py-4 space-y-2">
                    <div className="flex items-start justify-between gap-4">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[11px] font-mono border font-bold ${severityBadgeClass(finding.severity)}`}>
                            {finding.severity}
                          </span>
                          <span className="font-mono text-xs text-slate-400">{finding.rule_id}</span>
                          <span className="text-xs text-slate-500">[{finding.category}]</span>
                        </div>
                        <h5 className="font-semibold text-white text-sm">{finding.title}</h5>
                      </div>

                      <span className="text-xs font-mono text-slate-400 shrink-0">
                        Method: {finding.detection_method}
                      </span>
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed">{finding.description}</p>

                    {finding.affected_file && (
                      <div className="text-xs font-mono text-sentinel-cyan flex items-center gap-2">
                        <span>Target: {finding.affected_file}</span>
                        {finding.affected_line && <span>(Line: {finding.affected_line})</span>}
                      </div>
                    )}

                    {/* Expandable Evidence */}
                    {Object.keys(finding.evidence || {}).length > 0 && (
                      <div className="pt-1">
                        <button
                          type="button"
                          onClick={() => toggleEvidence(finding.finding_id)}
                          className="text-[11px] font-mono text-slate-400 hover:text-slate-200 flex items-center gap-1 transition-colors"
                        >
                          {expandedEvidence[finding.finding_id] ? (
                            <>
                              <ChevronUp className="w-3.5 h-3.5" />
                              <span>Hide Evidence Data</span>
                            </>
                          ) : (
                            <>
                              <ChevronDown className="w-3.5 h-3.5" />
                              <span>Show Evidence Data ({Object.keys(finding.evidence).length} items)</span>
                            </>
                          )}
                        </button>

                        {expandedEvidence[finding.finding_id] && (
                          <pre className="mt-2 p-3 rounded-lg bg-sentinel-bg border border-sentinel-border text-[11px] font-mono text-slate-300 overflow-x-auto">
                            {JSON.stringify(finding.evidence, null, 2)}
                          </pre>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
