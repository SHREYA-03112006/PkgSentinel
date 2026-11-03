import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { 
  Search, 
  ShieldCheck, 
  AlertTriangle, 
  AlertOctagon, 
  CheckCircle2, 
  FileCode, 
  Activity,
  ChevronDown,
  ChevronUp,
  RotateCcw
} from 'lucide-react';

interface FindingItem {
  findingId: string;
  moduleName: string;
  ruleId: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number;
  title: string;
  description: string;
  filePath?: string;
  lineNumber?: number;
  codeSnippet?: string;
  detectionMethod: string;
}

interface ScanReportResponse {
  jobId: string;
  ecosystem: 'NPM' | 'PYPI';
  name: string;
  version: string;
  status: 'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED';
  verdict?: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
  riskScore?: number;
  rawScore?: number;
  confidenceScore?: number;
  summaryNotes?: string;
  verdictReasons?: string[];
  analysisCoverage?: Record<string, string>;
  createdAt?: string;
  completedAt?: string;
  failureReason?: string;
  findings?: FindingItem[];
}

export const SingleScanPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [ecosystem, setEcosystem] = useState<'NPM' | 'PYPI'>('NPM');
  const [packageName, setPackageName] = useState('');
  const [version, setVersion] = useState('');

  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [activeStatus, setActiveStatus] = useState<'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED' | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [report, setReport] = useState<ScanReportResponse | null>(null);
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});

  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = () => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  };

  const pollScanStatus = useCallback(async (jobId: string) => {
    try {
      const res = await fetch(`/api/v1/scans/${jobId}`);
      if (!res.ok) {
        if (res.status === 404) {
          throw new Error(`Job ${jobId} not found`);
        }
        throw new Error(`HTTP ${res.status}`);
      }
      const data: ScanReportResponse = await res.json();
      setActiveStatus(data.status);

      if (data.status === 'COMPLETED') {
        stopPolling();
        setIsSubmitting(false);
        setReport(data);
        setPackageName(data.name);
        setVersion(data.version);
        setEcosystem(data.ecosystem);
      } else if (data.status === 'FAILED') {
        stopPolling();
        setIsSubmitting(false);
        setReport(data);
        setErrorMessage(data.failureReason || 'Package inspection failed');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Polling error';
      setErrorMessage(msg);
      stopPolling();
      setIsSubmitting(false);
    }
  }, []);

  const startPolling = useCallback((jobId: string) => {
    stopPolling();
    setActiveJobId(jobId);
    setActiveStatus('QUEUED');
    setIsSubmitting(true);
    setErrorMessage(null);
    setReport(null);

    pollScanStatus(jobId);
    pollingRef.current = setInterval(() => {
      pollScanStatus(jobId);
    }, 1500);
  }, [pollScanStatus]);

  useEffect(() => {
    const urlJobId = searchParams.get('jobId');
    if (urlJobId) {
      startPolling(urlJobId);
    }
    return () => {
      stopPolling();
    };
  }, [searchParams, startPolling]);

  const toggleFinding = (id: string) => {
    setExpandedFindings(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!packageName.trim() || !version.trim()) return;

    setIsSubmitting(true);
    setErrorMessage(null);
    setReport(null);
    setActiveStatus(null);
    stopPolling();

    try {
      const res = await fetch('/api/v1/scans', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Triggered-By': 'WEB_UI'
        },
        body: JSON.stringify({
          ecosystem,
          name: packageName.trim(),
          version: version.trim()
        })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.message || `Server error: HTTP ${res.status}`);
      }

      const jobData = await res.json();
      setSearchParams({ jobId: jobData.jobId });
      startPolling(jobData.jobId);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Submission failed';
      setErrorMessage(msg);
      setIsSubmitting(false);
    }
  };

  const handleReset = () => {
    stopPolling();
    setSearchParams({});
    setActiveJobId(null);
    setActiveStatus(null);
    setReport(null);
    setErrorMessage(null);
    setIsSubmitting(false);
  };

  const setDemoPreset = (eco: 'NPM' | 'PYPI', name: string, ver: string) => {
    setEcosystem(eco);
    setPackageName(name);
    setVersion(ver);
  };

  const severityCount = {
    CRITICAL: report?.findings?.filter(f => f.severity === 'CRITICAL').length || 0,
    HIGH: report?.findings?.filter(f => f.severity === 'HIGH').length || 0,
    MEDIUM: report?.findings?.filter(f => f.severity === 'MEDIUM').length || 0,
    LOW: report?.findings?.filter(f => f.severity === 'LOW').length || 0,
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Top Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-white tracking-tight">Package Heuristic Scanner</h1>
          <p className="text-xs text-slate-400 mt-0.5">Static zero-day inspection for npm & PyPI packages.</p>
        </div>
        {(report || activeJobId) && (
          <button
            onClick={handleReset}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>New Scan</span>
          </button>
        )}
      </div>

      {/* Query Form (Hidden when report is shown to keep focus on verdict) */}
      {!report && (
        <form onSubmit={handleSubmit} className="bg-[#0f172a] border border-slate-800 rounded-lg p-5 space-y-4">
          {/* Ecosystem Selection */}
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider mr-2">Ecosystem:</span>
            <div className="flex bg-slate-900 p-0.5 rounded-md border border-slate-800">
              <button
                type="button"
                onClick={() => setEcosystem('NPM')}
                disabled={isSubmitting}
                className={`px-3 py-1 rounded text-xs font-medium transition-all ${
                  ecosystem === 'NPM'
                    ? 'bg-rose-500/20 text-rose-300 font-semibold border border-rose-500/30'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                npm
              </button>
              <button
                type="button"
                onClick={() => setEcosystem('PYPI')}
                disabled={isSubmitting}
                className={`px-3 py-1 rounded text-xs font-medium transition-all ${
                  ecosystem === 'PYPI'
                    ? 'bg-blue-500/20 text-blue-300 font-semibold border border-blue-500/30'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                PyPI
              </button>
            </div>
          </div>

          {/* Package Coordinates Input */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="md:col-span-2">
              <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-1">
                Package Name
              </label>
              <input
                type="text"
                value={packageName}
                onChange={(e) => setPackageName(e.target.value)}
                placeholder={ecosystem === 'NPM' ? 'e.g. chalk or @scope/pkg' : 'e.g. requests'}
                required
                disabled={isSubmitting}
                className="w-full bg-[#1e293b] border border-slate-800 rounded-md px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono transition-colors"
              />
            </div>
            <div>
              <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-1">
                Version
              </label>
              <input
                type="text"
                value={version}
                onChange={(e) => setVersion(e.target.value)}
                placeholder="e.g. 1.0.0"
                required
                disabled={isSubmitting}
                className="w-full bg-[#1e293b] border border-slate-800 rounded-md px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono transition-colors"
              />
            </div>
          </div>

          {/* Demo Presets Bar */}
          <div className="pt-1 flex items-center gap-2 flex-wrap">
            <span className="text-[11px] font-mono text-slate-400">Presets:</span>
            <button
              type="button"
              onClick={() => setDemoPreset('NPM', 'chalk', '5.3.0')}
              className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-[11px] font-mono text-slate-300 transition-colors"
            >
              chalk@5.3.0
            </button>
            <button
              type="button"
              onClick={() => setDemoPreset('NPM', 'express', '4.19.2')}
              className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-[11px] font-mono text-slate-300 transition-colors"
            >
              express@4.19.2
            </button>
            <button
              type="button"
              onClick={() => setDemoPreset('PYPI', 'requests', '2.31.0')}
              className="px-2 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-[11px] font-mono text-slate-300 transition-colors"
            >
              requests@2.31.0
            </button>
            <button
              type="button"
              onClick={() => setDemoPreset('PYPI', 'requests-fake', '1.0.0')}
              className="px-2 py-0.5 rounded bg-rose-950/40 border border-rose-900/40 hover:bg-rose-900/50 text-[11px] font-mono text-rose-300 transition-colors"
            >
              requests-fake (Typosquat)
            </button>
          </div>

          {/* Submit Action */}
          <div className="pt-2">
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-2.5 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold rounded-md text-xs transition-colors flex items-center justify-center gap-2"
            >
              {isSubmitting ? (
                <>
                  <Activity className="w-3.5 h-3.5 animate-spin text-slate-950" />
                  <span>Analyzing Package...</span>
                </>
              ) : (
                <>
                  <Search className="w-3.5 h-3.5" />
                  <span>Analyze Package</span>
                </>
              )}
            </button>
          </div>

          {/* Asynchronous Lifecycle Progress */}
          {isSubmitting && (
            <div className="mt-3 p-3 rounded-md bg-slate-900 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">Job: <span className="text-cyan-400">{activeJobId || 'Initializing'}</span></span>
                <span className="text-cyan-400 flex items-center gap-1 font-semibold">
                  <Activity className="w-3 h-3 animate-spin" />
                  {activeStatus || 'DISPATCHING'}
                </span>
              </div>
              
              <div className="grid grid-cols-3 gap-2 text-[11px] font-mono text-center pt-1">
                <div className={`p-1.5 rounded border ${
                  activeStatus === 'QUEUED'
                    ? 'bg-cyan-500/20 border-cyan-400 text-white font-semibold'
                    : 'bg-slate-950 border-slate-800 text-slate-400'
                }`}>
                  1. Queued
                </div>
                <div className={`p-1.5 rounded border ${
                  activeStatus === 'PROCESSING'
                    ? 'bg-amber-500/20 border-amber-400 text-white font-semibold'
                    : 'bg-slate-950 border-slate-800 text-slate-400'
                }`}>
                  2. AST Analysis
                </div>
                <div className={`p-1.5 rounded border ${
                  activeStatus === 'COMPLETED'
                    ? 'bg-emerald-500/20 border-emerald-400 text-white font-semibold'
                    : 'bg-slate-950 border-slate-800 text-slate-400'
                }`}>
                  3. Persisted
                </div>
              </div>
            </div>
          )}

          {errorMessage && (
            <div className="p-3 rounded-md bg-rose-950/30 border border-rose-800/40 text-xs text-rose-300 font-mono">
              {errorMessage}
            </div>
          )}
        </form>
      )}

      {/* COMPLETED SECURITY REPORT */}
      {report && (
        <div className="space-y-4">
          {/* Verdict Scorecard Header */}
          <div className="bg-[#0f172a] border border-slate-800 rounded-lg p-5">
            <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold ${
                    report.ecosystem === 'NPM' ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30' : 'bg-blue-500/15 text-blue-400 border border-blue-500/30'
                  }`}>
                    {report.ecosystem}
                  </span>
                  <span className="text-xs font-mono text-slate-400">{report.jobId}</span>
                </div>
                <h2 className="text-xl font-bold font-mono text-white mt-1">
                  {report.name} <span className="text-slate-400 text-base">@{report.version}</span>
                </h2>
              </div>

              {/* Large Risk & Verdict Badges */}
              <div className="flex items-center gap-4">
                <div className="text-right">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">Risk Score</div>
                  <div className="text-3xl font-bold font-mono text-white leading-none mt-0.5">
                    {report.riskScore ?? 0}
                    <span className="text-xs text-slate-400 font-normal"> / 100</span>
                  </div>
                </div>

                <div className={`px-4 py-2 rounded-lg border flex items-center gap-2 font-bold font-mono text-sm ${
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

            {/* Severity Distribution & Confidence */}
            <div className="mt-3 flex items-center justify-between text-xs font-mono text-slate-400">
              <div className="flex items-center gap-3">
                <span>Findings:</span>
                <span className="text-rose-400 font-semibold">{severityCount.CRITICAL} Critical</span>
                <span className="text-rose-300">{severityCount.HIGH} High</span>
                <span className="text-amber-300">{severityCount.MEDIUM} Medium</span>
                <span className="text-cyan-300">{severityCount.LOW} Low</span>
              </div>
              {report.confidenceScore !== undefined && (
                <div className="text-slate-300">
                  Confidence: {Math.round(report.confidenceScore * 100)}%
                </div>
              )}
            </div>

            {/* Verdict Attribution Reasons */}
            {report.verdictReasons && report.verdictReasons.length > 0 && (
              <div className="mt-3 p-3 rounded bg-slate-900/80 border border-slate-800 text-xs">
                <span className="font-mono text-slate-400 uppercase tracking-wider text-[10px] block mb-1">
                  Verdict Attribution:
                </span>
                <ul className="space-y-1">
                  {report.verdictReasons.map((reason, idx) => (
                    <li key={idx} className="text-slate-200 flex items-start gap-1.5 font-mono text-[11px]">
                      <span className="text-cyan-400">•</span>
                      <span>{reason}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Analysis Coverage Pills */}
            {report.analysisCoverage && (
              <div className="mt-3 pt-3 border-t border-slate-800 flex flex-wrap items-center gap-2 text-[11px] font-mono">
                <span className="text-slate-400 mr-1">Coverage:</span>
                {Object.entries(report.analysisCoverage).map(([mod, status]) => (
                  <span
                    key={mod}
                    className={`px-2 py-0.5 rounded border ${
                      status === 'COMPLETED'
                        ? 'bg-slate-900 text-emerald-400 border-slate-800'
                        : 'bg-rose-950/30 text-rose-400 border-rose-900/30'
                    }`}
                  >
                    {mod}: {status}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Security Findings List */}
          <div className="bg-[#0f172a] border border-slate-800 rounded-lg p-5">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                <span>Security Findings ({report.findings?.length || 0})</span>
              </h3>
            </div>

            {(!report.findings || report.findings.length === 0) ? (
              <div className="py-8 text-center text-slate-400">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-1.5" />
                <p className="text-xs text-slate-200 font-medium">Clean bill of health</p>
                <p className="text-[11px] text-slate-400 mt-0.5">0 malicious indicators or suspicious APIs detected.</p>
              </div>
            ) : (
              <div className="divide-y divide-slate-800/80 mt-1">
                {report.findings.map((f) => {
                  const isExpanded = expandedFindings[f.findingId];
                  return (
                    <div key={f.findingId} className="py-3">
                      <div 
                        onClick={() => toggleFinding(f.findingId)}
                        className="flex items-start justify-between gap-3 cursor-pointer select-none"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                              f.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                              f.severity === 'HIGH' ? 'bg-rose-500/15 text-rose-300 border border-rose-500/20' :
                              f.severity === 'MEDIUM' ? 'bg-amber-500/15 text-amber-300 border border-amber-500/20' :
                              'bg-cyan-500/15 text-cyan-300 border border-cyan-500/20'
                            }`}>
                              {f.severity}
                            </span>
                            <span className="text-[11px] font-mono text-slate-400">{f.ruleId}</span>
                            <span className="text-[11px] text-slate-400">[{f.category}]</span>
                          </div>
                          <div className="text-xs font-semibold text-white">
                            {f.title}
                          </div>
                          {f.filePath && (
                            <div className="text-[11px] font-mono text-cyan-400">
                              Target: {f.filePath} {f.lineNumber ? `(Line: ${f.lineNumber})` : ''}
                            </div>
                          )}
                        </div>

                        <div className="flex items-center gap-2 text-slate-400 shrink-0 mt-1">
                          <span className="text-[10px] font-mono text-slate-400">
                            {isExpanded ? 'Collapse' : 'Details'}
                          </span>
                          {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                        </div>
                      </div>

                      {/* Expandable Technical Detail */}
                      {isExpanded && (
                        <div className="mt-3 p-3 rounded bg-slate-900 border border-slate-800 text-xs space-y-2">
                          <p className="text-slate-300 leading-relaxed text-xs">
                            {f.description}
                          </p>

                          <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-slate-400 pt-1">
                            <div>Module: <span className="text-slate-200">{f.moduleName}</span></div>
                            <div>Method: <span className="text-slate-200">{f.detectionMethod}</span></div>
                            <div>Confidence: <span className="text-slate-200">{Math.round(f.confidence * 100)}%</span></div>
                          </div>

                          {f.codeSnippet && (
                            <div className="pt-2">
                              <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">Evidence Code Snippet:</span>
                              <pre className="p-2.5 rounded bg-black/50 border border-slate-800 text-[11px] font-mono text-emerald-300 overflow-x-auto">
                                {f.codeSnippet}
                              </pre>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
