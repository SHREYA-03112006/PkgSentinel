import React, { useState, useEffect } from 'react';
import { ShieldCheck, AlertTriangle, XCircle, Search, ArrowUpRight, Clock, RefreshCw } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';

interface ScanReportSummary {
  jobId: string;
  ecosystem: string;
  name: string;
  version: string;
  status: 'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED';
  verdict?: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
  riskScore?: number;
  confidenceScore?: number;
  createdAt: string;
  completedAt?: string;
}

interface PageData {
  content: ScanReportSummary[];
  totalElements: number;
  totalPages: number;
}

interface MetricCardProps {
  title: string;
  value: string | number;
  change: string;
  icon: React.ComponentType<{ className?: string }>;
  tone: 'safe' | 'suspicious' | 'malicious' | 'accent';
}

const MetricCard: React.FC<MetricCardProps> = ({ title, value, change, icon: Icon, tone }) => {
  const toneStyles = {
    safe: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
    suspicious: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    malicious: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
    accent: 'text-sentinel-cyan bg-cyan-500/10 border-cyan-500/30',
  }[tone];

  return (
    <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-5 hover:border-slate-600 transition-colors">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">{title}</span>
        <div className={`p-2 rounded-lg border ${toneStyles}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <div className="mt-3">
        <div className="text-2xl font-bold font-mono text-white">{value}</div>
        <p className="text-xs text-slate-400 mt-1 flex items-center gap-1 font-mono">{change}</p>
      </div>
    </div>
  );
};

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanReportSummary[]>([]);
  const [totalScans, setTotalScans] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchRecentScans = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/v1/scans?page=0&size=10');
      if (!response.ok) {
        throw new Error(`Failed to load scans: HTTP ${response.status}`);
      }
      const data: PageData = await response.json();
      setScans(data.content || []);
      setTotalScans(data.totalElements || 0);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to connect to backend';
      setError(msg);
      setScans([]);
      setTotalScans(0);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchRecentScans();
  }, []);

  const safeCount = scans.filter((s) => s.verdict === 'SAFE').length;
  const suspiciousCount = scans.filter((s) => s.verdict === 'SUSPICIOUS').length;
  const maliciousCount = scans.filter((s) => s.verdict === 'MALICIOUS').length;

  const formatTimestamp = (isoString?: string) => {
    if (!isoString) return 'Pending';
    try {
      const d = new Date(isoString);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' ' + d.toLocaleDateString();
    } catch {
      return isoString;
    }
  };

  return (
    <div className="space-y-6">
      {/* Hero Banner */}
      <div className="bg-gradient-to-r from-sentinel-card via-slate-900 to-sentinel-card border border-sentinel-border rounded-xl p-6 relative overflow-hidden">
        <div className="absolute right-0 top-0 bottom-0 w-96 bg-cyan-500/5 blur-3xl pointer-events-none"></div>
        <div className="max-w-2xl">
          <span className="text-xs font-mono text-sentinel-cyan uppercase tracking-widest">Platform Status: Active</span>
          <h2 className="text-2xl font-bold text-white mt-1">Supply-Chain Security Operations</h2>
          <p className="text-slate-300 text-sm mt-2 leading-relaxed">
            Continuous zero-day package heuristic analysis for npm and PyPI ecosystems. 
            Evaluating metadata anomalies, typosquatting vectors, static AST hazards, and version drift.
          </p>
          <div className="mt-5 flex items-center gap-3">
            <Link
              to="/scan"
              className="inline-flex items-center gap-2 px-4 py-2 bg-sentinel-accent hover:bg-sentinel-accent-hover text-slate-950 font-semibold rounded-lg text-sm transition-colors shadow-sm shadow-cyan-500/20"
            >
              <Search className="w-4 h-4" />
              <span>Launch Single Scan</span>
            </Link>
            <Link
              to="/lockfile"
              className="inline-flex items-center gap-2 px-4 py-2 bg-sentinel-surface hover:bg-slate-700 text-slate-200 border border-sentinel-border font-medium rounded-lg text-sm transition-colors"
            >
              <span>Inspect Lockfile</span>
              <ArrowUpRight className="w-3.5 h-3.5 text-slate-400" />
            </Link>
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Packages Analyzed"
          value={totalScans}
          change={totalScans === 0 ? "Awaiting scan jobs" : `${totalScans} recorded scans`}
          icon={Search}
          tone="accent"
        />
        <MetricCard
          title="Safe Packages"
          value={safeCount}
          change="Clean bill of health"
          icon={ShieldCheck}
          tone="safe"
        />
        <MetricCard
          title="Suspicious Flagged"
          value={suspiciousCount}
          change="Manual review queue"
          icon={AlertTriangle}
          tone="suspicious"
        />
        <MetricCard
          title="Malicious Intercepted"
          value={maliciousCount}
          change="Exploits neutralized"
          icon={XCircle}
          tone="malicious"
        />
      </div>

      {/* Recent Activity Table */}
      <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-5">
        <div className="flex items-center justify-between pb-4 border-b border-sentinel-border">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-sentinel-cyan" />
            <h3 className="font-semibold text-white text-sm">Recent Scan Activity</h3>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-slate-400">Stream: stream:scan-jobs</span>
            <button
              onClick={fetchRecentScans}
              className="p-1.5 rounded-lg bg-sentinel-surface hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
              title="Refresh Activity"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {error && (
          <div className="my-4 p-3 rounded-lg bg-red-950/30 border border-red-800/40 text-xs text-red-300">
            {error} (Verify Spring Boot is active on port 8080)
          </div>
        )}

        {scans.length === 0 ? (
          <div className="py-12 text-center text-slate-400">
            <p className="text-sm">No packages scanned yet in this environment.</p>
            <p className="text-xs text-slate-500 mt-1">Submit an npm or PyPI package via the Package Scanner to begin live telemetry.</p>
          </div>
        ) : (
          <div className="overflow-x-auto mt-2">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-sentinel-border text-slate-400 font-mono uppercase tracking-wider">
                  <th className="py-3 px-3">Ecosystem</th>
                  <th className="py-3 px-3">Package Coordinates</th>
                  <th className="py-3 px-3">Status / Verdict</th>
                  <th className="py-3 px-3">Risk Score</th>
                  <th className="py-3 px-3">Timestamp</th>
                  <th className="py-3 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-border">
                {scans.map((scan) => (
                  <tr key={scan.jobId} className="hover:bg-sentinel-surface/40 transition-colors">
                    <td className="py-3 px-3 font-mono">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                        scan.ecosystem === 'NPM' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                      }`}>
                        {scan.ecosystem}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono font-medium text-white">
                      {scan.name} <span className="text-slate-400 font-normal">@{scan.version}</span>
                    </td>
                    <td className="py-3 px-3 font-mono">
                      {scan.verdict ? (
                        <span className={`px-2 py-0.5 rounded font-bold text-[11px] ${
                          scan.verdict === 'MALICIOUS'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                            : scan.verdict === 'SUSPICIOUS'
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                            : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                        }`}>
                          {scan.verdict}
                        </span>
                      ) : (
                        <span className={`px-2 py-0.5 rounded text-[11px] ${
                          scan.status === 'PROCESSING'
                            ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 animate-pulse'
                            : scan.status === 'FAILED'
                            ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                            : 'bg-slate-700/50 text-slate-300'
                        }`}>
                          {scan.status}
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-3 font-mono">
                      {scan.riskScore !== undefined && scan.riskScore !== null ? (
                        <span className="font-bold text-slate-200">
                          {scan.riskScore} <span className="text-slate-500 text-[10px]">/ 100</span>
                        </span>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-slate-400 font-mono">
                      {formatTimestamp(scan.createdAt)}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => navigate(`/scan?jobId=${scan.jobId}`)}
                        className="px-2.5 py-1 rounded bg-sentinel-surface hover:bg-slate-700 text-sentinel-cyan text-xs font-mono transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
