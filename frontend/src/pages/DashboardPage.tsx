import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  AlertTriangle, 
  AlertOctagon, 
  Search, 
  ArrowRight, 
  RefreshCw,
  FileCode
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

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
  findings?: Array<{
    findingId: string;
    ruleId: string;
    category: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    title: string;
    filePath?: string;
  }>;
}

interface PageData {
  content: ScanReportSummary[];
  totalElements: number;
}

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanReportSummary[]>([]);
  const [totalScans, setTotalScans] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchDashboardData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/scans?page=0&size=10');
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const data: PageData = await res.json();
      setScans(data.content || []);
      setTotalScans(data.totalElements || 0);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to reach API';
      setError(msg);
      setScans([]);
      setTotalScans(0);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const safeCount = scans.filter((s) => s.verdict === 'SAFE').length;
  const suspiciousCount = scans.filter((s) => s.verdict === 'SUSPICIOUS').length;
  const maliciousCount = scans.filter((s) => s.verdict === 'MALICIOUS').length;

  // Flatten top recent findings from loaded scans
  const recentFindings = scans.flatMap((s) => 
    (s.findings || []).map((f) => ({
      ...f,
      jobId: s.jobId,
      pkgName: s.name,
      pkgVersion: s.version
    }))
  ).slice(0, 5);

  const formatTime = (isoString?: string) => {
    if (!isoString) return '—';
    try {
      const d = new Date(isoString);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ' ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
      return isoString;
    }
  };

  return (
    <div className="space-y-6">
      {/* Metric Cards Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="bg-[#0f172a] border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Total Scans</span>
            <Search className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white mt-2">{totalScans}</div>
          <div className="text-[11px] text-slate-400 font-mono mt-0.5">Recorded scan jobs</div>
        </div>

        <div className="bg-[#0f172a] border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Threats Detected</span>
            <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400 mt-2">{maliciousCount}</div>
          <div className="text-[11px] text-slate-400 font-mono mt-0.5">Malicious verdicts</div>
        </div>

        <div className="bg-[#0f172a] border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Safe Packages</span>
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-2">{safeCount}</div>
          <div className="text-[11px] text-slate-400 font-mono mt-0.5">Verified clean</div>
        </div>

        <div className="bg-[#0f172a] border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-xs text-slate-400 font-medium">
            <span>Suspicious Packages</span>
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-2">{suspiciousCount}</div>
          <div className="text-[11px] text-slate-400 font-mono mt-0.5">Flagged heuristics</div>
        </div>
      </div>

      {/* Risk Distribution Bar (When scans exist) */}
      {totalScans > 0 && (
        <div className="bg-[#0f172a] border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-2.5">
            <span className="font-medium text-slate-300">Risk Profile Breakdown</span>
            <div className="flex items-center gap-3 text-[11px]">
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-400"></span>Safe ({safeCount})</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-amber-400"></span>Suspicious ({suspiciousCount})</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-rose-400"></span>Malicious ({maliciousCount})</span>
            </div>
          </div>
          <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden flex">
            {safeCount > 0 && (
              <div 
                style={{ width: `${(safeCount / totalScans) * 100}%` }} 
                className="bg-emerald-400 transition-all"
                title={`Safe: ${safeCount}`}
              />
            )}
            {suspiciousCount > 0 && (
              <div 
                style={{ width: `${(suspiciousCount / totalScans) * 100}%` }} 
                className="bg-amber-400 transition-all"
                title={`Suspicious: ${suspiciousCount}`}
              />
            )}
            {maliciousCount > 0 && (
              <div 
                style={{ width: `${(maliciousCount / totalScans) * 100}%` }} 
                className="bg-rose-400 transition-all"
                title={`Malicious: ${maliciousCount}`}
              />
            )}
          </div>
        </div>
      )}

      {/* Main Grid: Recent Scans & Security Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Scans Table (Span 2 cols on desktop) */}
        <div className={`bg-[#0f172a] border border-slate-800 rounded-lg p-5 ${recentFindings.length > 0 ? 'lg:col-span-2' : 'lg:col-span-3'}`}>
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">Recent Scans</h3>
            <div className="flex items-center gap-2">
              <button
                onClick={fetchDashboardData}
                className="p-1 rounded text-slate-400 hover:text-white transition-colors"
                title="Refresh"
              >
                <RefreshCw className={`w-3 h-3 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
              </button>
              <button
                onClick={() => navigate('/history')}
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
              >
                <span>View all</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
          </div>

          {error && (
            <div className="my-3 p-2.5 rounded bg-rose-950/20 border border-rose-800/30 text-xs text-rose-300 font-mono">
              Backend offline: {error}
            </div>
          )}

          {scans.length === 0 ? (
            <div className="py-12 text-center text-slate-400">
              <Search className="w-8 h-8 text-slate-600 mx-auto mb-2" />
              <p className="text-xs text-slate-300 font-medium">No scans recorded</p>
              <p className="text-[11px] text-slate-400 mt-0.5">Submit an npm or PyPI package to start real-time telemetry.</p>
              <button
                onClick={() => navigate('/scan')}
                className="mt-4 px-3 py-1.5 rounded-md bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-xs font-medium transition-colors"
              >
                Scan First Package
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto mt-2">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800/80 text-slate-400 font-mono text-[11px]">
                    <th className="py-2.5 px-2">Registry</th>
                    <th className="py-2.5 px-2">Package</th>
                    <th className="py-2.5 px-2">Verdict</th>
                    <th className="py-2.5 px-2">Risk</th>
                    <th className="py-2.5 px-2">Time</th>
                    <th className="py-2.5 px-2 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {scans.map((scan) => (
                    <tr 
                      key={scan.jobId} 
                      onClick={() => navigate(`/scan?jobId=${scan.jobId}`)}
                      className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                    >
                      <td className="py-2.5 px-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                          scan.ecosystem === 'NPM' 
                            ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' 
                            : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                        }`}>
                          {scan.ecosystem}
                        </span>
                      </td>
                      <td className="py-2.5 px-2 font-medium text-white">
                        {scan.name} <span className="text-slate-400 font-normal">@{scan.version}</span>
                      </td>
                      <td className="py-2.5 px-2">
                        {scan.verdict ? (
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            scan.verdict === 'MALICIOUS'
                              ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                              : scan.verdict === 'SUSPICIOUS'
                              ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                              : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                          }`}>
                            {scan.verdict}
                          </span>
                        ) : (
                          <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                            scan.status === 'PROCESSING'
                              ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 animate-pulse'
                              : scan.status === 'FAILED'
                              ? 'bg-rose-500/10 text-rose-400'
                              : 'bg-slate-800 text-slate-400'
                          }`}>
                            {scan.status}
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-2">
                        {scan.riskScore !== undefined && scan.riskScore !== null ? (
                          <span className="font-bold text-slate-200">
                            {scan.riskScore} <span className="text-slate-400 text-[10px]">/ 100</span>
                          </span>
                        ) : (
                          <span className="text-slate-400">—</span>
                        )}
                      </td>
                      <td className="py-2.5 px-2 text-slate-400 text-[11px]">
                        {formatTime(scan.createdAt)}
                      </td>
                      <td className="py-2.5 px-2 text-right">
                        <span className="text-xs text-cyan-400 hover:text-cyan-300">
                          Inspect
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Recent Security Findings (Only shown if findings exist) */}
        {recentFindings.length > 0 && (
          <div className="bg-[#0f172a] border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Flagged Findings</span>
                </h3>
                <span className="text-[11px] font-mono text-slate-400">{recentFindings.length}</span>
              </div>

              <div className="divide-y divide-slate-800/60 mt-2">
                {recentFindings.map((finding, idx) => (
                  <div 
                    key={idx}
                    onClick={() => navigate(`/scan?jobId=${finding.jobId}`)}
                    className="py-2.5 hover:bg-slate-800/30 cursor-pointer transition-colors"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                        finding.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400' :
                        finding.severity === 'HIGH' ? 'bg-rose-500/15 text-rose-300' :
                        finding.severity === 'MEDIUM' ? 'bg-amber-500/15 text-amber-300' :
                        'bg-cyan-500/15 text-cyan-300'
                      }`}>
                        {finding.severity}
                      </span>
                      <span className="text-[11px] font-mono text-slate-400">
                        {finding.pkgName}@{finding.pkgVersion}
                      </span>
                    </div>
                    <div className="text-xs text-slate-200 font-medium mt-1 truncate">
                      {finding.title}
                    </div>
                    {finding.filePath && (
                      <div className="text-[10px] font-mono text-slate-400 mt-0.5 truncate">
                        {finding.filePath}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 text-center">
              <button
                onClick={() => navigate('/history')}
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
              >
                Inspect all historical findings →
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
