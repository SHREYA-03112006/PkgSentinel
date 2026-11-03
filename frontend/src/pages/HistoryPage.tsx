import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Search, 
  RefreshCw, 
  Filter, 
  ExternalLink,
  ShieldCheck,
  AlertTriangle,
  AlertOctagon,
  Clock
} from 'lucide-react';

interface ScanHistoryItem {
  jobId: string;
  ecosystem: 'NPM' | 'PYPI';
  name: string;
  version: string;
  status: 'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED';
  verdict?: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
  riskScore?: number;
  confidenceScore?: number;
  createdAt: string;
  completedAt?: string;
  findings?: Array<unknown>;
}

interface PageData {
  content: ScanHistoryItem[];
  totalElements: number;
}

export const HistoryPage: React.FC = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanHistoryItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [registryFilter, setRegistryFilter] = useState<'ALL' | 'NPM' | 'PYPI'>('ALL');
  const [verdictFilter, setVerdictFilter] = useState<'ALL' | 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'FAILED'>('ALL');

  const fetchHistory = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/scans?page=0&size=50');
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const data: PageData = await res.json();
      setScans(data.content || []);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to load history';
      setError(msg);
      setScans([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const filteredScans = useMemo(() => {
    return scans.filter((item) => {
      // Search query filter
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase().trim();
        const matchesName = item.name.toLowerCase().includes(query);
        const matchesVer = item.version.toLowerCase().includes(query);
        const matchesJob = item.jobId.toLowerCase().includes(query);
        if (!matchesName && !matchesVer && !matchesJob) return false;
      }

      // Registry filter
      if (registryFilter !== 'ALL' && item.ecosystem !== registryFilter) {
        return false;
      }

      // Verdict filter
      if (verdictFilter !== 'ALL') {
        if (verdictFilter === 'FAILED') {
          if (item.status !== 'FAILED') return false;
        } else {
          if (item.verdict !== verdictFilter) return false;
        }
      }

      return true;
    });
  }, [scans, searchQuery, registryFilter, verdictFilter]);

  const formatTimestamp = (isoString?: string) => {
    if (!isoString) return '—';
    try {
      const d = new Date(isoString);
      return d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' }) + ' ' +
             d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch {
      return isoString;
    }
  };

  return (
    <div className="space-y-5">
      {/* Page Title & Refresh */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-white tracking-tight">Scan Audit History</h1>
          <p className="text-xs text-slate-400 mt-0.5">Historical forensic record of all analyzed packages.</p>
        </div>

        <button
          onClick={fetchHistory}
          disabled={isLoading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-lg p-3.5 flex flex-wrap items-center justify-between gap-3">
        {/* Search Input */}
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search package name or job ID..."
            className="w-full bg-[#1e293b] border border-slate-800 rounded-md pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono transition-colors"
          />
        </div>

        {/* Filter Dropdowns / Toggles */}
        <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
          <div className="flex items-center gap-1 text-slate-400 mr-1">
            <Filter className="w-3 h-3 text-cyan-400" />
            <span>Registry:</span>
          </div>

          <div className="flex bg-slate-900 p-0.5 rounded border border-slate-800">
            {(['ALL', 'NPM', 'PYPI'] as const).map((eco) => (
              <button
                key={eco}
                onClick={() => setRegistryFilter(eco)}
                className={`px-2 py-1 rounded text-[11px] font-medium transition-colors ${
                  registryFilter === eco
                    ? 'bg-cyan-500/20 text-cyan-300 font-semibold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {eco}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1 text-slate-400 ml-2 mr-1">
            <span>Verdict:</span>
          </div>

          <div className="flex bg-slate-900 p-0.5 rounded border border-slate-800">
            {(['ALL', 'SAFE', 'SUSPICIOUS', 'MALICIOUS'] as const).map((v) => (
              <button
                key={v}
                onClick={() => setVerdictFilter(v)}
                className={`px-2 py-1 rounded text-[11px] font-medium transition-colors ${
                  verdictFilter === v
                    ? 'bg-cyan-500/20 text-cyan-300 font-semibold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {v}
              </button>
            ))}
          </div>
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-md bg-rose-950/30 border border-rose-800/40 text-xs text-rose-300 font-mono">
          {error}
        </div>
      )}

      {/* History Table */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-lg overflow-hidden">
        {filteredScans.length === 0 ? (
          <div className="py-14 text-center text-slate-400">
            <Clock className="w-8 h-8 text-slate-600 mx-auto mb-2" />
            <p className="text-xs text-slate-200 font-medium">No matching scans found</p>
            <p className="text-[11px] text-slate-400 mt-0.5">
              {scans.length === 0 
                ? 'No packages have been scanned yet.' 
                : 'Try adjusting your search query or filters.'}
            </p>
            {scans.length === 0 && (
              <button
                onClick={() => navigate('/scan')}
                className="mt-3 px-3 py-1.5 rounded-md bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-xs font-medium transition-colors"
              >
                Scan Package Now
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-[11px] bg-slate-950/40">
                  <th className="py-2.5 px-3">Registry</th>
                  <th className="py-2.5 px-3">Package</th>
                  <th className="py-2.5 px-3">Version</th>
                  <th className="py-2.5 px-3">Risk Score</th>
                  <th className="py-2.5 px-3">Verdict</th>
                  <th className="py-2.5 px-3">Scanned Date</th>
                  <th className="py-2.5 px-3 text-right">Report</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredScans.map((scan) => (
                  <tr
                    key={scan.jobId}
                    onClick={() => navigate(`/scan?jobId=${scan.jobId}`)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-2.5 px-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                        scan.ecosystem === 'NPM'
                          ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                          : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                      }`}>
                        {scan.ecosystem}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-semibold text-white">
                      {scan.name}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400">
                      @{scan.version}
                    </td>
                    <td className="py-2.5 px-3">
                      {scan.riskScore !== undefined && scan.riskScore !== null ? (
                        <span className="font-bold text-slate-200">
                          {scan.riskScore} <span className="text-slate-400 text-[10px]">/ 100</span>
                        </span>
                      ) : (
                        <span className="text-slate-400">—</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3">
                      {scan.verdict ? (
                        <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          scan.verdict === 'MALICIOUS'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : scan.verdict === 'SUSPICIOUS'
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        }`}>
                          {scan.verdict === 'MALICIOUS' ? (
                            <AlertOctagon className="w-3 h-3" />
                          ) : scan.verdict === 'SUSPICIOUS' ? (
                            <AlertTriangle className="w-3 h-3" />
                          ) : (
                            <ShieldCheck className="w-3 h-3" />
                          )}
                          <span>{scan.verdict}</span>
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
                    <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                      {formatTimestamp(scan.createdAt)}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <span className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 text-xs">
                        <span>Inspect</span>
                        <ExternalLink className="w-3 h-3" />
                      </span>
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
