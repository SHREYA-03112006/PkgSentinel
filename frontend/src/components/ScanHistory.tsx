import React, { useState, useEffect, useMemo } from 'react';
import { History, Search, RefreshCw, ChevronRight, ShieldCheck, ShieldAlert, AlertTriangle, Layers, User } from 'lucide-react';
import { getScans } from '../services/scanService';
import { UIHistoryItem } from '../types/scan';
import { useAuth } from '../context/AuthContext';

interface ScanHistoryProps {
  onSelectScan: (id: string) => void;
  refreshTrigger: number;
}

export const ScanHistory: React.FC<ScanHistoryProps> = ({ onSelectScan, refreshTrigger }) => {
  const { isAuthenticated } = useAuth();
  const [history, setHistory] = useState<UIHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterEco, setFilterEco] = useState('ALL');
  const [filterDecision, setFilterDecision] = useState('ALL');
  const [myScansOnly, setMyScansOnly] = useState(false);

  const fetchHistory = async () => {
    setLoading(true);
    const data = await getScans(myScansOnly);
    setHistory(data);
    setLoading(false);
  };

  useEffect(() => {
    fetchHistory();
  }, [refreshTrigger, myScansOnly]);

  // Filtered dataset
  const filtered = useMemo(() => {
    return history.filter((item) => {
      const matchesSearch = item.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                            item.id.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesEco = filterEco === 'ALL' || item.ecosystem.toLowerCase() === filterEco.toLowerCase();
      const matchesDecision = filterDecision === 'ALL' || item.decision.toUpperCase() === filterDecision.toUpperCase();
      return matchesSearch && matchesEco && matchesDecision;
    });
  }, [history, searchTerm, filterEco, filterDecision]);

  return (
    <section id="history" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mb-16 select-none">
      <div className="rounded-3xl glass-card p-6 sm:p-8 shadow-soft-lg border border-white/90 space-y-6">

        {/* Title and Controls */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-200/60">
          <div>
            <h2 className="text-xl sm:text-2xl font-bold text-slate-800 tracking-tight flex items-center gap-2">
              <History className="w-6 h-6 text-pastel-lavender-600" />
              Recent Scan History & Audit Log
            </h2>
            <p className="text-sm text-slate-500 mt-0.5">
              Review previously analyzed packages, inspect security findings, and monitor dependency trends.
            </p>
          </div>

          <div className="flex items-center gap-2">
            {isAuthenticated && (
              <div className="flex bg-slate-100 p-0.5 rounded-xl border border-slate-200">
                <button
                  type="button"
                  onClick={() => setMyScansOnly(false)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                    !myScansOnly
                      ? 'bg-white text-slate-800 shadow-soft-xs'
                      : 'text-slate-500 hover:text-slate-700'
                  }`}
                >
                  All Scans
                </button>
                <button
                  type="button"
                  onClick={() => setMyScansOnly(true)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1 ${
                    myScansOnly
                      ? 'bg-pastel-lavender-500 text-white shadow-soft-xs'
                      : 'text-slate-500 hover:text-slate-700'
                  }`}
                >
                  <User className="w-3 h-3" />
                  <span>My Scans</span>
                </button>
              </div>
            )}
            <button
              onClick={fetchHistory}
              disabled={loading}
              className="text-xs font-semibold px-3 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 flex items-center gap-1.5 transition-all cursor-pointer"
              title="Refresh scan history from database"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-pastel-lavender-600' : ''}`} />
              <span>Refresh History</span>
            </button>
          </div>
        </div>

        {/* Filter bar */}
        <div className="grid grid-cols-1 sm:grid-cols-12 gap-3">
          {/* Search box */}
          <div className="sm:col-span-6 relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
              <Search className="w-4 h-4" />
            </div>
            <input
              type="text"
              placeholder="Search history by package name or job ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full h-10 pl-9 pr-4 rounded-xl bg-white border border-slate-200 text-xs text-slate-800 focus:outline-none focus:ring-2 focus:ring-pastel-lavender-400 shadow-soft-sm font-mono"
            />
          </div>

          {/* Ecosystem Filter */}
          <div className="sm:col-span-3">
            <select
              value={filterEco}
              onChange={(e) => setFilterEco(e.target.value)}
              className="w-full h-10 px-3 rounded-xl bg-white border border-slate-200 text-xs font-medium text-slate-700 focus:outline-none focus:ring-2 focus:ring-pastel-lavender-400 shadow-soft-sm cursor-pointer"
            >
              <option value="ALL">All Ecosystems (npm & PyPI)</option>
              <option value="npm">npm only</option>
              <option value="pypi">PyPI only</option>
            </select>
          </div>

          {/* Decision Filter */}
          <div className="sm:col-span-3">
            <select
              value={filterDecision}
              onChange={(e) => setFilterDecision(e.target.value)}
              className="w-full h-10 px-3 rounded-xl bg-white border border-slate-200 text-xs font-medium text-slate-700 focus:outline-none focus:ring-2 focus:ring-pastel-lavender-400 shadow-soft-sm cursor-pointer"
            >
              <option value="ALL">All Decisions</option>
              <option value="ALLOW">ALLOW (Clean)</option>
              <option value="WARN">WARN (Suspicious)</option>
              <option value="BLOCK">BLOCK (Malicious)</option>
            </select>
          </div>
        </div>

        {/* History Table */}
        <div className="overflow-x-auto">
          {loading ? (
            <div className="py-12 text-center text-slate-400 font-mono text-xs">
              <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-pastel-lavender-600" />
              <span>Fetching audit records from PostgreSQL...</span>
            </div>
          ) : filtered.length === 0 ? (
            <div className="py-12 text-center text-slate-400 space-y-2">
              <Layers className="w-8 h-8 text-slate-300 mx-auto" />
              <p className="text-sm text-slate-600 font-medium">No package scans found</p>
              <p className="text-xs text-slate-400 max-w-sm mx-auto">
                {history.length === 0 
                  ? 'No packages have been scanned yet in this environment. Run a scan above to populate audit telemetry.'
                  : 'No records match your active search and filter criteria.'}
              </p>
            </div>
          ) : (
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200/80 text-slate-500 font-semibold uppercase tracking-wider text-[11px]">
                  <th className="py-3 px-3">Ecosystem</th>
                  <th className="py-3 px-3">Package Coordinates</th>
                  <th className="py-3 px-3">Risk Index</th>
                  <th className="py-3 px-3">Decision</th>
                  <th className="py-3 px-3">Findings</th>
                  <th className="py-3 px-3">Timestamp</th>
                  <th className="py-3 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filtered.map((item) => {
                  let badge = 'bg-pastel-mint-100 text-pastel-mint-700 border-pastel-mint-200';
                  let Icon = ShieldCheck;
                  if (item.decision === 'BLOCK') {
                    badge = 'bg-pastel-blush-100 text-pastel-blush-600 border-pastel-blush-200';
                    Icon = ShieldAlert;
                  } else if (item.decision === 'WARN') {
                    badge = 'bg-pastel-powder-100 text-pastel-powder-700 border-pastel-powder-200';
                    Icon = AlertTriangle;
                  }

                  return (
                    <tr
                      key={item.id}
                      onClick={() => onSelectScan(item.id)}
                      className="hover:bg-slate-50/80 cursor-pointer transition-colors group"
                    >
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 rounded-md font-mono text-[10px] font-bold border ${
                          item.ecosystem === 'npm' 
                            ? 'bg-rose-50 text-rose-600 border-rose-200' 
                            : 'bg-blue-50 text-blue-600 border-blue-200'
                        }`}>
                          {item.ecosystem.toUpperCase()}
                        </span>
                      </td>

                      <td className="py-3 px-3">
                        <div className="font-mono font-bold text-slate-900 group-hover:text-pastel-lavender-600 transition-colors">
                          {item.name} <span className="text-slate-400 font-normal">@{item.version}</span>
                        </div>
                        <div className="text-[10px] text-slate-400 font-mono truncate max-w-xs">
                          {item.summary}
                        </div>
                      </td>

                      <td className="py-3 px-3 font-mono">
                        <span className="font-bold text-slate-800 text-sm">
                          {item.riskScore}
                        </span>
                        <span className="text-slate-400 text-[10px]"> / 100</span>
                      </td>

                      <td className="py-3 px-3">
                        <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full font-bold text-[10px] border ${badge}`}>
                          <Icon className="w-3 h-3" />
                          <span>{item.decision}</span>
                        </span>
                      </td>

                      <td className="py-3 px-3 font-mono">
                        {item.findingsCount > 0 ? (
                          <span className="px-2 py-0.5 rounded bg-pastel-blush-50 text-pastel-blush-600 font-bold border border-pastel-blush-200 text-[10px]">
                            {item.findingsCount} flagged
                          </span>
                        ) : (
                          <span className="text-slate-400 text-[11px]">0 indicators</span>
                        )}
                      </td>

                      <td className="py-3 px-3 text-slate-500 font-mono text-[11px]">
                        {new Date(item.timestamp).toLocaleDateString([], { month: 'short', day: 'numeric' })}{' '}
                        {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>

                      <td className="py-3 px-3 text-right">
                        <span className="text-xs font-semibold text-pastel-lavender-600 group-hover:text-pastel-lavender-700 flex items-center justify-end gap-1">
                          <span>Inspect</span>
                          <ChevronRight className="w-3.5 h-3.5" />
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

      </div>
    </section>
  );
};

export default ScanHistory;
