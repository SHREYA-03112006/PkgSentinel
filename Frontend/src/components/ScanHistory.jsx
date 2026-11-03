import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { History, Search, Filter, RotateCcw, ChevronRight, ShieldAlert, ShieldCheck, AlertTriangle, ArrowUpDown, Layers } from 'lucide-react';
import { getScans, resetDemoHistory } from '../api/scanService';

export default function ScanHistory({ onSelectScan, refreshTrigger }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterEco, setFilterEco] = useState('ALL');
  const [filterClass, setFilterClass] = useState('ALL');

  const fetchHistory = async () => {
    setLoading(true);
    const data = await getScans();
    setHistory(data);
    setLoading(false);
  };

  useEffect(() => {
    fetchHistory();
  }, [refreshTrigger]);

  const handleReset = () => {
    const defaultData = resetDemoHistory();
    setHistory(defaultData);
  };

  // Filtered dataset
  const filtered = history.filter((item) => {
    const matchesSearch = item.name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesEco = filterEco === 'ALL' || item.ecosystem.toLowerCase() === filterEco.toLowerCase();
    const matchesClass = filterClass === 'ALL' || item.classification.toUpperCase() === filterClass.toUpperCase();
    return matchesSearch && matchesEco && matchesClass;
  });

  return (
    <section id="history" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mb-16">
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
            <button
              onClick={handleReset}
              className="text-xs font-semibold px-3 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-600 flex items-center gap-1.5 transition-all"
              title="Reset history to sample defaults"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset Demo History</span>
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
              placeholder="Search history by package name..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full h-10 pl-9 pr-4 rounded-xl bg-white border border-slate-200 text-xs text-slate-800 focus:outline-none focus:ring-2 focus:ring-pastel-lavender-400 shadow-soft-sm"
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

          {/* Classification Filter */}
          <div className="sm:col-span-3">
            <select
              value={filterClass}
              onChange={(e) => setFilterClass(e.target.value)}
              className="w-full h-10 px-3 rounded-xl bg-white border border-slate-200 text-xs font-medium text-slate-700 focus:outline-none focus:ring-2 focus:ring-pastel-lavender-400 shadow-soft-sm cursor-pointer"
            >
              <option value="ALL">All Risk Levels</option>
              <option value="HIGH">High Risk (Block)</option>
              <option value="MEDIUM">Medium Risk (Warn)</option>
              <option value="LOW">Low Risk (Allow)</option>
            </select>
          </div>
        </div>

        {/* Scan Table */}
        {loading ? (
          <div className="py-12 text-center text-xs text-slate-400">
            Loading scan audit log...
          </div>
        ) : filtered.length === 0 ? (
          <div className="py-12 text-center space-y-2">
            <p className="text-sm font-semibold text-slate-700">No matching scan records found</p>
            <p className="text-xs text-slate-400">Try adjusting your search or scan a package using the scanner above.</p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-2xl border border-slate-200/80 bg-white">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-50/80 text-[11px] font-semibold uppercase tracking-wider text-slate-500 border-b border-slate-200">
                  <th className="py-3 px-4">Package & Version</th>
                  <th className="py-3 px-4">Ecosystem</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Decision</th>
                  <th className="py-3 px-4">Findings</th>
                  <th className="py-3 px-4">Scanned</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-xs">
                {filtered.map((item) => {
                  const isHigh = item.classification === 'HIGH';
                  const isMed = item.classification === 'MEDIUM';

                  let badge = 'bg-pastel-mint-100 text-pastel-mint-700 border-pastel-mint-200';
                  let scoreBadge = 'text-pastel-mint-600 bg-pastel-mint-50 border-pastel-mint-200';
                  if (isHigh) {
                    badge = 'bg-pastel-blush-100 text-pastel-blush-500 border-pastel-blush-200';
                    scoreBadge = 'text-pastel-blush-500 bg-pastel-blush-50 border-pastel-blush-200';
                  } else if (isMed) {
                    badge = 'bg-pastel-powder-100 text-pastel-powder-700 border-pastel-powder-200';
                    scoreBadge = 'text-pastel-powder-600 bg-pastel-powder-50 border-pastel-powder-200';
                  }

                  return (
                    <tr
                      key={item.id}
                      className="hover:bg-slate-50/80 transition-colors group"
                    >
                      {/* Name & Version */}
                      <td className="py-3.5 px-4 font-mono">
                        <div className="font-semibold text-slate-900 group-hover:text-pastel-lavender-600 transition-colors">
                          {item.name}
                        </div>
                        <div className="text-[11px] text-slate-400">
                          v{item.version}
                        </div>
                      </td>

                      {/* Ecosystem */}
                      <td className="py-3.5 px-4">
                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md font-mono text-[11px] font-medium bg-slate-100 text-slate-700 border border-slate-200">
                          {item.ecosystem}
                        </span>
                      </td>

                      {/* Score */}
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-2">
                          <span className={`font-mono font-bold px-2 py-0.5 rounded-lg border text-xs ${scoreBadge}`}>
                            {item.riskScore}
                          </span>
                          <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${badge}`}>
                            {item.classification}
                          </span>
                        </div>
                      </td>

                      {/* Decision */}
                      <td className="py-3.5 px-4 font-semibold">
                        <span className={`text-[11px] font-bold px-2.5 py-1 rounded-md ${item.decision === 'BLOCK' ? 'bg-pastel-blush-500 text-white' :
                          item.decision === 'WARN' ? 'bg-pastel-powder-500 text-white' :
                            'bg-pastel-mint-500 text-white'
                          }`}>
                          {item.decision}
                        </span>
                      </td>

                      {/* Findings */}
                      <td className="py-3.5 px-4 text-slate-500">
                        {item.findingsCount > 0 ? (
                          <span className="text-pastel-blush-500 font-medium">
                            {item.findingsCount} flagged
                          </span>
                        ) : (
                          <span className="text-pastel-mint-600 font-medium">Clean</span>
                        )}
                      </td>

                      {/* Date */}
                      <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                        {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>

                      {/* Action */}
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={() => onSelectScan(item.id)}
                          className="text-xs font-semibold px-3 py-1.5 rounded-xl bg-white border border-slate-200 text-slate-700 hover:bg-pastel-lavender-50 hover:text-pastel-lavender-700 hover:border-pastel-lavender-200 transition-all inline-flex items-center gap-1 shadow-soft-sm"
                        >
                          <span>Inspect</span>
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* REST API Callout */}
        <div className="flex items-center justify-between text-xs text-slate-400 pt-2">
          <span>Persisted via client storage; ready for Spring Boot <code>GET /api/scans</code></span>
          <span className="font-mono text-[11px]">Total Scanned: {history.length}</span>
        </div>

      </div>
    </section>
  );
}

