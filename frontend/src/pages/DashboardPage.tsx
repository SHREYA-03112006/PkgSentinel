import React from 'react';
import { ShieldCheck, AlertTriangle, XCircle, Search, ArrowUpRight, Clock } from 'lucide-react';
import { Link } from 'react-router-dom';

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
          value="0"
          change="Awaiting scan jobs"
          icon={Search}
          tone="accent"
        />
        <MetricCard
          title="Safe Packages"
          value="0"
          change="Clean bill of health"
          icon={ShieldCheck}
          tone="safe"
        />
        <MetricCard
          title="Suspicious Flagged"
          value="0"
          change="Manual review queue"
          icon={AlertTriangle}
          tone="suspicious"
        />
        <MetricCard
          title="Malicious Intercepted"
          value="0"
          change="Zero-day exploits neutralized"
          icon={XCircle}
          tone="malicious"
        />
      </div>

      {/* Live Feed Placeholder */}
      <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-5">
        <div className="flex items-center justify-between pb-4 border-b border-sentinel-border">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-sentinel-cyan" />
            <h3 className="font-semibold text-white text-sm">Recent Scan Activity</h3>
          </div>
          <span className="text-xs font-mono text-slate-400">Stream: stream:scan-jobs</span>
        </div>
        
        <div className="py-12 text-center text-slate-400">
          <p className="text-sm">No packages scanned yet in this environment.</p>
          <p className="text-xs text-slate-500 mt-1">Submit an npm or PyPI package via the Package Scanner to begin live telemetry.</p>
        </div>
      </div>
    </div>
  );
};

