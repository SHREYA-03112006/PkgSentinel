import React from 'react';
import { Bell, Activity, Database } from 'lucide-react';

export const Header: React.FC = () => {
  return (
    <header className="h-16 border-b border-sentinel-border bg-sentinel-card/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-10">
      <div className="flex items-center gap-4">
        <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Environment</span>
        <span className="px-2.5 py-0.5 rounded-full text-xs font-mono bg-cyan-950/80 text-sentinel-cyan border border-cyan-800/60">
          DEVELOPMENT MODE
        </span>
      </div>

      <div className="flex items-center gap-5 text-sm">
        <div className="flex items-center gap-2 text-xs font-mono text-slate-300 bg-sentinel-surface px-3 py-1.5 rounded-md border border-sentinel-border">
          <Database className="w-3.5 h-3.5 text-sentinel-cyan" />
          <span>PostgreSQL: Connected</span>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-300 bg-sentinel-surface px-3 py-1.5 rounded-md border border-sentinel-border">
          <Activity className="w-3.5 h-3.5 text-emerald-400" />
          <span>Redis Streams: Ready</span>
        </div>

        <button 
          title="System notifications" 
          aria-label="System notifications"
          className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-sentinel-surface transition-colors relative"
        >
          <Bell className="w-4 h-4" />
          <span className="w-2 h-2 rounded-full bg-sentinel-cyan absolute top-1.5 right-1.5 ring-2 ring-sentinel-card"></span>
        </button>
      </div>
    </header>
  );
};
