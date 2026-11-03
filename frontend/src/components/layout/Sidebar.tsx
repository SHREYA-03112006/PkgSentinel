import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  Search, 
  FileCode2, 
  History, 
  Settings,
  Cpu
} from 'lucide-react';

interface NavItem {
  name: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
}

const navItems: NavItem[] = [
  { name: 'Dashboard', path: '/', icon: LayoutDashboard },
  { name: 'Package Scanner', path: '/scan', icon: Search },
  { name: 'Lockfile Inspector', path: '/lockfile', icon: FileCode2 },
  { name: 'Scan History', path: '/history', icon: History },
  { name: 'Settings', path: '/settings', icon: Settings },
];

export const Sidebar: React.FC = () => {
  return (
    <aside className="w-64 border-r border-sentinel-border bg-sentinel-card flex flex-col justify-between shrink-0">
      <div>
        {/* Brand Header */}
        <div className="h-16 flex items-center gap-3 px-6 border-b border-sentinel-border bg-[#0a0f1d]/60">
          <div className="p-2 bg-sentinel-accent/10 border border-sentinel-accent/30 rounded-lg">
            <ShieldAlert className="w-6 h-6 text-sentinel-accent" />
          </div>
          <div>
            <h1 className="font-bold text-base tracking-wide text-white">PkgSentinel</h1>
            <p className="text-[10px] text-sentinel-cyan tracking-widest uppercase font-mono">Zero-Day Defense</p>
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="p-4 space-y-1.5">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-sentinel-accent/15 text-sentinel-cyan border border-sentinel-accent/30 shadow-sm shadow-cyan-950'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-sentinel-surface/50'
                }`
              }
            >
              <item.icon className="w-4 h-4 shrink-0" />
              <span>{item.name}</span>
            </NavLink>
          ))}
        </nav>
      </div>

      {/* Engine Status Pill */}
      <div className="p-4 border-t border-sentinel-border bg-[#0a0f1d]/40">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
          <span className="flex items-center gap-1.5 font-medium">
            <Cpu className="w-3.5 h-3.5 text-sentinel-cyan" />
            Security Core
          </span>
          <span className="flex items-center gap-1 text-[11px] text-emerald-400 font-mono">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            ACTIVE
          </span>
        </div>
        <div className="bg-sentinel-surface p-2.5 rounded-md border border-sentinel-border/70 text-[11px] text-slate-400 space-y-1 font-mono">
          <div className="flex justify-between">
            <span>Orchestrator:</span>
            <span className="text-slate-200">Spring Boot 3.3</span>
          </div>
          <div className="flex justify-between">
            <span>Detection Engine:</span>
            <span className="text-slate-200">Python 3.11+</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
