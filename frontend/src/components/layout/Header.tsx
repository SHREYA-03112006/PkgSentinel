import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { Database, Server } from 'lucide-react';

export const Header: React.FC = () => {
  const location = useLocation();
  const [backendStatus, setBackendStatus] = useState<'ONLINE' | 'DEGRADED' | 'CHECKING'>('CHECKING');

  useEffect(() => {
    let isMounted = true;
    const checkHealth = async () => {
      try {
        const res = await fetch('/api/v1/health');
        if (res.ok) {
          const data = await res.json();
          if (isMounted) {
            setBackendStatus(data.status === 'HEALTHY' ? 'ONLINE' : 'DEGRADED');
          }
        } else {
          if (isMounted) setBackendStatus('DEGRADED');
        }
      } catch {
        if (isMounted) setBackendStatus('DEGRADED');
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const getPageTitle = () => {
    switch (location.pathname) {
      case '/':
        return 'Overview';
      case '/scan':
        return 'Package Scanner';
      case '/history':
        return 'Scan History';
      default:
        return 'Overview';
    }
  };

  return (
    <header className="h-14 border-b border-slate-800 bg-[#0b101b]/90 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-10 select-none">
      <div className="flex items-center gap-3">
        <h2 className="text-sm font-semibold text-white tracking-tight">{getPageTitle()}</h2>
      </div>

      <div className="flex items-center gap-4 text-xs font-mono">
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-slate-300">
          <Server className="w-3 h-3 text-cyan-400" />
          <span>Engine:</span>
          <span className={`font-semibold flex items-center gap-1 ${
            backendStatus === 'ONLINE' ? 'text-emerald-400' : 'text-amber-400'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${
              backendStatus === 'ONLINE' ? 'bg-emerald-400' : 'bg-amber-400'
            }`}></span>
            {backendStatus === 'ONLINE' ? 'Online' : 'Degraded'}
          </span>
        </div>

        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-slate-400">
          <Database className="w-3 h-3 text-slate-400" />
          <span>Storage:</span>
          <span className="text-slate-200">PostgreSQL + Redis</span>
        </div>
      </div>
    </header>
  );
};
