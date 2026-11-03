import React, { useState, useEffect } from 'react';
import { Shield, Menu, X, ArrowRight } from 'lucide-react';
import { checkSystemHealth, SystemHealth } from '../services/scanService';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab }) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [health, setHealth] = useState<SystemHealth | null>(null);

  useEffect(() => {
    let isMounted = true;
    const fetchHealth = async () => {
      const data = await checkSystemHealth();
      if (isMounted) setHealth(data);
    };

    fetchHealth();
    const interval = setInterval(fetchHealth, 30000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const navItems = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'history', label: 'Scan History' },
    { id: 'about', label: 'About & Zero-Day' },
  ];

  const isHealthy = health?.status === 'HEALTHY';
  const isDegraded = health?.status === 'DEGRADED';

  return (
    <header className="sticky top-0 z-50 glass-panel border-b border-slate-200/70 shadow-soft-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-18 py-3">
          
          {/* Logo & Brand */}
          <div 
            onClick={() => setActiveTab('dashboard')} 
            className="flex items-center gap-3 cursor-pointer group select-none"
          >
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-pastel-lavender-500 to-pastel-powder-400 flex items-center justify-center text-white shadow-soft-sm group-hover:scale-105 transition-transform duration-200">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg text-slate-800 tracking-tight">
                  Pkg<span className="text-pastel-lavender-600">Sentinel</span>
                </span>
                <span className="text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full bg-pastel-lavender-100 text-pastel-lavender-600 border border-pastel-lavender-200">
                  Zero-Day Shield
                </span>
              </div>
              <p className="text-xs text-slate-500 hidden sm:block">Supply Chain Security Engine</p>
            </div>
          </div>

          {/* Desktop Navigation */}
          <nav className="hidden md:flex items-center gap-1 bg-slate-100/80 p-1.5 rounded-2xl border border-slate-200/60">
            {navItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`px-4 py-2 rounded-xl text-sm font-medium transition-all duration-200 relative ${
                    isActive
                      ? 'bg-white text-slate-800 shadow-soft-sm font-semibold'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'
                  }`}
                >
                  {item.label}
                  {isActive && (
                    <span className="absolute bottom-1.5 left-1/2 -translate-x-1/2 w-4 h-0.5 bg-pastel-lavender-500 rounded-full" />
                  )}
                </button>
              );
            })}
          </nav>

          {/* Live Status Indicator & CTA */}
          <div className="hidden lg:flex items-center gap-3">
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-xl border text-xs font-medium font-mono ${
              isHealthy 
                ? 'bg-pastel-mint-50 border-pastel-mint-200 text-pastel-mint-600' 
                : isDegraded 
                ? 'bg-pastel-powder-50 border-pastel-powder-200 text-pastel-powder-700'
                : 'bg-pastel-blush-50 border-pastel-blush-200 text-pastel-blush-500'
            }`}>
              <span className="relative flex h-2 w-2">
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                  isHealthy ? 'bg-pastel-mint-400' : isDegraded ? 'bg-amber-400' : 'bg-rose-400'
                }`}></span>
                <span className={`relative inline-flex rounded-full h-2 w-2 ${
                  isHealthy ? 'bg-pastel-mint-500' : isDegraded ? 'bg-amber-500' : 'bg-rose-500'
                }`}></span>
              </span>
              <span>{isHealthy ? 'Engine Online' : isDegraded ? 'Engine Degraded' : 'Engine Offline'}</span>
            </div>

            <button 
              onClick={() => {
                setActiveTab('dashboard');
                setTimeout(() => {
                  document.getElementById('scanner')?.scrollIntoView({ behavior: 'smooth' });
                }, 100);
              }}
              className="text-xs font-semibold px-3.5 py-2 bg-pastel-lavender-500 hover:bg-pastel-lavender-600 text-white rounded-xl shadow-soft-sm transition-all flex items-center gap-1.5"
            >
              <span>Scan Package</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Mobile menu button */}
          <div className="md:hidden flex items-center">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 rounded-xl text-slate-600 hover:text-slate-900 hover:bg-slate-100 focus:outline-none"
              aria-label="Toggle menu"
            >
              {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile menu */}
      {mobileMenuOpen && (
        <div className="md:hidden border-t border-slate-200/80 bg-white/95 backdrop-blur-md px-4 pt-3 pb-5 space-y-2">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => {
                setActiveTab(item.id);
                setMobileMenuOpen(false);
              }}
              className={`w-full text-left px-4 py-2.5 rounded-xl text-sm font-medium transition-all ${
                activeTab === item.id
                  ? 'bg-pastel-lavender-50 text-pastel-lavender-700 font-semibold'
                  : 'text-slate-600 hover:bg-slate-50'
              }`}
            >
              {item.label}
            </button>
          ))}
          <div className="pt-2">
            <button
              onClick={() => {
                setActiveTab('dashboard');
                setMobileMenuOpen(false);
                setTimeout(() => {
                  document.getElementById('scanner')?.scrollIntoView({ behavior: 'smooth' });
                }, 100);
              }}
              className="w-full text-center py-2.5 bg-pastel-lavender-500 text-white text-xs font-semibold rounded-xl"
            >
              Scan Package
            </button>
          </div>
        </div>
      )}
    </header>
  );
};

export default Navbar;
