import React, { useState } from 'react';
import { Shield, ShieldAlert, Activity, Menu, X, Terminal, ExternalLink } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'history', label: 'Scan History' },
    { id: 'about', label: 'About & Zero-Day' },
  ];

  return (
    <header className="sticky top-0 z-50 glass-panel border-b border-slate-200/70 shadow-soft-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-18">
          
          {/* Logo & Brand */}
          <div 
            onClick={() => setActiveTab('dashboard')} 
            className="flex items-center gap-3 cursor-pointer group"
          >
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-pastel-lavender-500 to-pastel-powder-400 flex items-center justify-center text-white shadow-soft-sm group-hover:scale-105 transition-transform duration-200">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg text-slate-800 tracking-tight">Pkg<span className="text-pastel-lavender-600">Sentinel</span></span>
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

          {/* Live Status indicator */}
          <div className="hidden lg:flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-pastel-mint-50 border border-pastel-mint-200 text-pastel-mint-600 text-xs font-medium">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-pastel-mint-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-pastel-mint-500"></span>
              </span>
              Engine Online (Demo Mode)
            </div>
            <a 
              href="#scanner" 
              onClick={(e) => {
                setActiveTab('dashboard');
                setTimeout(() => {
                  document.getElementById('scanner')?.scrollIntoView({ behavior: 'smooth' });
                }, 100);
              }}
              className="text-xs font-semibold px-3.5 py-2 bg-pastel-lavender-500 hover:bg-pastel-lavender-600 text-white rounded-xl shadow-soft-sm transition-all"
            >
              Scan Package
            </a>
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
              className={`w-full text-left px-4 py-2.5 rounded-xl text-sm font-medium transition-colors ${
                activeTab === item.id
                  ? 'bg-pastel-lavender-100 text-pastel-lavender-700 font-semibold'
                  : 'text-slate-700 hover:bg-slate-100'
              }`}
            >
              {item.label}
            </button>
          ))}
          <div className="pt-2">
            <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-pastel-mint-50 border border-pastel-mint-200 text-pastel-mint-700 text-xs font-medium">
              <span className="w-2 h-2 rounded-full bg-pastel-mint-500 animate-pulse"></span>
              Engine Status: Active (Simulated API)
            </div>
          </div>
        </div>
      )}
    </header>
  );
}
