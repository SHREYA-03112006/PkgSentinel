import React from 'react';
import { motion } from 'framer-motion';
import { ShieldAlert, ShieldCheck, Cpu, Code2, Zap } from 'lucide-react';

interface HeroProps {
  onSelectPreset: (name: string, ecosystem: string) => void;
}

export const Hero: React.FC<HeroProps> = ({ onSelectPreset }) => {
  const presets = [
    { name: 'requests-fake', eco: 'pypi', badge: 'Typosquat (Block)', color: 'blush' },
    { name: 'chalk', eco: 'npm', badge: 'AST Heuristic (Warn)', color: 'powder' },
    { name: 'requests', eco: 'pypi', badge: 'Clean (Allow)', color: 'mint' },
    { name: 'express', eco: 'npm', badge: 'Clean (Allow)', color: 'lavender' }
  ];

  return (
    <section className="relative overflow-hidden pt-10 pb-14 md:pt-12 md:pb-16 select-none">
      {/* Soft Pastel Ambient Blobs */}
      <div className="absolute top-0 left-1/4 w-96 h-96 bg-pastel-lavender-200/40 rounded-full blur-3xl pointer-events-none -z-10" />
      <div className="absolute top-12 right-1/4 w-80 h-80 bg-pastel-powder-200/40 rounded-full blur-3xl pointer-events-none -z-10" />
      <div className="absolute bottom-4 left-1/3 w-72 h-72 bg-pastel-mint-200/30 rounded-full blur-3xl pointer-events-none -z-10" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-center">
          
          {/* Left Text Column */}
          <motion.div 
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="lg:col-span-7 space-y-5"
          >
            {/* Pill Header */}
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-pastel-lavender-100 border border-pastel-lavender-200 text-pastel-lavender-700 text-xs font-semibold shadow-soft-sm">
              <Zap className="w-3.5 h-3.5 text-pastel-lavender-600" />
              <span>Zero-Day Dependency Firewall</span>
            </div>

            {/* Main Headline */}
            <h1 className="text-3xl sm:text-5xl font-extrabold text-slate-900 tracking-tight leading-[1.15]">
              Your Guardian Against <br className="hidden sm:inline" />
              <span className="bg-gradient-to-r from-pastel-lavender-600 via-purple-600 to-indigo-600 bg-clip-text text-transparent">
                Malicious Packages.
              </span>
            </h1>

            {/* Subtext */}
            <p className="text-sm sm:text-base text-slate-600 max-w-xl leading-relaxed">
              Traditional vulnerability scanners only catch known CVEs after outbreaks happen. 
              <strong className="text-slate-800 font-semibold"> PkgSentinel</strong> catches zero-day supply chain attacks 
              by analyzing stealthy lifecycle scripts, unexpected publisher takeovers, and code obfuscation before installation.
            </p>

            {/* Quick Action Preset Chips */}
            <div className="pt-1">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2.5">
                Try demo packages with distinct threat profiles:
              </p>
              <div className="flex flex-wrap gap-2">
                {presets.map((preset) => {
                  let badgeStyle = 'bg-pastel-lavender-100 text-pastel-lavender-700 hover:bg-pastel-lavender-200 border-pastel-lavender-200';
                  if (preset.color === 'blush') {
                    badgeStyle = 'bg-pastel-blush-100 text-pastel-blush-600 hover:bg-pastel-blush-200 border-pastel-blush-200';
                  } else if (preset.color === 'mint') {
                    badgeStyle = 'bg-pastel-mint-100 text-pastel-mint-700 hover:bg-pastel-mint-200 border-pastel-mint-200';
                  } else if (preset.color === 'powder') {
                    badgeStyle = 'bg-pastel-powder-100 text-pastel-powder-700 hover:bg-pastel-powder-200 border-pastel-powder-200';
                  }

                  return (
                    <button
                      key={preset.name}
                      onClick={() => onSelectPreset(preset.name, preset.eco)}
                      className={`text-xs font-mono font-medium px-3 py-1.5 rounded-xl border transition-all duration-150 flex items-center gap-1.5 shadow-soft-sm hover:scale-[1.02] ${badgeStyle}`}
                    >
                      <span>{preset.name}</span>
                      <span className="text-[10px] font-sans px-1.5 py-0.5 rounded-md bg-white/70 font-semibold">
                        {preset.badge}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Feature Highlights Pills */}
            <div className="grid grid-cols-3 gap-3 pt-3 max-w-lg border-t border-slate-200/60">
              <div className="text-center p-2 rounded-xl bg-white/70 border border-slate-200/50">
                <div className="text-base font-bold text-slate-800">npm & PyPI</div>
                <div className="text-[11px] text-slate-500">Dual Ecosystem</div>
              </div>
              <div className="text-center p-2 rounded-xl bg-white/70 border border-slate-200/50">
                <div className="text-base font-bold text-pastel-lavender-600">Zero-Day</div>
                <div className="text-[11px] text-slate-500">Heuristic Signals</div>
              </div>
              <div className="text-center p-2 rounded-xl bg-white/70 border border-slate-200/50">
                <div className="text-base font-bold text-pastel-mint-600">Real-Time</div>
                <div className="text-[11px] text-slate-500">Static AST Audit</div>
              </div>
            </div>
          </motion.div>

          {/* Right Visual Column (Interactive Security Shield Card) */}
          <motion.div 
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.6, delay: 0.1 }}
            className="lg:col-span-5 relative"
          >
            <div className="relative mx-auto max-w-md">
              {/* Outer Glow Halo */}
              <div className="absolute -inset-1.5 bg-gradient-to-r from-pastel-lavender-300 via-pastel-powder-300 to-pastel-mint-300 rounded-3xl blur-lg opacity-60"></div>

              {/* Main Visual Glass Card */}
              <div className="relative rounded-3xl bg-white/90 backdrop-blur-xl border border-white/80 p-5 shadow-soft-lg space-y-4">
                
                {/* Visual Header */}
                <div className="flex items-center justify-between pb-3 border-b border-slate-100">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-pastel-blush-400" />
                    <span className="w-2.5 h-2.5 rounded-full bg-pastel-powder-400" />
                    <span className="w-2.5 h-2.5 rounded-full bg-pastel-mint-400" />
                    <span className="text-[11px] font-mono text-slate-400 ml-2">sentinel-pipeline.py</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-slate-100 text-slate-600 font-medium">
                    SHA-256 Verified
                  </span>
                </div>

                {/* Central Visual: Package Sandboxing Diagram */}
                <div className="p-3.5 rounded-2xl bg-gradient-to-b from-pastel-lavender-50/70 to-pastel-powder-50/70 border border-slate-200/50">
                  <div className="flex items-center justify-between mb-2.5">
                    <span className="text-xs font-semibold text-slate-700 flex items-center gap-1.5">
                      <Cpu className="w-3.5 h-3.5 text-pastel-lavender-600" />
                      Dynamic Inspection Pipeline
                    </span>
                    <span className="text-[10px] font-mono text-pastel-mint-600 font-bold bg-pastel-mint-100 px-2 py-0.5 rounded-full">
                      SAFE SANDBOX
                    </span>
                  </div>

                  {/* Flow representation */}
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex items-center justify-between p-2 rounded-xl bg-white/90 border border-slate-200/70 shadow-soft-sm">
                      <span className="flex items-center gap-2 text-slate-700">
                        <Code2 className="w-3.5 h-3.5 text-pastel-powder-500" />
                        Lifecycle Hooks Audit
                      </span>
                      <span className="text-[10px] text-pastel-mint-600 font-semibold bg-pastel-mint-50 px-2 py-0.5 rounded">PASSED</span>
                    </div>

                    <div className="flex items-center justify-between p-2 rounded-xl bg-white/90 border border-slate-200/70 shadow-soft-sm">
                      <span className="flex items-center gap-2 text-slate-700">
                        <ShieldAlert className="w-3.5 h-3.5 text-pastel-blush-400" />
                        Entropy & Deobfuscation
                      </span>
                      <span className="text-[10px] text-pastel-lavender-600 font-semibold bg-pastel-lavender-50 px-2 py-0.5 rounded">H &lt; 7.0 (NORMAL)</span>
                    </div>

                    <div className="flex items-center justify-between p-2 rounded-xl bg-white/90 border border-slate-200/70 shadow-soft-sm">
                      <span className="flex items-center gap-2 text-slate-700">
                        <ShieldCheck className="w-3.5 h-3.5 text-pastel-mint-500" />
                        Maintainer Provenance
                      </span>
                      <span className="text-[10px] text-pastel-mint-600 font-semibold bg-pastel-mint-50 px-2 py-0.5 rounded">VERIFIED</span>
                    </div>
                  </div>
                </div>

                {/* Status bar */}
                <div className="flex items-center justify-between p-3 rounded-2xl bg-slate-900 text-white shadow-soft-md">
                  <div className="flex items-center gap-2.5">
                    <div className="w-8 h-8 rounded-xl bg-pastel-lavender-500/30 border border-pastel-lavender-400 flex items-center justify-center text-pastel-lavender-300 font-bold text-xs">
                      0-D
                    </div>
                    <div>
                      <div className="text-xs font-semibold text-slate-200">Zero-Day Defense Active</div>
                      <div className="text-[10px] text-slate-400">Pre-install gatekeeper</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-[11px] font-bold text-pastel-mint-400 bg-pastel-mint-950/60 border border-pastel-mint-800/80 px-2.5 py-1 rounded-lg">
                      SHIELD ACTIVE
                    </span>
                  </div>
                </div>

              </div>
            </div>
          </motion.div>

        </div>
      </div>
    </section>
  );
};

export default Hero;

