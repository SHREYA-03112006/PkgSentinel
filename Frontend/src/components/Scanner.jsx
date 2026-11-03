import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Package, Layers, Sparkles, AlertCircle, RefreshCw, CheckCircle2, Shield, ArrowRight } from 'lucide-react';
import { scanPackage } from '../api/scanService';

const SCAN_STEPS = [
  'Resolving package manifest & dependency graph...',
  'Decompressing archive & inspecting lifecycle scripts...',
  'Scanning AST for obfuscation & high Shannon entropy...',
  'Evaluating publisher provenance & repository anomalies...',
  'Calculating Zero-Day Risk Index (0-100)...'
];

export default function Scanner({ onScanComplete, selectedPreset, isExternalLoading }) {
  const [packageName, setPackageName] = useState('');
  const [ecosystem, setEcosystem] = useState('npm');
  const [version, setVersion] = useState('latest');
  const [loading, setLoading] = useState(false);
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [error, setError] = useState('');

  // When a preset is selected from Hero or elsewhere
  useEffect(() => {
    if (selectedPreset) {
      setPackageName(selectedPreset.name);
      if (selectedPreset.ecosystem) setEcosystem(selectedPreset.ecosystem);
      setVersion('latest');
      setError('');
    }
  }, [selectedPreset]);

  // Handle Scan Submit
  const handleScan = async (e) => {
    e?.preventDefault();
    const trimmed = packageName.trim();
    if (!trimmed) {
      setError('Please enter a package name to inspect (e.g. "color-setup-v2", "requests", "express").');
      return;
    }

    setError('');
    setLoading(true);
    setCurrentStepIndex(0);

    // Step cycle interval for realistic UX
    const interval = setInterval(() => {
      setCurrentStepIndex((prev) => (prev < SCAN_STEPS.length - 1 ? prev + 1 : prev));
    }, 350);

    try {
      const result = await scanPackage({
        name: trimmed,
        ecosystem,
        version: version.trim() || 'latest'
      });
      clearInterval(interval);
      setLoading(false);
      onScanComplete(result);
    } catch (err) {
      clearInterval(interval);
      setLoading(false);
      setError('An error occurred during scanning. Please try again.');
    }
  };

  return (
    <section id="scanner" className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 mb-12">
      {/* Scanner Card */}
      <motion.div 
        initial={{ opacity: 0, y: 15 }}
        animate={{ opacity: 1, y: 0 }}
        className="rounded-3xl glass-card p-6 sm:p-8 shadow-soft-lg border border-white/90 relative overflow-hidden"
      >
        {/* Subtle Top Accent Ribbon */}
        <div className="absolute top-0 left-0 right-0 h-1.5 bg-gradient-to-r from-pastel-lavender-400 via-pastel-powder-400 to-pastel-mint-400" />

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-6">
          <div>
            <h2 className="text-xl sm:text-2xl font-bold text-slate-800 tracking-tight flex items-center gap-2">
              <Package className="w-6 h-6 text-pastel-lavender-600" />
              Package Vulnerability Scanner
            </h2>
            <p className="text-sm text-slate-500 mt-1">
              Deep zero-day heuristic audit for npm and PyPI software dependencies.
            </p>
          </div>
          <span className="self-start sm:self-auto text-xs font-semibold px-3 py-1 rounded-full bg-pastel-warm-100 text-slate-600 border border-slate-200">
            v2.4 Heuristic Engine
          </span>
        </div>

        {/* Scan Input Form */}
        <form onSubmit={handleScan} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-12 gap-3.5">
            
            {/* Ecosystem Selector */}
            <div className="md:col-span-3">
              <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wider mb-1.5">
                Ecosystem
              </label>
              <div className="relative">
                <select
                  value={ecosystem}
                  onChange={(e) => setEcosystem(e.target.value)}
                  disabled={loading}
                  className="w-full h-12 pl-3.5 pr-8 rounded-2xl bg-white border border-slate-200 text-sm font-medium text-slate-700 focus:outline-none focus:ring-2 focus:ring-pastel-lavender-400 focus:border-transparent transition-all shadow-soft-sm appearance-none cursor-pointer"
                >
                  <option value="npm">npm (Node.js)</option>
                  <option value="pypi">PyPI (Python)</option>
                </select>
                <div className="absolute inset-y-0 right-0 flex items-center px-3 pointer-events-none text-slate-400">
                  <Layers className="w-4 h-4" />
                </div>
              </div>
            </div>

            {/* Package Name Input */}
            <div className="md:col-span-6">
              <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wider mb-1.5">
                Package Name <span className="text-pastel-blush-500">*</span>
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  <Search className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  value={packageName}
                  onChange={(e) => {
                    setPackageName(e.target.value);
                    if (error) setError('');
                  }}
                  disabled={loading}
                  placeholder={ecosystem === 'npm' ? 'e.g. color-setup-v2, express' : 'e.g. py-cryptoutil-plus, requests'}
                  className="w-full h-12 pl-10 pr-4 rounded-2xl bg-white border border-slate-200 text-sm font-mono text-slate-800 placeholder:text-slate-400 placeholder:font-sans focus:outline-none focus:ring-2 focus:ring-pastel-lavender-400 focus:border-transparent transition-all shadow-soft-sm"
                />
              </div>
            </div>

            {/* Version Input */}
            <div className="md:col-span-3">
              <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wider mb-1.5">
                Target Version
              </label>
              <input
                type="text"
                value={version}
                onChange={(e) => setVersion(e.target.value)}
                disabled={loading}
                placeholder="latest"
                className="w-full h-12 px-3.5 rounded-2xl bg-white border border-slate-200 text-sm font-mono text-slate-700 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-pastel-lavender-400 focus:border-transparent transition-all shadow-soft-sm"
              />
            </div>
          </div>

          {/* Validation Error Message */}
          {error && (
            <div className="flex items-center gap-2 p-3 rounded-xl bg-pastel-blush-50 border border-pastel-blush-200 text-pastel-blush-500 text-xs font-medium">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Action Row */}
          <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3">
            <div className="text-xs text-slate-500 flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-pastel-lavender-500" />
              <span>Zero-day detection applies static AST & behavioral heuristic rules</span>
            </div>

            <button
              type="submit"
              disabled={loading}
              className={`w-full sm:w-auto px-8 h-12 rounded-2xl font-semibold text-sm transition-all duration-200 flex items-center justify-center gap-2 shadow-soft-md ${
                loading
                  ? 'bg-pastel-lavender-300 text-white cursor-not-allowed'
                  : 'bg-pastel-lavender-500 hover:bg-pastel-lavender-600 active:scale-[0.98] text-white hover:shadow-glow-lavender'
              }`}
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-white" />
                  <span>Scanning Package...</span>
                </>
              ) : (
                <>
                  <Shield className="w-4 h-4" />
                  <span>Scan Package</span>
                  <ArrowRight className="w-4 h-4 ml-0.5" />
                </>
              )}
            </button>
          </div>
        </form>

        {/* Loading Progress State */}
        <AnimatePresence>
          {loading && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-6 pt-6 border-t border-slate-100"
            >
              <div className="p-4 rounded-2xl bg-gradient-to-r from-pastel-lavender-50 via-pastel-powder-50 to-pastel-mint-50 border border-slate-200/60 space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-slate-700 flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-pastel-lavender-500 animate-ping" />
                    Deep Zero-Day Inspection in Progress
                  </span>
                  <span className="font-mono text-pastel-lavender-600 font-bold">
                    Step {currentStepIndex + 1} of {SCAN_STEPS.length}
                  </span>
                </div>

                {/* Animated Progress Bar */}
                <div className="w-full bg-white rounded-full h-2 overflow-hidden shadow-inner border border-slate-200/50">
                  <motion.div
                    className="h-full bg-gradient-to-r from-pastel-lavender-500 via-pastel-powder-500 to-pastel-mint-500"
                    initial={{ width: '10%' }}
                    animate={{ width: `${((currentStepIndex + 1) / SCAN_STEPS.length) * 100}%` }}
                    transition={{ duration: 0.3 }}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <p className="text-xs font-mono text-slate-600 truncate">
                    &gt; {SCAN_STEPS[currentStepIndex]}
                  </p>
                  <span className="text-[11px] text-slate-400 font-sans">Simulating Sandbox AST</span>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

      </motion.div>
    </section>
  );
}
