import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Package, Search, AlertCircle, Activity, ArrowRight } from 'lucide-react';
import { scanPackage } from '../services/scanService';
import { UIScanResult } from '../types/report';

interface ScannerProps {
  onScanComplete: (result: UIScanResult) => void;
  selectedPreset: { name: string; ecosystem?: string } | null;
}

export const Scanner: React.FC<ScannerProps> = ({ onScanComplete, selectedPreset }) => {
  const [packageName, setPackageName] = useState('');
  const [ecosystem, setEcosystem] = useState<'npm' | 'pypi'>('npm');
  const [version, setVersion] = useState('');
  const [loading, setLoading] = useState(false);
  const [progressStage, setProgressStage] = useState('Submitting scan job to orchestrator...');
  const [progressStatus, setProgressStatus] = useState<'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED'>('QUEUED');
  const [error, setError] = useState('');

  // Handle selected preset from Hero
  useEffect(() => {
    if (selectedPreset) {
      setPackageName(selectedPreset.name);
      if (selectedPreset.ecosystem) {
        setEcosystem(selectedPreset.ecosystem.toLowerCase() === 'pypi' ? 'pypi' : 'npm');
      }
      setVersion('');
      setError('');
    }
  }, [selectedPreset]);

  // Handle Form Submission
  const handleScan = async (e?: React.FormEvent) => {
    e?.preventDefault();
    const trimmed = packageName.trim();
    if (!trimmed) {
      setError('Please enter a package name to inspect (e.g. "chalk", "requests", "express").');
      return;
    }

    setError('');
    setLoading(true);
    setProgressStage('Submitting scan request to orchestrator outbox...');
    setProgressStatus('QUEUED');

    try {
      const result = await scanPackage({
        name: trimmed,
        ecosystem,
        version: version.trim() || 'latest',
        onProgress: ({ stage, status }) => {
          setProgressStage(stage);
          setProgressStatus(status as 'QUEUED' | 'PROCESSING' | 'COMPLETED');
        }
      });
      setLoading(false);
      onScanComplete(result);
    } catch (err: unknown) {
      setLoading(false);
      const msg = err instanceof Error ? err.message : 'An error occurred during package analysis.';
      setError(msg);
    }
  };

  return (
    <section id="scanner" className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 mb-12 select-none">
      <motion.div 
        initial={{ opacity: 0, y: 15 }}
        animate={{ opacity: 1, y: 0 }}
        className="rounded-3xl glass-card p-6 sm:p-8 shadow-soft-lg border border-white/90 relative overflow-hidden"
      >
        {/* Top Accent Ribbon */}
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
            Real Asynchronous Engine
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
              <div className="flex bg-slate-100/90 p-1 rounded-xl border border-slate-200">
                <button
                  type="button"
                  disabled={loading}
                  onClick={() => setEcosystem('npm')}
                  className={`flex-1 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                    ecosystem === 'npm'
                      ? 'bg-white text-pastel-lavender-700 shadow-soft-sm'
                      : 'text-slate-500 hover:text-slate-800'
                  }`}
                >
                  npm
                </button>
                <button
                  type="button"
                  disabled={loading}
                  onClick={() => setEcosystem('pypi')}
                  className={`flex-1 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                    ecosystem === 'pypi'
                      ? 'bg-white text-pastel-powder-700 shadow-soft-sm'
                      : 'text-slate-500 hover:text-slate-800'
                  }`}
                >
                  PyPI
                </button>
              </div>
            </div>

            {/* Package Name Input */}
            <div className="md:col-span-6">
              <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wider mb-1.5">
                Package Coordinates
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                  <Search className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  placeholder={ecosystem === 'npm' ? 'e.g. chalk, express, @scope/pkg' : 'e.g. requests, urllib3, flask'}
                  value={packageName}
                  onChange={(e) => setPackageName(e.target.value)}
                  disabled={loading}
                  className="w-full h-11 pl-9 pr-3 rounded-xl bg-white border border-slate-200 text-xs font-mono text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-pastel-lavender-400 shadow-soft-sm transition-all"
                />
              </div>
            </div>

            {/* Version Input */}
            <div className="md:col-span-3">
              <label className="block text-xs font-semibold text-slate-600 uppercase tracking-wider mb-1.5">
                Version <span className="text-slate-400 font-normal">(optional)</span>
              </label>
              <input
                type="text"
                placeholder="latest"
                value={version}
                onChange={(e) => setVersion(e.target.value)}
                disabled={loading}
                className="w-full h-11 px-3 rounded-xl bg-white border border-slate-200 text-xs font-mono text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-pastel-lavender-400 shadow-soft-sm transition-all"
              />
            </div>

          </div>

          {/* Error Banner */}
          <AnimatePresence>
            {error && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="p-3 rounded-xl bg-pastel-blush-50 border border-pastel-blush-200 text-pastel-blush-600 text-xs flex items-center gap-2 font-medium"
              >
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Submit Action */}
          <div className="pt-2">
            <button
              type="submit"
              disabled={loading}
              className="w-full h-12 rounded-xl bg-gradient-to-r from-pastel-lavender-500 to-pastel-powder-500 hover:from-pastel-lavender-600 hover:to-pastel-powder-600 text-white font-semibold text-sm shadow-soft-md transition-all flex items-center justify-center gap-2 disabled:opacity-50 cursor-pointer"
            >
              {loading ? (
                <>
                  <Activity className="w-4 h-4 animate-spin text-white" />
                  <span>Inspecting Package Heuristics...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Analyze Zero-Day Vulnerabilities</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </form>

        {/* Live Progress Stepper (While loading) */}
        {loading && (
          <div className="mt-5 p-4 rounded-2xl bg-white/90 border border-slate-200/80 shadow-soft-sm space-y-3">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-600 font-semibold flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 animate-spin text-pastel-lavender-600" />
                {progressStage}
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-pastel-lavender-100 text-pastel-lavender-700">
                {progressStatus}
              </span>
            </div>

            <div className="grid grid-cols-3 gap-2 text-[11px] font-mono text-center">
              <div className={`p-2 rounded-lg border transition-all ${
                progressStatus === 'QUEUED'
                  ? 'bg-pastel-lavender-100 border-pastel-lavender-300 text-pastel-lavender-700 font-bold'
                  : 'bg-slate-50 border-slate-200 text-slate-400'
              }`}>
                1. Redis Outbox
              </div>
              <div className={`p-2 rounded-lg border transition-all ${
                progressStatus === 'PROCESSING'
                  ? 'bg-pastel-powder-100 border-pastel-powder-300 text-pastel-powder-700 font-bold'
                  : 'bg-slate-50 border-slate-200 text-slate-400'
              }`}>
                2. AST Heuristics
              </div>
              <div className={`p-2 rounded-lg border transition-all ${
                progressStatus === 'COMPLETED'
                  ? 'bg-pastel-mint-100 border-pastel-mint-300 text-pastel-mint-700 font-bold'
                  : 'bg-slate-50 border-slate-200 text-slate-400'
              }`}>
                3. Report Finalized
              </div>
            </div>
          </div>
        )}
      </motion.div>
    </section>
  );
};

export default Scanner;
