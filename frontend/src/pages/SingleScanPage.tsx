import React, { useState } from 'react';
import { Search, Zap, Layers, ArrowRight } from 'lucide-react';

export const SingleScanPage: React.FC = () => {
  const [ecosystem, setEcosystem] = useState<'NPM' | 'PYPI'>('NPM');
  const [packageName, setPackageName] = useState('');
  const [version, setVersion] = useState('');
  const [scanDepth, setScanDepth] = useState<'FAST' | 'DEEP'>('FAST');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitMessage, setSubmitMessage] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!packageName.trim() || !version.trim()) return;

    setIsSubmitting(true);
    setSubmitMessage(null);

    // Call Spring Boot REST API
    fetch('http://localhost:8080/api/v1/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ecosystem,
        name: packageName.trim(),
        version: version.trim(),
        depth: scanDepth
      })
    })
      .then(res => {
        if (!res.ok) throw new Error(`HTTP error ${res.status}`);
        return res.json();
      })
      .then(data => {
        setSubmitMessage(`Scan job successfully enqueued: ${data.jobId} (Status: ${data.status})`);
      })
      .catch(err => {
        setSubmitMessage(`Failed to reach backend orchestrator: ${err.message}. Ensure backend is running.`);
      })
      .finally(() => {
        setIsSubmitting(false);
      });
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white">Target Package Analysis</h2>
        <p className="text-sm text-slate-400 mt-1">
          Perform heuristic zero-day inspection on a specific package before installation.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="bg-sentinel-card border border-sentinel-border rounded-xl p-6 space-y-6">
        {/* Ecosystem Selection */}
        <div>
          <label className="block text-xs font-mono uppercase tracking-wider text-slate-300 mb-2">
            Target Ecosystem
          </label>
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => setEcosystem('NPM')}
              className={`flex items-center justify-center gap-2 py-3 px-4 rounded-lg font-medium text-sm border transition-all ${
                ecosystem === 'NPM'
                  ? 'bg-sentinel-accent/20 border-sentinel-cyan text-white shadow-sm shadow-cyan-950'
                  : 'bg-sentinel-surface border-sentinel-border text-slate-400 hover:text-white'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-red-400"></span>
              <span>npm (JavaScript / TypeScript)</span>
            </button>
            <button
              type="button"
              onClick={() => setEcosystem('PYPI')}
              className={`flex items-center justify-center gap-2 py-3 px-4 rounded-lg font-medium text-sm border transition-all ${
                ecosystem === 'PYPI'
                  ? 'bg-sentinel-accent/20 border-sentinel-cyan text-white shadow-sm shadow-cyan-950'
                  : 'bg-sentinel-surface border-sentinel-border text-slate-400 hover:text-white'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-blue-400"></span>
              <span>PyPI (Python Ecosystem)</span>
            </button>
          </div>
        </div>

        {/* Package Coordinates */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="md:col-span-2">
            <label className="block text-xs font-mono uppercase tracking-wider text-slate-300 mb-2">
              Package Name
            </label>
            <input
              type="text"
              value={packageName}
              onChange={(e) => setPackageName(e.target.value)}
              placeholder={ecosystem === 'NPM' ? 'e.g. chalk or @scope/pkg' : 'e.g. requests'}
              required
              className="w-full bg-sentinel-surface border border-sentinel-border rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-sentinel-cyan transition-colors"
            />
          </div>
          <div>
            <label className="block text-xs font-mono uppercase tracking-wider text-slate-300 mb-2">
              Version
            </label>
            <input
              type="text"
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              placeholder="e.g. 1.0.0"
              required
              className="w-full bg-sentinel-surface border border-sentinel-border rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-sentinel-cyan transition-colors font-mono"
            />
          </div>
        </div>

        {/* Scan Depth Selector */}
        <div>
          <label className="block text-xs font-mono uppercase tracking-wider text-slate-300 mb-2">
            Scan Depth Mode
          </label>
          <div className="grid grid-cols-2 gap-3">
            <div
              onClick={() => setScanDepth('FAST')}
              className={`p-4 rounded-lg border cursor-pointer transition-all ${
                scanDepth === 'FAST'
                  ? 'bg-sentinel-accent/10 border-sentinel-cyan text-white'
                  : 'bg-sentinel-surface border-sentinel-border text-slate-400 hover:border-slate-600'
              }`}
            >
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-amber-400" />
                <span className="font-semibold text-sm">Fast-Path Static Scan</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Metadata scrutiny, typosquatting proximity, AST analysis, and Shannon entropy estimation.
              </p>
            </div>

            <div
              onClick={() => setScanDepth('DEEP')}
              className={`p-4 rounded-lg border cursor-pointer transition-all ${
                scanDepth === 'DEEP'
                  ? 'bg-sentinel-accent/10 border-sentinel-cyan text-white'
                  : 'bg-sentinel-surface border-sentinel-border text-slate-400 hover:border-slate-600'
              }`}
            >
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-sentinel-cyan" />
                <span className="font-semibold text-sm">Deep Dynamic Sandbox</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Includes Fast-Path plus isolated Docker canary installation with egress sinkhole logging.
              </p>
            </div>
          </div>
        </div>

        {/* Submit Button */}
        <div className="pt-2">
          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full py-3 bg-sentinel-accent hover:bg-sentinel-accent-hover disabled:opacity-50 text-slate-950 font-bold rounded-lg text-sm transition-colors flex items-center justify-center gap-2 shadow-sm shadow-cyan-500/20"
          >
            {isSubmitting ? (
              <span>Enqueueing Scan Request...</span>
            ) : (
              <>
                <Search className="w-4 h-4" />
                <span>Submit for Inspection</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>

        {submitMessage && (
          <div className="p-4 rounded-lg bg-sentinel-surface border border-sentinel-border text-xs font-mono text-slate-200">
            {submitMessage}
          </div>
        )}
      </form>
    </div>
  );
};
