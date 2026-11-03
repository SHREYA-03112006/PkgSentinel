import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, CheckCircle2, XCircle, 
  Terminal, ExternalLink, Copy, Check, Info, FileCode, Users, Hash, 
  Network, Sparkles, ArrowUpRight 
} from 'lucide-react';

export default function ScanResult({ result, onScanAnother }) {
  const [copied, setCopied] = useState(false);

  if (!result) return null;

  const {
    name,
    ecosystem,
    version,
    riskScore,
    classification,
    decision,
    summary,
    findings = [],
    metadata = {},
    timestamp
  } = result;

  // Determine pastel styling based on decision
  const isBlock = decision === 'BLOCK';
  const isWarn = decision === 'WARN';
  const isAllow = decision === 'ALLOW';

  let theme = {
    badgeBg: 'bg-pastel-mint-100',
    badgeText: 'text-pastel-mint-700',
    badgeBorder: 'border-pastel-mint-300',
    gaugeColor: '#22C55E',
    gaugeBg: '#DCFCE7',
    decisionBg: 'bg-pastel-mint-50',
    decisionBorder: 'border-pastel-mint-200',
    decisionText: 'text-pastel-mint-700',
    icon: ShieldCheck,
    title: 'Safe to Install'
  };

  if (isBlock) {
    theme = {
      badgeBg: 'bg-pastel-blush-100',
      badgeText: 'text-pastel-blush-500',
      badgeBorder: 'border-pastel-blush-300',
      gaugeColor: '#F43F5E',
      gaugeBg: '#FFE4E6',
      decisionBg: 'bg-pastel-blush-50',
      decisionBorder: 'border-pastel-blush-200',
      decisionText: 'text-pastel-blush-500',
      icon: XCircle,
      title: 'Dangerous / Malicious Package'
    };
  } else if (isWarn) {
    theme = {
      badgeBg: 'bg-pastel-powder-100',
      badgeText: 'text-pastel-powder-600',
      badgeBorder: 'border-pastel-powder-300',
      gaugeColor: '#0EA5E9',
      gaugeBg: '#E0F2FE',
      decisionBg: 'bg-pastel-powder-50',
      decisionBorder: 'border-pastel-powder-200',
      decisionText: 'text-pastel-powder-600',
      icon: AlertTriangle,
      title: 'Suspicious Anomalies Detected'
    };
  }

  const DecisionIcon = theme.icon;

  const handleCopy = () => {
    const text = `PkgSentinel Security Audit Report\nPackage: ${name}@${version} (${ecosystem})\nRisk Score: ${riskScore}/100 (${classification})\nDecision: ${decision}\nSummary: ${summary}\nFindings: ${findings.length}`;
    navigator.clipboard?.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // SVG Gauge calculations
  const radius = 48;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (riskScore / 100) * circumference;

  return (
    <motion.section 
      id="scan-result"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 mb-14"
    >
      <div className="rounded-3xl glass-card p-6 sm:p-8 shadow-soft-lg border border-white/90 space-y-7 relative overflow-hidden">
        
        {/* Top Header Row */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-200/60">
          <div className="space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-semibold uppercase px-2.5 py-0.5 rounded-lg bg-slate-100 text-slate-600 border border-slate-200">
                {ecosystem.toUpperCase()}
              </span>
              <h3 className="text-2xl font-bold font-mono text-slate-900 tracking-tight">
                {name}
              </h3>
              <span className="text-sm font-mono text-slate-500">
                @{version}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Scanned on {new Date(timestamp).toLocaleString()} • ID: {result.id}
            </p>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={handleCopy}
              className="text-xs font-semibold px-3 py-2 rounded-xl bg-white border border-slate-200 text-slate-700 hover:bg-slate-50 flex items-center gap-1.5 shadow-soft-sm transition-all"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-pastel-mint-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
              <span>{copied ? 'Copied' : 'Copy Report'}</span>
            </button>
            <button
              onClick={onScanAnother}
              className="text-xs font-semibold px-3.5 py-2 rounded-xl bg-pastel-lavender-500 hover:bg-pastel-lavender-600 text-white shadow-soft-sm transition-all"
            >
              Scan Another
            </button>
          </div>
        </div>

        {/* Hero Score & Decision Banner */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
          
          {/* Visual Circular Risk Gauge */}
          <div className="md:col-span-5 flex flex-col items-center justify-center p-6 rounded-2xl bg-gradient-to-b from-white to-slate-50/80 border border-slate-200/60 shadow-soft-sm">
            <div className="relative w-36 h-36 flex items-center justify-center">
              {/* Circular SVG Gauge */}
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 120 120">
                <circle
                  cx="60"
                  cy="60"
                  r={radius}
                  stroke={theme.gaugeBg}
                  strokeWidth="10"
                  fill="transparent"
                />
                <motion.circle
                  cx="60"
                  cy="60"
                  r={radius}
                  stroke={theme.gaugeColor}
                  strokeWidth="10"
                  strokeDasharray={circumference}
                  initial={{ strokeDashoffset: circumference }}
                  animate={{ strokeDashoffset }}
                  transition={{ duration: 1.2, ease: 'easeOut' }}
                  strokeLinecap="round"
                  fill="transparent"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="text-3xl font-extrabold font-mono text-slate-800">
                  {riskScore}
                </span>
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                  Risk Score
                </span>
              </div>
            </div>

            <div className="mt-3 text-center">
              <span className={`inline-block px-3 py-1 rounded-full text-xs font-bold border ${theme.badgeBg} ${theme.badgeText} ${theme.badgeBorder}`}>
                {classification} RISK ({riskScore}/100)
              </span>
            </div>
          </div>

          {/* Decision Summary Card */}
          <div className="md:col-span-7 space-y-4">
            <div className={`p-5 rounded-2xl border ${theme.decisionBg} ${theme.decisionBorder} space-y-2.5`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 font-bold text-base">
                  <DecisionIcon className={`w-5 h-5 ${theme.decisionText}`} />
                  <span className={theme.decisionText}>Security Decision: {decision}</span>
                </div>
                <span className={`text-[11px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-md bg-white border ${theme.decisionBorder} ${theme.decisionText}`}>
                  {decision === 'ALLOW' ? 'Verified Safe' : decision === 'WARN' ? 'Caution Advised' : 'Blocklist Triggered'}
                </span>
              </div>
              <p className="text-sm text-slate-700 leading-relaxed font-medium">
                {summary}
              </p>
            </div>

            {/* Quick Metadata Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-xs">
              <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200/60">
                <span className="text-slate-400 block text-[10px] uppercase font-semibold">Publisher</span>
                <span className="font-mono font-medium text-slate-800 truncate block">
                  {metadata.publisher || 'Unknown'}
                </span>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200/60">
                <span className="text-slate-400 block text-[10px] uppercase font-semibold">Shannon Entropy</span>
                <span className="font-mono font-medium text-slate-800">
                  {metadata.entropyScore ? `${metadata.entropyScore} bits` : 'N/A'}
                </span>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200/60 col-span-2 sm:col-span-1">
                <span className="text-slate-400 block text-[10px] uppercase font-semibold">Install Hooks</span>
                <span className={`font-mono font-bold ${metadata.installScriptDetected ? 'text-pastel-blush-500' : 'text-pastel-mint-600'}`}>
                  {metadata.installScriptDetected ? 'Active (Pre/Post)' : 'None (Safe)'}
                </span>
              </div>
            </div>
          </div>

        </div>

        {/* Suspicious Findings Section */}
        <div className="pt-2">
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-base font-bold text-slate-800 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-pastel-lavender-600" />
              Detailed Heuristic Findings ({findings.length})
            </h4>
            {findings.length > 0 && (
              <span className="text-xs text-pastel-blush-500 font-medium">
                {findings.length} zero-day indicator{findings.length > 1 ? 's' : ''} flagged
              </span>
            )}
          </div>

          {findings.length === 0 ? (
            <div className="p-6 rounded-2xl bg-pastel-mint-50/50 border border-pastel-mint-200 text-center space-y-2">
              <CheckCircle2 className="w-8 h-8 text-pastel-mint-500 mx-auto" />
              <h5 className="text-sm font-semibold text-slate-800">No Malicious Indicators Detected</h5>
              <p className="text-xs text-slate-600 max-w-md mx-auto">
                No suspicious postinstall scripts, obfuscated payloads, or rogue maintainer patterns were found in package metadata or code tree.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {findings.map((item, idx) => {
                let badgeColor = 'bg-pastel-powder-100 text-pastel-powder-700 border-pastel-powder-200';
                if (item.severity === 'CRITICAL') {
                  badgeColor = 'bg-pastel-blush-100 text-pastel-blush-600 border-pastel-blush-200';
                } else if (item.severity === 'HIGH') {
                  badgeColor = 'bg-pastel-blush-50 text-pastel-blush-500 border-pastel-blush-200';
                }

                return (
                  <motion.div
                    key={idx}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.1 }}
                    className="p-4 rounded-2xl bg-white border border-slate-200/80 shadow-soft-sm space-y-2"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5">
                      <div className="flex items-center gap-2">
                        <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${badgeColor}`}>
                          {item.severity}
                        </span>
                        <span className="text-xs font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                          {item.category}
                        </span>
                      </div>
                      <span className="text-[11px] font-mono text-slate-400">Rule ID: IND-{100 + idx}</span>
                    </div>

                    <h5 className="text-sm font-bold text-slate-900">
                      {item.title}
                    </h5>

                    <p className="text-xs text-slate-600 leading-relaxed font-mono bg-slate-50 p-2.5 rounded-xl border border-slate-200/60">
                      {item.detail}
                    </p>

                    <div className="flex items-center gap-1.5 text-xs text-slate-500 pt-1">
                      <strong className="text-slate-700 font-semibold">Action:</strong>
                      <span>{item.recommendation}</span>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          )}
        </div>

        {/* Demo Simulated Banner */}
        <div className="p-3.5 rounded-2xl bg-pastel-lavender-50 border border-pastel-lavender-200 flex items-center justify-between gap-3 text-xs text-pastel-lavender-800">
          <div className="flex items-center gap-2">
            <Info className="w-4 h-4 text-pastel-lavender-600 shrink-0" />
            <span>
              <strong>Simulated Demo Environment:</strong> Findings represent simulated zero-day behavioral analysis designed to model Spring Boot API responses.
            </span>
          </div>
          <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-white text-pastel-lavender-700 border border-pastel-lavender-200 shrink-0 hidden sm:inline">
            POST /api/scan
          </span>
        </div>

      </div>
    </motion.section>
  );
}

