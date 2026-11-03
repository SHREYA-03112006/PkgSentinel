import React from 'react';
import { motion } from 'framer-motion';
import { 
  ShieldCheck, AlertOctagon, Terminal, UserCheck, Eye, GitCommit, 
  FileText, Database, Server, CheckCircle2, ArrowRight 
} from 'lucide-react';

export default function About() {
  const pillars = [
    {
      icon: Terminal,
      title: '1. Suspicious Installation Scripts',
      desc: 'Intercepts preinstall, postinstall, and setup.py hooks that attempt child_process execution, raw socket opening, or environment variable harvesting.',
      color: 'blush'
    },
    {
      icon: UserCheck,
      title: '2. Unexpected Maintainer Changes',
      desc: 'Detects supply-chain account takeovers when popular or dormant packages suddenly transfer maintainer keys or switch to disposable email domains.',
      color: 'lavender'
    },
    {
      icon: Eye,
      title: '3. Code Obfuscation & Entropy',
      desc: 'Calculates Shannon entropy across files to detect packed, hex-encoded, or encrypted payloads designed to bypass static regex checkers.',
      color: 'powder'
    },
    {
      icon: GitCommit,
      title: '4. Unusual Version Changes',
      desc: 'Flags suspicious version leaps (e.g. 1.0.4 to 9.0.0), irregular semver releases within minutes, and unannounced major breaking changes.',
      color: 'mint'
    },
    {
      icon: FileText,
      title: '5. Suspicious Package Metadata',
      desc: 'Identifies typosquatting candidates targeting top libraries, 404 project repositories, and fabricated developer profile information.',
      color: 'lavender'
    }
  ];

  const apis = [
    { method: 'POST', endpoint: '/api/scan', desc: 'Submit a package name, ecosystem, and version for deep heuristic scanning.' },
    { method: 'GET', endpoint: '/api/scans', desc: 'Retrieve the historical log of scanned packages and risk classifications.' },
    { method: 'GET', endpoint: '/api/scans/{id}', desc: 'Retrieve full telemetry, findings, and metadata for a specific scan ID.' }
  ];

  return (
    <section id="about" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mb-20 space-y-12">
      
      {/* Intro Card */}
      <div className="rounded-3xl glass-card p-6 sm:p-10 shadow-soft-lg border border-white/90">
        <div className="max-w-3xl space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-pastel-lavender-100 text-pastel-lavender-700 text-xs font-semibold">
            <ShieldCheck className="w-4 h-4" />
            <span>The Zero-Day Paradigm</span>
          </div>

          <h2 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
            Why Traditional Vulnerability Scanners Fail
          </h2>

          <p className="text-slate-600 text-sm sm:text-base leading-relaxed">
            Conventional tools rely almost exclusively on <strong className="text-slate-800">CVE databases</strong>. 
            By definition, a CVE is only assigned <span className="underline decoration-pastel-blush-400">after</span> malware has already 
            infiltrated production machines and been publicly reported.
          </p>

          <p className="text-slate-600 text-sm sm:text-base leading-relaxed">
            <strong className="text-slate-800">PkgSentinel</strong> flips the model. By inspecting package behavior at the moment of intake, 
            it detects anomalies in package lifecycle scripts, publisher activity, and code entropy—stopping malicious packages before a CVE is ever written.
          </p>
        </div>
      </div>

      {/* 5 Pillars Grid */}
      <div className="space-y-6">
        <div>
          <h3 className="text-xl font-bold text-slate-900 tracking-tight">
            5 Core Heuristic Detection Pillars
          </h3>
          <p className="text-xs text-slate-500 mt-1">
            How PkgSentinel spots malicious intent without waiting for public vulnerability databases.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {pillars.map((pillar, idx) => {
            const Icon = pillar.icon;
            let cardBg = 'bg-pastel-lavender-50/70 border-pastel-lavender-200 text-pastel-lavender-700';
            if (pillar.color === 'blush') {
              cardBg = 'bg-pastel-blush-50/70 border-pastel-blush-200 text-pastel-blush-600';
            } else if (pillar.color === 'powder') {
              cardBg = 'bg-pastel-powder-50/70 border-pastel-powder-200 text-pastel-powder-700';
            } else if (pillar.color === 'mint') {
              cardBg = 'bg-pastel-mint-50/70 border-pastel-mint-200 text-pastel-mint-700';
            }

            return (
              <motion.div
                key={idx}
                whileHover={{ y: -3 }}
                className="p-6 rounded-3xl bg-white border border-slate-200/80 shadow-soft-sm space-y-3"
              >
                <div className={`w-10 h-10 rounded-2xl flex items-center justify-center border ${cardBg}`}>
                  <Icon className="w-5 h-5" />
                </div>
                <h4 className="text-base font-bold text-slate-800">
                  {pillar.title}
                </h4>
                <p className="text-xs text-slate-600 leading-relaxed">
                  {pillar.desc}
                </p>
              </motion.div>
            );
          })}
        </div>
      </div>

      {/* Backend Integration Readiness Section */}
      <div className="rounded-3xl glass-card p-6 sm:p-8 shadow-soft-lg border border-white/90 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-200/60">
          <div>
            <div className="flex items-center gap-2">
              <Server className="w-5 h-5 text-pastel-lavender-600" />
              <h3 className="text-lg font-bold text-slate-900 tracking-tight">
                Spring Boot REST API Integration Contract
              </h3>
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Separated architecture: frontend connects via <code className="font-mono text-pastel-lavender-600">src/api/scanService.js</code> with zero UI refactoring required.
            </p>
          </div>

          <span className="text-xs font-semibold px-3 py-1 rounded-full bg-pastel-mint-100 text-pastel-mint-700 border border-pastel-mint-200 self-start sm:self-auto">
            REST Contract Ready
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {apis.map((api, idx) => (
            <div key={idx} className="p-4 rounded-2xl bg-slate-50 border border-slate-200 space-y-2">
              <div className="flex items-center gap-2">
                <span className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded ${
                  api.method === 'POST' ? 'bg-pastel-lavender-500 text-white' : 'bg-pastel-mint-600 text-white'
                }`}>
                  {api.method}
                </span>
                <span className="text-xs font-mono font-bold text-slate-800">{api.endpoint}</span>
              </div>
              <p className="text-xs text-slate-600">{api.desc}</p>
            </div>
          ))}
        </div>

        <div className="p-4 rounded-2xl bg-pastel-warm-100 border border-slate-200/80 text-xs text-slate-600 flex items-center justify-between">
          <span>When your Spring Boot application is ready, switch <code>USE_MOCK_DATA = false</code> in <code>src/api/scanService.js</code>.</span>
          <span className="font-mono text-[11px] font-semibold text-slate-800">Target: http://localhost:8080</span>
        </div>
      </div>

    </section>
  );
}

