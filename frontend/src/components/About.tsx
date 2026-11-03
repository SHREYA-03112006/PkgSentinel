import React from 'react';
import { motion } from 'framer-motion';
import { 
  ShieldCheck, Terminal, UserCheck, Eye, GitCommit, 
  FileText, Server, Lock
} from 'lucide-react';

export const About: React.FC = () => {
  const pillars = [
    {
      icon: Terminal,
      title: '1. Suspicious Lifecycle Scripts',
      desc: 'Parses npm package.json (preinstall, postinstall) and PyPI distributions to intercept child_process executions, raw socket opens, and secret environment harvesting before package installation.',
      color: 'blush'
    },
    {
      icon: UserCheck,
      title: '2. Publisher & Identity Forensics',
      desc: 'Evaluates maintainer metadata patterns, detecting newly registered disposable email domains, sudden ownership reassignments, and repository URL mismatches.',
      color: 'lavender'
    },
    {
      icon: Eye,
      title: '3. Shannon Entropy & Deobfuscation',
      desc: 'Computes character and byte-level Shannon entropy across package files to unmask XOR-packed, hex-encoded, and layered base64 payloads designed to evade static scanners.',
      color: 'powder'
    },
    {
      icon: GitCommit,
      title: '4. Typosquatting & Homoglyphs',
      desc: 'Applies length-bounded Damerau-Levenshtein distance, Unicode homoglyph matching (Cyrillic/Latin), and PEP 503 PyPI canonicalization against popular ecosystems.',
      color: 'mint'
    },
    {
      icon: FileText,
      title: '5. Explainable Risk Scoring Engine',
      desc: 'Normalizes severity vectors through asymptotic scoring, critical verdict overrides, multi-vector high rules, and clear attribution factors—without black-box opacity.',
      color: 'lavender'
    },
    {
      icon: Lock,
      title: '6. Safe Ingestion & Containment',
      desc: 'Guards against TarSlip, ZipSlip directory traversals, decompression bombs, and SSRF private IP requests while strictly masking permissions and forbidding code execution.',
      color: 'powder'
    }
  ];

  const apis = [
    { method: 'POST', endpoint: '/api/v1/auth/register', desc: 'Secure user registration with PBKDF2 HMAC-SHA256 password hashing.' },
    { method: 'POST', endpoint: '/api/v1/auth/login', desc: 'User login returning high-entropy session bearer token.' },
    { method: 'GET', endpoint: '/api/v1/auth/me', desc: 'Retrieve authenticated user session profile and role.' },
    { method: 'POST', endpoint: '/api/v1/scans', desc: 'Submit a package name, ecosystem, and version for asynchronous zero-day inspection.' },
    { method: 'GET', endpoint: '/api/v1/scans/{jobId}', desc: 'Retrieve real-time scan job status (QUEUED, PROCESSING, COMPLETED, FAILED) and full report.' },
    { method: 'GET', endpoint: '/api/v1/scans', desc: 'Query paginated forensic scan audit history with verdicts and risk scores.' },
    { method: 'GET', endpoint: '/api/v1/health', desc: 'Monitor operational health of Spring Boot, PostgreSQL storage, and Redis Streams.' }
  ];

  return (
    <section id="about" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mb-20 space-y-12 select-none">
      
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
            Conventional vulnerability management tools rely almost exclusively on <strong className="text-slate-800">CVE databases</strong>. 
            By definition, a CVE is only published <span className="underline decoration-pastel-blush-400">after</span> malware has already 
            infiltrated developer machines, hijacked tokens, and been publicly disclosed.
          </p>

          <p className="text-slate-600 text-sm sm:text-base leading-relaxed">
            <strong className="text-slate-800">PkgSentinel</strong> eliminates this detection lag. By analyzing package source and metadata at intake, 
            it flags malicious lifecycle scripts, AST execution hazards, and typosquatting attacks—stopping supply-chain threats before developers ever run <code className="px-1.5 py-0.5 rounded bg-slate-100 font-mono text-xs text-pastel-lavender-700">npm install</code> or <code className="px-1.5 py-0.5 rounded bg-slate-100 font-mono text-xs text-pastel-powder-700">pip install</code>.
          </p>
        </div>
      </div>

      {/* Detection Pillars Grid */}
      <div className="space-y-6">
        <div>
          <h3 className="text-xl font-bold text-slate-900 tracking-tight">
            Core Heuristic Detection Capabilities
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
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.08 }}
                className="p-5 rounded-3xl bg-white border border-slate-200/80 shadow-soft-sm space-y-3 flex flex-col justify-between"
              >
                <div className="space-y-2.5">
                  <div className={`w-10 h-10 rounded-2xl flex items-center justify-center border ${cardBg}`}>
                    <Icon className="w-5 h-5" />
                  </div>
                  <h4 className="text-sm font-bold text-slate-900 tracking-tight">
                    {pillar.title}
                  </h4>
                  <p className="text-xs text-slate-600 leading-relaxed">
                    {pillar.desc}
                  </p>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>

      {/* Architecture & API Endpoints */}
      <div className="rounded-3xl glass-card p-6 sm:p-8 shadow-soft-lg border border-white/90 space-y-5">
        <div>
          <h3 className="text-lg font-bold text-slate-900 tracking-tight flex items-center gap-2">
            <Server className="w-5 h-5 text-pastel-lavender-600" />
            Backend Architecture & Verified Endpoints
          </h3>
          <p className="text-xs text-slate-500 mt-1">
            Spring Boot 3.3.4 orchestrator + PostgreSQL persistence + Redis Streams transport + Python 3.11 AST security worker.
          </p>
        </div>

        <div className="divide-y divide-slate-100 border-t border-slate-100">
          {apis.map((api, idx) => (
            <div key={idx} className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2.5">
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                  api.method === 'POST'
                    ? 'bg-pastel-lavender-100 text-pastel-lavender-700 border-pastel-lavender-200'
                    : 'bg-pastel-powder-100 text-pastel-powder-700 border-pastel-powder-200'
                }`}>
                  {api.method}
                </span>
                <code className="text-xs font-mono font-semibold text-slate-800">{api.endpoint}</code>
              </div>
              <p className="text-xs text-slate-500 max-w-md sm:text-right">
                {api.desc}
              </p>
            </div>
          ))}
        </div>
      </div>

    </section>
  );
};

export default About;
