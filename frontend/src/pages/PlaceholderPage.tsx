import React from 'react';

interface PlaceholderProps {
  title: string;
  description: string;
  phase: string;
}

export const PlaceholderPage: React.FC<PlaceholderProps> = ({ title, description, phase }) => {
  return (
    <div className="bg-sentinel-card border border-sentinel-border rounded-xl p-8 text-center max-w-xl mx-auto my-12">
      <span className="px-3 py-1 rounded-full text-xs font-mono bg-cyan-950/80 text-sentinel-cyan border border-cyan-800/60 uppercase">
        {phase}
      </span>
      <h2 className="text-xl font-bold text-white mt-4">{title}</h2>
      <p className="text-sm text-slate-400 mt-2 leading-relaxed">{description}</p>
      <div className="mt-6 p-4 bg-sentinel-surface rounded-lg border border-sentinel-border text-xs font-mono text-slate-400">
        Engine contract defined in Architecture v2.1. Feature scheduled for implementation in this roadmap phase.
      </div>
    </div>
  );
};

