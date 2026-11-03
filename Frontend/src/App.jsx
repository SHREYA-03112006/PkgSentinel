import React, { useState } from 'react';
import Navbar from './components/Navbar';
import Hero from './components/Hero';
import Scanner from './components/Scanner';
import ScanResult from './components/ScanResult';
import ScanHistory from './components/ScanHistory';
import About from './components/About';
import { getScanById } from './api/scanService';
import { Shield, Heart, Terminal, Sparkles } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [currentScanResult, setCurrentScanResult] = useState(null);
  const [selectedPreset, setSelectedPreset] = useState(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  // Handle preset selected in Hero
  const handleSelectPreset = (name, ecosystem) => {
    setSelectedPreset({ name, ecosystem });
    // Smooth scroll to scanner
    const el = document.getElementById('scanner');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  // Handle scan complete
  const handleScanComplete = (result) => {
    setCurrentScanResult(result);
    setRefreshTrigger(prev => prev + 1);
    // Smooth scroll to results
    setTimeout(() => {
      document.getElementById('scan-result')?.scrollIntoView({ behavior: 'smooth' });
    }, 150);
  };

  // Handle history item inspect
  const handleSelectScanFromHistory = async (id) => {
    const fullData = await getScanById(id);
    if (fullData) {
      setCurrentScanResult(fullData);
      setActiveTab('dashboard');
      setTimeout(() => {
        document.getElementById('scan-result')?.scrollIntoView({ behavior: 'smooth' });
      }, 150);
    }
  };

  const handleScanAnother = () => {
    setCurrentScanResult(null);
    document.getElementById('scanner')?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#FAF8F5] text-slate-800">
      
      {/* Top Navbar */}
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />

      {/* Main Content Area */}
      <main className="flex-1">
        {activeTab === 'dashboard' && (
          <>
            <Hero onSelectPreset={handleSelectPreset} />
            <Scanner 
              onScanComplete={handleScanComplete}
              selectedPreset={selectedPreset}
            />
            {currentScanResult && (
              <ScanResult 
                result={currentScanResult} 
                onScanAnother={handleScanAnother} 
              />
            )}
            <ScanHistory 
              onSelectScan={handleSelectScanFromHistory}
              refreshTrigger={refreshTrigger}
            />
          </>
        )}

        {activeTab === 'history' && (
          <div className="pt-8">
            <ScanHistory 
              onSelectScan={handleSelectScanFromHistory}
              refreshTrigger={refreshTrigger}
            />
          </div>
        )}

        {activeTab === 'about' && (
          <div className="pt-8">
            <About />
          </div>
        )}
      </main>

      {/* Clean Footer */}
      <footer className="border-t border-slate-200/80 bg-white/70 backdrop-blur-sm py-8 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-500">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-lg bg-pastel-lavender-500 flex items-center justify-center text-white">
              <Shield className="w-3.5 h-3.5" />
            </div>
            <span className="font-semibold text-slate-700">PkgSentinel</span>
            <span>— Zero-Day Malicious Package Detection</span>
          </div>

          <div className="flex items-center gap-4 text-slate-400">
            <span>Pastel Theme Edition</span>
            <span>•</span>
            <span>npm & PyPI Protection</span>
            <span>•</span>
            <span>Spring Boot Ready</span>
          </div>
        </div>
      </footer>

    </div>
  );
}

