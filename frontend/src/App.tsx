import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import Navbar from './components/Navbar';
import Hero from './components/Hero';
import Scanner from './components/Scanner';
import ScanResult from './components/ScanResult';
import ScanHistory from './components/ScanHistory';
import About from './components/About';
import AuthModal from './components/AuthModal';
import { AuthProvider, useAuth } from './context/AuthContext';
import { getScanById } from './services/scanService';
import { UIScanResult } from './types/report';
import { Shield } from 'lucide-react';

const MainLayout: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [activeTab, setActiveTab] = useState<'dashboard' | 'history' | 'about'>('dashboard');
  const [currentScanResult, setCurrentScanResult] = useState<UIScanResult | null>(null);
  const [selectedPreset, setSelectedPreset] = useState<{ name: string; ecosystem?: string } | null>(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  const { authModalOpen, authModalMode, closeAuthModal, openAuthModal } = useAuth();

  // Check URL parameters on mount
  useEffect(() => {
    const authParam = searchParams.get('auth');
    if (authParam === 'signin' || authParam === 'login') {
      openAuthModal('signin');
    } else if (authParam === 'signup' || authParam === 'register') {
      openAuthModal('signup');
    }

    const tabParam = searchParams.get('tab');
    if (tabParam === 'history' || tabParam === 'about') {
      setActiveTab(tabParam);
    }
  }, [searchParams, openAuthModal]);

  // Deep-link support for ?jobId=...
  useEffect(() => {
    const urlJobId = searchParams.get('jobId');
    if (urlJobId) {
      getScanById(urlJobId).then((report) => {
        if (report) {
          setCurrentScanResult(report);
          setActiveTab('dashboard');
          setTimeout(() => {
            document.getElementById('scan-result')?.scrollIntoView({ behavior: 'smooth' });
          }, 200);
        }
      });
    }
  }, [searchParams]);

  // Handle preset selected in Hero
  const handleSelectPreset = (name: string, ecosystem: string) => {
    setSelectedPreset({ name, ecosystem });
    setActiveTab('dashboard');
    setTimeout(() => {
      document.getElementById('scanner')?.scrollIntoView({ behavior: 'smooth' });
    }, 100);
  };

  // Handle scan complete
  const handleScanComplete = (result: UIScanResult) => {
    setCurrentScanResult(result);
    setRefreshTrigger(prev => prev + 1);
    setSearchParams({ jobId: result.id });
    setTimeout(() => {
      document.getElementById('scan-result')?.scrollIntoView({ behavior: 'smooth' });
    }, 150);
  };

  // Handle history item inspection
  const handleSelectScanFromHistory = async (id: string) => {
    const fullData = await getScanById(id);
    if (fullData) {
      setCurrentScanResult(fullData);
      setActiveTab('dashboard');
      setSearchParams({ jobId: id });
      setTimeout(() => {
        document.getElementById('scan-result')?.scrollIntoView({ behavior: 'smooth' });
      }, 150);
    }
  };

  const handleScanAnother = () => {
    setCurrentScanResult(null);
    setSearchParams({});
    document.getElementById('scanner')?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#FAF8F5] text-slate-800 selection:bg-pastel-lavender-200 selection:text-pastel-lavender-700 font-sans">
      
      {/* Top Navbar */}
      <Navbar activeTab={activeTab} setActiveTab={(tab) => setActiveTab(tab as 'dashboard' | 'history' | 'about')} />

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

      {/* Global Authentication Modal */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={closeAuthModal}
        initialMode={authModalMode}
      />

      {/* Clean Footer */}
      <footer className="border-t border-slate-200/80 bg-white/70 backdrop-blur-sm py-8 mt-12 select-none">
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
            <span>Spring Boot Connected</span>
          </div>
        </div>
      </footer>

    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <MainLayout />
    </AuthProvider>
  );
};

export default App;
