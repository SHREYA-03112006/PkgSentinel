import React from 'react';
import { Routes, Route } from 'react-router-dom';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { DashboardPage } from './pages/DashboardPage';
import { SingleScanPage } from './pages/SingleScanPage';
import { PlaceholderPage } from './pages/PlaceholderPage';

const App: React.FC = () => {
  return (
    <div className="flex h-screen overflow-hidden bg-sentinel-bg">
      {/* Fixed Sidebar */}
      <Sidebar />

      {/* Main Workspace Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header />
        
        <main className="flex-1 overflow-y-auto p-6">
          <div className="max-w-7xl mx-auto">
            <Routes>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/scan" element={<SingleScanPage />} />
              <Route 
                path="/lockfile" 
                element={
                  <PlaceholderPage 
                    title="Dependency Lockfile Scanner" 
                    description="Upload and analyze package-lock.json, yarn.lock, and requirements.txt dependency graphs with tree decomposition."
                    phase="Phase 2 Feature"
                  />
                } 
              />
              <Route 
                path="/history" 
                element={
                  <PlaceholderPage 
                    title="Audit & Scan History" 
                    description="Comprehensive historical log of all package analysis verdicts, forensic indicators, and scan jobs."
                    phase="Phase 2 Feature"
                  />
                } 
              />
              <Route 
                path="/settings" 
                element={
                  <PlaceholderPage 
                    title="Platform & Registry Settings" 
                    description="Configure private namespace scopes for dependency confusion detection, custom registry endpoints, and API tokens."
                    phase="Phase 2 Feature"
                  />
                } 
              />
            </Routes>
          </div>
        </main>
      </div>
    </div>
  );
};

export default App;
