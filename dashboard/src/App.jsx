import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './pages/Dashboard';
import ThreatHistory from './pages/ThreatHistory';
import TrainingMode from './pages/TrainingMode';
import Settings from './pages/Settings';

function App() {
  return (
    <div>
      <Router>
        <div className="flex h-screen overflow-hidden bg-slate-950">
          <Sidebar />
          <div className="flex-1 flex flex-col overflow-hidden">
            <Header />
            <main className="flex-1 overflow-y-auto p-8">
              <Routes>
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/threats" element={<ThreatHistory />} />
                <Route path="/training" element={<TrainingMode />} />
                <Route path="/settings" element={<Settings />} />
              </Routes>
            </main>
          </div>
        </div>
      </Router>
    </div>
  );
}

export default App;
