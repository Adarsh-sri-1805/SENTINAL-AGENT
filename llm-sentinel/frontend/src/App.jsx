import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom';

import Sidebar from './components/layout/Sidebar';
import Header from './components/layout/Header';

import OverviewPage from './pages/OverviewPage';
import LLMSecurityPage from './pages/LLMSecurityPage';
import AgenticAIPage from './pages/AgenticAIPage';
import MitigationCenterPage from './pages/MitigationCenterPage';
import MCPSecurityPage from './pages/MCPSecurityPage';
import ResultsReportsPage from './pages/ResultsReportsPage';
import WazuhMonitoringPage from './pages/WazuhMonitoringPage';

import { getSecurityMode, setSecurityMode, getWazuhStatus } from './api/client';

const PAGE_TITLES = {
  '/': { title: 'Security Operations Center Overview', subtitle: 'Real-time telemetry, threat distribution & attack outcome metrics' },
  '/llm-security': { title: 'OWASP LLM Security Testing', subtitle: 'Target A: Customer Support Chatbot (15 Test Cases across 5 Mandatory Risks)' },
  '/agentic-ai': { title: 'OWASP Agentic AI Security Testing', subtitle: 'Target B: Autonomous AI Agent with Controlled Tools (15 Test Cases)' },
  '/mitigations': { title: 'Mitigation Center & Policy Controls', subtitle: '10 Defensive Guardrails & Automated Before/After Comparative Evaluation' },
  '/mcp-security': { title: 'Model Context Protocol (MCP) Security', subtitle: 'Local MCP Server Hardening, RBAC, Observation Isolation & Attack Evaluation' },
  '/reports': { title: 'Results & Compliance Reports', subtitle: 'Comprehensive Test Execution Logs, CSV Data Export & Executive Report Summary' },
  '/wazuh': { title: 'Wazuh SIEM Security Monitoring', subtitle: 'Real-time Event Ingestion, JSONL Exporter & Custom Detection Rules' },
};

function AppContent() {
  const location = useLocation();
  const [securityMode, setMode] = useState('protected');
  const [wazuhConnected, setWazuhConnected] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const fetchGlobalState = async () => {
    try {
      setIsRefreshing(true);
      const [modeRes, wazuhRes] = await Promise.all([
        getSecurityMode().catch(() => ({ mode: 'protected' })),
        getWazuhStatus().catch(() => ({ connected: false })),
      ]);
      if (modeRes?.mode) setMode(modeRes.mode);
      if (wazuhRes) setWazuhConnected(Boolean(wazuhRes.connected));
    } catch {
      // Graceful fallback
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchGlobalState();
  }, [location.pathname]);

  const handleToggleMode = async (newMode) => {
    try {
      await setSecurityMode(newMode);
      setMode(newMode);
    } catch (err) {
      console.error('Failed to update mode:', err);
    }
  };

  const pageInfo = PAGE_TITLES[location.pathname] || {
    title: 'LLM Sentinel',
    subtitle: 'AI Security Testing Framework',
  };

  return (
    <div className="flex h-screen bg-soc-bg text-soc-text overflow-hidden">
      {/* Sidebar Navigation */}
      <Sidebar securityMode={securityMode} wazuhConnected={wazuhConnected} />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col h-screen overflow-hidden">
        {/* Top Header */}
        <Header
          title={pageInfo.title}
          subtitle={pageInfo.subtitle}
          securityMode={securityMode}
          onToggleMode={handleToggleMode}
          onRefresh={fetchGlobalState}
          isRefreshing={isRefreshing}
        />

        {/* Page Body */}
        <main className="flex-1 overflow-y-auto p-8">
          <Routes>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/llm-security" element={<LLMSecurityPage />} />
            <Route path="/agentic-ai" element={<AgenticAIPage />} />
            <Route path="/mitigations" element={<MitigationCenterPage />} />
            <Route path="/mcp-security" element={<MCPSecurityPage />} />
            <Route path="/reports" element={<ResultsReportsPage />} />
            <Route path="/wazuh" element={<WazuhMonitoringPage />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}
