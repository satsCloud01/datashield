import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Landing from './pages/Landing';
import Dashboard from './pages/Dashboard';
import Scanner from './pages/Scanner';
import TokenVault from './pages/TokenVault';
import PolicyStudio from './pages/PolicyStudio';
import Interceptor from './pages/Interceptor';
import SemanticValidator from './pages/SemanticValidator';
import AuditTrail from './pages/AuditTrail';
import Compliance from './pages/Compliance';
import Settings from './pages/Settings';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route element={<Layout />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scanner" element={<Scanner />} />
        <Route path="/token-vault" element={<TokenVault />} />
        <Route path="/policy-studio" element={<PolicyStudio />} />
        <Route path="/interceptor" element={<Interceptor />} />
        <Route path="/semantic-validator" element={<SemanticValidator />} />
        <Route path="/audit-trail" element={<AuditTrail />} />
        <Route path="/compliance" element={<Compliance />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
