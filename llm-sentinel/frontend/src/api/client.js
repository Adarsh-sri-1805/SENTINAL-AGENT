import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  timeout: 90000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Interceptor for error handling
api.interceptors.response.use(
  (response) => response.data,
  (error) => {
    const message =
      error.response?.data?.detail ||
      error.response?.data?.message ||
      error.message ||
      'An unexpected network error occurred';
    return Promise.reject(new Error(message));
  }
);

// -----------------------------------------------------------------------------
// Dashboard Overview & Telemetry
// -----------------------------------------------------------------------------
export const getDashboardOverview = () => api.get('/dashboard/overview');
export const getRiskDistribution = () => api.get('/dashboard/risk-distribution');
export const getRecentEvents = (limit = 25) => api.get(`/dashboard/recent-events?limit=${limit}`);

// -----------------------------------------------------------------------------
// Security Mode & Mitigations
// -----------------------------------------------------------------------------
export const getSecurityMode = () => api.get('/security/mode');
export const setSecurityMode = (mode) => api.post('/security/mode', { mode });
export const getMitigationsStatus = () => api.get('/security/mitigations/status');
export const toggleMitigation = (risk_id, enabled) => api.post('/security/mitigations/toggle', { risk_id, enabled });
export const runBeforeAfterEvaluation = (filter_risk = null) =>
  api.post('/security/evaluate/before-after', { filter_risk }, { timeout: 180000 });
export const getComparisons = (limit = 20) => api.get(`/security/evaluate/comparisons?limit=${limit}`);
export const getComparisonDetail = (comparison_id) => api.get(`/security/evaluate/comparisons/${comparison_id}`);

// -----------------------------------------------------------------------------
// Attack Testing Engine (LLM01-10 and ASI01-06)
// -----------------------------------------------------------------------------
export const getTestCases = (filter_risk = null) => {
  const query = filter_risk ? `?risk_id=${filter_risk}` : '';
  return api.get(`/security/tests${query}`);
};
export const getAgenticTestCases = (filter_risk = null) => {
  const query = filter_risk ? `?risk_id=${filter_risk}` : '';
  return api.get(`/security/agentic-tests${query}`);
};
export const runSingleTest = (test_id, mode = null) =>
  api.post('/security/tests/run', { test_id, mode });
export const runSingleAgenticTest = (test_id, mode = null) =>
  api.post('/security/agentic-tests/run', { test_id, mode });
export const runAllTests = (filter_risk = null, mode = null) =>
  api.post('/security/tests/run-all', { filter_risk, mode }, { timeout: 120000 });
export const runAllAgenticTests = (filter_risk = null, mode = null) =>
  api.post('/security/agentic-tests/run-all', { filter_risk, mode }, { timeout: 120000 });
export const getTestResults = (params = {}) => {
  const query = new URLSearchParams(params).toString();
  return api.get(`/security/test-results${query ? `?${query}` : ''}`);
};
export const getTestRuns = (limit = 20) => api.get(`/security/results?limit=${limit}`);
export const getTestRunDetail = (run_id) => api.get(`/security/results/${run_id}`);

// -----------------------------------------------------------------------------
// Model Context Protocol (MCP) Security
// -----------------------------------------------------------------------------
export const getMCPStatus = () => api.get('/mcp/status');
export const getMCPServers = () => api.get('/mcp/servers');
export const getMCPTools = (mode = null) => api.get(`/mcp/tools${mode ? `?mode=${mode}` : ''}`);
export const getMCPResources = () => api.get('/mcp/resources');
export const readMCPResource = (uri, mode = null) =>
  api.get(`/mcp/resources/read?uri=${encodeURIComponent(uri)}${mode ? `&mode=${mode}` : ''}`);
export const invokeMCPTool = (tool_name, args = {}, user_id = 'guest', mode = null) =>
  api.post('/mcp/tools/invoke', { tool_name, arguments: args, user_id, mode });
export const getMCPEvents = (limit = 50) => api.get(`/mcp/security/events?limit=${limit}`);
export const getMCPTests = () => api.get('/mcp/security/tests');
export const runAllMCPSecurityTests = () => api.post('/mcp/security/run-all');

// -----------------------------------------------------------------------------
// Wazuh SIEM Integration
// -----------------------------------------------------------------------------
export const getWazuhStatus = () => api.get('/wazuh/status');
export const getWazuhAlerts = (limit = 50) => api.get(`/wazuh/alerts?limit=${limit}`);
export const exportWazuhEvents = () => api.post('/wazuh/export-events');

export default api;
