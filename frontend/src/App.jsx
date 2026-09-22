import React, { useState, useEffect, useRef } from 'react';
import './index.css';

const API_BASE = '/api';

export default function App() {
  const [theme, setTheme] = useState('dark');
  const [activeTab, setActiveTab] = useState('lookup'); // 'lookup', 'alerts', 'blacklist', 'stats', 'benchmark'
  const [wsConnected, setWsConnected] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [toastMsg, setToastMsg] = useState(null);

  // Lookup state
  const [indicatorInput, setIndicatorInput] = useState('');
  const [lookupLoading, setLookupLoading] = useState(false);
  const [lookupResult, setLookupResult] = useState(null);
  const [lookupError, setLookupError] = useState(null);

  // Blacklist state
  const [blacklistItems, setBlacklistItems] = useState([]);
  const [blacklistTypeFilter, setBlacklistTypeFilter] = useState('');
  const [newBlacklistIndicator, setNewBlacklistIndicator] = useState('');
  const [blacklistLoading, setBlacklistLoading] = useState(false);

  // Stats state
  const [stats, setStats] = useState(null);
  const [statsLoading, setStatsLoading] = useState(false);

  // Benchmark state
  const [benchRequests, setBenchRequests] = useState(50);
  const [benchUnique, setBenchUnique] = useState(15);
  const [benchRepetition, setBenchRepetition] = useState(0.75);
  const [benchLoading, setBenchLoading] = useState(false);
  const [benchResult, setBenchResult] = useState(null);

  const wsRef = useRef(null);

  // Toggle Theme
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => (prev === 'dark' ? 'light' : 'dark'));
  };

  const showToast = (msg) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(null), 3500);
  };

  // WebSocket for Real-time Alerts
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/ws/alerts`;

    const connectWs = () => {
      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          setWsConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            setAlerts(prev => [data, ...prev.slice(0, 49)]);
            showToast(`ALERT: High-risk indicator detected: ${data.indicator || 'Unknown'}`);
          } catch (e) {
            console.error('Failed to parse WS event', e);
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
          // Reconnect after 3 seconds
          setTimeout(connectWs, 3000);
        };

        ws.onerror = () => {
          setWsConnected(false);
          ws.close();
        };
      } catch (err) {
        setWsConnected(false);
        setTimeout(connectWs, 3000);
      }
    };

    connectWs();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  // Fetch Stats
  const fetchStats = async () => {
    setStatsLoading(true);
    try {
      const res = await fetch(`${API_BASE}/stats`);
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.error('Failed to fetch stats', err);
    } finally {
      setStatsLoading(false);
    }
  };

  // Fetch Blacklist
  const fetchBlacklist = async () => {
    setBlacklistLoading(true);
    try {
      const query = blacklistTypeFilter ? `?indicator_type=${blacklistTypeFilter}` : '';
      const res = await fetch(`${API_BASE}/blacklist${query}`);
      if (res.ok) {
        const data = await res.json();
        setBlacklistItems(data.items || []);
      }
    } catch (err) {
      console.error('Failed to fetch blacklist', err);
    } finally {
      setBlacklistLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'stats') {
      fetchStats();
    } else if (activeTab === 'blacklist') {
      fetchBlacklist();
    }
  }, [activeTab, blacklistTypeFilter]);

  // Handle Threat Lookup
  const handleLookup = async (overrideIndicator) => {
    const target = (overrideIndicator || indicatorInput).trim();
    if (!target) return;

    setLookupLoading(true);
    setLookupError(null);
    setLookupResult(null);

    try {
      const res = await fetch(`${API_BASE}/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator: target }),
      });

      const data = await res.json();
      if (!res.ok) {
        setLookupError(data.detail || 'Lookup failed');
      } else {
        setLookupResult(data);
        if (target !== indicatorInput) setIndicatorInput(target);
      }
    } catch (err) {
      setLookupError(err.message || 'Network error connecting to backend');
    } finally {
      setLookupLoading(false);
    }
  };

  // Force Refresh Indicator Cache
  const handleRefresh = async () => {
    if (!lookupResult?.normalized_indicator) return;
    const ind = encodeURIComponent(lookupResult.normalized_indicator);
    setLookupLoading(true);
    try {
      const res = await fetch(`${API_BASE}/refresh/${ind}`, { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        setLookupResult(data);
        showToast('Cache refreshed directly from CTI authority.');
      } else {
        showToast(`Refresh failed: ${data.detail || 'Error'}`);
      }
    } catch (err) {
      showToast(`Error: ${err.message}`);
    } finally {
      setLookupLoading(false);
    }
  };

  // Add to Blacklist
  const handleAddBlacklist = async (e) => {
    e.preventDefault();
    if (!newBlacklistIndicator.trim()) return;

    try {
      const res = await fetch(`${API_BASE}/blacklist`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator: newBlacklistIndicator.trim() }),
      });
      const data = await res.json();
      if (res.ok) {
        showToast('Indicator added to blacklist');
        setNewBlacklistIndicator('');
        fetchBlacklist();
      } else {
        showToast(`Error: ${data.detail || 'Failed to add'}`);
      }
    } catch (err) {
      showToast(`Network error: ${err.message}`);
    }
  };

  // Remove from Blacklist
  const handleRemoveBlacklist = async (indicator) => {
    try {
      const res = await fetch(`${API_BASE}/blacklist/${encodeURIComponent(indicator)}`, {
        method: 'DELETE',
      });
      if (res.ok) {
        showToast('Indicator removed from blacklist');
        fetchBlacklist();
      } else {
        const data = await res.json();
        showToast(`Failed: ${data.detail || 'Error'}`);
      }
    } catch (err) {
      showToast(`Network error: ${err.message}`);
    }
  };

  // Client-side benchmark simulation calling backend lookup pipeline
  const runBenchmark = async () => {
    setBenchLoading(true);
    setBenchResult(null);

    try {
      // Simulate synthetic workload
      const indicators = Array.from({ length: benchUnique }, (_, i) => `198.51.100.${i + 1}`);
      const popular = indicators.slice(0, Math.max(1, Math.floor(benchUnique * 0.2)));
      const workload = [];
      for (let i = 0; i < benchRequests; i++) {
        if (Math.random() < benchRepetition && popular.length) {
          workload.push(popular[Math.floor(Math.random() * popular.length)]);
        } else {
          workload.push(indicators[Math.floor(Math.random() * indicators.length)]);
        }
      }

      let cacheHits = 0;
      let cacheMisses = 0;
      const latencies = [];
      const startTime = performance.now();

      for (const item of workload) {
        const t0 = performance.now();
        const res = await fetch(`${API_BASE}/check`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ indicator: item }),
        });
        const data = await res.json();
        const t1 = performance.now();
        latencies.push(t1 - t0);

        if (data.cached) {
          cacheHits++;
        } else {
          cacheMisses++;
        }
      }

      const totalTime = performance.now() - startTime;
      const avgLat = latencies.reduce((a, b) => a + b, 0) / latencies.length;
      const sorted = [...latencies].sort((a, b) => a - b);

      setBenchResult({
        totalRequests: benchRequests,
        executionTime: (totalTime / 1000).toFixed(2),
        avgLatency: avgLat.toFixed(2),
        p50: sorted[Math.floor(sorted.length * 0.5)].toFixed(2),
        p95: sorted[Math.floor(sorted.length * 0.95)].toFixed(2),
        cacheHits,
        cacheMisses,
        hitRate: ((cacheHits / benchRequests) * 100).toFixed(1),
        avoidedCalls: cacheHits,
      });
      showToast('Benchmark run finished successfully.');
    } catch (err) {
      showToast(`Benchmark error: ${err.message}`);
    } finally {
      setBenchLoading(false);
    }
  };

  return (
    <div className="app-container">
      {/* Toast Notification */}
      {toastMsg && <div className="toast">{toastMsg}</div>}

      {/* Header */}
      <header className="app-header glass-panel">
        <div className="brand-section">
          <div className="brand-logo">Aegis CTI</div>
          <div className="brand-subtitle">Redis Threat Intelligence Cache</div>
        </div>
        <div className="header-controls">
          <div className="ws-status-badge">
            <span className={`ws-dot ${!wsConnected ? 'disconnected' : ''}`} />
            {wsConnected ? 'WS Stream Active' : 'WS Connecting...'}
          </div>
          <button className="btn btn-icon" onClick={toggleTheme} title="Toggle Black/White Theme">
            {theme === 'dark' ? 'LIGHT MODE' : 'DARK MODE'}
          </button>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="tabs-nav">
        <button
          className={`tab-btn ${activeTab === 'lookup' ? 'active' : ''}`}
          onClick={() => setActiveTab('lookup')}
        >
          Threat Lookup
        </button>
        <button
          className={`tab-btn ${activeTab === 'alerts' ? 'active' : ''}`}
          onClick={() => setActiveTab('alerts')}
        >
          Live Alerts ({alerts.length})
        </button>
        <button
          className={`tab-btn ${activeTab === 'blacklist' ? 'active' : ''}`}
          onClick={() => setActiveTab('blacklist')}
        >
          Redis Blacklist
        </button>
        <button
          className={`tab-btn ${activeTab === 'stats' ? 'active' : ''}`}
          onClick={() => setActiveTab('stats')}
        >
          Operational Stats
        </button>
        <button
          className={`tab-btn ${activeTab === 'benchmark' ? 'active' : ''}`}
          onClick={() => setActiveTab('benchmark')}
        >
          Benchmark Lab
        </button>
      </nav>

      {/* TAB 1: THREAT LOOKUP */}
      {activeTab === 'lookup' && (
        <div className="view-section">
          <div className="search-container glass-panel">
            <form
              className="search-input-group"
              onSubmit={(e) => {
                e.preventDefault();
                handleLookup();
              }}
            >
              <input
                type="text"
                className="search-input"
                placeholder="Enter IP address, Domain, or URL (e.g., 198.51.100.25, google.com, http://bad.test)..."
                value={indicatorInput}
                onChange={(e) => setIndicatorInput(e.target.value)}
              />
              <button type="submit" className="btn btn-primary" disabled={lookupLoading}>
                {lookupLoading ? 'Evaluating...' : 'Query Threat Cache'}
              </button>
            </form>

            <div className="quick-indicators">
              <span>Quick Test:</span>
              <button className="quick-tag" onClick={() => handleLookup('198.51.100.25')}>
                198.51.100.25 (Malicious CTI)
              </button>
              <button className="quick-tag" onClick={() => handleLookup('google.com')}>
                google.com (Trusted Root)
              </button>
              <button className="quick-tag" onClick={() => handleLookup('https://docs.google.com/document')}>
                docs.google.com (Subdomain URL)
              </button>
              <button className="quick-tag" onClick={() => handleLookup('google.com.evil.com')}>
                google.com.evil.com (Domain Spoof Test)
              </button>
            </div>
          </div>

          {/* Error display */}
          {lookupError && (
            <div className="glass-panel" style={{ padding: '20px' }}>
              <div style={{ fontWeight: 700, textTransform: 'uppercase', marginBottom: '8px' }}>
                Lookup Failure
              </div>
              <div style={{ color: 'var(--text-muted)' }}>{lookupError}</div>
            </div>
          )}

          {/* Result Presentation Card */}
          {lookupResult && (
            <div className="result-card glass-panel">
              <div className="result-header">
                <div className="result-title-group">
                  <div className="result-indicator-text">{lookupResult.normalized_indicator}</div>
                  <div className="result-meta-row">
                    <span className="tag">{lookupResult.indicator_type}</span>
                    <span>Source: {lookupResult.source}</span>
                    <span>TTL: {lookupResult.ttl_seconds ? `${lookupResult.ttl_seconds}s` : 'N/A'}</span>
                    <span>Status: {lookupResult.cached ? 'CACHED (Redis Hit)' : 'FRESH (Provider Miss)'}</span>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                  <button className="btn" onClick={handleRefresh} disabled={lookupLoading}>
                    Force Refresh
                  </button>
                  <div
                    className={`result-verdict-badge ${
                      lookupResult.malicious ? 'verdict-malicious' : 'verdict-clean'
                    }`}
                  >
                    {lookupResult.malicious ? 'MALICIOUS VERDICT' : 'BENIGN / CLEAN'}
                  </div>
                </div>
              </div>

              <div className="metrics-grid">
                <div className="metric-box">
                  <div className="metric-label">Threat Score</div>
                  <div className="metric-value">{lookupResult.threat_score} / 100</div>
                  <div className="metric-sub">
                    {lookupResult.threat_score >= 80
                      ? 'High-risk severe threat'
                      : lookupResult.threat_score > 0
                      ? 'Elevated suspicion'
                      : 'Zero threat detected'}
                  </div>
                </div>

                <div className="metric-box">
                  <div className="metric-label">Confidence</div>
                  <div className="metric-value">{(lookupResult.confidence * 100).toFixed(0)}%</div>
                  <div className="metric-sub">Provider assessment accuracy</div>
                </div>

                <div className="metric-box">
                  <div className="metric-label">Trusted Domain Signal</div>
                  <div className="metric-value">
                    {lookupResult.is_trusted_domain ? 'VERIFIED' : 'NONE'}
                  </div>
                  <div className="metric-sub">
                    {lookupResult.is_trusted_domain
                      ? 'Matches verified organizational root'
                      : 'No root domain whitelist match'}
                  </div>
                </div>

                <div className="metric-box">
                  <div className="metric-label">Operational Cache</div>
                  <div className="metric-value">{lookupResult.cached ? 'HIT' : 'MISS'}</div>
                  <div className="metric-sub">
                    {lookupResult.cached ? 'Retrieved from Redis Hash' : 'Stored in Redis with dynamic TTL'}
                  </div>
                </div>
              </div>

              {lookupResult.categories?.length > 0 && (
                <div>
                  <div className="form-label" style={{ marginBottom: '8px' }}>Threat Categories</div>
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    {lookupResult.categories.map((cat, idx) => (
                      <span key={idx} className="tag">{cat}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: LIVE ALERTS (WEBSOCKET STREAM) */}
      {activeTab === 'alerts' && (
        <div className="view-section">
          <div className="alerts-panel glass-panel">
            <div className="panel-title-bar">
              <div className="panel-title">Real-Time Threat Alerts Stream</div>
              <button className="btn" onClick={() => setAlerts([])}>Clear Feed</button>
            </div>

            {alerts.length === 0 ? (
              <div style={{ padding: '32px 0', textAlign: 'center', color: 'var(--text-muted)' }}>
                No alerts detected yet. High-risk lookups will stream here automatically over WebSockets.
              </div>
            ) : (
              <div className="alerts-list">
                {alerts.map((al, i) => (
                  <div key={i} className="alert-item">
                    <div className="alert-info-col">
                      <div className="alert-indicator">{al.indicator}</div>
                      <div className="alert-subinfo">
                        <span>Type: {al.indicator_type}</span>
                        <span>Score: {al.threat_score}/100</span>
                        <span>Source: {al.source}</span>
                        <span>{al.timestamp ? new Date(al.timestamp).toLocaleTimeString() : 'Just now'}</span>
                      </div>
                    </div>
                    <button
                      className="btn btn-icon"
                      onClick={() => {
                        setActiveTab('lookup');
                        handleLookup(al.indicator);
                      }}
                    >
                      Inspect
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: REDIS BLACKLIST MANAGEMENT */}
      {activeTab === 'blacklist' && (
        <div className="view-section">
          <div className="glass-panel" style={{ padding: '24px' }}>
            <div className="panel-title-bar" style={{ marginBottom: '20px' }}>
              <div className="panel-title">Redis-Native Security Blacklists (O(1) Blocking Sets)</div>
            </div>

            <form onSubmit={handleAddBlacklist} style={{ display: 'flex', gap: '12px', marginBottom: '24px' }}>
              <input
                type="text"
                className="form-input"
                style={{ flex: 1 }}
                placeholder="Add IP, Domain, or URL to active Redis blacklist..."
                value={newBlacklistIndicator}
                onChange={(e) => setNewBlacklistIndicator(e.target.value)}
              />
              <button type="submit" className="btn btn-primary">Add Indicator</button>
            </form>

            <div style={{ display: 'flex', gap: '12px', alignItems: 'center', marginBottom: '16px' }}>
              <span className="form-label">Filter Type:</span>
              <button
                className={`btn ${blacklistTypeFilter === '' ? 'btn-primary' : ''}`}
                onClick={() => setBlacklistTypeFilter('')}
              >
                All
              </button>
              <button
                className={`btn ${blacklistTypeFilter === 'ip' ? 'btn-primary' : ''}`}
                onClick={() => setBlacklistTypeFilter('ip')}
              >
                IP
              </button>
              <button
                className={`btn ${blacklistTypeFilter === 'domain' ? 'btn-primary' : ''}`}
                onClick={() => setBlacklistTypeFilter('domain')}
              >
                Domain
              </button>
              <button
                className={`btn ${blacklistTypeFilter === 'url' ? 'btn-primary' : ''}`}
                onClick={() => setBlacklistTypeFilter('url')}
              >
                URL
              </button>
            </div>

            <div className="blacklist-table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Indicator</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {blacklistLoading ? (
                    <tr>
                      <td colSpan="2" style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                        Loading blacklist records...
                      </td>
                    </tr>
                  ) : blacklistItems.length === 0 ? (
                    <tr>
                      <td colSpan="2" style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                        No blacklisted indicators in this set.
                      </td>
                    </tr>
                  ) : (
                    blacklistItems.map((item, idx) => (
                      <tr key={idx}>
                        <td>{item}</td>
                        <td>
                          <button
                            className="btn btn-icon"
                            onClick={() => handleRemoveBlacklist(item)}
                          >
                            Remove
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: OPERATIONAL STATS */}
      {activeTab === 'stats' && (
        <div className="view-section">
          <div className="glass-panel" style={{ padding: '24px' }}>
            <div className="panel-title-bar" style={{ marginBottom: '20px' }}>
              <div className="panel-title">System Performance & Operational Counters</div>
              <button className="btn" onClick={fetchStats} disabled={statsLoading}>
                {statsLoading ? 'Refreshing...' : 'Refresh Metrics'}
              </button>
            </div>

            {stats ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                <div className="metrics-grid">
                  <div className="metric-box">
                    <div className="metric-label">Total Lookups</div>
                    <div className="metric-value">{stats.total_lookups || 0}</div>
                    <div className="metric-sub">Cumulative requests evaluated</div>
                  </div>
                  <div className="metric-box">
                    <div className="metric-label">Cache Hit Rate</div>
                    <div className="metric-value">{((stats.cache_hit_rate || 0) * 100).toFixed(1)}%</div>
                    <div className="metric-sub">{stats.cache_hits || 0} hits / {stats.cache_misses || 0} misses</div>
                  </div>
                  <div className="metric-box">
                    <div className="metric-label">Provider Lookups</div>
                    <div className="metric-value">{stats.provider_lookups || 0}</div>
                    <div className="metric-sub">Upstream CTI queries executed</div>
                  </div>
                  <div className="metric-box">
                    <div className="metric-label">Malicious Detections</div>
                    <div className="metric-value">{stats.malicious_detections || 0}</div>
                    <div className="metric-sub">Confirmed high-risk findings</div>
                  </div>
                </div>

                {stats.latency_stats && (
                  <div>
                    <div className="panel-title" style={{ marginBottom: '16px' }}>Latency Distribution</div>
                    <div className="metrics-grid">
                      <div className="metric-box">
                        <div className="metric-label">Average Latency</div>
                        <div className="metric-value">{stats.latency_stats.avg_ms} ms</div>
                      </div>
                      <div className="metric-box">
                        <div className="metric-label">p50 Median</div>
                        <div className="metric-value">{stats.latency_stats.p50_ms} ms</div>
                      </div>
                      <div className="metric-box">
                        <div className="metric-label">p95 Tail</div>
                        <div className="metric-value">{stats.latency_stats.p95_ms} ms</div>
                      </div>
                      <div className="metric-box">
                        <div className="metric-label">Min / Max Range</div>
                        <div className="metric-value">{stats.latency_stats.min_ms} / {stats.latency_stats.max_ms} ms</div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)' }}>Loading operational statistics...</div>
            )}
          </div>
        </div>
      )}

      {/* TAB 5: BENCHMARK LAB */}
      {activeTab === 'benchmark' && (
        <div className="view-section">
          <div className="glass-panel" style={{ padding: '24px' }}>
            <div className="panel-title-bar" style={{ marginBottom: '20px' }}>
              <div className="panel-title">Cache Performance Benchmarking</div>
            </div>

            <div className="benchmark-controls">
              <div className="form-group">
                <label className="form-label">Total Requests</label>
                <input
                  type="number"
                  className="form-input"
                  value={benchRequests}
                  onChange={(e) => setBenchRequests(Number(e.target.value))}
                  min="10"
                  max="500"
                />
              </div>
              <div className="form-group">
                <label className="form-label">Unique Indicators</label>
                <input
                  type="number"
                  className="form-input"
                  value={benchUnique}
                  onChange={(e) => setBenchUnique(Number(e.target.value))}
                  min="2"
                  max="100"
                />
              </div>
              <div className="form-group">
                <label className="form-label">Repetition Frequency</label>
                <input
                  type="number"
                  step="0.05"
                  className="form-input"
                  value={benchRepetition}
                  onChange={(e) => setBenchRepetition(Number(e.target.value))}
                  min="0"
                  max="1"
                />
              </div>
              <button
                className="btn btn-primary"
                onClick={runBenchmark}
                disabled={benchLoading}
                style={{ height: '42px' }}
              >
                {benchLoading ? 'Executing Workload...' : 'Execute Benchmark'}
              </button>
            </div>

            {benchResult && (
              <div style={{ marginTop: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
                <div className="benchmark-comparison-grid">
                  <div className="comparison-card glass-panel highlight">
                    <div className="panel-title">Redis Cache-First Results</div>
                    <div className="metrics-grid">
                      <div className="metric-box">
                        <div className="metric-label">Execution Time</div>
                        <div className="metric-value">{benchResult.executionTime} s</div>
                      </div>
                      <div className="metric-box">
                        <div className="metric-label">Cache Hit Rate</div>
                        <div className="metric-value">{benchResult.hitRate}%</div>
                      </div>
                      <div className="metric-box">
                        <div className="metric-label">Avg Latency</div>
                        <div className="metric-value">{benchResult.avgLatency} ms</div>
                      </div>
                      <div className="metric-box">
                        <div className="metric-label">Provider Calls Avoided</div>
                        <div className="metric-value">{benchResult.avoidedCalls}</div>
                      </div>
                    </div>
                  </div>

                  <div className="comparison-card glass-panel">
                    <div className="panel-title">Workload Summary</div>
                    <div className="metric-sub" style={{ lineHeight: '1.8' }}>
                      • Total Requests: <strong>{benchResult.totalRequests}</strong><br />
                      • Cache Hits (Redis Served): <strong>{benchResult.cacheHits}</strong><br />
                      • Cache Misses (Provider Queries): <strong>{benchResult.cacheMisses}</strong><br />
                      • p50 Median Latency: <strong>{benchResult.p50} ms</strong><br />
                      • p95 Tail Latency: <strong>{benchResult.p95} ms</strong>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
