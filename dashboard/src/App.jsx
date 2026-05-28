import { useMemo, useState, useCallback } from "react";

const severityOrder = ["critical", "high", "medium", "low", "info"];
const TABS = ["dashboard", "scan", "programs", "secrets"];
const DEFAULT_API = "http://localhost:8000";

const BOUNTY_RANGES = {
  critical: "$1,000–$10,000+",
  high: "$500–$3,000",
  medium: "$100–$1,000",
  low: "$25–$200",
  info: "$0",
};

const BOUNTY_MIN = { critical: 1000, high: 500, medium: 100, low: 25, info: 0 };
const BOUNTY_MAX = { critical: 10000, high: 3000, medium: 1000, low: 200, info: 0 };

function prettyJson(value) {
  return JSON.stringify(value, null, 2);
}

function riskClass(level) {
  const key = String(level || "informational").toLowerCase();
  return `risk-${key}`;
}

function platformTag(platform) {
  const p = String(platform || "custom").toLowerCase();
  const tags = {
    hackerone: "tag-hackerone",
    bugcrowd: "tag-bugcrowd",
    intigriti: "tag-intigriti",
  };
  return tags[p] || "tag-custom";
}

function normalizeReport(report, fileName) {
  const risk = report.risk || { score: 0, level: "informational", severity_counts: {} };
  const summary = report.summary || { ok: 0, warning: 0, error: 0 };
  return {
    ...report,
    fileName,
    risk,
    summary,
    results: Array.isArray(report.results) ? report.results : [],
  };
}

export default function App() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [reports, setReports] = useState([]);
  const [selectedTarget, setSelectedTarget] = useState("");
  const [apiBase, setApiBase] = useState(DEFAULT_API);
  const [targetInput, setTargetInput] = useState("");
  const [scanTimeout, setScanTimeout] = useState(8);
  const [headersText, setHeadersText] = useState("");
  const [cookiesText, setCookiesText] = useState("");
  const [bearerToken, setBearerToken] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [maxPages, setMaxPages] = useState(20);
  const [maxDepth, setMaxDepth] = useState(2);
  const [enableNuclei, setEnableNuclei] = useState(false);
  const [nucleiTemplates, setNucleiTemplates] = useState("");
  const [nucleiSeverities, setNucleiSeverities] = useState("low,medium,high,critical");
  const [nucleiTags, setNucleiTags] = useState("");
  const [zapBaseUrl, setZapBaseUrl] = useState("");
  const [authLoginUrl, setAuthLoginUrl] = useState("");
  const [authLoginMethod, setAuthLoginMethod] = useState("POST");
  const [authLoginForm, setAuthLoginForm] = useState("");
  const [authLoginJson, setAuthLoginJson] = useState("");
  const [jobStatus, setJobStatus] = useState(null);
  const [scanMode, setScanMode] = useState("bounty");
  const [workers, setWorkers] = useState(8);
  const [rateLimit, setRateLimit] = useState(15);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [copiedId, setCopiedId] = useState(null);

  // Programs
  const [programs, setPrograms] = useState([]);
  const [showAddProgram, setShowAddProgram] = useState(false);
  const [newProgram, setNewProgram] = useState({
    name: "", platform: "custom", url: "", in_scope: "", out_scope: "", notes: "",
  });

  // Aggregate stats
  const aggregate = useMemo(() => {
    const totals = {
      targets: reports.length,
      risk: 0,
      findings: 0,
      warning: 0,
      error: 0,
      ok: 0,
      severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    };
    for (const report of reports) {
      totals.risk += Number(report.risk?.score || 0);
      totals.ok += Number(report.summary?.ok || 0);
      totals.warning += Number(report.summary?.warning || 0);
      totals.error += Number(report.summary?.error || 0);
      totals.findings += report.results.length;
      for (const key of severityOrder) {
        totals.severity[key] += Number(report.risk?.severity_counts?.[key] || 0);
      }
    }
    return totals;
  }, [reports]);

  // Bounty estimate
  const bountyEstimate = useMemo(() => {
    let min = 0, max = 0;
    for (const sev of severityOrder) {
      const count = aggregate.severity[sev] || 0;
      // Only count warning-status findings
      min += count * (BOUNTY_MIN[sev] || 0);
      max += count * (BOUNTY_MAX[sev] || 0);
    }
    return { min, max };
  }, [aggregate]);

  // Selected report
  const selected = useMemo(() => {
    if (!reports.length) return null;
    if (!selectedTarget) return reports[0];
    return reports.find((r) => r.target === selectedTarget) || reports[0];
  }, [reports, selectedTarget]);

  // Filtered findings
  const filteredResults = useMemo(() => {
    if (!selected) return [];
    if (severityFilter === "all") return selected.results;
    return selected.results.filter((r) => r.severity === severityFilter);
  }, [selected, severityFilter]);

  // Secrets from findings
  const secrets = useMemo(() => {
    if (!selected) return [];
    const jsSecrets = selected.results.find((r) => r.name === "js_secrets");
    return jsSecrets?.evidence?.findings || [];
  }, [selected]);

  // File import
  function onFilesChosen(event) {
    const files = Array.from(event.target.files || []);
    if (!files.length) return;
    Promise.all(
      files.map(async (file) => {
        const text = await file.text();
        const parsed = JSON.parse(text);
        return normalizeReport(parsed, file.name);
      })
    )
      .then((loaded) => {
        setReports(loaded);
        setSelectedTarget(loaded[0]?.target || "");
        setActiveTab("dashboard");
      })
      .catch((err) => alert(`Failed to parse reports: ${err.message}`));
  }

  function parseKeyValueLines(text, separator) {
    const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
    const out = {};
    for (const line of lines) {
      const idx = line.indexOf(separator);
      if (idx === -1) continue;
      out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    }
    return out;
  }

  // Run scan
  async function runScan() {
    if (!targetInput.trim()) { alert("Enter a target."); return; }
    const payload = {
      target: targetInput.trim(),
      timeout: Number(scanTimeout) || 8,
      auth_headers: parseKeyValueLines(headersText, ":"),
      auth_cookies: parseKeyValueLines(cookiesText, "="),
      bearer_token: bearerToken.trim() || null,
      max_pages: Number(maxPages) || 20,
      max_depth: Number(maxDepth) || 2,
      enable_nuclei: Boolean(enableNuclei),
      nuclei_templates: nucleiTemplates.trim() || null,
      nuclei_severities: nucleiSeverities.split(",").map((x) => x.trim()).filter(Boolean),
      nuclei_tags: nucleiTags.split(",").map((x) => x.trim()).filter(Boolean),
      zap_base_url: zapBaseUrl.trim() || null,
      auth_login_url: authLoginUrl.trim() || null,
      auth_login_method: authLoginMethod.trim() || "POST",
      auth_login_form: parseKeyValueLines(authLoginForm, "="),
      auth_login_json: authLoginJson.trim() ? JSON.parse(authLoginJson) : {},
      write_report: true,
      out_dir: "reports",
      mode: scanMode,
      workers: Number(workers) || 8,
      rate_limit_rps: Number(rateLimit) || 15,
    };

    setIsScanning(true);
    try {
      const response = await fetch(`${apiBase}/scan/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!response.ok) throw new Error(`API error: ${response.status}`);
      const data = await response.json();
      const jobId = data.job_id;
      setJobStatus({
        job_id: jobId, status: "running", progress: 0,
        estimate_seconds: data.estimate_seconds, elapsed_seconds: 0, logs: [],
      });

      const poll = async () => {
        const statusResp = await fetch(`${apiBase}/scan/status/${jobId}`);
        if (!statusResp.ok) return;
        const statusData = await statusResp.json();
        setJobStatus(statusData);
        if (statusData.status === "complete") {
          const report = normalizeReport(statusData.report, statusData.saved_path || payload.target);
          setReports((prev) => [report, ...prev.filter((i) => i.target !== report.target)]);
          setSelectedTarget(report.target);
          setIsScanning(false);
          setActiveTab("dashboard");
          return;
        }
        if (statusData.status !== "missing") {
          window.setTimeout(poll, 1200);
        }
      };
      window.setTimeout(poll, 1200);
    } catch (err) {
      alert(`Scan failed: ${err.message}`);
      setIsScanning(false);
    }
  }

  // Programs
  const fetchPrograms = useCallback(async () => {
    try {
      const resp = await fetch(`${apiBase}/programs`);
      if (resp.ok) setPrograms(await resp.json());
    } catch { /* ignore */ }
  }, [apiBase]);

  async function addProgram() {
    try {
      await fetch(`${apiBase}/programs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...newProgram,
          in_scope: newProgram.in_scope.split(",").map((s) => s.trim()).filter(Boolean),
          out_scope: newProgram.out_scope.split(",").map((s) => s.trim()).filter(Boolean),
        }),
      });
      setShowAddProgram(false);
      setNewProgram({ name: "", platform: "custom", url: "", in_scope: "", out_scope: "", notes: "" });
      fetchPrograms();
    } catch (err) { alert(`Failed: ${err.message}`); }
  }

  async function deleteProgram(name) {
    if (!confirm(`Delete program "${name}"?`)) return;
    try {
      await fetch(`${apiBase}/programs/${encodeURIComponent(name)}`, { method: "DELETE" });
      fetchPrograms();
    } catch { /* ignore */ }
  }

  async function scanProgram(program) {
    setTargetInput(program.in_scope?.[0] || "");
    setScanMode("bounty");
    setActiveTab("scan");
  }

  // Copy finding report
  async function copyFindingReport(result, target) {
    try {
      const resp = await fetch(`${apiBase}/reports/finding`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, finding_name: result.name }),
      });
      if (resp.ok) {
        const data = await resp.json();
        await navigator.clipboard.writeText(data.markdown);
        setCopiedId(result.name);
        window.setTimeout(() => setCopiedId(null), 2000);
      }
    } catch {
      // Fallback: simple copy
      const text = `## ${result.name}\nSeverity: ${result.severity}\n\n${result.details}\n\nEvidence:\n${prettyJson(result.evidence)}`;
      await navigator.clipboard.writeText(text);
      setCopiedId(result.name);
      window.setTimeout(() => setCopiedId(null), 2000);
    }
  }

  // Tab icon
  function tabIcon(tab) {
    const icons = { dashboard: "📊", scan: "🔍", programs: "🏆", secrets: "🔑" };
    return icons[tab] || "";
  }

  return (
    <div className="page">
      {/* Navigation */}
      <nav className="nav-tabs">
        {TABS.map((tab) => (
          <button
            key={tab}
            className={`nav-tab ${activeTab === tab ? "active" : ""}`}
            onClick={() => {
              setActiveTab(tab);
              if (tab === "programs") fetchPrograms();
            }}
          >
            {tabIcon(tab)} {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </nav>

      {/* Hero */}
      <header className="hero">
        <div>
          <p className="kicker">VAPT</p>
          <h1>Bug Bounty Command Center</h1>
          <p className="subtitle">
            All-in-one reconnaissance, vulnerability scanning, and bounty report generation for authorized bug bounty programs.
          </p>
          {reports.length > 0 && (
            <span className="mode-badge">
              {selected?.metadata?.mode === "bounty" ? "🐛 BOUNTY MODE" : "🛡 STANDARD MODE"}
            </span>
          )}
        </div>
        <label className="upload" id="import-reports-btn">
          <input type="file" accept=".json" multiple onChange={onFilesChosen} />
          <span>📂 Import Reports</span>
        </label>
      </header>

      {/* ═══ DASHBOARD TAB ═══ */}
      {activeTab === "dashboard" && (
        <>
          {/* KPI */}
          <section className="kpi-grid">
            <article>
              <h3>Targets Scanned</h3>
              <strong>{aggregate.targets}</strong>
            </article>
            <article>
              <h3>Total Risk Score</h3>
              <strong className="kpi-accent">{aggregate.risk}</strong>
            </article>
            <article>
              <h3>Total Findings</h3>
              <strong>{aggregate.findings}</strong>
            </article>
            <article>
              <h3>Warnings / Errors</h3>
              <strong>{aggregate.warning} / {aggregate.error}</strong>
            </article>
          </section>

          {/* Bounty Estimator */}
          {aggregate.findings > 0 && (
            <section className="bounty-summary">
              <div>
                <h3>💰 Estimated Bounty Range</h3>
                <div className="bounty-amount">
                  ${bountyEstimate.min.toLocaleString()} – ${bountyEstimate.max.toLocaleString()}
                </div>
              </div>
              <div className="bounty-breakdown">
                {severityOrder.map((sev) => {
                  const count = aggregate.severity[sev];
                  if (!count) return null;
                  return (
                    <div className="bounty-item" key={sev}>
                      <div className="count" style={{ color: `var(--${sev})` }}>{count}</div>
                      <div className="range">{sev.toUpperCase()}<br />{BOUNTY_RANGES[sev]}</div>
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          {/* Severity Chart */}
          <section className="chart-box">
            <h2>Severity Distribution</h2>
            <div className="bars">
              {severityOrder.map((key) => {
                const value = aggregate.severity[key];
                const max = Math.max(...severityOrder.map((k) => aggregate.severity[k]), 1);
                const pct = Math.max(6, Math.round((value / max) * 100));
                return (
                  <div className="bar-row" key={key}>
                    <span className="label" style={{ color: `var(--${key})` }}>{key.toUpperCase()}</span>
                    <div className="bar-track">
                      <div className={`bar ${key}`} style={{ width: `${pct}%` }} />
                    </div>
                    <span className="value">{value}</span>
                  </div>
                );
              })}
            </div>
          </section>

          {/* Target Detail */}
          {selected && (
            <>
              <section className="target-picker">
                <h2>Target Detail</h2>
                <select value={selected.target} onChange={(e) => setSelectedTarget(e.target.value)} id="target-selector">
                  {reports.map((r) => (
                    <option value={r.target} key={r.target}>{r.target}</option>
                  ))}
                </select>
                <div className={`risk-pill ${riskClass(selected.risk.level)}`}>
                  Risk: {selected.risk.level} ({selected.risk.score})
                </div>
              </section>

              <section className="meta">
                <div>
                  <h3>Target</h3>
                  <p>{selected.target}</p>
                </div>
                <div>
                  <h3>Resolved IPs</h3>
                  <p>{(selected.resolved_ips || []).join(", ") || "N/A"}</p>
                </div>
                <div>
                  <h3>Scan Mode</h3>
                  <p>{selected.metadata?.mode || "standard"}</p>
                </div>
                <div>
                  <h3>Generated (UTC)</h3>
                  <p>{selected.metadata?.generated_at_utc || "N/A"}</p>
                </div>
              </section>

              {/* Findings */}
              <section className="findings">
                <h2>Findings ({filteredResults.length})</h2>

                <div className="filter-bar">
                  {["all", ...severityOrder].map((f) => (
                    <button
                      key={f}
                      className={`filter-btn ${severityFilter === f ? `active ${f}` : ""}`}
                      onClick={() => setSeverityFilter(f)}
                    >
                      {f === "all" ? "All" : f.toUpperCase()}
                      {f !== "all" && ` (${selected.results.filter((r) => r.severity === f).length})`}
                    </button>
                  ))}
                </div>

                <div className="finding-grid">
                  {filteredResults.map((result) => (
                    <article className={`finding sev-${result.severity}`} key={result.name} id={`finding-${result.name}`}>
                      <div className="finding-top">
                        <h3>{result.name}</h3>
                        <span className={`badge ${result.severity}`}>{result.severity}</span>
                      </div>
                      <p className="status">
                        {result.status === "ok" ? "✓" : result.status === "warning" ? "⚠" : "✗"} {result.status}
                      </p>
                      <p>{result.details}</p>
                      {!!result.recommendations?.length && (
                        <ul>
                          {result.recommendations.map((rec, i) => <li key={i}>{rec}</li>)}
                        </ul>
                      )}
                      {!!result.evidence && (
                        <details>
                          <summary>Evidence</summary>
                          <pre>{prettyJson(result.evidence)}</pre>
                        </details>
                      )}
                      {result.status === "warning" && result.severity !== "info" && (
                        <div className="finding-actions">
                          <button
                            className={`btn-sm ${copiedId === result.name ? "copied" : ""}`}
                            onClick={() => copyFindingReport(result, selected.target)}
                          >
                            {copiedId === result.name ? "✓ Copied!" : "📋 Copy Report"}
                          </button>
                        </div>
                      )}
                    </article>
                  ))}
                </div>

                {filteredResults.length === 0 && (
                  <div className="empty-state">
                    <span className="icon">🔍</span>
                    <p>No findings match the selected filter.</p>
                  </div>
                )}
              </section>
            </>
          )}

          {!selected && (
            <div className="empty-state">
              <span className="icon">🚀</span>
              <p>Import JSON reports or run a scan to see results here.</p>
            </div>
          )}
        </>
      )}

      {/* ═══ SCAN TAB ═══ */}
      {activeTab === "scan" && (
        <section className="scan-panel">
          <div>
            <h2>🔍 Run Authorized Scan</h2>
            <p className="panel-note">
              Launch scans against authorized targets. Start the API server with: <code>py -m uvicorn vapt_tool.server:app --reload</code>
            </p>
          </div>

          {/* Mode selector */}
          <div className="mode-selector">
            <button
              className={`mode-btn ${scanMode === "standard" ? "active" : ""}`}
              onClick={() => setScanMode("standard")}
            >
              🛡 Standard Mode
            </button>
            <button
              className={`mode-btn bounty ${scanMode === "bounty" ? "active" : ""}`}
              onClick={() => setScanMode("bounty")}
            >
              🐛 Bounty Mode (Extended)
            </button>
          </div>

          <div className="scan-grid">
            <label>
              API Base URL
              <input value={apiBase} onChange={(e) => setApiBase(e.target.value)} placeholder={DEFAULT_API} />
            </label>
            <label>
              Target
              <input value={targetInput} onChange={(e) => setTargetInput(e.target.value)} placeholder="example.com" id="scan-target-input" />
            </label>
            <label>
              Timeout (seconds)
              <input type="number" min="1" max="60" value={scanTimeout} onChange={(e) => setScanTimeout(e.target.value)} />
            </label>
            <label>
              Workers (threads)
              <input type="number" min="1" max="32" value={workers} onChange={(e) => setWorkers(e.target.value)} />
            </label>
            <label>
              Rate Limit (req/s)
              <input type="number" min="1" max="100" value={rateLimit} onChange={(e) => setRateLimit(e.target.value)} />
            </label>
            <label>
              Max Pages (crawl)
              <input type="number" min="1" max="200" value={maxPages} onChange={(e) => setMaxPages(e.target.value)} />
            </label>
            <label>
              Max Depth (crawl)
              <input type="number" min="0" max="5" value={maxDepth} onChange={(e) => setMaxDepth(e.target.value)} />
            </label>
            <label>
              Auth Headers (Key:Value per line)
              <textarea value={headersText} onChange={(e) => setHeadersText(e.target.value)} rows="2" />
            </label>
            <label>
              Auth Cookies (key=value per line)
              <textarea value={cookiesText} onChange={(e) => setCookiesText(e.target.value)} rows="2" />
            </label>
            <label>
              Bearer Token
              <input value={bearerToken} onChange={(e) => setBearerToken(e.target.value)} placeholder="eyJ..." />
            </label>
            <label>
              Auth Login URL
              <input value={authLoginUrl} onChange={(e) => setAuthLoginUrl(e.target.value)} placeholder="https://example.com/login" />
            </label>
            <label>
              Auth Login Method
              <select value={authLoginMethod} onChange={(e) => setAuthLoginMethod(e.target.value)}>
                <option>POST</option>
                <option>GET</option>
                <option>PUT</option>
              </select>
            </label>
            <label>
              Auth Login Form (key=value per line)
              <textarea value={authLoginForm} onChange={(e) => setAuthLoginForm(e.target.value)} rows="2" />
            </label>
            <label>
              Auth Login JSON
              <textarea value={authLoginJson} onChange={(e) => setAuthLoginJson(e.target.value)} rows="2" placeholder='{"username":"user","password":"pass"}' />
            </label>
            <label className="checkbox">
              <input type="checkbox" checked={enableNuclei} onChange={(e) => setEnableNuclei(e.target.checked)} />
              Enable Nuclei (if installed)
            </label>
            <label>
              Nuclei Severities
              <input value={nucleiSeverities} onChange={(e) => setNucleiSeverities(e.target.value)} />
            </label>
            <label>
              ZAP Base URL
              <input value={zapBaseUrl} onChange={(e) => setZapBaseUrl(e.target.value)} placeholder="http://localhost:8080" />
            </label>
          </div>

          <button className="scan-button" onClick={runScan} disabled={isScanning} id="run-scan-btn">
            {isScanning ? "⏳ Scanning..." : scanMode === "bounty" ? "🐛 Run Bounty Scan" : "🛡 Run Scan"}
          </button>

          {jobStatus && (
            <div className="scan-status">
              <div><strong>Status:</strong> {jobStatus.status}</div>
              <div><strong>Progress:</strong> {jobStatus.progress}%</div>
              <div><strong>Est. Time:</strong> {jobStatus.estimate_seconds}s • <strong>Elapsed:</strong> {jobStatus.elapsed_seconds}s</div>
              <div className="progress-track">
                <div className="progress-bar" style={{ width: `${jobStatus.progress}%` }} />
              </div>
              {jobStatus.current_step && (
                <div><strong>Current:</strong> <span style={{ color: "var(--accent)" }}>{jobStatus.current_step}</span></div>
              )}
              <div className="scan-log">
                {(jobStatus.logs || []).map((log, index) => (
                  <div key={`${log.ts}-${index}`} className={`step-${log.state}`}>
                    {log.state === "done" ? "✓" : "▸"} {log.step}
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      {/* ═══ PROGRAMS TAB ═══ */}
      {activeTab === "programs" && (
        <section className="programs-panel">
          <h2>🏆 Bug Bounty Programs</h2>

          <div style={{ marginBottom: 16 }}>
            <button className="btn-sm" onClick={() => setShowAddProgram(!showAddProgram)} style={{ padding: "8px 20px", fontSize: "0.82rem" }}>
              {showAddProgram ? "✕ Cancel" : "＋ Add Program"}
            </button>
            <button className="btn-sm" onClick={fetchPrograms} style={{ padding: "8px 20px", fontSize: "0.82rem", marginLeft: 8 }}>
              ↻ Refresh
            </button>
          </div>

          {showAddProgram && (
            <div className="add-program-form">
              <h3>Add New Program</h3>
              <div className="form-row">
                <label>
                  Program Name
                  <input value={newProgram.name} onChange={(e) => setNewProgram({ ...newProgram, name: e.target.value })} placeholder="Example Corp" />
                </label>
                <label>
                  Platform
                  <select value={newProgram.platform} onChange={(e) => setNewProgram({ ...newProgram, platform: e.target.value })}>
                    <option value="hackerone">HackerOne</option>
                    <option value="bugcrowd">Bugcrowd</option>
                    <option value="intigriti">Intigriti</option>
                    <option value="custom">Custom</option>
                  </select>
                </label>
                <label>
                  Program URL
                  <input value={newProgram.url} onChange={(e) => setNewProgram({ ...newProgram, url: e.target.value })} placeholder="https://hackerone.com/example" />
                </label>
              </div>
              <div className="form-row">
                <label>
                  In-Scope Domains (comma-separated)
                  <textarea value={newProgram.in_scope} onChange={(e) => setNewProgram({ ...newProgram, in_scope: e.target.value })} rows="2" placeholder="example.com, api.example.com" />
                </label>
                <label>
                  Out-of-Scope (comma-separated)
                  <textarea value={newProgram.out_scope} onChange={(e) => setNewProgram({ ...newProgram, out_scope: e.target.value })} rows="2" placeholder="dev.example.com" />
                </label>
                <label>
                  Notes
                  <textarea value={newProgram.notes} onChange={(e) => setNewProgram({ ...newProgram, notes: e.target.value })} rows="2" placeholder="Focus areas, tips..." />
                </label>
              </div>
              <button className="scan-button" onClick={addProgram} style={{ marginTop: 8 }}>Save Program</button>
            </div>
          )}

          {programs.length === 0 && !showAddProgram && (
            <div className="empty-state">
              <span className="icon">🏆</span>
              <p>No programs saved. Add your first bug bounty program or start the API server to manage programs.</p>
            </div>
          )}

          <div className="program-grid">
            {programs.map((p) => (
              <article className="program-card" key={p.name}>
                <h3>{p.name}</h3>
                <span className={`platform-tag ${platformTag(p.platform)}`}>{p.platform}</span>
                <p className="scope-count">
                  {p.in_scope?.length || 0} in-scope • {p.out_scope?.length || 0} excluded
                </p>
                <p className="scope-list">
                  {(p.in_scope || []).slice(0, 5).join(", ")}
                  {(p.in_scope?.length || 0) > 5 ? ` +${p.in_scope.length - 5} more` : ""}
                </p>
                {p.notes && <p style={{ color: "var(--text-muted)", fontSize: "0.75rem", marginTop: 8 }}>{p.notes}</p>}
                <div className="program-actions">
                  <button className="btn-sm" onClick={() => scanProgram(p)}>🔍 Scan</button>
                  {p.url && <button className="btn-sm" onClick={() => window.open(p.url, "_blank")}>↗ Open</button>}
                  <button className="btn-sm" onClick={() => deleteProgram(p.name)} style={{ borderColor: "var(--critical)", color: "var(--critical)" }}>✕ Delete</button>
                </div>
              </article>
            ))}
          </div>
        </section>
      )}

      {/* ═══ SECRETS TAB ═══ */}
      {activeTab === "secrets" && (
        <section className="secrets-panel">
          <h2>🔑 Discovered Secrets</h2>

          {secrets.length === 0 && (
            <div className="empty-state">
              <span className="icon">🔐</span>
              <p>No secrets found yet. Run a bounty-mode scan to discover leaked API keys and tokens in JavaScript files.</p>
            </div>
          )}

          {secrets.map((s, i) => (
            <div className="secret-item" key={i}>
              <div>
                <div className="secret-type">{s.type}</div>
                <div className="secret-value">{s.match}</div>
                <div className="secret-source">Source: {s.source}</div>
                {s.context && (
                  <div className="secret-source" style={{ marginTop: 4 }}>Context: ...{s.context}...</div>
                )}
              </div>
              <button
                className="btn-sm"
                onClick={async () => {
                  await navigator.clipboard.writeText(s.match);
                  setCopiedId(`secret-${i}`);
                  window.setTimeout(() => setCopiedId(null), 2000);
                }}
              >
                {copiedId === `secret-${i}` ? "✓" : "📋"}
              </button>
            </div>
          ))}
        </section>
      )}
    </div>
  );
}
