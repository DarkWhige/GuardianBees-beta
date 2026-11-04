import { useEffect, useState } from "react";

const API_URL =
  import.meta.env.VITE_API_URL ||
  `${window.location.protocol}//${window.location.hostname}:8000`;

const defaultAlert = {
  src_ip: "192.168.1.50",
  window_start: new Date().toISOString(),
  score: 1.5,
  requests: 120,
  n_ports: 18,
  n_dst: 12,
  n_proto: 2,
  bytes: 250000,
  syn_requests: 80,
  outgoing_requests: 120,
  local_requests: 0,
  n_dns_queries: 35,
  dns_queries: "example.com, suspicious.test",
};

async function request(path, options = {}) {
  const response = await fetch(`${API_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const body = await response.json();
  if (!response.ok) {
    throw new Error(body.detail || `Request failed (${response.status})`);
  }
  return body;
}

export default function App() {
  const [health, setHealth] = useState("checking");
  const [status, setStatus] = useState(null);
  const [behaviors, setBehaviors] = useState([]);
  const [alert, setAlert] = useState(defaultAlert);
  const [analysis, setAnalysis] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function refresh() {
    try {
      const [healthResult, statusResult, behaviorResult] = await Promise.all([
        request("/health"),
        request("/analyzer/status"),
        request("/ai/normal-behaviors"),
      ]);
      setHealth(healthResult.status);
      setStatus(statusResult);
      setBehaviors(behaviorResult.behaviors || []);
      setError("");
    } catch (requestError) {
      setHealth("offline");
      setError(requestError.message);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function analyze(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await request("/ai/test", {
        method: "POST",
        body: JSON.stringify(alert),
      });
      setAnalysis(result);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  async function markNormal() {
    setBusy(true);
    setError("");
    try {
      await request("/ai/normal-behaviors", {
        method: "POST",
        body: JSON.stringify(alert),
      });
      await refresh();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  function updateField(event) {
    const { name, value } = event.target;
    setAlert((current) => ({
      ...current,
      [name]: ["score", "requests", "n_ports", "n_dst", "n_proto", "bytes",
        "syn_requests", "outgoing_requests", "local_requests", "n_dns_queries"]
        .includes(name) ? Number(value) : value,
    }));
  }

  return (
    <main className="shell">
      <header className="header">
        <div>
          <p className="eyebrow">NETWORK SECURITY</p>
          <h1>GuardianBees</h1>
          <p className="subtitle">Anomaly detection and AI-assisted triage</p>
        </div>
        <div className={`status ${health === "ok" ? "online" : "offline"}`}>
          <span />
          Backend {health}
        </div>
      </header>

      {error && <div className="error">{error}</div>}

      <section className="grid">
        <article className="card overview">
          <div className="card-title">
            <h2>Detector</h2>
            <button onClick={refresh} className="secondary">Refresh</button>
          </div>
          <div className="metrics">
            <div><strong>{status?.trained ? "Ready" : "Not trained"}</strong><span>Model status</span></div>
            <div><strong>{status?.training_records ?? "—"}</strong><span>Training records</span></div>
            <div><strong>{behaviors.length}</strong><span>Normal behaviors</span></div>
          </div>
        </article>

        <article className="card">
          <div className="card-title">
            <h2>Meta analysis</h2>
            <span className="tag">muse-spark</span>
          </div>
          <form onSubmit={analyze}>
            <div className="form-grid">
              <label>Source IP<input name="src_ip" value={alert.src_ip} onChange={updateField} /></label>
              <label>Anomaly score<input name="score" type="number" step="0.1" value={alert.score} onChange={updateField} /></label>
              <label>Requests<input name="requests" type="number" value={alert.requests} onChange={updateField} /></label>
              <label>Unique ports<input name="n_ports" type="number" value={alert.n_ports} onChange={updateField} /></label>
              <label>Destinations<input name="n_dst" type="number" value={alert.n_dst} onChange={updateField} /></label>
              <label>Bytes<input name="bytes" type="number" value={alert.bytes} onChange={updateField} /></label>
            </div>
            <label>DNS queries<input name="dns_queries" value={alert.dns_queries} onChange={updateField} /></label>
            <div className="actions">
              <button disabled={busy}>{busy ? "Analyzing..." : "Analyze alert"}</button>
              <button type="button" className="secondary" onClick={markNormal} disabled={busy}>Mark as normal</button>
            </div>
          </form>
        </article>

        <article className="card result">
          <div className="card-title"><h2>Assessment</h2></div>
          {analysis ? (
            <div className="assessment">
              <div className="score">{analysis.analysis.danger_score}<small>/10</small></div>
              <div><span className="severity">{analysis.analysis.severity}</span><p>{analysis.analysis.summary}</p></div>
              <div className="action"><strong>Recommended action</strong><span>{analysis.analysis.action}</span></div>
            </div>
          ) : <p className="empty">Run an analysis to see the AI assessment.</p>}
        </article>
      </section>

      <section className="card list">
        <div className="card-title"><h2>Normal behavior allow-list</h2><span className="muted">{behaviors.length} saved</span></div>
        {behaviors.length === 0 ? <p className="empty">No behavior has been approved yet.</p> : (
          <div className="behavior-list">{behaviors.map((behavior, index) => (
            <div className="behavior" key={index}><strong>{behavior.source_ip}</strong><code>{JSON.stringify(behavior.observed)}</code></div>
          ))}</div>
        )}
      </section>
    </main>
  );
}
