import { useEffect, useState } from "react";

const API_URL =
  import.meta.env.VITE_API_URL ||
  `${window.location.protocol}//${window.location.hostname}:8000`;

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
  const [windowData, setWindowData] = useState({ window_start: null, records: [] });
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState("");
  const [savingIp, setSavingIp] = useState(null);
  async function refresh() {
    try {
      const [healthResult, statusResult, behaviorResult, windowResult, alertsResult] = await Promise.all([
        request("/health"),
        request("/analyzer/status"),
        request("/ai/normal-behaviors"),
        request("/analyzer/window"),
        request("/analyzer/alerts"),
      ]);
      setHealth(healthResult.status);
      setStatus(statusResult);
      setBehaviors(behaviorResult.behaviors || []);
      setWindowData(windowResult);
      setAlerts(alertsResult.alerts || []);
      setError("");
    } catch (requestError) {
      setHealth("offline");
      setError(requestError.message);
    }
  }

  useEffect(() => {
    refresh();
    const interval = window.setInterval(refresh, 5000);
    return () => window.clearInterval(interval);
  }, []);

  async function markFalseAlert(record) {
    setSavingIp(record.src_ip);
    setError("");
    try {
      await request("/ai/normal-behaviors", {
        method: "POST",
        body: JSON.stringify({
          src_ip: record.src_ip,
          window_start: record.window_start,
          requests: record.requests,
          n_ports: record.n_ports,
          n_dst: record.n_dst,
          n_proto: record.n_proto,
          bytes: record.bytes,
          syn_requests: record.syn_requests,
          outgoing_requests: record.outgoing_requests,
          local_requests: record.local_requests,
          n_dns_queries: record.n_dns_queries,
          dns_queries: record.dns_queries || "",
        }),
      });
      await request(`/analyzer/alerts/${encodeURIComponent(record.src_ip)}/resolve`, {
        method: "POST",
      });
      await refresh();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setSavingIp(null);
    }
  }

  async function resolveAlert(record) {
      setSavingIp(record.src_ip);
      setError("");
      try {
        await request(`/analyzer/alerts/${encodeURIComponent(record.src_ip)}/resolve`, {
          method: "POST",
        });
        await refresh();
      } catch (requestError) {
        setError(requestError.message);
      } finally {
        setSavingIp(null);
    }
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

        <article className="card batch-card">
          <div className="card-title">
            <div>
              <h2>Meta analysis</h2>
              <p className="card-caption">Latest 30-second batch</p>
            </div>
            <span className="tag">{windowData.records.length} IP</span>
          </div>
          {windowData.records.length === 0 ? <p className="empty">No traffic in the latest batch.</p> : (
            <div className="window-list">
              {windowData.records.map((record) => (
                <div className="window-row" key={`${record.src_ip}-${record.window_start}`}>
                  <strong>{record.src_ip}</strong>
                  <span className={`event ${record.status}`}>
                    {record.status === "meta-error" ? "Meta error" : record.status === "ai-alert" ? "AI alert" : record.status === "anomaly" ? "Alert detected" : "Normal traffic"}
                  </span>
                  <span>{record.requests} requests · {record.n_ports} ports · {record.n_dst} destinations</span>
                  <span className="danger-score">{record.danger_score_pct}%</span>
                </div>
              ))}
            </div>
          )}
        </article>
      </section>

      <section className="alerts-panel">
        <div className="card-title">
          <div>
            <h2>Detected alerts</h2>
            <p className="card-caption">Details of behaviors requiring your attention</p>
          </div>
          <span className="alert-count">{alerts.length}</span>
        </div>
        {alerts.length === 0 ? <p className="empty">No active alerts.</p> : (
          <div className="alert-list">
            {alerts.map((record) => (
              <article className={`alert-card ${record.status}`} key={`alert-${record.src_ip}-${record.window_start}`}>
                <div className="alert-card-header">
                  <div>
                    <span className="alert-label">
                      {record.status === "meta-error" ? "Meta error" : record.status === "ai-alert" ? "AI alert" : "Detected anomaly"}
                    </span>
                    <h3>{record.src_ip}</h3>
                  </div>
                  <div className="alert-score">
                    <strong>{record.danger_score_pct}%</strong>
                    <span>danger score</span>
                  </div>
                </div>
                <div className="alert-facts">
                  <span><strong>{record.requests}</strong> requests</span>
                  <span><strong>{record.n_ports}</strong> ports</span>
                  <span><strong>{record.n_dst}</strong> destinations</span>
                  <span><strong>{record.bytes}</strong> bytes</span>
                </div>
                <div className="alert-content">
                  <p><strong>Description</strong>{record.description}</p>
                  <p><strong>IP owner</strong>{record.ip_owner || "Unknown organization"}</p>
                  <p><strong>Direction</strong>{record.traffic_direction || "Unknown"}</p>
                  <p><strong>Destination ports</strong>{record.dst_ports || "Unknown"}</p>
                  {record.threat_indicators?.length > 0 && (
                    <p><strong>Indicators</strong>{record.threat_indicators.join(" · ")}</p>
                  )}
                  <p><strong>Meta summary</strong>{record.summary || "Meta AI unavailable or provided no confirmation."}</p>
                  <p><strong>Severity</strong>{record.severity || "Unconfirmed"}</p>
                  <p><strong>Recommended action</strong>{record.action || "Check this IP address."}</p>
                </div>
                <div className="alert-actions">
                  <button
                    className="secondary"
                    onClick={() => markFalseAlert(record)}
                    disabled={savingIp === record.src_ip}
                  >
                    {savingIp === record.src_ip ? "Saving..." : "False alert"}
                  </button>
                </div>
              </article>
            ))}
          </div>
        )}
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
