import { useState, useEffect } from 'react';

/**
 * Sidebar — right panel with tabs: Plan, Activity, Tools, Findings, History
 */
function Sidebar({ activeTab, setActiveTab, events, tools, findings, plan, demoMode }) {
  const tabs = [
    { id: 'plan', label: 'Plan' },
    { id: 'activity', label: 'Activity' },
    { id: 'findings', label: `Findings (${findings.length})` },
    { id: 'tools', label: `Tools (${tools.length})` },
    { id: 'history', label: 'History' },
  ];

  return (
    <div className="sidebar">
      <div className="sidebar-tabs">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            className={`sidebar-tab ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="sidebar-content">
        {activeTab === 'plan' && <PlanPanel plan={plan} events={events} />}
        {activeTab === 'activity' && <ActivityPanel events={events} />}
        {activeTab === 'findings' && <FindingsPanel findings={findings} />}
        {activeTab === 'tools' && <ToolsPanel tools={tools} />}
        {activeTab === 'history' && <HistoryPanel />}
      </div>
    </div>
  );
}

// ── Plan Panel ──
function PlanPanel({ plan, events }) {
  if (!plan) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">📋</div>
        <p>No assessment plan active. Send an objective in chat to have the AI formulate a tailored assessment plan.</p>
      </div>
    );
  }

  return (
    <div>
      <div className="card" style={{ borderColor: 'var(--accent-blue)' }}>
        <div className="card-header">
          <span className="card-title" style={{ color: 'var(--accent-cyan)' }}>AI Assessment Plan</span>
          <span className="severity-badge informational">Active</span>
        </div>
        <div style={{ fontSize: '0.82rem', lineHeight: '1.6', whiteSpace: 'pre-wrap', color: 'var(--text-secondary)' }}>
          {plan}
        </div>
      </div>
      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
        Kali AI adapts this plan dynamically based on actual tool outputs.
      </div>
    </div>
  );
}

// ── Activity Timeline ──
function ActivityPanel({ events }) {
  if (events.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">📡</div>
        <p>No activity yet. Execute an objective to observe autonomous agent decisions in real time.</p>
      </div>
    );
  }

  return (
    <div className="timeline">
      {events.map((event, i) => (
        <TimelineItem key={i} event={event} />
      ))}
    </div>
  );
}

function TimelineItem({ event }) {
  const { event_type, data } = event;

  const labels = {
    assessment_start: 'Assessment Started',
    thinking: 'Thinking & Decision',
    plan: 'Plan Formulated',
    tool_start: 'Tool Executing',
    tool_result: 'Tool Completed',
    finding: 'Finding Discovered',
    validation_failed: 'Security Validation Block',
    complete: 'Assessment Complete',
    error: 'System Error',
    assessment_end: 'Assessment Finalized',
  };

  let description = '';
  switch (event_type) {
    case 'assessment_start':
      description = `Target: ${data.target || 'localhost'} | Objective: ${data.objective || ''}`;
      break;
    case 'thinking':
      description = data.message || 'Evaluating next action...';
      break;
    case 'plan':
      description = (data.plan || '').slice(0, 140) + '...';
      break;
    case 'tool_start':
      description = `Invoked ${data.tool_id} (Step ${data.step})`;
      if (data.ai_reasoning) {
        description += ` — ${data.ai_reasoning}`;
      }
      break;
    case 'tool_result':
      description = `${data.tool_id}: ${data.success ? 'Success' : 'Failed'} (${data.execution_time}s)`;
      if (data.findings_extracted) {
        description += ` • ${data.findings_extracted} finding(s) normalized`;
      }
      break;
    case 'finding':
      description = `${data.new_count || 1} new finding(s) correlated (Total: ${data.total_count})`;
      break;
    case 'validation_failed':
      description = `Blocked ${data.tool_id}: ${(data.errors || []).join('; ')}`;
      break;
    case 'complete':
      description = `Report compiled with ${data.total_tool_calls || 0} tool runs and ${data.total_findings || 0} findings.`;
      break;
    case 'error':
      description = data.error || 'Unknown runtime error';
      break;
    case 'assessment_end':
      description = `Completed ${data.total_steps || 0} steps with status '${data.status}'.`;
      break;
    default:
      description = JSON.stringify(data).slice(0, 100);
  }

  return (
    <div className="timeline-item">
      <div className={`timeline-dot ${event_type}`} />
      <div className="timeline-label">{labels[event_type] || event_type}</div>
      <div className="timeline-text">{description}</div>
    </div>
  );
}

// ── Findings Panel ──
function FindingsPanel({ findings }) {
  if (!findings || findings.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">🔍</div>
        <p>No findings recorded yet. Execute an assessment to discover and correlate security issues.</p>
      </div>
    );
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const f of findings) {
    const sev = (f.severity || 'informational').toLowerCase();
    counts[sev] = (counts[sev] || 0) + 1;
  }

  return (
    <div>
      <div style={{ display: 'flex', gap: '0.4rem', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
        {Object.entries(counts).map(([sev, count]) => {
          if (count === 0) return null;
          return (
            <span key={sev} className={`severity-badge ${sev}`}>
              {sev}: {count}
            </span>
          );
        })}
      </div>

      {findings.map((f, i) => (
        <div key={f.id || i} className={`finding-card ${f.severity}`}>
          <div className="card-header">
            <span className="card-title" style={{ fontSize: '0.78rem' }}>{f.title}</span>
            <span className={`severity-badge ${f.severity}`}>{f.severity}</span>
          </div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
            Asset: <code style={{ color: 'var(--accent-cyan)' }}>{f.affected_asset}</code> • Tool: {f.source_tool}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '0.3rem', lineHeight: '1.4' }}>
            {f.description}
          </div>
          {f.evidence && f.evidence.length > 0 && (
            <div style={{ marginTop: '0.4rem', padding: '0.35rem 0.5rem', background: 'var(--bg-secondary)', borderRadius: '4px', fontSize: '0.68rem', color: 'var(--text-muted)' }}>
              <strong>Evidence:</strong> {f.evidence.join(' | ')}
            </div>
          )}
          {f.remediation && (
            <div style={{ marginTop: '0.3rem', fontSize: '0.68rem', color: 'var(--accent-green)' }}>
              💡 <strong>Remediation:</strong> {f.remediation}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Tools Panel ──
function ToolsPanel({ tools }) {
  if (!tools || tools.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">🔧</div>
        <p>Loading security tools registry...</p>
      </div>
    );
  }

  const iconLetters = {
    nmap_scan: 'NM',
    whatweb_scan: 'WW',
    nuclei_scan: 'NC',
    nikto_scan: 'NK',
    sslyze_scan: 'SL',
    zap_scan: 'ZP',
    gobuster_scan: 'GB',
  };

  return (
    <div>
      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
        {tools.length} security tools registered with native function schemas
      </div>
      {tools.map((tool) => (
        <div key={tool.id} className="tool-card">
          <div className={`tool-icon ${tool.category}`}>
            {iconLetters[tool.id] || tool.id.slice(0, 2).toUpperCase()}
          </div>
          <div className="tool-info">
            <div className="tool-name">{tool.name}</div>
            <div className="tool-desc">{tool.description}</div>
          </div>
          <span className={`tool-status ${tool.status}`}>{tool.status}</span>
        </div>
      ))}
    </div>
  );
}

// ── History Panel ──
function HistoryPanel() {
  const [assessments, setAssessments] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('http://localhost:8000/api/assessments')
      .then((r) => r.json())
      .then((data) => {
        setAssessments(data.assessments || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="empty-state">
        <div className="spinner" />
      </div>
    );
  }

  if (assessments.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">📜</div>
        <p>No past assessments found in SQLite database.</p>
      </div>
    );
  }

  return (
    <div>
      {assessments.map((a) => (
        <div key={a.id} className="card">
          <div className="card-title" style={{ fontSize: '0.8rem' }}>{a.objective}</div>
          <div className="card-subtitle" style={{ fontSize: '0.7rem', marginTop: '0.2rem' }}>
            Status: <strong>{a.status}</strong> • {new Date(a.created_at).toLocaleString()}
          </div>
          <div className="card-subtitle" style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)' }}>
            {a.steps?.length || 0} steps executed • {a.findings?.length || 0} findings correlated
          </div>
        </div>
      ))}
    </div>
  );
}

export default Sidebar;
