import { useState, useEffect, useRef, useCallback } from 'react';
import { fetchHealth, fetchTools, sendChat, parseSSE } from './api';
import Sidebar from './components/Sidebar';

function App() {
  const [messages, setMessages] = useState([
    {
      role: 'system',
      content: 'Welcome to Kali AI — Autonomous Cybersecurity Operator.\nProvide an authorized target and security objective to begin (e.g., "Perform a basic security assessment of my test website").',
    },
  ]);
  const [input, setInput] = useState('');
  const [target, setTarget] = useState('localhost');
  const [isRunning, setIsRunning] = useState(false);
  const [demoMode, setDemoMode] = useState(true);
  const [connected, setConnected] = useState(false);
  const [tools, setTools] = useState([]);
  const [events, setEvents] = useState([]);
  const [findings, setFindings] = useState([]);
  const [plan, setPlan] = useState(null);
  const [activeTab, setActiveTab] = useState('activity');

  const messagesEndRef = useRef(null);

  useEffect(() => {
    fetchHealth()
      .then((data) => {
        setConnected(true);
        setDemoMode(data.demo_mode);
      })
      .catch(() => setConnected(false));

    fetchTools()
      .then((data) => setTools(data.tools || []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSend = useCallback(async () => {
    const msg = input.trim();
    if (!msg || isRunning) return;

    setInput('');
    setIsRunning(true);
    setEvents([]);
    setFindings([]);
    setPlan(null);

    setMessages((prev) => [...prev, { role: 'user', content: msg }]);
    setMessages((prev) => [
      ...prev,
      { role: 'loading', content: 'Analyzing objective & planning assessment...' },
    ]);

    try {
      const reader = await sendChat(msg, target);
      let finalReport = '';

      for await (const event of parseSSE(reader)) {
        setEvents((prev) => [...prev, event]);

        switch (event.event_type) {
          case 'thinking':
            setMessages((prev) => {
              const copy = [...prev];
              const idx = copy.findLastIndex((m) => m.role === 'loading');
              if (idx >= 0) {
                copy[idx] = { role: 'loading', content: event.data.message || 'Reasoning...' };
              }
              return copy;
            });
            break;

          case 'plan':
            setPlan(event.data.plan);
            setMessages((prev) => {
              const copy = prev.filter((m) => m.role !== 'loading');
              return [
                ...copy,
                { role: 'assistant', content: `📋 **AI Assessment Plan**:\n${event.data.plan}` },
                { role: 'loading', content: 'Selecting first approved security tool...' },
              ];
            });
            break;

          case 'tool_start':
            setMessages((prev) => {
              const copy = [...prev];
              const idx = copy.findLastIndex((m) => m.role === 'loading');
              const reason = event.data.ai_reasoning ? `\n_${event.data.ai_reasoning}_` : '';
              if (idx >= 0) {
                copy[idx] = {
                  role: 'loading',
                  content: `🔧 Executing ${event.data.tool_id}...${reason}`,
                };
              }
              return copy;
            });
            break;

          case 'tool_result': {
            const success = event.data.success;
            const toolId = event.data.tool_id;
            const time = event.data.execution_time;
            const extracted = event.data.findings_extracted || 0;
            const summary = `${success ? '✅' : '❌'} **${toolId}** finished in ${time}s (${extracted} findings identified)`;
            setMessages((prev) => {
              const copy = prev.filter((m) => m.role !== 'loading');
              return [
                ...copy,
                { role: 'assistant', content: summary },
                { role: 'loading', content: 'Analyzing evidence & deciding next action...' },
              ];
            });
            break;
          }

          case 'finding':
            if (event.data.findings) {
              setFindings(event.data.findings);
            }
            break;

          case 'validation_failed':
            setMessages((prev) => {
              const copy = prev.filter((m) => m.role !== 'loading');
              return [
                ...copy,
                {
                  role: 'assistant',
                  content: `⛔ **Security Validation Blocked Action**:\n${(event.data.errors || []).join('\n')}`,
                },
                { role: 'loading', content: 'Adapting to validation boundary...' },
              ];
            });
            break;

          case 'complete':
            finalReport = event.data.report || '';
            break;

          case 'error':
            setMessages((prev) => {
              const copy = prev.filter((m) => m.role !== 'loading');
              return [
                ...copy,
                { role: 'assistant', content: `❌ **Execution Error**: ${event.data.error}` },
              ];
            });
            break;

          default:
            break;
        }
      }

      setMessages((prev) => {
        const copy = prev.filter((m) => m.role !== 'loading');
        if (finalReport) {
          return [...copy, { role: 'assistant', content: finalReport }];
        }
        return copy;
      });
    } catch (err) {
      setMessages((prev) => {
        const copy = prev.filter((m) => m.role !== 'loading');
        return [
          ...copy,
          {
            role: 'assistant',
            content: `❌ **Backend Unreachable**: ${err.message}. Ensure backend is running at http://localhost:8000.`,
          },
        ];
      });
    } finally {
      setIsRunning(false);
    }
  }, [input, target, isRunning]);

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div className="app-container">
      {/* ── Header ── */}
      <header className="header">
        <div className="header-left">
          <div className="header-logo">K</div>
          <div>
            <h1>Kali x Whiark AI</h1>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Autonomous Cybersecurity Operator (Chatbot: Kali AI)</div>
          </div>
        </div>
        <div className="header-right">
          {demoMode ? (
            <span className="demo-badge">Demo Mode (Mock Intelligence)</span>
          ) : (
            <span className="demo-badge" style={{ background: 'var(--accent-green)', color: '#fff' }}>
              Gemini API Connected
            </span>
          )}
          <div
            className="status-dot"
            style={{ background: connected ? 'var(--accent-green)' : 'var(--accent-red)' }}
            title={connected ? 'Backend Online' : 'Backend Offline'}
          />
        </div>
      </header>

      {/* ── Main Content Grid ── */}
      <div className="main-content">
        {/* ── Chat Panel ── */}
        <div className="chat-panel">
          <div className="chat-messages">
            {messages.map((msg, i) => {
              if (msg.role === 'loading') {
                return (
                  <div key={i} className="loading-message">
                    <div className="spinner" />
                    <span>{msg.content}</span>
                  </div>
                );
              }
              return (
                <div key={i} className={`message message-${msg.role}`}>
                  {msg.content}
                </div>
              );
            })}
            <div ref={messagesEndRef} />
          </div>

          <div className="chat-input-area">
            <div className="chat-input-row">
              <input
                className="target-input"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="Target (e.g. localhost, 127.0.0.1)"
                disabled={isRunning}
              />
              <input
                className="chat-input"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Enter security objective (e.g. 'Perform a basic security assessment of my test website')..."
                disabled={isRunning}
              />
              <button
                className="send-btn"
                onClick={handleSend}
                disabled={isRunning || !input.trim()}
              >
                {isRunning ? <div className="spinner" /> : '▶'}
                {isRunning ? 'Analyzing...' : 'Execute'}
              </button>
            </div>
          </div>
        </div>

        {/* ── Right Dashboard Sidebar ── */}
        <Sidebar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          events={events}
          tools={tools}
          findings={findings}
          plan={plan}
          demoMode={demoMode}
        />
      </div>
    </div>
  );
}

export default App;
