const API_BASE = 'http://localhost:8000/api';

/**
 * Fetch health status
 */
export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

/**
 * Fetch registered tools
 */
export async function fetchTools() {
  const res = await fetch(`${API_BASE}/tools`);
  return res.json();
}

/**
 * Fetch past assessments
 */
export async function fetchAssessments() {
  const res = await fetch(`${API_BASE}/assessments`);
  return res.json();
}

/**
 * Fetch a single assessment
 */
export async function fetchAssessment(id) {
  const res = await fetch(`${API_BASE}/assessments/${id}`);
  return res.json();
}

/**
 * Send a chat message and return an SSE reader.
 * The caller iterates the reader to get AgentEvents.
 */
export async function sendChat(message, target) {
  const res = await fetch(`${API_BASE}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, target: target || null }),
  });

  if (!res.ok) {
    throw new Error(`Chat request failed: ${res.status}`);
  }

  return res.body.getReader();
}

/**
 * Parse SSE chunks from a ReadableStream reader.
 * Yields parsed JSON objects from "data: {...}" lines.
 */
export async function* parseSSE(reader) {
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('data: ')) {
        try {
          const json = JSON.parse(trimmed.slice(6));
          yield json;
        } catch {
          // Skip malformed JSON
        }
      }
    }
  }
}
