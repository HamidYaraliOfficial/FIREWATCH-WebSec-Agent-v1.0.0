import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

const API = import.meta.env.VITE_API_BASE || 'http://localhost:8000';

function Badge({ children, level }) {
  return React.createElement('span', { className: `badge ${level || ''}` }, children);
}

function App() {
  const [scans, setScans] = useState([]);
  const [url, setUrl] = useState('http://127.0.0.1:9000/');
  const [message, setMessage] = useState('');
  const [selected, setSelected] = useState(null);
  const [findings, setFindings] = useState([]);
  const [busy, setBusy] = useState(false);

  async function refresh() {
    const r = await fetch(`${API}/api/v1/scans`);
    setScans(await r.json());
  }

  useEffect(() => { refresh().catch(e => setMessage(e.message)); }, []);

  useEffect(() => {
    const timer = setInterval(() => refresh().catch(() => {}), 3000);
    return () => clearInterval(timer);
  }, []);

  async function createScan(e) {
    e.preventDefault();
    setBusy(true); setMessage('Submitting scan...');
    try {
      const r = await fetch(`${API}/api/v1/scans`, {
        method: 'POST', headers: {'content-type': 'application/json'},
        body: JSON.stringify({ target_url: url, max_pages: 50, max_depth: 4, passive_only: true })
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail || 'Failed to create scan');
      setMessage(`Scan ${data.id} queued.`);
      await refresh();
    } catch (e) { setMessage(e.message); }
    finally { setBusy(false); }
  }

  async function selectScan(scan) {
    setSelected(scan);
    try {
      const r = await fetch(`${API}/api/v1/scans/${scan.id}/findings`);
      setFindings(await r.json());
    } catch (e) { setFindings([]); setMessage(e.message); }
  }

  const counts = useMemo(() => {
    return findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {});
  }, [findings]);

  return React.createElement('div', {className:'app'},
    React.createElement('header', {className:'topbar'},
      React.createElement('div', null,
        React.createElement('div', {className:'brand'}, 'FIREWATCH'),
        React.createElement('div', {className:'sub'}, 'Web Security Agent · Authorized Testing')
      ),
      React.createElement('button', {onClick: refresh, className:'ghost'}, 'Refresh')
    ),
    React.createElement('main', {className:'content'},
      React.createElement('section', {className:'hero card'},
        React.createElement('div', null,
          React.createElement('h1', null, 'Security Assessment Console'),
          React.createElement('p', null, 'Deterministic discovery, evidence-driven findings, and auditable scan jobs.')
        ),
        React.createElement('form', {onSubmit:createScan, className:'scan-form'},
          React.createElement('input', {value:url, onChange:e=>setUrl(e.target.value), placeholder:'https://authorized-target.example'}),
          React.createElement('button', {disabled:busy, type:'submit'}, busy ? 'Queueing…' : 'Start Scan')
        ),
        React.createElement('div', {className:'message'}, message)
      ),
      React.createElement('section', {className:'grid'},
        React.createElement('div', {className:'card'},
          React.createElement('h2', null, 'Scans'),
          scans.length === 0 ? React.createElement('div', {className:'empty'}, 'No scans yet.') :
          scans.map(s => React.createElement('button', {key:s.id, onClick:()=>selectScan(s), className:`scan-row ${selected?.id===s.id?'active':''}`},
            React.createElement('div', {className:'scan-url'}, s.target_url),
            React.createElement('div', {className:'scan-meta'}, React.createElement(Badge,{level:s.status},s.status), React.createElement('span',null,new Date(s.created_at).toLocaleString()))
          ))
        ),
        React.createElement('div', {className:'card'},
          React.createElement('h2', null, selected ? 'Findings' : 'Select a scan'),
          selected && React.createElement('div', {className:'summary'},
            ['critical','high','medium','low','info'].map(k => React.createElement('div',{key:k,className:'metric'},React.createElement(Badge,{level:k},k.toUpperCase()),React.createElement('strong',null,counts[k]||0)))
          ),
          selected ? findings.map(f => React.createElement('article',{key:f.id,className:'finding'},
            React.createElement('div',{className:'finding-head'},React.createElement('h3',null,f.title),React.createElement(Badge,{level:f.severity},f.severity.toUpperCase())),
            React.createElement('div',{className:'finding-meta'},`${f.rule_id} · ${(f.confidence*100).toFixed(0)}% confidence · risk ${f.risk_score}`),
            React.createElement('div',{className:'endpoint'},f.endpoint),
            React.createElement('p',null,f.description),
            React.createElement('p',null,React.createElement('b',null,'Evidence: '),f.evidence_summary),
            React.createElement('p',null,React.createElement('b',null,'Remediation: '),f.remediation)
          )) : null
        )
      )
    )
  );
}

createRoot(document.getElementById('root')).render(React.createElement(App));
