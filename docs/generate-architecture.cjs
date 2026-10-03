// Rebuild the editable Excalidraw scene and its lightweight SVG preview.
// Run from the repository root: node docs/generate-architecture.cjs
const fs = require('node:fs');
const path = require('node:path');
const elements = [];
let n = 0;
const colors = { ink: '#1e293b', blue: '#1971c2', green: '#087f5b', orange: '#b86e00', red: '#c92a2a', muted: '#64748b' };
function base(type, x, y, width, height, extra = {}) {
  const id = `architecture-${++n}`;
  const e = { id, type, x, y, width, height, angle: 0, strokeColor: colors.ink,
    backgroundColor: 'transparent', fillStyle: 'solid', strokeWidth: 1.5,
    strokeStyle: 'solid', roughness: 0, opacity: 100, groupIds: [], frameId: null,
    roundness: null, seed: n * 7919, version: 1, versionNonce: n * 104729,
    isDeleted: false, boundElements: null, updated: 1791046800000, link: null,
    locked: false, ...extra };
  elements.push(e); return e;
}
function text(x, y, value, size = 20, color = colors.ink, groupIds = []) {
  const lines = value.split('\n');
  return base('text', x, y, Math.max(...lines.map(l => l.length)) * size * .59, lines.length * size * 1.3,
    { text: value, originalText: value, fontSize: size, fontFamily: 2, textAlign: 'left', verticalAlign: 'top',
      containerId: null, autoResize: true, lineHeight: 1.3, strokeColor: color, groupIds });
}
function card(x, y, w, h, title, body, tone = 'blue', planned = false) {
  const group = [`card-${n + 1}`];
  const fill = { blue: '#e7f5ff', green: '#e6fcf5', orange: '#fff4e6', red: '#fff5f5', muted: '#f1f5f9' }[tone];
  base('rectangle', x, y, w, h, { strokeColor: colors[tone], backgroundColor: fill,
    roundness: { type: 3 }, strokeStyle: planned ? 'dashed' : 'solid', groupIds: group });
  text(x + 22, y + 18, title, 24, colors[tone], group);
  text(x + 22, y + 61, body, 20, colors.ink, group);
}
function arrow(points, tone = 'blue', dashed = false) {
  const [x, y] = points[0];
  return base('arrow', x, y, Math.max(...points.map(p => p[0])) - Math.min(...points.map(p => p[0])),
    Math.max(...points.map(p => p[1])) - Math.min(...points.map(p => p[1])),
    { points: points.map(p => [p[0] - x, p[1] - y]), strokeColor: colors[tone],
      strokeStyle: dashed ? 'dashed' : 'solid', strokeWidth: 2, startBinding: null, endBinding: null,
      startArrowhead: null, endArrowhead: 'arrow', elbowed: false });
}

text(60, 35, 'PIKA / AI Control Layer', 44);
text(60, 95, 'Architecture • main @ 2ca033c + local demo integration • 03 October 2026', 22, colors.muted);
text(1510, 52, 'Solid = implemented\nDashed / amber = planned', 20, colors.muted);

card(60, 170, 400, 140, 'Dashboard / prompt UI', 'Next.js :3000 → /api/chat\nServer adds key + purpose\nReporting links → /api/*');
card(570, 170, 390, 140, 'Live policy configuration', 'policy.yaml + identities.yaml\nsignatures.json; mtime reload\nProfiles; last good policy on error', 'green');
card(1020, 170, 380, 140, 'Session state • in memory', 'User, agent, purpose + budgets\nToken vault, labels + quarantine\nMemory only; resets on restart', 'green');

base('rectangle', 530, 335, 910, 605, { strokeColor: colors.blue, backgroundColor: '#f8fbff', roundness: { type: 3 } });
text(558, 348, 'FastAPI gateway :8000 • shared policy engine', 25, colors.blue);
card(570, 405, 830, 200, '1  Identity + request checks → sanitized input',
  'Bearer key → user / agent; purpose required; session owner checked\nModel allowlist + session budgets + signature checks\nPII / secrets → reversible tokens (regex + checksums)\nNew prompts / tool results → judge after redaction\nJudge: offline DemoJudge OR external Jev (TypeSafe)', 'blue');
card(570, 690, 830, 215, '2  Response checks → permitted actions',
  'Role → allowed tools; signatures on tool arguments\nSensitive data → external sink: block by policy\nTool-call budgets; detokenize only for allowed sinks\nRedact model text; remove blocked tool calls\nUpdate token / cost / local-compute usage', 'green');

card(60, 405, 400, 200, 'Agent / SDK client', 'demo/agent.py • OpenAI SDK\nBearer key → user + agent\nX-Purpose + X-Session\nPOST /v1/chat/completions\nTools + results in chat history');
card(60, 730, 400, 190, 'Demo tools • agent executes', 'get_customer → fake bank records\nsend_email → local JSONL outbox\ncharge_card → simulated payment\nNo MCP server in current MVP', 'muted');
arrow([[260, 606], [260, 725]], 'muted');
text(276, 636, 'Permitted calls;\nraw tool results', 18, colors.muted);
arrow([[465, 460], [565, 460]]);
text(475, 420, 'Request', 16, colors.blue);
arrow([[568, 790], [510, 790], [510, 660], [460, 660], [460, 580]], 'green');
text(475, 610, 'Filtered\nresponse', 16, colors.green);
arrow([[765, 315], [765, 399]], 'green');
arrow([[1210, 315], [1210, 399]], 'green');

card(1530, 405, 450, 235, 'Model routing / upstream', 'mock/compromised • offline script\nOllama • local, optional profile\nOpenRouter • external, optional\nOnly policy-allowed models\nNon-streaming Chat Completions');
arrow([[1405, 460], [1525, 460]]);
text(1440, 420, 'Safe input', 16, colors.blue);
arrow([[1755, 645], [1755, 790], [1405, 790]], 'green');
text(1545, 750, 'Model response / tool calls', 18, colors.green);
card(1530, 850, 450, 140, 'Default offline demo', 'Compose: mock model + DemoJudge\nNo keys required; keyword checks\nLive Jev uses redacted text only', 'muted');

card(60, 1050, 400, 200, 'Current enforcement boundary', 'API keys authenticate the client.\nReporting APIs have no auth.\nAgent still sees raw tool data.\nDirect actions can bypass proxy.\nMCP / managed egress: planned.', 'red');
card(570, 1050, 830, 215, 'Audit + telemetry • exchanges + identity denials',
  'Hash-chained JSONL on persistent audit-data volume\nUser / agent / purpose + policy hash; blocked identity attempts\nOutcomes, decisions, per-check latency + cumulative usage\nAllowed tool proposals do not prove execution or success\nGET /api/metrics • /api/events • /api/audit/verify|export', 'green');
arrow([[985, 945], [985, 1045]], 'green');
text(1004, 980, 'Decision record', 18, colors.green);
card(1530, 1050, 450, 190, 'Compliance / security audience', 'Current: reporting API + UI links\nPlanned: flow view, blocked-access\nreview, alerts and policy management\n/api/events is JSON; SSE is planned', 'muted');
arrow([[1405, 1130], [1525, 1130]], 'green');

text(60, 1330, 'Product direction • from the planning doc and repository backlog', 30, colors.orange);
text(60, 1380, 'These capabilities are proposed; they are not part of the working runtime above.', 21, colors.muted);
card(60, 1440, 450, 205, 'Beyond API-key identity', 'Request signing / roster sync\nAgent hierarchy; delegation narrows\nTime-bound access and information\nbarriers / sensitive HR data', 'orange', true);
card(550, 1440, 450, 205, 'Workflow enforcement', 'MCP gateway + harness hooks\nInspect actual tool effects\nManaged egress / client configuration\nAdditional API adapters + streaming', 'orange', true);
card(1040, 1440, 450, 205, 'Human approvals', 'Second-person approval\nBind approval to exact argument hash\nRequest access + review workflow\nNo approval action implemented yet', 'orange', true);
card(1530, 1440, 450, 205, 'Richer checks + visibility', 'Attachment-aware classification\nVerify against source of truth\nSecurity dashboard + agent-flow UI\nExpand YAML control test cases', 'orange', true);
text(60, 1695, 'Sources: linked Project PIKA Google Doc • gateway/acl/* • demo/* • policy/* • compose.yaml • docs/decisions.md + backlog.md', 18, colors.muted);

const scene = { type: 'excalidraw', version: 2, source: 'https://excalidraw.com', elements,
  appState: { viewBackgroundColor: '#ffffff', gridSize: null, theme: 'light' }, files: {} };
fs.writeFileSync(path.join(__dirname, 'architecture.excalidraw'), JSON.stringify(scene, null, 2) + '\n');
const escape = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const svg = elements.map(e => {
  const dash = e.strokeStyle === 'dashed' ? ' stroke-dasharray="9 6"' : '';
  if (e.type === 'rectangle') return `<rect x="${e.x}" y="${e.y}" width="${e.width}" height="${e.height}" rx="12" fill="${e.backgroundColor}" stroke="${e.strokeColor}" stroke-width="${e.strokeWidth}"${dash}/>`;
  if (e.type === 'text') return `<text fill="${e.strokeColor}" font-family="Arial, sans-serif" font-size="${e.fontSize}">${e.text.split('\n').map((line, i) => `<tspan x="${e.x}" y="${e.y + e.fontSize + i * e.fontSize * e.lineHeight}">${escape(line)}</tspan>`).join('')}</text>`;
  return `<polyline points="${e.points.map(([x,y]) => `${e.x+x},${e.y+y}`).join(' ')}" fill="none" stroke="${e.strokeColor}" stroke-width="${e.strokeWidth}"${dash} marker-end="url(#${e.strokeColor.slice(1)})"/>`;
}).join('\n');
const markers = Object.values(colors).map(c => `<marker id="${c.slice(1)}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10" fill="none" stroke="${c}" stroke-width="1.5"/></marker>`).join('');
fs.writeFileSync(path.join(__dirname, 'architecture.svg'), `<svg xmlns="http://www.w3.org/2000/svg" width="2040" height="1760" viewBox="0 0 2040 1760"><title>PIKA / AI Control Layer architecture</title><desc>Implemented model-proxy runtime, policy and session state, agent-executed demo tools, persistent audit reporting, and a separate planned roadmap.</desc><rect width="2040" height="1760" fill="white"/><defs>${markers}</defs>${svg}</svg>\n`);
console.log(`Generated architecture.excalidraw and architecture.svg (${elements.length} editable elements).`);
