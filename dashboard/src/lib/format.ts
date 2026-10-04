import type { Action, AuditEvent, Decision, ExchangeEvent, Outcome } from "./api";

// Human names for the controls in policy/policy.yaml. Unknown ids fall back to the id itself.
export const CONTROLS: Record<string, { name: string; kind: string; scope: string }> = {
  "models.allowlist": { name: "Model allowlist", kind: "Access", scope: "Only models listed in the policy" },
  budget: { name: "Session budget", kind: "Budget", scope: "Tokens, cost, tool calls and compute per session" },
  "pii.card": { name: "Card number protection", kind: "Privacy", scope: "Card numbers (regex + Luhn) → reversible token" },
  "pii.iban": { name: "IBAN protection", kind: "Privacy", scope: "IBANs → reversible token" },
  "pii.pesel": { name: "National ID protection", kind: "Privacy", scope: "PESEL with checksum → reversible token" },
  "pii.passport": { name: "Passport protection", kind: "Privacy", scope: "Labelled passport numbers → reversible token" },
  "pii.dob": { name: "Date-of-birth protection", kind: "Privacy", scope: "Labelled dates of birth → reversible token" },
  "pii.detokenize": { name: "Real value released", kind: "Privacy", scope: "Real values only for approved tools" },
  "barrier.mnpi": { name: "Information barrier", kind: "Barrier", scope: "Restricted deals withheld from the public side" },
  "access.scope": { name: "Client scope", kind: "Scope", scope: "Tool arguments limited to assigned clients" },
  secrets: { name: "Secret protection", kind: "Privacy", scope: "API keys and private keys → token" },
  signatures: { name: "Threat signatures", kind: "Threat", scope: "Known attack patterns from the signature feed" },
  "access.tools": { name: "Role → tool access", kind: "Access", scope: "Each role may call only its listed tools" },
  "flow.sensitive_to_external": { name: "Sensitive data stays inside", kind: "Flow", scope: "Tokens and MNPI may not reach external sinks" },
  "injection.jev": { name: "Prompt-injection check", kind: "Injection", scope: "Quarantine text that tries to instruct the agent" },
  spotlight: { name: "Spotlighting", kind: "Injection", scope: "Tool results reach the model marked as data" },
  identity: { name: "Identity", kind: "Identity", scope: "API key → user and agent, purpose required" },
  "access.purpose": { name: "Purpose rules (HR)", kind: "Access", scope: "No model judges employees; personnel files reach no model" },
  "access.datalake": { name: "Data lake queries", kind: "Access", scope: "Only named queries the role may run, refused before they run" },
  classification: { name: "Data classes", kind: "Barrier", scope: "Content above a destination's class limit is withheld" },
};

export const controlName = (id: string) => CONTROLS[id]?.name ?? id;

// OWASP Top 10 for LLM Applications (2025) categories each control addresses.
export const OWASP_LLM: Record<string, string> = {
  LLM01: "Prompt injection",
  LLM02: "Sensitive information disclosure",
  LLM03: "Supply chain",
  LLM05: "Improper output handling",
  LLM06: "Excessive agency",
  LLM10: "Unbounded consumption",
};
export const OWASP: Record<string, string[]> = {
  "models.allowlist": ["LLM03"],
  budget: ["LLM10"],
  "pii.card": ["LLM02"],
  "pii.iban": ["LLM02"],
  "pii.pesel": ["LLM02"],
  "pii.passport": ["LLM02"],
  "pii.dob": ["LLM02"],
  secrets: ["LLM02"],
  signatures: ["LLM03", "LLM01"],
  "access.tools": ["LLM06"],
  "access.scope": ["LLM06"],
  "barrier.mnpi": ["LLM02"],
  "flow.sensitive_to_external": ["LLM02", "LLM06"],
  "injection.jev": ["LLM01"],
  spotlight: ["LLM01", "LLM05"],
};

export const OUTCOME_LABEL: Record<Outcome, string> = {
  allowed: "Allowed",
  redacted: "Hidden",
  flagged: "Flagged",
  blocked: "Blocked",
};

export const ACTION_LABEL: Record<Action, string> = { allow: "Allow", flag: "Flag", redact: "Redact", block: "Block" };

const pad = (n: number, w = 2) => String(n).padStart(w, "0");

export function utcTime(ts: number, ms = true) {
  const d = new Date(ts * 1000);
  const t = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
  return ms ? `${t}.${pad(d.getUTCMilliseconds(), 3)}` : t;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
export function utcDate(ts: number) {
  const d = new Date(ts * 1000);
  return `${pad(d.getUTCDate())} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

export const eventId = (e: AuditEvent) => `EVT-${pad(e.seq, 6)}`;
export const shortHash = (h: string) => (h ? `${h.slice(0, 8)}…${h.slice(-8)}` : "—");

/** snake_case tool name → "Snake case". */
export const humanize = (s: string) => {
  const t = s.replace(/[_.]/g, " ").trim();
  return t.charAt(0).toUpperCase() + t.slice(1);
};

/** What an exchange was about, for the Action / Resource column. */
export function eventTitle(e: AuditEvent): { title: string; detail: string } {
  if (e.type === "policy_change") {
    if (e.error) return { title: "Policy edit rejected", detail: "Last good policy stays active" };
    const n = e.changes?.length ?? 0;
    if (!n) return { title: "Policy loaded", detail: `${e.version} · ${e.profile}` };
    return { title: "Policy changed", detail: `${e.version} · ${n} field${n === 1 ? "" : "s"}` };
  }
  const calls = e.tool_calls ?? [];
  const call = calls.find((c) => c.outcome === "blocked") ?? calls[0];
  if (call) {
    const more = calls.length > 1 ? ` +${calls.length - 1}` : "";
    return { title: humanize(call.name) + more, detail: `Tool call · ${call.name}` };
  }
  const denied = e.decisions.find((d) => d.where === "request" && d.action === "block");
  if (denied) return { title: "Request denied", detail: controlName(denied.control) };
  const fromTool = e.decisions.some((d) => d.where === "tool_result");
  return { title: fromTool ? "Tool result to model" : "Prompt to model", detail: e.purpose ?? "Model request" };
}

/** What FlowGuard did (the gateway's headline), and what the agent was doing at the time. */
export function eventLines(e: AuditEvent): { title: string; detail: string } {
  if (e.type === "policy_change") return { title: e.summary?.headline ?? eventTitle(e).title, detail: eventTitle(e).detail };
  const names = [...new Set((e.tool_calls ?? []).map((c) => c.name))];
  const fromTool = e.decisions.some((d) => d.where === "tool_result");
  const detail = names.length
    ? `Tool call${names.length > 1 ? "s" : ""}: ${names.slice(0, 2).join(", ")}${names.length > 2 ? ` +${names.length - 2}` : ""}`
    : e.model == null
      ? "Request refused before any check"
      : fromTool
        ? "Tool result on its way to the model"
        : "Prompt to the model";
  return { title: e.summary?.headline ?? eventTitle(e).title, detail };
}

/** The most severe decision of an exchange: what the headline should say. */
export function headline(e: ExchangeEvent): { tone: Outcome; title: string; body: string } | null {
  const block = e.decisions.find((d) => d.action === "block");
  if (block) return { tone: "blocked", title: blockTitle(block), body: block.reason };
  const redactions = e.decisions.filter((d) => d.action === "redact");
  if (redactions.length) {
    const quarantined = redactions.filter((d) => d.control === "injection.jev").length;
    const hidden = redactions.length - quarantined;
    const parts = [];
    if (hidden) parts.push(`${hidden} value${hidden === 1 ? "" : "s"} replaced with tokens`);
    if (quarantined) parts.push(`${quarantined} message${quarantined === 1 ? "" : "s"} quarantined`);
    return { tone: "redacted", title: "Removed before the model saw it", body: parts.join(" · ") + "." };
  }
  const flag = e.decisions.find((d) => d.action === "flag");
  if (flag) return { tone: "flagged", title: flag.control === "pii.detokenize" ? "Released only to an approved tool" : "Let through and flagged", body: flag.reason };
  return null;
}

export function blockTitle(d: Decision) {
  if (d.control.startsWith("flow.")) return "Blocked before it left";
  if (d.control === "identity") return "Blocked at the door";
  if (d.control === "budget") return "Blocked by the budget";
  if (d.where.startsWith("tool_call")) return "Blocked before it ran";
  return "Request blocked";
}

export const whereLabel = (w: string) => {
  if (w.startsWith("tool_call:")) return `Proposed call · ${w.slice(10)}`;
  return { request: "Request", prompt: "User prompt", tool_result: "Tool result", response: "Model's answer", model_output: "Model's answer", assistant: "Model's earlier answer", session: "Session", model: "Model choice" }[w] ?? w;
};
