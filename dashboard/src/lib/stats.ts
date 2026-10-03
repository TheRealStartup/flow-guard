import type { AuditEvent, ExchangeEvent, Outcome } from "./api";

// Everything the Overview shows, computed from the audit events of one time range, so every number agrees.

export const OUTCOMES: Outcome[] = ["allowed", "redacted", "flagged", "blocked"]; // stack order, bottom → top

export const RANGES = [
  { value: "15m", label: "15 min", seconds: 15 * 60, bucket: 60 },
  { value: "1h", label: "1 hour", seconds: 3600, bucket: 120 },
  { value: "24h", label: "24 hours", seconds: 86400, bucket: 3600 },
  { value: "7d", label: "7 days", seconds: 7 * 86400, bucket: 6 * 3600 },
] as const;
export type RangeKey = (typeof RANGES)[number]["value"];

/** Controls whose redactions hide a value behind a token (as opposed to quarantining a message). */
const VALUE_CONTROLS = new Set(["pii.card", "pii.iban", "pii.pesel", "pii.passport", "secrets"]);
const JUDGE = "injection.jev";
export const NO_IDENTITY = "unknown"; // requests denied before an API key resolved to a user

export type Bucket = { start: number; counts: Record<Outcome, number>; total: number };
export type ControlRow = { control: string; block: number; redact: number; flag: number; total: number };
export type ActorRow = { user: string; agents: string[]; requests: number; blocked: number; redacted: number; flagged: number; topControl: string | null; last: number; labels: string[] };

function quantile(xs: number[], q: number): number | null {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const i = (s.length - 1) * q;
  const lo = Math.floor(i);
  return s[lo] + (s[Math.ceil(i)] - s[lo]) * (i - lo);
}

function summarise(ex: ExchangeEvent[]) {
  const counts = Object.fromEntries(OUTCOMES.map((o) => [o, 0])) as Record<Outcome, number>;
  let hidden = 0;
  let quarantined = 0;
  let released = 0;
  let flowBlocks = 0;
  for (const e of ex) {
    counts[e.outcome]++;
    for (const d of e.decisions) {
      if (d.action === "redact" && VALUE_CONTROLS.has(d.control)) hidden++;
      if ((d.control === JUDGE && d.action !== "allow" && d.action !== "flag") || (d.control === "barrier.mnpi" && d.action === "redact")) quarantined++;
      if (d.control === "pii.detokenize") released++;
      if (d.control.startsWith("flow.") && d.action === "block") flowBlocks++;
    }
  }
  return { requests: ex.length, counts, hidden, quarantined, released, flowBlocks };
}

export function computeOverview(events: AuditEvent[], range: RangeKey, now: number) {
  const r = RANGES.find((x) => x.value === range)!;
  const from = now - r.seconds;
  const all = events.filter((e): e is ExchangeEvent => e.type === "exchange");
  const ex = all.filter((e) => e.ts >= from);
  const previous = all.filter((e) => e.ts >= from - r.seconds && e.ts < from);

  // Time buckets, aligned to the bucket size so they don't shift on every poll.
  const first = Math.floor(from / r.bucket) * r.bucket;
  const buckets: Bucket[] = [];
  for (let t = first; t <= now; t += r.bucket)
    buckets.push({ start: t, counts: Object.fromEntries(OUTCOMES.map((o) => [o, 0])) as Record<Outcome, number>, total: 0 });
  for (const e of ex) {
    const b = buckets[Math.floor((e.ts - first) / r.bucket)];
    if (!b) continue;
    b.counts[e.outcome]++;
    b.total++;
  }

  // What each control caught (allow decisions are checks that passed, not catches).
  const controls = new Map<string, ControlRow>();
  for (const e of ex)
    for (const d of e.decisions) {
      if (d.action === "allow") continue;
      const row = controls.get(d.control) ?? { control: d.control, block: 0, redact: 0, flag: 0, total: 0 };
      row[d.action]++;
      row.total++;
      controls.set(d.control, row);
    }

  // Latency: all checks per request, the rule path without the AI judge (decision D3), the judge alone, the model.
  const checks = ex.map((e) => e.controls_ms);
  // Rule decisions report ~0 ms each, so measure the rule path as the gateway's check time minus the judge's time.
  const rules = ex.map((e) => Math.max(0, e.controls_ms - e.decisions.filter((d) => d.control === JUDGE).reduce((s, d) => s + d.ms, 0)));
  const judge = ex.flatMap((e) => e.decisions.filter((d) => d.control === JUDGE).map((d) => d.ms));
  const model = ex.map((e) => e.upstream_ms).filter((x): x is number => x != null);
  const perControl = new Map<string, number[]>();
  for (const e of ex) for (const d of e.decisions) if (d.ms) perControl.set(d.control, [...(perControl.get(d.control) ?? []), d.ms]);

  // Who triggers the controls.
  const actors = new Map<string, ActorRow>();
  for (const e of ex) {
    const key = e.user ?? NO_IDENTITY;
    const a = actors.get(key) ?? { user: key, agents: [], requests: 0, blocked: 0, redacted: 0, flagged: 0, topControl: null, last: 0, labels: [] };
    a.requests++;
    if (e.outcome === "blocked") a.blocked++;
    if (e.outcome === "redacted") a.redacted++;
    if (e.outcome === "flagged") a.flagged++;
    if (e.agent && !a.agents.includes(e.agent)) a.agents.push(e.agent);
    for (const l of e.usage?.labels ?? []) if (!a.labels.includes(l)) a.labels.push(l);
    a.last = Math.max(a.last, e.ts);
    actors.set(key, a);
  }
  for (const a of actors.values()) {
    const fired = new Map<string, number>();
    for (const e of ex) if ((e.user ?? NO_IDENTITY) === a.user) for (const d of e.decisions) if (d.action !== "allow") fired.set(d.control, (fired.get(d.control) ?? 0) + 1);
    a.topControl = [...fired.entries()].sort((x, y) => y[1] - x[1])[0]?.[0] ?? null;
  }

  return {
    range: r,
    now: summarise(ex),
    before: summarise(previous),
    buckets,
    controls: [...controls.values()].sort((a, b) => b.total - a.total),
    latency: {
      checksP50: quantile(checks, 0.5),
      checksP95: quantile(checks, 0.95),
      rulesP50: quantile(rules, 0.5),
      rulesP95: quantile(rules, 0.95),
      judgeAvg: judge.length ? judge.reduce((s, x) => s + x, 0) / judge.length : null,
      modelP50: quantile(model, 0.5),
      perControl: [...perControl.entries()].map(([control, xs]) => ({ control, avg: xs.reduce((s, x) => s + x, 0) / xs.length })).sort((a, b) => b.avg - a.avg),
    },
    actors: [...actors.values()].sort((a, b) => b.blocked - a.blocked || b.requests - a.requests),
    agents: new Set(ex.map((e) => e.agent).filter(Boolean)).size,
    recentBlocks: ex.filter((e) => e.outcome === "blocked").slice(-6).reverse(),
    sparkline: buckets.slice(-12).map((b) => b.total),
  };
}

export type Overview = ReturnType<typeof computeOverview>;

/** Round an axis maximum up to a clean number with ~4 ticks. */
export function niceMax(v: number) {
  if (v <= 4) return 4;
  const step = 10 ** Math.floor(Math.log10(v / 4));
  const m = [1, 2, 2.5, 5, 10].find((k) => (v / 4) <= k * step)! * step;
  return m * 4;
}

export const compact = (n: number) => (n >= 10000 ? `${(n / 1000).toFixed(1)}K` : n.toLocaleString("en-US"));
export const ms = (v: number | null) =>
  v == null ? "—" : v >= 1000 ? `${(v / 1000).toFixed(1)} s` : v >= 10 ? `${v.toFixed(0)} ms` : v >= 0.1 ? `${v.toFixed(1)} ms` : "<0.1 ms";
