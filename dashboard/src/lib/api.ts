"use client";

import { useCallback, useEffect, useRef, useState } from "react";

// Shapes returned by the gateway (docs/api.md, live docs at :8000/docs). Values are already masked or tokenized.

export type Outcome = "allowed" | "flagged" | "redacted" | "blocked";
export type Action = "allow" | "flag" | "redact" | "block";

export type Decision = {
  control: string;
  action: Action;
  where: string; // request | prompt | tool_result | tool_call:<name> | response
  reason: string;
  ms: number;
  score: number | null;
  excerpt: string | null;
  token?: string | null; // the reversible token a redaction put in place of the value
  source?: string | null; // the tool call a tool result answers, e.g. "read_file README.md"
};

// What one audit entry means, computed by the gateway (gateway/acl/report.py) so every page shows the same label and
// the same counts for the same event. Verdict order: attack > blocked > quarantined > withheld > hidden > released > flagged > allowed.
export type Verdict = "attack" | "blocked" | "quarantined" | "withheld" | "hidden" | "released" | "flagged" | "allowed" | "policy" | "rejected";
export type Counts = { hidden: number; quarantined: number; withheld: number; released: number; blocked: number };
export type Summary = {
  verdict: Verdict;
  label: string; // "Attack caught", "Blocked", "Hidden", …
  headline: string; // what FlowGuard did, e.g. "Client scope: AC-7730 is not olivia's client"
  reason: string; // one or two plain sentences
  control: string | null; // the decisive control
  counts?: Counts; // exchanges only
};

export type ToolCall = {
  name: string;
  arguments: string;
  outcome: "allowed" | "blocked" | "allowed_with_real_values";
  control: string | null;
};

export type ExchangeEvent = {
  type: "exchange";
  seq: number;
  ts: number;
  session: string | null;
  user: string | null;
  agent: string | null;
  purpose: string | null;
  role: string | null;
  model: string | null;
  model_served?: string | null;
  provider?: string | null;
  profile: string;
  policy_version: string;
  outcome: Outcome;
  // Attacks this exchange defused (prompt injection, known attack signature, fake data marker, data exfiltration).
  // A quarantined injection keeps the outcome "redacted", so this is what marks it as a stopped attack.
  threats?: string[];
  decisions: Decision[];
  tool_calls?: ToolCall[];
  summary?: Summary;
  spotlighted?: number;
  controls_ms: number;
  upstream_ms: number | null;
  usage: { tokens?: number; cost_usd?: number; tool_calls?: number; labels?: string[] };
  prev_hash: string;
  hash: string;
};

export type PolicyChange = { what: string; old: unknown; new: unknown };

export type PolicyChangeEvent = {
  type: "policy_change";
  seq: number;
  ts: number;
  version: string;
  previous: string | null;
  profile: string;
  changes: PolicyChange[];
  error?: string | null;
  summary?: Summary;
  prev_hash: string;
  hash: string;
};

export type AuditEvent = ExchangeEvent | PolicyChangeEvent;

export type Health = {
  ok: boolean;
  policy_version: string;
  profile: string;
  policy_error: string | null;
  judge: "demo" | "jev" | "custom";
};

export type Verify = { ok: boolean; entries: number; head: string; broken_at?: number };

export type ControlConfig = { action: Action; [k: string]: unknown };

export type Policy = {
  version: string;
  profile: string;
  controls: Record<string, ControlConfig>;
  error: string | null;
  signatures: string[];
  last_change: PolicyChangeEvent | null;
};

export type PolicyHistoryItem = {
  ts?: number;
  version: string;
  previous: string | null;
  profile: string;
  changes: PolicyChange[];
  error?: string | null;
};

export type TryStep =
  | { kind: "model"; acl: TryAcl | null; content: string | null; tool_calls: { name: string; arguments: string }[] }
  | { kind: "tool"; name: string; result_preview: string }
  | { kind: "denied"; status: number; acl: TryAcl | null; message: string | null };

export type TryAcl = {
  seq: number;
  outcome: Outcome;
  decisions: Decision[];
  policy_version: string;
  session: string;
  user: string;
  agent: string;
  threats?: string[];
  summary?: Summary;
  controls_ms?: number;
  upstream_ms?: number | null;
};

// A poisoned source the run read, in the scenario's own hand-written words (never the injected text).
export type TryAttack = { where: string; source: string; wants: string };

export type TryResult = { session: string; user: string; scenario: string; model: string; steps: TryStep[]; attacks?: TryAttack[] };

export async function getJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { cache: "no-store", ...init });
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json() as Promise<T>;
}

/** Fetch `path` now and every `ms` after. Keeps the last good value if a poll fails. */
export function usePoll<T>(path: string | null, ms = 2000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const pathRef = useRef(path);

  const load = useCallback(async () => {
    const p = pathRef.current;
    if (!p) return;
    try {
      const value = await getJSON<T>(p);
      if (pathRef.current !== p) return;
      setData(value);
      setError(null);
      setUpdatedAt(new Date());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    pathRef.current = path;
    if (!path) return;
    load();
    const id = setInterval(load, ms);
    return () => clearInterval(id);
  }, [path, ms, load]);

  return { data, error, updatedAt, reload: load };
}
