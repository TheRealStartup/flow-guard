"use client";

import { useCallback, useEffect, useMemo, useSyncExternalStore } from "react";
import { getJSON, usePoll, type AuditEvent, type Policy, type PolicyHistoryItem } from "@/lib/api";

// Live audit feed: one EventSource on /api/stream per browser tab, shared by every component through a
// module-level store. Initial load from /api/events, then entries arrive as they are appended (docs/api.md).
// If the stream drops, poll /api/events every 2 s and keep retrying the stream with backoff.

const POLL_MS = 2000;
const FRESH_MS = 4000; // how long a newly arrived entry counts as `fresh` (row highlight)
const TICK_MS = 10_000; // while live, bump updatedAt so relative ranges ("last 15 minutes") stay current

type State = {
  events: AuditEvent[] | null; // newest first, like /api/events
  error: string | null;
  updatedAt: Date | null;
  live: boolean;
  fresh: ReadonlySet<number>; // seqs that arrived after the initial load, for the last few seconds
};

let state: State = { events: null, error: null, updatedAt: null, live: false, fresh: new Set() };
const SERVER_STATE = state;
const listeners = new Set<() => void>();
const policyListeners = new Set<() => void>();
const limits = new Map<symbol, number>();

let started = false;
let source: EventSource | null = null;
let pollTimer: ReturnType<typeof setInterval> | null = null;
let retryTimer: ReturnType<typeof setTimeout> | null = null;
let tickTimer: ReturnType<typeof setInterval> | null = null;
let backoff = 1000;
let loaded = 0; // the limit the store was last loaded with

const cap = () => Math.max(1, ...limits.values());
const topSeq = () => state.events?.[0]?.seq ?? -1;

function set(patch: Partial<State>) {
  state = { ...state, ...patch };
  listeners.forEach((fn) => fn());
}

/** Merge entries (any order) into the newest-first list: dedup by seq, cap at the largest requested limit. */
function merge(incoming: AuditEvent[], replace = false) {
  const initial = state.events === null;
  const prev = replace ? [] : (state.events ?? []);
  const known = new Set(prev.map((e) => e.seq));
  const added = incoming.filter((e) => !known.has(e.seq));
  if (!added.length && state.events && !replace) {
    set({ updatedAt: new Date(), error: null });
    return;
  }
  const events = [...added, ...prev].sort((a, b) => b.seq - a.seq).slice(0, cap());
  const fresh = new Set(state.fresh);
  if (!initial && !replace) {
    for (const e of added) fresh.add(e.seq);
    setTimeout(() => {
      const next = new Set(state.fresh);
      added.forEach((e) => next.delete(e.seq));
      set({ fresh: next });
    }, FRESH_MS);
  }
  set({ events, fresh, updatedAt: new Date(), error: null });
  if (!initial && !replace && added.some((e) => e.type === "policy_change")) policyListeners.forEach((fn) => fn());
}

async function load() {
  const limit = cap();
  try {
    const list = await getJSON<AuditEvent[]>(`/api/events?limit=${limit}`);
    // A lower top seq than ours means the gateway's log was reset: start over instead of mixing two logs.
    const reset = state.events !== null && (list[0]?.seq ?? -1) < topSeq();
    const first = state.events === null;
    merge(list, reset || first);
    loaded = Math.max(loaded, limit);
    return true;
  } catch (e) {
    set({ error: e instanceof Error ? e.message : String(e) });
    return false;
  }
}

function startPolling() {
  if (!pollTimer) pollTimer = setInterval(load, POLL_MS);
}

function stopPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
}

function connect() {
  retryTimer = null;
  if (!started) return;
  // since = the newest entry we hold: the gateway replays anything after it, so a reconnect has no gaps.
  const es = new EventSource(`/api/stream?since=${topSeq()}`);
  source = es;
  es.onopen = () => {
    backoff = 1000;
    stopPolling();
    set({ live: true, error: null, updatedAt: new Date() });
  };
  es.addEventListener("audit", (m) => merge([JSON.parse((m as MessageEvent<string>).data) as AuditEvent]));
  es.onerror = () => {
    // Take over reconnecting ourselves, so each attempt resumes from the newest seq (which polling advances too).
    es.close();
    if (source !== es) return;
    source = null;
    set({ live: false });
    startPolling();
    retryTimer = setTimeout(connect, backoff);
    backoff = Math.min(backoff * 2, 10_000);
  };
}

async function start() {
  started = true;
  tickTimer = setInterval(() => state.live && set({ updatedAt: new Date() }), TICK_MS);
  while (started && !(await load())) await new Promise((r) => setTimeout(r, POLL_MS));
  if (started && !source && !retryTimer) connect();
}

function stop() {
  started = false;
  source?.close();
  source = null;
  stopPolling();
  if (retryTimer) clearTimeout(retryTimer);
  if (tickTimer) clearInterval(tickTimer);
  retryTimer = tickTimer = null;
  set({ live: false });
}

/** Register a consumer (with how many entries it wants); the first one opens the stream, the last one closes it. */
function retain(limit: number) {
  const key = Symbol();
  limits.set(key, limit);
  if (!started) start();
  else if (limit > loaded && state.events) load(); // a consumer wants more history than we hold
  return () => {
    limits.delete(key);
    if (!limits.size) stop();
  };
}

function subscribe(fn: () => void) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/**
 * The audit log, newest first, kept current by the gateway's Server-Sent Events stream.
 * `live` is true while the stream is connected; otherwise it polls /api/events every 2 s and retries the stream.
 * `fresh` holds the seqs that arrived in the last few seconds (to highlight new rows).
 */
export function useAuditEvents(limit = 5000): {
  data: AuditEvent[] | null;
  error: string | null;
  updatedAt: Date | null;
  live: boolean;
  fresh: ReadonlySet<number>;
} {
  const s = useSyncExternalStore(subscribe, () => state, () => SERVER_STATE);
  useEffect(() => retain(limit), [limit]);
  const data = useMemo(() => (s.events && s.events.length > limit ? s.events.slice(0, limit) : s.events), [s.events, limit]);
  return { data, error: s.error, updatedAt: s.updatedAt, live: s.live, fresh: s.fresh };
}

/** Calls `fn` whenever a policy reload (or a rejected edit) reaches the audit log. Keeps the stream open. */
export function useOnPolicyChange(fn: () => void) {
  useEffect(() => {
    const release = retain(1);
    policyListeners.add(fn);
    return () => {
      policyListeners.delete(fn);
      release();
    };
  }, [fn]);
}

/** /api/policy and /api/policy/history, refreshed the moment a policy change streams in (slow poll as a fallback). */
export function usePolicyLive() {
  const live = useSyncExternalStore(subscribe, () => state.live, () => false);
  const policy = usePoll<Policy>("/api/policy", live ? 30_000 : 3000);
  const history = usePoll<PolicyHistoryItem[]>("/api/policy/history", live ? 30_000 : 3000);
  const { reload: reloadPolicy } = policy;
  const { reload: reloadHistory } = history;
  useOnPolicyChange(
    useCallback(() => {
      reloadPolicy();
      reloadHistory();
    }, [reloadPolicy, reloadHistory]),
  );
  return { policy: policy.data, history: history.data, live };
}
