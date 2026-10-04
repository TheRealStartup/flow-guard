"use client";

import { useCallback, useMemo, useState } from "react";
import { History, Radio, RefreshCw, TriangleAlert, X } from "lucide-react";
import { usePoll, type Action, type ControlConfig, type PolicyChange } from "@/lib/api";
import { useAuditEvents, useOnPolicyChange, usePolicyLive } from "@/lib/stream";
import { CONTROLS, OWASP, OWASP_LLM, utcTime } from "@/lib/format";
import { Panel, PanelHeader } from "@/components/kit";
import { cn } from "@/lib/utils";

type Budget = { max_tokens?: number; max_cost_usd?: number; max_tool_calls?: number; max_compute_seconds?: number };

type Details = {
  version: string;
  profile: string;
  error: string | null;
  defaults: { on_error?: string };
  base_controls: Record<string, ControlConfig>;
  profiles: Record<string, Record<string, Partial<ControlConfig>>>;
  controls: Record<string, ControlConfig>;
  models: Record<string, { upstream: string; input_per_m?: number; output_per_m?: number; max_class?: string; effective_class: string }>;
  levels: string[];
  upstreams: string[];
  supported_actions: Record<string, Action[]>;
  budgets: { session?: Budget; daily?: Budget };
  identity: { mode: string; require_purpose: boolean; keys: { user: string; agent: string }[] };
  users: Record<string, { role: string; side?: string; assigned_clients?: string[]; deals?: number }>; // deals: a count, ids are codenames
  roles: Record<string, { tools: string[]; budget?: Budget; daily_budget?: Budget }>;
  sinks: { external?: string[]; detokenize?: string[] };
  scopes: Record<string, { argument: string; user_field: string }>;
  barriers: { public_message: string; restricted: { terms: number }[] };
  signatures: { id: string; where: string[]; ref: string; title?: string; severity?: string | null; published?: string | null; cve?: string | null; sources?: string[] }[];
  feed?: { url: string | null; checked: number | null; updated: number | null; version: string | null; error: string | null; count?: number; tested?: number };
};

/** The one-line "what does this control check, with which settings" column. */
function settingsOf(id: string, c: ControlConfig, d: Details): string {
  const b = d.budgets.session ?? {};
  const onErr = c.on_error ? ` · on error ${c.on_error}` : "";
  switch (id) {
    case "models.allowlist":
      return `${Object.keys(d.models).length} approved models · any other model is ${({ block: "refused", flag: "let through and recorded", allow: "let through" } as Record<string, string>)[c.action] ?? c.action}`;
    case "budget":
      return `${(b.max_tokens ?? 0) / 1000}k tokens · $${b.max_cost_usd} · ${b.max_tool_calls} calls · ${b.max_compute_seconds} s model time / session`;
    case "pii.card":
      return "regex + Luhn checksum → reversible token";
    case "pii.iban":
      return "regex + mod-97 checksum → reversible token";
    case "pii.pesel":
      return "regex + PESEL checksum → reversible token";
    case "pii.passport":
      return "only where the text labels a passport number";
    case "secrets":
      return "AWS keys, sk-… API keys, GitHub tokens, private keys";
    case "signatures":
      return `${d.signatures.length} signatures · feed ${String(c.feed ?? "")}`;
    case "access.tools":
      return `${Object.keys(d.roles).length} roles → allowed tools`;
    case "access.scope":
      return Object.entries(d.scopes).map(([tool, s]) => `${tool}.${s.argument} ∈ user's ${s.user_field}`).join(" · ") || "no scopes defined";
    case "barrier.mnpi":
      return `${d.barriers.restricted.length} restricted deal${d.barriers.restricted.length === 1 ? "" : "s"} · public side sees “${d.barriers.public_message}”`;
    case "flow.sensitive_to_external":
      return `mode ${c.mode} · sinks ${(d.sinks.external ?? []).join(", ")}`;
    case "injection.jev":
      return `threshold ${c.threshold} · timeout ${c.timeout_s} s${onErr}`;
    case "spotlight":
      return `mode ${c.mode} · tool results wrapped in data markers`;
    case "access.purpose": {
      const rules = (Array.isArray(c.rules) ? c.rules : []) as { roles?: string[]; forbidden?: string[]; signatures?: unknown[] }[];
      return rules.map((r) => `${(r.roles ?? []).join(", ")}: no ${(r.forbidden ?? []).join(", ").replaceAll("_", " ")} (${r.signatures?.length ?? 0} patterns)`).join(" · ") || "no rules";
    }
    case "access.datalake":
      return "named queries only, refused before they run if the result could not be sent on";
    default:
      // Never print nested settings raw ("[object Object]"): summarise lists and objects by size.
      return Object.entries(c)
        .filter(([k]) => k !== "action")
        .map(([k, v]) => `${k} ${Array.isArray(v) ? `${v.length} entries` : v && typeof v === "object" ? `${Object.keys(v).length} settings` : v}`)
        .join(" · ");
  }
}

const kindOf = (id: string) => (id === "injection.jev" ? "AI judge" : id === "signatures" ? "feed" : "rule");

export default function PoliciesPage() {
  const { policy, history, live } = usePolicyLive();
  const details = usePoll<Details>("/api/policy/details", live ? 30_000 : 3000);
  const { reload } = details;
  useOnPolicyChange(useCallback(() => reload(), [reload]));
  const { data: events, updatedAt } = useAuditEvents();
  const [dismissed, setDismissed] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [toggleError, setToggleError] = useState<string | null>(null);

  // The gateway writes the action into policy.yaml and reloads; the stream then refreshes this page.
  async function setAction(id: string, action: Action) {
    setPending(id);
    setToggleError(null);
    try {
      const r = await fetch(`/api/policy/controls/${encodeURIComponent(id)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      });
      if (!r.ok) setToggleError(`${id}: ${((await r.json().catch(() => null)) as { detail?: string } | null)?.detail ?? `error ${r.status}`}`);
      reload();
    } catch {
      setToggleError(`${id}: the gateway could not be reached`);
    } finally {
      setPending(null);
    }
  }

  const d = details.data;
  // "Now" comes from the feed (it ticks while live), so renders stay pure. Counts cover a rolling 24 hours.
  const now = (updatedAt?.getTime() ?? 0) / 1000;
  const since = now - 86400;
  const fired = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of events ?? [])
      if (e.type === "exchange" && e.ts >= since) for (const x of e.decisions) if (x.action !== "allow") m.set(x.control, (m.get(x.control) ?? 0) + 1);
    return m;
  }, [events, since]);

  // The newest reload with changes, shown as a banner until dismissed (judges edit the file during the demo).
  const latest = history?.find((h) => h.changes?.length || h.error);
  const showBanner = latest && latest.version + (latest.ts ?? "") !== dismissed && latest.ts && now - latest.ts < 15 * 60;

  return (
    <>
      <div className="mb-8 flex flex-wrap items-baseline gap-x-5 gap-y-2">
        <h1 className="text-[32px] leading-tight font-normal">Policy</h1>
        <p className="max-w-2xl text-[17px] text-muted-foreground">
          What is enforced right now. Change an action below or edit <span className="font-mono text-[15px] text-foreground">policy.yaml</span>: this page shows the new version and what
          changed, without a restart.
        </p>
        <span className="ml-auto flex items-center gap-2 text-[15px] text-muted-foreground">
          {live ? <Radio className="size-4 text-primary" /> : <RefreshCw className="size-4" />}
          {live ? "Live" : "Polling every 3 s"} · <span className="font-mono text-sm">{d?.version ?? policy?.version ?? "…"}</span>
        </span>
      </div>

      {d?.error && (
        <div className="mb-6 flex gap-3 rounded-lg border border-block/30 bg-block-soft px-5 py-4 text-block">
          <TriangleAlert className="mt-0.5 size-5 shrink-0" />
          <div>
            <div className="font-semibold">The last edit to policy.yaml was rejected. Version {d.version} stays active.</div>
            <div className="mt-1 font-mono text-sm break-words">{d.error}</div>
          </div>
        </div>
      )}

      {showBanner && latest && !latest.error && (
        <div className="mb-6 flex gap-3 rounded-lg border border-redact/30 bg-redact-soft px-5 py-4 text-redact">
          <History className="mt-0.5 size-5 shrink-0" />
          <div className="min-w-0 flex-1">
            <div className="font-semibold">
              Policy reloaded{latest.ts ? ` at ${utcTime(latest.ts, false)} UTC` : ""}: {latest.previous} → {latest.version} · {latest.changes.length} field
              {latest.changes.length === 1 ? "" : "s"} changed
            </div>
            <ChangeList changes={latest.changes} className="mt-2" />
          </div>
          <button className="self-start p-1 hover:opacity-70" onClick={() => setDismissed(latest.version + (latest.ts ?? ""))} aria-label="Dismiss">
            <X className="size-4" />
          </button>
        </div>
      )}

      <Panel className="mb-6 overflow-hidden">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-6 pt-5 pb-4">
          <h2 className="text-lg font-semibold">Controls</h2>
          <span className="text-[15px] text-muted-foreground">
            profile {d?.profile ?? "…"} · click an action to change it (written to policy.yaml, audited like any edit)
          </span>
          <span className="ml-auto text-sm text-muted-foreground">
            If a check fails: <b className="font-medium text-foreground">{d?.defaults.on_error ?? "block"}</b> · Fired = blocked, redacted or flagged in the last 24 h
          </span>
        </div>
        {toggleError && (
          <div className="mx-6 mb-4 flex items-start gap-2 rounded-md bg-block-soft px-4 py-2.5 text-sm text-block">
            <TriangleAlert className="mt-0.5 size-4 shrink-0" />
            <span className="flex-1">{toggleError}</span>
            <button onClick={() => setToggleError(null)} aria-label="Dismiss">
              <X className="size-4" />
            </button>
          </div>
        )}
        <table className="w-full text-left text-[15px]">
          <thead className="border-y bg-muted text-xs font-semibold tracking-wide text-muted-foreground uppercase">
            <tr>
              <th className="py-3 pl-6">Control</th>
              <th className="py-3">Kind</th>
              <th className="py-3">Action</th>
              <th className="py-3">Settings</th>
              <th className="py-3 pr-4 text-right">Fired · 24 h</th>
              <th className="py-3 pr-6">OWASP</th>
            </tr>
          </thead>
          <tbody>
            {d &&
              Object.entries(d.controls).map(([id, c]) => {
                const override = d.profiles[d.profile]?.[id];
                return (
                  <tr key={id} className="border-b last:border-b-0 hover:bg-selected/60">
                    <td className="py-3 pl-6">
                      <div className="font-mono text-sm">{id}</div>
                      <div className="text-sm text-muted-foreground">{CONTROLS[id]?.name ?? ""}</div>
                    </td>
                    <td className="py-3 pr-3">
                      <span className={cn("rounded border px-1.5 py-0.5 text-xs whitespace-nowrap", id === "injection.jev" ? "border-redact/40 text-redact" : "text-muted-foreground")}>{kindOf(id)}</span>
                    </td>
                    <td className="py-3 pr-3">
                      <ActionToggle
                        value={c.action as Action}
                        options={d.supported_actions[id] ?? ["allow", "flag", "redact", "block"]}
                        labels={ACTION_LABELS[id]}
                        pending={pending === id}
                        locked={override && "action" in override ? `The ${d.profile} profile sets this action. Change profiles.${d.profile} in policy.yaml.` : null}
                        onChange={(a) => setAction(id, a)}
                      />
                    </td>
                    <td className="py-3 pr-3 text-muted-foreground">{settingsOf(id, c, d)}</td>
                    <td className="py-3 pr-4 text-right font-mono tabular-nums">{fired.get(id) ?? 0}</td>
                    <td className="py-3 pr-6 font-mono text-xs">
                      {(OWASP[id] ?? []).map((o) => (
                        <div key={o} title={OWASP_LLM[o]}>
                          {o}
                        </div>
                      ))}
                    </td>
                  </tr>
                );
              })}
            {!d && (
              <tr>
                <td colSpan={6} className="py-10 text-center text-muted-foreground">
                  Loading the policy…
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Panel>

      {d && (
        <div className="grid grid-cols-1 gap-6 [&>*]:min-w-0 xl:grid-cols-2">
          <Models d={d} onChanged={reload} />
          <Budgets d={d} />
        </div>
      )}
      {d && <Signatures d={d} onChanged={reload} />}
    </>
  );
}

function ChangeList({ changes, className }: { changes: PolicyChange[]; className?: string }) {
  if (!changes.length) return <div className={cn("text-sm text-muted-foreground", className)}>Gateway started with this version.</div>;
  return (
    <ul className={cn("flex flex-col gap-0.5 font-mono text-xs", className)}>
      {changes.map((c, i) => (
        <li key={i} className="break-all">
          <span className="text-foreground">{c.what}</span>: <span className="text-block line-through">{fmt(c.old)}</span> → <span className="text-allow">{fmt(c.new)}</span>
        </li>
      ))}
    </ul>
  );
}

const fmt = (v: unknown) => {
  const s = JSON.stringify(v);
  return s === undefined ? "—" : s.length > 80 ? s.slice(0, 77) + "…" : s;
};

function Models({ d, onChanged }: { d: Details; onChanged: () => void }) {
  const [name, setName] = useState("");
  const [upstream, setUpstream] = useState(d.upstreams[0] ?? "openrouter");
  const [cls, setCls] = useState(d.levels[1] ?? "internal");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mode = d.controls["models.allowlist"]?.action;

  async function send(url: string, init: RequestInit) {
    setBusy(true);
    setError(null);
    try {
      const r = await fetch(url, init);
      if (!r.ok) setError(((await r.json().catch(() => null)) as { detail?: string } | null)?.detail ?? `error ${r.status}`);
      else setName("");
      onChanged();
    } catch {
      setError("the gateway could not be reached");
    } finally {
      setBusy(false);
    }
  }
  const approve = () =>
    send("/api/policy/models", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ model: name.trim(), upstream, max_class: cls }) });
  const remove = (id: string) => send(`/api/policy/models/${id.split("/").map(encodeURIComponent).join("/")}`, { method: "DELETE" });

  return (
    <Panel>
      <PanelHeader title="Approved models" count={Object.keys(d.models).length} />
      <ul className="divide-y">
        {Object.entries(d.models).map(([id, m]) => (
          <li key={id} className="flex items-center gap-2 px-6 py-2.5">
            <span className="truncate font-mono text-sm">{id}</span>
            <span className="ml-auto shrink-0 text-sm text-muted-foreground">
              {m.upstream === "mock" ? "scripted, never leaves this machine" : m.upstream === "openrouter" ? "OpenRouter" : m.upstream}
              {m.input_per_m != null ? ` · $${m.input_per_m}/$${m.output_per_m} per M tokens` : ""}
            </span>
            {m.upstream === "mock" && (
              <span className="shrink-0 rounded bg-flag-soft px-1.5 py-0.5 text-xs text-flag" title="Plays a hijacked model for demos and tests: it obeys every hidden instruction">
                test only
              </span>
            )}
            <span className="shrink-0 rounded border px-1.5 py-0.5 font-mono text-xs" title="Highest data class this model may receive">
              ≤ {m.effective_class}
            </span>
            <button
              onClick={() => remove(id)}
              disabled={busy}
              aria-label={`Remove ${id}`}
              title="Remove from the approved list"
              className="shrink-0 rounded p-1 text-muted-foreground hover:bg-accent hover:text-block disabled:opacity-50"
            >
              <X className="size-4" />
            </button>
          </li>
        ))}
      </ul>
      <form
        className="flex flex-wrap items-center gap-2 border-t px-6 py-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim()) approve();
        }}
      >
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="provider/model, e.g. mistralai/mistral-small-3.2"
          aria-label="Model name"
          className="min-w-0 flex-1 rounded-md border border-input bg-muted px-3 py-1.5 font-mono text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
        />
        <select value={upstream} onChange={(e) => setUpstream(e.target.value)} aria-label="Runs on" className="rounded-md border bg-card px-2 py-1.5 text-sm">
          {d.upstreams.map((u) => (
            <option key={u}>{u}</option>
          ))}
        </select>
        <select value={cls} onChange={(e) => setCls(e.target.value)} aria-label="Highest data class" className="rounded-md border bg-card px-2 py-1.5 text-sm">
          {d.levels.map((l) => (
            <option key={l} value={l}>
              ≤ {l}
            </option>
          ))}
        </select>
        <button type="submit" disabled={busy || !name.trim()} className="rounded-md border bg-card px-3 py-1.5 text-sm font-medium hover:bg-accent disabled:opacity-50">
          Approve
        </button>
      </form>
      {error && <p className="px-6 pb-3 text-sm text-block">{error}</p>}
      <p className="border-t px-6 py-3 text-sm text-muted-foreground">
        {mode === "block"
          ? "Enforced: any other model is refused before the request leaves the gateway."
          : mode === "flag"
            ? "Monitor: other models are let through, recorded, and receive only the lowest data class."
            : "Off: any model is let through."}{" "}
        A new model sees no client data until its class is raised.
      </p>
    </Panel>
  );
}

const ROLE_LABEL: Record<string, string> = {
  support_junior: "Support (junior)",
  fraud_analyst: "Fraud analyst",
  onboarding_analyst: "Onboarding analyst",
  mna_banker: "M&A banker",
  developer: "Developer",
  hr_admin: "HR administrator",
};
const roleLabel = (r: string) => ROLE_LABEL[r] ?? r.charAt(0).toUpperCase() + r.slice(1).replaceAll("_", " ");

const BUDGET_COLS: { key: keyof Budget; label: string; fmt: (v: number) => string }[] = [
  { key: "max_cost_usd", label: "Cost", fmt: (v) => `$${v}` },
  { key: "max_tokens", label: "Tokens", fmt: (v) => (v >= 1e6 ? `${+(v / 1e6).toFixed(1)}M` : `${(v / 1000).toLocaleString("en-US")}k`) },
  { key: "max_tool_calls", label: "Tool calls", fmt: (v) => String(v) },
  { key: "max_compute_seconds", label: "Model time", fmt: (v) => (v >= 60 ? `${v / 60} min` : `${v} s`) },
];

/** One aligned table: a row for the default and one per role that changes it; only the columns this level uses. */
function BudgetRows({ base, roles }: { base: Budget; roles: [string, Budget | undefined][] }) {
  const cols = BUDGET_COLS.filter((c) => base[c.key] != null || roles.some(([, b]) => b?.[c.key] != null));
  const rows: [string, Budget, boolean][] = [["Default (all roles)", base, true], ...roles.filter(([, b]) => b).map(([r, b]) => [roleLabel(r), { ...base, ...b }, false] as [string, Budget, boolean])];
  return (
    <table className="mx-6 my-2 w-[calc(100%-3rem)] text-[15px]">
      <thead className="text-xs text-muted-foreground">
        <tr>
          <th className="py-1 text-left font-normal" />
          {cols.map((c) => (
            <th key={c.key} className="py-1 text-right font-normal">
              {c.label}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map(([label, b, isDefault]) => (
          <tr key={label}>
            <td className={cn("py-1 pr-3", isDefault ? "font-medium" : "text-muted-foreground")}>{label}</td>
            {cols.map((c) => (
              <td key={c.key} className="py-1 pl-3 text-right font-mono text-sm tabular-nums">
                {b[c.key] != null ? c.fmt(b[c.key] as number) : "—"}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Budgets({ d }: { d: Details }) {
  const roles = Object.entries(d.roles);
  return (
    <Panel>
      <PanelHeader title="Budgets" />
      <div className="px-6 pt-3 text-sm font-medium">Per session · stops runaway loops</div>
      <BudgetRows base={d.budgets.session ?? {}} roles={roles.map(([n, r]) => [n, r.budget])} />
      <div className="border-t px-6 pt-3 text-sm font-medium">Per person per day (UTC) · all sessions together</div>
      <BudgetRows base={d.budgets.daily ?? {}} roles={roles.map(([n, r]) => [n, r.daily_budget])} />
      <p className="border-t px-6 py-3 text-sm text-muted-foreground">
        Defined per role, counted per person. Whichever limit is hit first stops the agent (action: {d.controls.budget?.action}).
      </p>
    </Panel>
  );
}

const SEVERITY_TONE: Record<string, string> = {
  critical: "bg-block-soft text-block",
  high: "bg-flag-soft text-flag",
  medium: "bg-redact-soft text-redact",
  low: "bg-muted text-muted-foreground",
};
const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

function Signatures({ d, onChanged }: { d: Details; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const f = d.feed;
  const sigs = [...d.signatures].sort((a, b) => (RANK[a.severity ?? "low"] ?? 4) - (RANK[b.severity ?? "low"] ?? 4) || (b.published ?? "").localeCompare(a.published ?? ""));
  async function pull() {
    setBusy(true);
    try {
      await fetch("/api/feed/refresh", { method: "POST" });
      onChanged();
    } finally {
      setBusy(false);
    }
  }
  return (
    <Panel className="mt-6">
      <PanelHeader title="Known-attack signatures" count={sigs.length}>
        <button onClick={pull} disabled={busy || !f?.url} className="rounded-md border bg-card px-3 py-1.5 text-sm hover:bg-accent disabled:opacity-50">
          <RefreshCw className={cn("mr-1.5 inline size-4", busy && "animate-spin")} />
          Pull feed now
        </button>
      </PanelHeader>
      <p className={cn("border-b px-6 py-3 text-sm", f?.error ? "text-block" : "text-muted-foreground")}>
        {!f?.url
          ? "Local file only: no feed_url set in policy.yaml."
          : f.error
            ? `Feed ${f.url} rejected or unreachable (${f.error}). The last good signatures stay active.`
            : `Pulled from ${f.url} · version ${f.version ?? "?"} · checked ${f.checked ? utcTime(f.checked) : "never"} · checked before it was enforced: patterns compile${
                f.tested ? `, ${f.tested} of ${f.count} signatures passed their own example attacks` : "; no signature carries example attacks yet"
              }.`}
      </p>
      <table className="w-full text-left text-[15px]">
        <thead className="border-b bg-muted text-sm text-muted-foreground">
          <tr>
            <th className="py-2.5 pl-6 font-normal">Severity</th>
            <th className="py-2.5 font-normal">Attack</th>
            <th className="py-2.5 font-normal">Checked in</th>
            <th className="py-2.5 font-normal">Known since</th>
            <th className="py-2.5 pr-6 font-normal">Source</th>
          </tr>
        </thead>
        <tbody>
          {sigs.map((s) => (
            <tr key={s.id} className="border-b align-top last:border-b-0">
              <td className="py-3 pl-6">
                {s.severity && <span className={cn("rounded px-1.5 py-0.5 text-xs font-medium capitalize", SEVERITY_TONE[s.severity])}>{s.severity}</span>}
              </td>
              <td className="py-3 pr-3">
                <div>{s.title || s.ref}</div>
                <div className="font-mono text-xs text-muted-foreground">{s.id}</div>
              </td>
              <td className="py-3 pr-3 text-sm text-muted-foreground">{s.where.join(", ").replaceAll("_", " ")}</td>
              <td className="py-3 pr-3 font-mono text-sm">{s.published ?? "—"}</td>
              <td className="py-3 pr-6 text-sm">
                {s.cve && <div className="font-mono">{s.cve}</div>}
                {(s.sources ?? []).slice(0, 2).map((u) => (
                  <a key={u} href={u} target="_blank" rel="noreferrer" className="block max-w-64 truncate text-muted-foreground underline hover:text-foreground">
                    {u.replace(/^https?:\/\//, "")}
                  </a>
                ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  );
}

/** Controls whose actions read better in their own words (the stored value stays allow / flag / block). */
const ACTION_LABELS: Record<string, Partial<Record<Action, string>>> = {
  "models.allowlist": { allow: "Off", flag: "Monitor", block: "Enforce" },
};

const TOGGLE: Record<Action, string> = {
  allow: "bg-allow-soft text-allow",
  flag: "bg-flag-soft text-flag",
  redact: "bg-redact-soft text-redact",
  block: "bg-block-soft text-block",
};

/** The actions this control implements (from the gateway); the active one carries its decision colour. */
function ActionToggle({
  value,
  options,
  labels,
  pending,
  locked,
  onChange,
}: {
  value: Action;
  options: Action[];
  labels?: Partial<Record<Action, string>>;
  pending: boolean;
  locked: string | null;
  onChange: (a: Action) => void;
}) {
  return (
    <div
      role="radiogroup"
      aria-label="Action"
      title={locked ?? undefined}
      className={cn("inline-flex overflow-hidden rounded-md border text-xs", pending && "opacity-60", locked && "opacity-70")}
    >
      {options.map((a) => (
        <button
          key={a}
          role="radio"
          aria-checked={value === a}
          disabled={pending || !!locked || value === a}
          onClick={() => onChange(a)}
          className={cn(
            "border-r px-2 py-1 capitalize last:border-r-0 disabled:cursor-default",
            value === a ? cn(TOGGLE[a], "font-semibold") : "bg-card text-muted-foreground enabled:hover:bg-accent",
          )}
        >
          {labels?.[a] ?? a}
        </button>
      ))}
    </div>
  );
}
