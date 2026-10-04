"use client";

import { useCallback, useMemo, useState } from "react";
import { History, Radio, RefreshCw, TriangleAlert, X } from "lucide-react";
import { usePoll, type Action, type ControlConfig, type PolicyChange } from "@/lib/api";
import { useAuditEvents, useOnPolicyChange, usePolicyLive } from "@/lib/stream";
import { CONTROLS, OWASP, OWASP_LLM, utcTime } from "@/lib/format";
import { Panel, PanelHeader } from "@/components/kit";
import { cn } from "@/lib/utils";

type Details = {
  version: string;
  profile: string;
  error: string | null;
  defaults: { on_error?: string };
  base_controls: Record<string, ControlConfig>;
  profiles: Record<string, Record<string, Partial<ControlConfig>>>;
  controls: Record<string, ControlConfig>;
  models: Record<string, { upstream: string; input_per_m?: number; output_per_m?: number }>;
  budgets: { session?: { max_tokens?: number; max_cost_usd?: number; max_tool_calls?: number; max_compute_seconds?: number } };
  identity: { mode: string; require_purpose: boolean; keys: { user: string; agent: string }[] };
  users: Record<string, { role: string; side?: string; assigned_clients?: string[]; deals?: number }>; // deals: a count, ids are codenames
  roles: Record<string, { tools: string[] }>;
  sinks: { external?: string[]; detokenize?: string[] };
  scopes: Record<string, { argument: string; user_field: string }>;
  barriers: { public_message: string; restricted: { terms: number }[] };
  signatures: { id: string; where: string[]; ref: string }[];
};

/** The one-line "what does this control check, with which settings" column. */
function settingsOf(id: string, c: ControlConfig, d: Details): string {
  const b = d.budgets.session ?? {};
  const onErr = c.on_error ? ` · on error ${c.on_error}` : "";
  switch (id) {
    case "models.allowlist":
      return `${Object.keys(d.models).length} models (${[...new Set(Object.values(d.models).map((m) => m.upstream))].join(", ")})`;
    case "budget":
      return `${(b.max_tokens ?? 0) / 1000}k tokens · $${b.max_cost_usd} · ${b.max_tool_calls} calls · ${b.max_compute_seconds} s compute / session`;
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
    default:
      return Object.entries(c).filter(([k]) => k !== "action").map(([k, v]) => `${k} ${v}`).join(" · ");
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
                      <span className={cn("rounded border px-1.5 py-0.5 text-xs", id === "injection.jev" ? "border-redact/40 text-redact" : "text-muted-foreground")}>{kindOf(id)}</span>
                    </td>
                    <td className="py-3 pr-3">
                      <ActionToggle
                        value={c.action as Action}
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
          <Models d={d} />
          <Budgets d={d} />
        </div>
      )}
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

function Models({ d }: { d: Details }) {
  return (
    <Panel>
      <PanelHeader title="Allowed models" count={Object.keys(d.models).length} />
      <ul className="divide-y">
        {Object.entries(d.models).map(([id, m]) => (
          <li key={id} className="flex items-baseline gap-2 px-6 py-2.5">
            <span className="truncate font-mono text-sm">{id}</span>
            <span className="ml-auto shrink-0 text-sm text-muted-foreground">
              {m.upstream}
              {m.input_per_m != null ? ` · $${m.input_per_m}/$${m.output_per_m} per M` : ""}
            </span>
          </li>
        ))}
      </ul>
      <p className="border-t px-6 py-3 text-sm text-muted-foreground">Any other model is refused before the request leaves the gateway.</p>
    </Panel>
  );
}

function Budgets({ d }: { d: Details }) {
  const b = d.budgets.session ?? {};
  const rows: [string, string][] = [
    ["Tokens", (b.max_tokens ?? 0).toLocaleString("en-US")],
    ["Cost", `$${b.max_cost_usd}`],
    ["Tool calls", String(b.max_tool_calls)],
    ["Compute", `${b.max_compute_seconds} s`],
  ];
  return (
    <Panel>
      <PanelHeader title="Session budget" />
      <dl className="grid grid-cols-2 gap-y-2 px-6 py-4 text-[15px]">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-muted-foreground">{k}</dt>
            <dd className="text-right font-mono">{v}</dd>
          </div>
        ))}
      </dl>
      <p className="border-t px-6 py-3 text-sm text-muted-foreground">Whichever limit is hit first stops the session (action: {d.controls.budget?.action}).</p>
    </Panel>
  );
}

const TOGGLE: Record<Action, string> = {
  allow: "bg-allow-soft text-allow",
  flag: "bg-flag-soft text-flag",
  redact: "bg-redact-soft text-redact",
  block: "bg-block-soft text-block",
};

/** Allow · Flag · Redact · Block for one control; the active one carries its decision colour. */
function ActionToggle({ value, pending, locked, onChange }: { value: Action; pending: boolean; locked: string | null; onChange: (a: Action) => void }) {
  return (
    <div
      role="radiogroup"
      aria-label="Action"
      title={locked ?? undefined}
      className={cn("inline-flex overflow-hidden rounded-md border text-xs", pending && "opacity-60", locked && "opacity-70")}
    >
      {(["allow", "flag", "redact", "block"] as Action[]).map((a) => (
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
          {a}
        </button>
      ))}
    </div>
  );
}
