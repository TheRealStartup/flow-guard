"use client";

import { useCallback, useMemo, useState } from "react";
import { History, Radio, RefreshCw, Route, TriangleAlert, X } from "lucide-react";
import { usePoll, type Action, type ControlConfig, type PolicyChange } from "@/lib/api";
import { useAuditEvents, useOnPolicyChange, usePolicyLive } from "@/lib/stream";
import { CONTROLS, OWASP, OWASP_LLM, utcTime } from "@/lib/format";
import { ActionPill, Panel, PanelHeader, Pill, SectionLabel } from "@/components/kit";
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

const PROFILES = ["strict", "balanced", "permissive"];

/** Effective controls if `profile` were active: base controls plus that profile's overrides. */
function applyProfile(d: Details, profile: string) {
  const out: Record<string, ControlConfig> = JSON.parse(JSON.stringify(d.base_controls));
  for (const [id, patch] of Object.entries(d.profiles[profile] ?? {})) out[id] = { ...(out[id] ?? { action: "allow" }), ...patch } as ControlConfig;
  return out;
}

function diffControls(a: Record<string, ControlConfig>, b: Record<string, ControlConfig>): PolicyChange[] {
  const out: PolicyChange[] = [];
  for (const id of [...new Set([...Object.keys(a), ...Object.keys(b)])].sort())
    for (const k of [...new Set([...Object.keys(a[id] ?? {}), ...Object.keys(b[id] ?? {})])].sort())
      if (JSON.stringify(a[id]?.[k]) !== JSON.stringify(b[id]?.[k])) out.push({ what: `${id}.${k}`, old: a[id]?.[k], new: b[id]?.[k] });
  return out;
}

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
  const [preview, setPreview] = useState<string | null>(null);
  const [dismissed, setDismissed] = useState<string | null>(null);

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
          What is enforced right now. When someone edits <span className="font-mono text-[15px] text-foreground">policy.yaml</span>, this page shows the new version and what
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

      <Panel className="mb-6 px-6 py-5">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-4">
          <div className="flex items-baseline gap-3">
            <h2 className="text-lg font-semibold">Active profile</h2>
            <span className="text-[15px] text-muted-foreground">set in policy.yaml (read-only here)</span>
          </div>
          <div className="inline-flex overflow-hidden rounded-md border" role="radiogroup" aria-label="Profiles">
            {PROFILES.map((p) => {
              const active = d?.profile === p;
              return (
                <button
                  key={p}
                  role="radio"
                  aria-checked={active}
                  onClick={() => setPreview(active || preview === p ? null : p)}
                  title={active ? "Active profile" : `Preview what ${p} would change`}
                  className={cn(
                    "border-r px-4 py-2 text-[15px] last:border-r-0",
                    active ? "bg-primary text-primary-foreground" : preview === p ? "bg-selected" : "bg-card hover:bg-accent",
                  )}
                >
                  {p}
                </button>
              );
            })}
          </div>
          <span className="text-sm text-muted-foreground">
            If a check fails or times out: <b className="font-medium text-foreground">{d?.defaults.on_error ?? "block"}</b> (fail {d?.defaults.on_error === "allow" ? "open" : "closed"})
          </span>
        </div>
        {d && preview && <ProfilePreview d={d} profile={preview} onClose={() => setPreview(null)} />}
        {d && !preview && Object.keys(d.profiles[d.profile] ?? {}).length > 0 && (
          <p className="mt-3 text-sm text-muted-foreground">
            {d.profile} overrides {Object.keys(d.profiles[d.profile]).length} control{Object.keys(d.profiles[d.profile]).length === 1 ? "" : "s"}, marked below. Click another
            profile to preview what switching would change.
          </p>
        )}
        {d && !preview && !Object.keys(d.profiles[d.profile] ?? {}).length && (
          <p className="mt-3 text-sm text-muted-foreground">{d.profile} uses the base controls unchanged. Click another profile to preview what switching would change.</p>
        )}
      </Panel>

      <Panel className="mb-6 overflow-hidden">
        <div className="flex items-baseline gap-3 px-6 pt-5 pb-4">
          <h2 className="text-lg font-semibold">Controls</h2>
          <span className="text-[15px] text-muted-foreground">after the profile is applied</span>
          <span className="ml-auto text-sm text-muted-foreground">Block beats redact beats flag. Fired = blocked, redacted or flagged in the last 24 hours.</span>
        </div>
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
                      <div className="flex flex-col items-start gap-1">
                        <ActionPill action={c.action as Action} />
                        {override && (
                          <span className="text-[11px] text-muted-foreground" title={JSON.stringify(override)}>
                            set by {d.profile}
                          </span>
                        )}
                      </div>
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
          <Sinks d={d} />
          <Models d={d} />
          <Budgets d={d} />
          <Signatures d={d} />
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

function ProfilePreview({ d, profile, onClose }: { d: Details; profile: string; onClose: () => void }) {
  const changes = diffControls(d.controls, applyProfile(d, profile));
  return (
    <div className="mt-4 rounded-md border bg-muted px-4 py-3">
      <div className="mb-2 flex items-baseline gap-2">
        <span className="font-medium">
          Switching to {profile} would change {changes.length} setting{changes.length === 1 ? "" : "s"}
        </span>
        <span className="text-sm text-muted-foreground">
          preview only · edit <span className="font-mono">active_profile: {profile}</span> to apply
        </span>
        <button className="ml-auto p-1 text-muted-foreground hover:text-foreground" onClick={onClose} aria-label="Close preview">
          <X className="size-4" />
        </button>
      </div>
      {changes.length ? <ChangeList changes={changes} /> : <div className="text-sm text-muted-foreground">Nothing: same controls as now.</div>}
    </div>
  );
}

function Sinks({ d }: { d: Details }) {
  return (
    <Panel>
      <PanelHeader icon={<Route className="size-5" />} title="Data sinks" />
      <div className="flex flex-col gap-4 px-6 py-5">
        <div>
          <SectionLabel className="mb-1">External · data leaves here</SectionLabel>
          <div className="flex flex-wrap gap-1">
            {(d.sinks.external ?? []).map((t) => (
              <Pill key={t} tone="block" dot={false} className="font-mono text-xs">
                {t}
              </Pill>
            ))}
          </div>
          <p className="mt-1 text-sm text-muted-foreground">Calls carrying tokens or MNPI are blocked ({String(d.controls["flow.sensitive_to_external"]?.mode ?? "value")} mode).</p>
        </div>
        <div>
          <SectionLabel className="mb-1">Real values released to</SectionLabel>
          <div className="flex flex-wrap gap-1">
            {(d.sinks.detokenize ?? []).map((t) => (
              <Pill key={t} tone="flag" dot={false} className="font-mono text-xs">
                {t}
              </Pill>
            ))}
          </div>
          <p className="mt-1 text-sm text-muted-foreground">Only these tools get the card number, IBAN or passport back; everything else sees tokens.</p>
        </div>
      </div>
    </Panel>
  );
}

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

function Signatures({ d }: { d: Details }) {
  return (
    <Panel>
      <PanelHeader title="Threat signatures" count={d.signatures.length}>
        <span className="font-mono text-xs text-muted-foreground">{String(d.controls.signatures?.feed ?? "")}</span>
      </PanelHeader>
      <ul className="max-h-64 divide-y overflow-y-auto">
        {d.signatures.map((s) => (
          <li key={s.id} className="px-6 py-2.5" title={s.ref}>
            <div className="flex items-baseline gap-2">
              <span className="font-mono text-sm">{s.id}</span>
              <span className="ml-auto shrink-0 text-xs text-muted-foreground">{s.where.join(", ")}</span>
            </div>
            <div className="truncate text-xs text-muted-foreground">{s.ref}</div>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
