"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ArrowRight, Gauge, Radio, RefreshCw, ShieldCheck, ShieldAlert, Table2, Users } from "lucide-react";
import { usePoll, type Health, type Verify } from "@/lib/api";
import { useAuditEvents } from "@/lib/stream";
import { CONTROLS, OUTCOME_LABEL, controlName, eventId, shortHash, utcDate, utcTime } from "@/lib/format";
import { NO_IDENTITY, OUTCOMES, RANGES, compact, computeOverview, ms, type Bucket, type Overview, type RangeKey } from "@/lib/stats";
import { ControlBars, Legend, MARK, ACTION_MARK, Meter, OutcomeColumns, Sparkline } from "@/components/charts";
import { PageHeader, Panel, PanelHeader, Pill, SectionLabel } from "@/components/kit";
import { cn } from "@/lib/utils";

type Metrics = {
  sessions: Record<
    string,
    {
      user: string;
      agent: string;
      tokens: number;
      cost_usd: number;
      tool_calls: number;
      compute_s: number;
      labels: string[];
      // Computed by the gateway with the same limits it enforces (default + the role's override).
      nearest: { limit_name: string; used: number; limit: number; share: number } | null;
    }
  >;
  budget: { max_tokens: number; max_cost_usd: number; max_tool_calls: number; max_compute_seconds: number };
  // Per person, today (UTC), against the daily budget of their role; computed by the gateway.
  daily?: Record<string, { tokens: number; cost_usd: number; limits: { max_tokens?: number; max_cost_usd?: number }; share: number }>;
};

const D3_TARGET_MS = 300; // decision D3: p95 target for the rule path, AI judge reported separately

export default function OverviewPage() {
  const [range, setRange] = useState<RangeKey>("24h");
  const { data: events, updatedAt, error, live } = useAuditEvents();
  // Budgets and the chain status change only when an entry is appended: refetch then, with a slow poll as a fallback.
  const { data: metrics, reload: reloadMetrics } = usePoll<Metrics>("/api/metrics", live ? 30_000 : 3000);
  const { data: verify, reload: reloadVerify } = usePoll<Verify>("/api/audit/verify", live ? 30_000 : 5000);
  const { data: health } = usePoll<Health>("/api/health", 5000);
  const top = events?.[0]?.seq;
  useEffect(() => {
    if (top === undefined) return;
    reloadMetrics();
    reloadVerify();
  }, [top, reloadMetrics, reloadVerify]);

  const o = useMemo(() => computeOverview(events ?? [], range, (updatedAt?.getTime() ?? 0) / 1000), [events, range, updatedAt]);
  const lastPolicy = events?.find((e) => e.type === "policy_change");

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="What the gateway checked, hid, stopped and let through, live from the audit log."
      />

      {/* One filter row scopes everything below it. */}
      <div className="mb-6 flex items-center gap-4">
        <div className="inline-flex rounded-md border bg-card p-1" role="radiogroup" aria-label="Time range">
          {RANGES.map((r) => (
            <button
              key={r.value}
              role="radio"
              aria-checked={range === r.value}
              onClick={() => setRange(r.value)}
              className={cn("rounded px-4 py-1.5 text-[15px] whitespace-nowrap", range === r.value ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-accent")}
            >
              {r.label}
            </button>
          ))}
        </div>
        <span className="text-[15px] text-muted-foreground">Every number below covers the last {o.range.label}.</span>
        <span className={cn("ml-auto flex items-center gap-2 text-[15px] text-muted-foreground", error && "text-block")}>
          {live ? <Radio className="size-4 text-primary" /> : <RefreshCw className="size-4" />}
          {error && !live
            ? "Gateway unreachable, retrying"
            : updatedAt
              ? `Updated ${utcTime(updatedAt.getTime() / 1000, false)} UTC · ${live ? "Live" : "Polling every 2 s"}`
              : "Loading…"}
        </span>
      </div>

      <div className={cn("transition-opacity", !events && "opacity-50")}>
        <Tiles o={o} />

        <div className="mb-6 grid grid-cols-1 gap-6 [&>*]:min-w-0 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
          <Panel>
            <PanelHeader title="Decisions over time" count={`${o.now.requests} requests`}>
              <TableToggle o={o} />
            </PanelHeader>
            <div className="px-6 pt-4 pb-5">
              <Legend items={[...OUTCOMES].reverse().map((k) => ({ label: OUTCOME_LABEL[k], color: MARK[k], value: o.now.counts[k] }))} />
              <div className="mt-5">
                {o.now.requests ? <OutcomeColumns buckets={o.buckets} label={(b) => bucketLabel(b, o)} /> : <Empty text={`No requests in the last ${o.range.label}.`} />}
              </div>
            </div>
          </Panel>
          <RecentBlocks o={o} />
        </div>

        <div className="mb-6 grid grid-cols-1 gap-6 [&>*]:min-w-0 xl:grid-cols-2">
          <Panel>
            <PanelHeader title="What the controls caught" count={o.controls.reduce((s, r) => s + r.total, 0)} />
            <div className="px-6 pt-4 pb-5">
              <Legend items={[{ label: "Blocked", color: ACTION_MARK.block }, { label: "Redacted", color: ACTION_MARK.redact }, { label: "Flagged", color: ACTION_MARK.flag }]} />
              <div className="mt-5">{o.controls.length ? <ControlBars rows={o.controls} /> : <Empty text="No control has fired in this range." />}</div>
            </div>
          </Panel>
          <Latency o={o} />
        </div>

        <div className="mb-6 grid grid-cols-1 gap-6 [&>*]:min-w-0 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
          <Actors o={o} />
          <Budgets metrics={metrics} />
        </div>

        <Panel className="grid grid-cols-1 divide-y md:grid-cols-3 md:divide-x md:divide-y-0">
          <Trust
            icon={verify && !verify.ok ? <ShieldAlert className="size-5 text-block" /> : <ShieldCheck className="size-5 text-allow" />}
            title={verify ? (verify.ok ? "Audit chain verified" : `Chain broken at entry ${verify.broken_at}`) : "Checking audit chain…"}
            note={verify ? `${verify.entries} entries · head ${shortHash(verify.head)}` : ""}
          />
          <Trust
            icon={<Gauge className="size-5" />}
            title={health ? `Policy ${health.policy_version} · ${health.profile}` : "Policy…"}
            note={lastPolicy ? `Last reload ${utcDate(lastPolicy.ts)} ${utcTime(lastPolicy.ts, false)} UTC` : "Reloads live when policy.yaml changes"}
          />
          <Trust
            icon={<ShieldAlert className={cn("size-5", health?.judge === "demo" ? "text-flag" : "text-allow")} />}
            title={health ? (health.judge === "demo" ? "Injection judge: offline demo checker" : `Injection judge: ${health.judge}`) : "Judge…"}
            note={health?.judge === "demo" ? "Keyword stand-in, not a security classifier" : "Fails closed if the check errors"}
          />
        </Panel>
      </div>
    </>
  );
}

function Tiles({ o }: { o: Overview }) {
  const { now, before } = o;
  const pct = (n: number) => (now.requests ? `${Math.round((n / now.requests) * 100)}%` : "0%");
  const delta = (a: number, b: number) => {
    const d = a - b;
    return `${d > 0 ? "+" : d < 0 ? "−" : "±"}${Math.abs(d)} vs previous ${o.range.label}`;
  };
  const p95 = o.latency.rulesP95;
  return (
    <div className="mb-6 grid grid-cols-2 overflow-hidden rounded-lg border bg-card xl:grid-cols-4 xl:divide-x">
      <Tile label="Requests checked" value={compact(now.requests)} note={`${o.actors.length} users · ${o.agents} agents`} sub={delta(now.requests, before.requests)} trend={<Sparkline values={o.sparkline} />} />
      <Tile
        label="Attacks stopped"
        mark="var(--block)"
        value={compact(now.attacks)}
        note={Object.entries(now.attackKinds).map(([k, n]) => `${n} ${k}${n === 1 ? "" : "s"}`).join(" · ") || "none in this range"}
        sub={`${now.counts.blocked} requests blocked (${pct(now.counts.blocked)}) · ${delta(now.attacks, before.attacks)}`}
      />
      <Tile
        label="Data protected"
        mark="var(--redact)"
        value={compact(now.hidden)}
        note={`values tokenized · ${now.quarantined} messages quarantined`}
        sub={now.released ? `${now.released} real values released to approved tools` : "No real values released"}
      />
      <Tile
        label="Rule checks p95"
        mark={p95 != null && p95 > D3_TARGET_MS ? "var(--block)" : "var(--allow)"}
        value={ms(p95)}
        note={`target ${D3_TARGET_MS} ms · p50 ${ms(o.latency.rulesP50)}`}
        sub={`AI judge avg ${ms(o.latency.judgeAvg)}, reported separately`}
      />
    </div>
  );
}

function Tile({ label, value, note, sub, trend, mark }: { label: string; value: string; note: string; sub: string; trend?: React.ReactNode; mark?: string }) {
  return (
    <div className="px-6 py-5">
      <div className="flex items-center gap-2 text-sm font-medium tracking-wide uppercase">
        {mark && <span className="size-2.5 rounded-[3px]" style={{ background: mark }} />}
        {label}
      </div>
      <div className="mt-2 flex items-end justify-between gap-3">
        <span className="text-[32px] leading-none font-semibold">{value}</span>
        {trend}
      </div>
      <div className="mt-3 text-[15px] text-muted-foreground">{note}</div>
      <div className="mt-1 text-sm text-muted-foreground">{sub}</div>
    </div>
  );
}

function bucketLabel(b: Bucket, o: Overview) {
  const end = b.start + o.range.bucket;
  if (o.range.bucket >= 3600 * 6) return `${utcDate(b.start)} ${utcTime(b.start, false).slice(0, 5)}`;
  return `${utcTime(b.start, false).slice(0, 5)} – ${utcTime(end, false).slice(0, 5)}`;
}

function TableToggle({ o }: { o: Overview }) {
  const [open, setOpen] = useState(false);
  const rows = o.buckets.filter((b) => b.total > 0);
  return (
    <>
      <button onClick={() => setOpen(!open)} className="inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm hover:bg-accent" aria-expanded={open}>
        <Table2 className="size-4" /> {open ? "Hide table" : "Table"}
      </button>
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-primary/40 p-8" onClick={() => setOpen(false)}>
          <div className="max-h-full w-full max-w-2xl overflow-auto rounded-lg bg-card p-6 shadow-xl" onClick={(e) => e.stopPropagation()}>
            <h2 className="mb-4 text-lg font-semibold">Decisions over time · last {o.range.label}</h2>
            <table className="w-full text-left text-sm tabular-nums">
              <thead className="border-b text-muted-foreground">
                <tr>
                  <th className="py-2 font-normal">Time (UTC)</th>
                  <th className="py-2 text-right font-normal">Requests</th>
                  {[...OUTCOMES].reverse().map((k) => (
                    <th key={k} className="py-2 text-right font-normal">
                      {OUTCOME_LABEL[k]}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((b) => (
                  <tr key={b.start} className="border-b last:border-b-0">
                    <td className="py-1.5">{bucketLabel(b, o)}</td>
                    <td className="py-1.5 text-right">{b.total}</td>
                    {[...OUTCOMES].reverse().map((k) => (
                      <td key={k} className="py-1.5 text-right">
                        {b.counts[k]}
                      </td>
                    ))}
                  </tr>
                ))}
                {!rows.length && (
                  <tr>
                    <td colSpan={6} className="py-6 text-center text-muted-foreground">
                      No requests in this range.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  );
}

function RecentBlocks({ o }: { o: Overview }) {
  return (
    <Panel className="flex flex-col">
      <PanelHeader title="Latest attacks and blocks" count={o.recentBlocks.length} />
      <ul className="flex-1 divide-y">
        {o.recentBlocks.map((e) => {
          const d = e.decisions.find((x) => x.action === "block") ?? e.decisions.find((x) => x.control === "injection.jev" && x.action === "redact");
          const s = e.summary;
          return (
            <li key={e.seq}>
              <Link href={`/audit?q=${eventId(e)}`} className="flex gap-3 px-6 py-3 hover:bg-selected/60">
                <span className="mt-1.5 size-2 shrink-0 rounded-full bg-block" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline gap-2">
                    <span className="truncate font-medium" title={s?.reason}>
                      {s?.headline ?? (d ? controlName(d.control) : "Blocked")}
                    </span>
                    <span className="ml-auto shrink-0 font-mono text-xs text-muted-foreground">{utcTime(e.ts, false)}</span>
                  </div>
                  <div className="truncate text-sm text-muted-foreground">
                    {s?.label ?? (e.threats?.length ? "Attack caught" : "Blocked")} · {e.user ?? NO_IDENTITY}
                    {d ? ` · ${controlName(d.control)}` : ""}
                  </div>
                </div>
              </Link>
            </li>
          );
        })}
        {!o.recentBlocks.length && <li className="px-6 py-10 text-center text-muted-foreground">No attacks or blocks in this range.</li>}
      </ul>
      <Link href="/audit?outcome=attack" className="flex items-center gap-2 border-t px-6 py-3 text-sm text-muted-foreground hover:text-foreground">
        All caught attacks in the audit trail <ArrowRight className="size-4" />
      </Link>
    </Panel>
  );
}

function Latency({ o }: { o: Overview }) {
  const l = o.latency;
  const max = Math.max(1, ...l.perControl.map((c) => c.avg));
  const rows: [string, string, string][] = [
    ["Rule checks", `${ms(l.rulesP50)} / ${ms(l.rulesP95)}`, "check time minus the AI judge"],
    ["All checks", `${ms(l.checksP50)} / ${ms(l.checksP95)}`, "the gateway's own time per request"],
    ["AI judge", ms(l.judgeAvg), "average per check"],
    ["Model", ms(l.modelP50), "median upstream time"],
  ];
  return (
    <Panel>
      <PanelHeader title="Latency" count="p50 / p95" />
      <div className="px-6 pt-4 pb-5">
        <dl className="grid grid-cols-[7rem_8rem_1fr] gap-y-2 text-[15px]">
          {rows.map(([k, v, n]) => (
            <div key={k} className="contents">
              <dt className="text-muted-foreground">{k}</dt>
              <dd className="font-medium tabular-nums">{v}</dd>
              <dd className="text-sm text-muted-foreground">{n}</dd>
            </div>
          ))}
        </dl>
        <SectionLabel className="mt-6 mb-3">Average per control</SectionLabel>
        <div className="flex flex-col gap-2">
          {l.perControl.slice(0, 6).map((c) => (
            <div key={c.control} className="grid grid-cols-[11rem_1fr] items-center gap-3 text-sm" title={c.control}>
              <span className="truncate">{controlName(c.control)}</span>
              <div className="flex items-center gap-2">
                <div className="h-2 rounded-r-[4px] bg-primary" style={{ width: `${Math.max(1, (c.avg / max) * 80)}%` }} />
                <span className="tabular-nums text-muted-foreground">{ms(c.avg)}</span>
              </div>
            </div>
          ))}
          {!l.perControl.length && <Empty text="No timings in this range." />}
        </div>
      </div>
    </Panel>
  );
}

function Actors({ o }: { o: Overview }) {
  return (
    <Panel className="overflow-hidden">
      <PanelHeader icon={<Users className="size-5" />} title="Users and agents" count={o.actors.length} />
      <table className="w-full text-left text-[15px]">
        <thead className="border-b bg-muted text-xs font-semibold tracking-wide text-muted-foreground uppercase">
          <tr>
            <th className="py-3 pl-6">User</th>
            <th className="py-3">Agents</th>
            <th className="w-24 px-3 py-3 text-right">Requests</th>
            <th className="w-24 px-3 py-3 text-right">Blocked</th>
            <th className="w-24 px-3 py-3 text-right">Redacted</th>
            <th className="py-3 pl-6">Most frequent control</th>
            <th className="py-3 pr-6">Data held</th>
          </tr>
        </thead>
        <tbody>
          {o.actors.map((a) => (
            <tr key={a.user} className="border-b last:border-b-0 hover:bg-selected/60">
              <td className="py-3 pl-6">
                <Link href={`/audit?q=${encodeURIComponent(a.user)}`} className="font-mono text-sm hover:underline">
                  {a.user}
                </Link>
                <div className="text-xs whitespace-nowrap text-muted-foreground">last {utcTime(a.last, false)}</div>
              </td>
              <td className="max-w-48 truncate py-3 pr-3 font-mono text-sm text-muted-foreground">{a.agents.join(", ") || "—"}</td>
              <td className="px-3 py-3 text-right tabular-nums">{a.requests}</td>
              <td className="px-3 py-3 text-right tabular-nums">{a.blocked ? <span className="font-medium text-block">{a.blocked}</span> : 0}</td>
              <td className="px-3 py-3 text-right tabular-nums">{a.redacted}</td>
              <td className="py-3 pl-6 text-sm">{a.topControl ? CONTROLS[a.topControl]?.name ?? a.topControl : <span className="text-muted-foreground">none</span>}</td>
              <td className="py-3 pr-6">
                <div className="flex flex-wrap gap-1">
                  {a.labels.map((l) => (
                    <Pill key={l} tone="redact" dot={false} className="font-mono text-xs">
                      {l}
                    </Pill>
                  ))}
                </div>
              </td>
            </tr>
          ))}
          {!o.actors.length && (
            <tr>
              <td colSpan={7} className="py-10 text-center text-muted-foreground">
                No traffic in this range.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </Panel>
  );
}

const LIMIT: Record<string, { label: string; fmt: (v: number) => string }> = {
  max_tokens: { label: "Tokens", fmt: (v) => (v >= 1e6 ? `${+(v / 1e6).toFixed(1)}M` : v >= 1000 ? `${Math.round(v / 1000)}k` : String(v)) },
  max_cost_usd: { label: "Cost", fmt: (v) => `$${v.toFixed(2)}` },
  max_tool_calls: { label: "Tool calls", fmt: (v) => String(v) },
  max_compute_seconds: { label: "Compute", fmt: (v) => `${Math.round(v)} s` },
};

function Budgets({ metrics }: { metrics: Metrics | null }) {
  const rows = metrics
    ? Object.entries(metrics.sessions)
        .filter(([, s]) => s.nearest)
        .map(([id, s]) => ({ id, user: s.user, agent: s.agent, n: s.nearest! }))
        .sort((x, y) => y.n.share - x.n.share)
        .slice(0, 6)
    : [];
  return (
    <Panel>
      <PanelHeader title="Session budgets" count={metrics ? Object.keys(metrics.sessions).length : "…"} />
      <div className="px-6 pt-4 pb-5">
        <p className="mb-4 text-sm text-muted-foreground">
          Live sessions since the gateway started, closest to a limit first. Each session has the budget of its role; it is stopped at 100%.
        </p>
        <div className="flex flex-col gap-4">
          {rows.map((r) => (
            <div key={r.id}>
              <div className="mb-1 flex items-baseline gap-2 text-sm">
                <Link href={`/audit?q=${encodeURIComponent(r.id)}`} className="truncate font-mono hover:underline">
                  {r.id}
                </Link>
                <span className="shrink-0 text-muted-foreground">
                  {r.user} · {r.agent}
                </span>
                <span className="ml-auto shrink-0 text-muted-foreground">
                  {LIMIT[r.n.limit_name]?.label ?? r.n.limit_name} {LIMIT[r.n.limit_name]?.fmt(r.n.used) ?? r.n.used} of{" "}
                  {LIMIT[r.n.limit_name]?.fmt(r.n.limit) ?? r.n.limit} ({Math.round(r.n.share * 100)}%)
                </span>
              </div>
              <Meter value={Math.min(r.n.used, r.n.limit)} max={r.n.limit} label={`${r.id} ${r.n.limit_name}`} />
            </div>
          ))}
          {metrics && !rows.length && <Empty text="No live sessions." />}
        </div>
        {metrics?.daily && Object.keys(metrics.daily).length > 0 && (
          <>
            <p className="mt-6 mb-3 text-sm text-muted-foreground">Per person today (UTC), all sessions together, against the daily budget of their role.</p>
            <div className="flex flex-col gap-3">
              {Object.entries(metrics.daily)
                .sort(([, a], [, b]) => b.share - a.share)
                .slice(0, 6)
                .map(([user, u]) => (
                  <div key={user}>
                    <div className="mb-1 flex items-baseline gap-2 text-sm">
                      <span className="font-mono">{user}</span>
                      <span className="ml-auto shrink-0 text-muted-foreground">
                        {LIMIT.max_tokens.fmt(u.tokens)} of {u.limits.max_tokens != null ? LIMIT.max_tokens.fmt(u.limits.max_tokens) : "∞"} tokens ·{" "}
                        {LIMIT.max_cost_usd.fmt(u.cost_usd)} of {u.limits.max_cost_usd != null ? LIMIT.max_cost_usd.fmt(u.limits.max_cost_usd) : "∞"} ({Math.round(u.share * 100)}%)
                      </span>
                    </div>
                    <Meter value={Math.min(u.share, 1)} max={1} label={`${user} daily budget`} />
                  </div>
                ))}
            </div>
          </>
        )}
      </div>
    </Panel>
  );
}

function Trust({ icon, title, note }: { icon: React.ReactNode; title: string; note: string }) {
  return (
    <div className="flex gap-3 px-6 py-4">
      <span className="mt-0.5">{icon}</span>
      <div className="min-w-0">
        <div className="font-medium">{title}</div>
        <div className="truncate font-mono text-xs text-muted-foreground">{note}</div>
      </div>
    </div>
  );
}

const Empty = ({ text }: { text: string }) => <div className="py-10 text-center text-muted-foreground">{text}</div>;
