"use client";

import { useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { ArrowUp, ChevronLeft, ChevronRight, Download, Radio, RefreshCw, RotateCcw, Search } from "lucide-react";
import { usePoll, type AuditEvent, type Verify } from "@/lib/api";
import { useAuditEvents } from "@/lib/stream";
import { controlName, eventLines, utcDate, utcTime } from "@/lib/format";
import { Btn, Field, PageHeader, Panel, PanelHeader, Select, Stat, StatRow, VerdictPill } from "@/components/kit";
import { cn } from "@/lib/utils";
import { EventDetail } from "./event-detail";

const RANGES = [
  { value: "15m", label: "Last 15 minutes", seconds: 15 * 60 },
  { value: "1h", label: "Last hour", seconds: 3600 },
  { value: "today", label: "Today (UTC)", seconds: 0 },
  { value: "7d", label: "Last 7 days", seconds: 7 * 86400 },
  { value: "all", label: "All time", seconds: Infinity },
];

// The gateway's verdicts (one per event, the same label as the row badge). "attack" is linked from the Overview.
const OUTCOMES = [
  { value: "", label: "All outcomes" },
  { value: "attack", label: "Attack caught" },
  { value: "blocked", label: "Blocked" },
  { value: "withheld", label: "Withheld" },
  { value: "hidden", label: "Hidden" },
  { value: "released", label: "Released" },
  { value: "flagged", label: "Flagged" },
  { value: "allowed", label: "Allowed" },
  { value: "policy_change", label: "Policy changes" },
];

/** The verdict an outcome filter compares against; falls back to the raw outcome for entries without a summary. */
function verdictOf(e: AuditEvent): string {
  if (e.type === "policy_change") return "policy_change";
  if (e.summary) return e.summary.verdict === "quarantined" ? "attack" : e.summary.verdict;
  return e.threats?.length ? "attack" : e.outcome === "redacted" ? "hidden" : e.outcome;
}

const PAGE_SIZES = [12, 25, 50];

function rangeStart(range: string): number {
  const r = RANGES.find((x) => x.value === range)!;
  if (r.value === "today") {
    const d = new Date();
    return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) / 1000;
  }
  return Date.now() / 1000 - r.seconds;
}

/** Tool names an exchange proposed, or a pseudo-action for exchanges without tool calls. */
function actionsOf(e: AuditEvent): string[] {
  if (e.type === "policy_change") return ["policy"];
  const names = (e.tool_calls ?? []).map((c) => c.name);
  return names.length ? names : ["model"];
}

const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;
const uniq = (xs: (string | null | undefined)[]) => [...new Set(xs.filter(Boolean) as string[])].sort();

export function AuditTrail() {
  const params = useSearchParams();
  const [range, setRange] = useState("all");
  const [action, setAction] = useState("");
  const [agent, setAgent] = useState("");
  const [user, setUser] = useState("");
  const [outcome, setOutcome] = useState(params.get("outcome") ?? "");
  const [query, setQuery] = useState(params.get("q") ?? params.get("session") ?? "");
  const [pageSize, setPageSize] = useState(12);
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<number | null>(null);
  // Past page 1, hide entries newer than this seq so live arrivals don't shift the rows being read.
  const [frozenAt, setFrozenAt] = useState<number | null>(null);

  const { data: events, updatedAt, error, live, fresh } = useAuditEvents();
  const { data: verify } = usePoll<Verify>("/api/audit/verify", 5000);

  const all = useMemo(() => events ?? [], [events]);
  const inRange = useMemo(() => {
    const from = rangeStart(range);
    return all.filter((e) => e.ts >= from);
    // updatedAt re-evaluates relative ranges ("last 15 minutes") on every poll
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [all, range, updatedAt]);

  const exchanges = inRange.filter((e) => e.type === "exchange");
  // One verdict per request, so the tiles never count the same request twice.
  const verdicts = { attack: 0, blocked: 0, hidden: 0, withheld: 0, flagged: 0 } as Record<string, number>;
  for (const e of exchanges) verdicts[verdictOf(e)] = (verdicts[verdictOf(e)] ?? 0) + 1;
  const agents = uniq(exchanges.map((e) => e.agent));

  const options = useMemo(() => {
    const ex = all.filter((e) => e.type === "exchange");
    return {
      actions: uniq(ex.flatMap(actionsOf).filter((a) => a !== "model")),
      agents: uniq(ex.map((e) => e.agent)),
      users: uniq(ex.map((e) => e.user)),
    };
  }, [all]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return inRange.filter((e) => {
      if (frozenAt !== null && e.seq > frozenAt) return false;
      if (outcome && verdictOf(e) !== outcome) return false;
      if (action && !actionsOf(e).includes(action)) return false;
      if (agent && (e.type !== "exchange" || e.agent !== agent)) return false;
      if (user && (e.type !== "exchange" || e.user !== user)) return false;
      if (!q) return true;
      const hay = [
        `evt-${String(e.seq).padStart(6, "0")}`,
        String(e.seq),
        e.hash,
        ...actionsOf(e),
        e.summary?.headline,
        e.summary?.label,
        ...(e.type === "exchange"
          ? [e.session, e.user, e.agent, e.purpose, e.role, ...e.decisions.flatMap((d) => [d.control, controlName(d.control)])]
          : [e.version, ...e.changes.map((c) => c.what)]),
      ];
      return hay.some((h) => h?.toLowerCase().includes(q));
    });
  }, [inRange, outcome, action, agent, user, query, frozenAt]);

  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  const current = Math.min(page, pages - 1);
  const visible = rows.slice(current * pageSize, current * pageSize + pageSize);
  // Pin the default selection to the first row shown, so the detail panel doesn't jump to each new arrival.
  if (selected === null && visible.length) setSelected(visible[0].seq);
  const detail = rows.find((e) => e.seq === selected) ?? visible[0] ?? null;
  const newer = frozenAt === null ? 0 : all.filter((e) => e.seq > frozenAt).length;

  const goPage = (p: number) => {
    setPage(p);
    setFrozenAt(p > 0 ? (frozenAt ?? all[0]?.seq ?? null) : null);
  };
  const filtered = Boolean(action || agent || user || outcome || query);
  const reset = () => {
    setAction("");
    setAgent("");
    setUser("");
    setOutcome("");
    setQuery("");
    goPage(0);
  };
  const set = (fn: (v: string) => void) => (v: string) => {
    fn(v);
    goPage(0);
  };
  const rangeLabel = RANGES.find((r) => r.value === range)!.label.toLowerCase();

  return (
    <>
      <PageHeader
        title="Agent audit trail"
        subtitle="A hash-chained record of every request, policy decision and proposed tool call."
        actions={
          <a href="/api/audit/export" download>
            <Btn variant="primary">
              <Download className="size-5" /> Export JSONL
            </Btn>
          </a>
        }
      />

      <StatRow>
        <Stat
          label="Agent requests"
          value={events ? exchanges.length : "—"}
          unit={range === "all" ? "all time" : rangeLabel}
          note={events ? `${plural(agents.length, "agent")} · ${verdicts.flagged} flagged for review · ${plural(inRange.length - exchanges.length, "policy event")} besides` : "Loading the audit log…"}
        />
        <Stat label="Attacks caught" value={events ? verdicts.attack : "—"} tone="block" note="Injections quarantined or data stopped on its way out" />
        <Stat label="Blocked" value={events ? verdicts.blocked : "—"} tone="block" note="Not attacks: outside scope or role, over budget, no valid key" />
        <Stat
          label="Data hidden"
          value={events ? verdicts.hidden + verdicts.withheld : "—"}
          tone="redact"
          note="Requests where values were tokenized or content withheld"
        />
      </StatRow>

      <Panel className="mb-6 px-6 pt-5 pb-4">
        <div className="grid grid-cols-2 items-end gap-4 lg:grid-cols-[1.3fr_1fr_1fr_1fr_1fr_auto]">
          <Field label="Date">
            <Select value={range} onChange={set(setRange)} options={RANGES} />
          </Field>
          <Field label="Action">
            <Select
              value={action}
              onChange={set(setAction)}
              options={[
                { value: "", label: "All actions" },
                { value: "model", label: "Model requests (no tool call)" },
                { value: "policy", label: "Policy changes" },
                ...options.actions.map((a) => ({ value: a, label: a })),
              ]}
            />
          </Field>
          <Field label="Agent ID">
            <Select value={agent} onChange={set(setAgent)} options={[{ value: "", label: "All agents" }, ...options.agents.map((a) => ({ value: a, label: a }))]} />
          </Field>
          <Field label="User ID">
            <Select value={user} onChange={set(setUser)} options={[{ value: "", label: "All users" }, ...options.users.map((u) => ({ value: u, label: u }))]} />
          </Field>
          <Field label="Outcome">
            <Select value={outcome} onChange={set(setOutcome)} options={OUTCOMES} />
          </Field>
          <Btn onClick={reset} disabled={!filtered}>
            <RotateCcw className="size-4" /> Reset
          </Btn>
        </div>
        <div className="mt-4 flex items-center text-[15px] text-muted-foreground">
          <span>
            Showing {filtered ? `${rows.length} matching event${rows.length === 1 ? "" : "s"}` : "all events"} · {rangeLabel}
          </span>
          <span className={cn("ml-auto flex items-center gap-2", error && "text-block")}>
            {live ? <Radio className="size-4 text-primary" /> : <RefreshCw className="size-4" />}
            {error
              ? "Gateway unreachable, retrying"
              : updatedAt
                ? `Updated ${utcTime(updatedAt.getTime() / 1000, false)} UTC · ${live ? "Live" : "Polling every 2 s"}`
                : "Loading…"}
          </span>
        </div>
      </Panel>

      <div className="flex items-start gap-6">
        <Panel className="min-w-0 flex-1 overflow-hidden">
          <PanelHeader title="Activity log" count={rows.length}>
            {newer > 0 && (
              <Btn onClick={() => goPage(0)} className="h-10">
                <ArrowUp className="size-4" /> {newer} new {newer === 1 ? "event" : "events"}
              </Btn>
            )}
            <div className="relative w-80">
              <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
              <input
                value={query}
                onChange={(e) => set(setQuery)(e.target.value)}
                placeholder="Search event, session, tool, control or reason…"
                className="h-10 w-full rounded-md border border-input pr-3 pl-9 text-[15px] outline-none placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring/50"
              />
            </div>
          </PanelHeader>

          <table className="w-full table-fixed text-left">
            <thead className="border-b bg-muted text-xs font-semibold tracking-wide text-muted-foreground uppercase">
              <tr>
                <th className="w-28 py-3 pl-5">Time (UTC) ↓</th>
                <th className="py-3">What happened</th>
                <th className="w-36 py-3">User · agent</th>
                <th className="w-32 py-3">Outcome</th>
                <th className="w-6" />
              </tr>
            </thead>
            <tbody>
              {visible.map((e) => {
                const { title, detail: sub } = eventLines(e);
                const active = detail?.seq === e.seq;
                return (
                  <tr
                    key={e.seq}
                    onClick={() => setSelected(e.seq)}
                    className={cn(
                      "cursor-pointer border-b border-l-2 border-l-transparent transition-colors duration-700 last:border-b-0 hover:bg-selected/60 hover:duration-0",
                      (active || fresh.has(e.seq)) && "bg-selected",
                      active && "border-l-primary",
                    )}
                  >
                    <td className="py-3 pl-5">
                      <div className="font-mono text-sm whitespace-nowrap">{utcTime(e.ts, false)}</div>
                      <div className="text-sm whitespace-nowrap text-muted-foreground">{utcDate(e.ts)}</div>
                    </td>
                    <td className="py-3 pr-4">
                      <div className="line-clamp-2 font-medium break-words" title={e.summary?.reason}>
                        {title}
                      </div>
                      <div className="truncate text-sm text-muted-foreground">{sub}</div>
                    </td>
                    <td className="truncate py-3 pr-3 text-sm">
                      <div className="truncate font-mono">{e.type === "exchange" ? (e.user ?? "—") : "policy.yaml"}</div>
                      <div className="truncate font-mono text-muted-foreground">{e.type === "exchange" ? (e.agent ?? "—") : ""}</div>
                    </td>
                    <td className="py-3">
                      <VerdictPill event={e} />
                    </td>
                    <td className="py-3 pr-4 text-muted-foreground">
                      <ChevronRight className={cn("size-4", active && "text-foreground")} />
                    </td>
                  </tr>
                );
              })}
              {!visible.length && (
                <tr>
                  <td colSpan={6} className="py-16 text-center text-muted-foreground">
                    {events ? "No events match these filters." : "Loading the audit log…"}
                  </td>
                </tr>
              )}
            </tbody>
          </table>

          <div className="flex items-center gap-3 border-t px-5 py-4 text-[15px]">
            <span className="text-muted-foreground">Rows per page</span>
            <Select
              className="w-20"
              value={String(pageSize)}
              onChange={(v) => {
                setPageSize(Number(v));
                goPage(0);
              }}
              options={PAGE_SIZES.map((n) => ({ value: String(n), label: String(n) }))}
            />
            <span className="ml-auto text-muted-foreground">
              {rows.length ? `${current * pageSize + 1}–${Math.min(rows.length, (current + 1) * pageSize)} of ${rows.length}` : "0 of 0"}
            </span>
            <Pager page={current} pages={pages} onPage={goPage} />
          </div>
          <div className="border-t bg-muted px-5 py-3 text-sm text-muted-foreground">
            Masked by the gateway: card numbers, IBANs, national IDs and secrets never appear in this log, only tokens.
          </div>
        </Panel>

        <EventDetail
          event={detail}
          verify={verify}
          onSession={(s) => {
            // A session is read as one story: clear the other filters so none of its steps are hidden.
            for (const reset of [setAction, setAgent, setUser, setOutcome]) reset("");
            setRange("all");
            set(setQuery)(s);
          }}
        />
      </div>
    </>
  );
}

function Pager({ page, pages, onPage }: { page: number; pages: number; onPage: (p: number) => void }) {
  const nums = pages <= 5 ? [...Array(pages).keys()] : [...new Set([0, 1, 2, page - 1, page, page + 1, pages - 1].filter((p) => p >= 0 && p < pages))].sort((a, b) => a - b);
  return (
    <div className="flex items-center gap-1">
      <button className="p-2 text-muted-foreground disabled:opacity-40" disabled={page === 0} onClick={() => onPage(page - 1)} aria-label="Previous page">
        <ChevronLeft className="size-4" />
      </button>
      {nums.map((p, i) => (
        <span key={p} className="flex items-center">
          {i > 0 && p - nums[i - 1] > 1 && <span className="px-2 text-muted-foreground">…</span>}
          <button
            onClick={() => onPage(p)}
            className={cn("h-9 min-w-9 rounded-md px-2 tabular-nums", p === page ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-accent")}
          >
            {p + 1}
          </button>
        </span>
      ))}
      <button className="p-2 text-muted-foreground disabled:opacity-40" disabled={page >= pages - 1} onClick={() => onPage(page + 1)} aria-label="Next page">
        <ChevronRight className="size-4" />
      </button>
    </div>
  );
}
