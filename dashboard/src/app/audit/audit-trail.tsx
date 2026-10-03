"use client";

import { useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { ChevronLeft, ChevronRight, Download, RefreshCw, RotateCcw, Search } from "lucide-react";
import { usePoll, type AuditEvent, type Outcome, type Verify } from "@/lib/api";
import { eventTitle, utcDate, utcTime } from "@/lib/format";
import { Btn, Field, OutcomePill, PageHeader, Panel, PanelHeader, Pill, Select, Stat, StatRow } from "@/components/kit";
import { cn } from "@/lib/utils";
import { EventDetail } from "./event-detail";

const RANGES = [
  { value: "15m", label: "Last 15 minutes", seconds: 15 * 60 },
  { value: "1h", label: "Last hour", seconds: 3600 },
  { value: "today", label: "Today (UTC)", seconds: 0 },
  { value: "7d", label: "Last 7 days", seconds: 7 * 86400 },
  { value: "all", label: "All time", seconds: Infinity },
];

const OUTCOMES = [
  { value: "", label: "All outcomes" },
  { value: "blocked", label: "Blocked" },
  { value: "redacted", label: "Redacted" },
  { value: "flagged", label: "Flagged" },
  { value: "allowed", label: "Allowed" },
  { value: "policy_change", label: "Policy changes" },
];

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

const uniq = (xs: (string | null | undefined)[]) => [...new Set(xs.filter(Boolean) as string[])].sort();

export function AuditTrail() {
  const params = useSearchParams();
  const [range, setRange] = useState("all");
  const [action, setAction] = useState("");
  const [agent, setAgent] = useState("");
  const [user, setUser] = useState("");
  const [outcome, setOutcome] = useState("");
  const [query, setQuery] = useState(params.get("session") ?? "");
  const [pageSize, setPageSize] = useState(12);
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<number | null>(null);

  const { data: events, updatedAt, error } = usePoll<AuditEvent[]>("/api/events?limit=5000", 2000);
  const { data: verify } = usePoll<Verify>("/api/audit/verify", 5000);

  const all = useMemo(() => events ?? [], [events]);
  const inRange = useMemo(() => {
    const from = rangeStart(range);
    return all.filter((e) => e.ts >= from);
    // updatedAt re-evaluates relative ranges ("last 15 minutes") on every poll
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [all, range, updatedAt]);

  const exchanges = inRange.filter((e) => e.type === "exchange");
  const count = (o: Outcome) => exchanges.filter((e) => e.outcome === o).length;
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
      if (outcome === "policy_change" ? e.type !== "policy_change" : outcome && (e.type !== "exchange" || e.outcome !== outcome)) return false;
      if (action && !actionsOf(e).includes(action)) return false;
      if (agent && (e.type !== "exchange" || e.agent !== agent)) return false;
      if (user && (e.type !== "exchange" || e.user !== user)) return false;
      if (!q) return true;
      const hay = [
        `evt-${String(e.seq).padStart(6, "0")}`,
        String(e.seq),
        e.hash,
        ...actionsOf(e),
        ...(e.type === "exchange"
          ? [e.session, e.user, e.agent, e.purpose, e.role, ...e.decisions.map((d) => d.control)]
          : [e.version, ...e.changes.map((c) => c.what)]),
      ];
      return hay.some((h) => h?.toLowerCase().includes(q));
    });
  }, [inRange, outcome, action, agent, user, query]);

  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  const current = Math.min(page, pages - 1);
  const visible = rows.slice(current * pageSize, current * pageSize + pageSize);
  const detail = rows.find((e) => e.seq === selected) ?? visible[0] ?? null;

  const filtered = Boolean(action || agent || user || outcome || query);
  const reset = () => {
    setAction("");
    setAgent("");
    setUser("");
    setOutcome("");
    setQuery("");
    setPage(0);
  };
  const set = (fn: (v: string) => void) => (v: string) => {
    fn(v);
    setPage(0);
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
        <Stat label="Total events" value={exchanges.length} unit={range === "all" ? "all time" : rangeLabel} note={`Across ${agents.length} active agent${agents.length === 1 ? "" : "s"}`} />
        <Stat label="Blocked" value={count("blocked")} tone="block" note="Stopped by policy controls" />
        <Stat label="Redacted" value={count("redacted")} tone="redact" note="Sensitive values hidden from the model" />
        <Stat label="Flagged" value={count("flagged")} tone="flag" note="Let through, recorded for review" />
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
            Showing {filtered ? `${rows.length} matching events` : "all events"} · {rangeLabel}
          </span>
          <span className={cn("ml-auto flex items-center gap-2", error && "text-block")}>
            <RefreshCw className="size-4" />
            {error ? "Gateway unreachable, retrying" : updatedAt ? `Updated ${utcTime(updatedAt.getTime() / 1000, false)} UTC · Auto-refresh 2 s` : "Loading…"}
          </span>
        </div>
      </Panel>

      <div className="flex items-start gap-6">
        <Panel className="min-w-0 flex-1 overflow-hidden">
          <PanelHeader title="Activity log" count={rows.length}>
            <div className="relative w-80">
              <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
              <input
                value={query}
                onChange={(e) => set(setQuery)(e.target.value)}
                placeholder="Search event ID, session, tool or control…"
                className="h-10 w-full rounded-md border border-input pr-3 pl-9 text-[15px] outline-none placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring/50"
              />
            </div>
          </PanelHeader>

          <table className="w-full table-fixed text-left">
            <thead className="border-b bg-muted text-xs font-semibold tracking-wide text-muted-foreground uppercase">
              <tr>
                <th className="w-40 py-3 pl-5">Timestamp (UTC) ↓</th>
                <th className="py-3">Action / Resource</th>
                <th className="w-44 py-3">Agent ID</th>
                <th className="w-28 py-3">User ID</th>
                <th className="w-32 py-3">Outcome</th>
                <th className="w-10" />
              </tr>
            </thead>
            <tbody>
              {visible.map((e) => {
                const { title, detail: sub } = eventTitle(e);
                const active = detail?.seq === e.seq;
                return (
                  <tr
                    key={e.seq}
                    onClick={() => setSelected(e.seq)}
                    className={cn(
                      "cursor-pointer border-b border-l-2 border-l-transparent last:border-b-0 hover:bg-selected/60",
                      active && "border-l-primary bg-selected",
                    )}
                  >
                    <td className="py-3 pl-5">
                      <div className="font-mono text-sm">{utcTime(e.ts)}</div>
                      <div className="text-sm text-muted-foreground">{utcDate(e.ts)}</div>
                    </td>
                    <td className="truncate py-3 pr-4">
                      <div className="truncate font-medium">{title}</div>
                      <div className="truncate text-sm text-muted-foreground">{sub}</div>
                    </td>
                    <td className="truncate py-3 pr-3 font-mono text-sm">{e.type === "exchange" ? (e.agent ?? "—") : "policy.yaml"}</td>
                    <td className="truncate py-3 pr-3 font-mono text-sm">{e.type === "exchange" ? (e.user ?? "—") : "—"}</td>
                    <td className="py-3">
                      {e.type === "exchange" ? (
                        <OutcomePill outcome={e.outcome} />
                      ) : (
                        <Pill tone={e.error ? "block" : "neutral"}>{e.error ? "Rejected" : "Policy"}</Pill>
                      )}
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
                setPage(0);
              }}
              options={PAGE_SIZES.map((n) => ({ value: String(n), label: String(n) }))}
            />
            <span className="ml-auto text-muted-foreground">
              {rows.length ? `${current * pageSize + 1}–${Math.min(rows.length, (current + 1) * pageSize)} of ${rows.length}` : "0 of 0"}
            </span>
            <Pager page={current} pages={pages} onPage={setPage} />
          </div>
          <div className="border-t bg-muted px-5 py-3 text-sm text-muted-foreground">
            Masked by the gateway: card numbers, IBANs, national IDs and secrets never appear in this log, only tokens.
          </div>
        </Panel>

        <EventDetail event={detail} verify={verify} onSession={(s) => set(setQuery)(s)} />
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
