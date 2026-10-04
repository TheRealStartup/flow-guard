"use client";

import { useState } from "react";
import { controlName } from "@/lib/format";
import { OUTCOMES, SERIES_LABEL, niceMax, type Bucket, type ControlRow, type Series } from "@/lib/stats";
import { cn } from "@/lib/utils";

// Plain HTML/SVG charts in the dashboard's palette. Mark specs: bars ≤ 24px, 4px rounded data-end, 2px surface gaps,
// hairline grid, hover tooltip on every mark, legend for ≥ 2 series. Text always uses text tokens, never mark colors.

export const MARK: Record<Series, string> = {
  allowed: "var(--allow)",
  hidden: "var(--redact)",
  flagged: "var(--flag-mark)",
  stopped: "var(--block)",
};
export const ACTION_MARK = { block: "var(--block)", redact: "var(--redact)", flag: "var(--flag-mark)" } as const;

export function Legend({ items }: { items: { label: string; color: string; value?: number | string }[] }) {
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-sm text-muted-foreground">
      {items.map((i) => (
        <span key={i.label} className="flex items-center gap-2">
          <span className="size-2.5 rounded-[3px]" style={{ background: i.color }} />
          {i.label}
          {i.value !== undefined && <span className="font-medium text-foreground tabular-nums">{i.value}</span>}
        </span>
      ))}
    </div>
  );
}

type Tip = { x: number; y: number; title: string; rows: { label: string; value: string; color?: string }[] } | null;

function Tooltip({ tip }: { tip: Tip }) {
  if (!tip) return null;
  return (
    <div
      className="pointer-events-none absolute z-10 min-w-40 -translate-x-1/2 -translate-y-full rounded-md border bg-card px-3 py-2 text-sm shadow-lg"
      style={{ left: tip.x, top: tip.y - 8 }}
    >
      <div className="mb-1 text-xs text-muted-foreground">{tip.title}</div>
      {tip.rows.map((r) => (
        <div key={r.label} className="flex items-center gap-2 py-0.5">
          {r.color && <span className="h-0.5 w-3 rounded-full" style={{ background: r.color }} />}
          <span className="font-semibold tabular-nums">{r.value}</span>
          <span className="text-muted-foreground">{r.label}</span>
        </div>
      ))}
    </div>
  );
}

/** Requests per time bucket, stacked by verdict group. */
export function OutcomeColumns({ buckets, label, height = 220 }: { buckets: Bucket[]; label: (b: Bucket) => string; height?: number }) {
  const [tip, setTip] = useState<Tip>(null);
  const [hover, setHover] = useState<number | null>(null);
  const max = niceMax(Math.max(0, ...buckets.map((b) => b.total)));
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * max);
  const every = Math.max(1, Math.ceil(buckets.length / 6));

  return (
    <div className="relative" onPointerLeave={() => { setTip(null); setHover(null); }}>
      <div className="flex">
        {/* y axis */}
        <div className="relative w-10 shrink-0" style={{ height }}>
          {ticks.map((t) => (
            <span key={t} className="absolute right-2 -translate-y-1/2 text-xs text-muted-foreground tabular-nums" style={{ top: height - (t / max) * height }}>
              {Number.isInteger(t) ? t : t.toFixed(1)}
            </span>
          ))}
        </div>
        {/* plot */}
        <div className="relative flex-1" style={{ height }}>
          {ticks.map((t) => (
            <div key={t} className="absolute inset-x-0 h-px bg-grid" style={{ top: height - (t / max) * height }} />
          ))}
          <div className="absolute inset-0 flex items-end">
            {buckets.map((b, i) => (
              <div
                key={b.start}
                className="flex h-full flex-1 items-end justify-center"
                tabIndex={0}
                aria-label={`${label(b)}: ${b.total} requests`}
                onPointerMove={(e) => {
                  const box = (e.currentTarget.closest(".relative.flex-1") as HTMLElement).getBoundingClientRect();
                  const col = e.currentTarget.getBoundingClientRect();
                  setHover(i);
                  setTip({
                    x: col.left - box.left + col.width / 2 + 40,
                    y: height - (b.total / max) * height,
                    title: label(b),
                    rows: [
                      { label: "requests", value: String(b.total) },
                      ...[...OUTCOMES].reverse().map((o) => ({ label: SERIES_LABEL[o].toLowerCase(), value: String(b.counts[o]), color: MARK[o] })),
                    ],
                  });
                }}
              >
                <div className={cn("flex w-full max-w-6 flex-col-reverse transition-opacity", hover !== null && hover !== i && "opacity-60")} style={{ margin: "0 1px" }}>
                  {OUTCOMES.filter((o) => b.counts[o] > 0).map((o, j, shown) => (
                    <div
                      key={o}
                      style={{
                        height: Math.max(2, (b.counts[o] / max) * height - 2),
                        background: MARK[o],
                        marginTop: j === shown.length - 1 ? 0 : 2,
                        borderRadius: j === shown.length - 1 ? "4px 4px 0 0" : 0,
                      }}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
      {/* x axis */}
      <div className="ml-10 flex pt-2">
        {buckets.map((b, i) => (
          <div key={b.start} className="flex-1 text-center text-xs text-muted-foreground tabular-nums">
            {i % every === 0 ? label(b).split(" – ")[0] : ""}
          </div>
        ))}
      </div>
      <Tooltip tip={tip} />
    </div>
  );
}

/** One horizontal bar per control, split by what it did. Value at the tip. */
export function ControlBars({ rows, limit = 8 }: { rows: ControlRow[]; limit?: number }) {
  const [tip, setTip] = useState<Tip>(null);
  const shown = rows.slice(0, limit);
  const max = Math.max(1, ...shown.map((r) => r.total));
  return (
    <div className="relative flex flex-col gap-3" onPointerLeave={() => setTip(null)}>
      {shown.map((r) => {
        const parts = (["block", "redact", "flag"] as const).filter((k) => r[k] > 0);
        return (
          <div
            key={r.control}
            className="grid grid-cols-[11rem_1fr] items-center gap-3"
            tabIndex={0}
            onPointerMove={(e) => {
              const box = (e.currentTarget.parentElement as HTMLElement).getBoundingClientRect();
              setTip({
                x: e.clientX - box.left,
                y: e.currentTarget.getBoundingClientRect().top - box.top,
                title: `${controlName(r.control)} · ${r.control}`,
                rows: parts.map((k) => ({ label: { block: "blocked", redact: "hidden or quarantined", flag: "flagged" }[k], value: String(r[k]), color: ACTION_MARK[k] })),
              });
            }}
          >
            <span className="truncate text-sm" title={r.control}>
              {controlName(r.control)}
            </span>
            <div className="flex items-center gap-2">
              <div className="flex h-5 items-stretch gap-0.5" style={{ width: `${(r.total / max) * 85}%` }}>
                {parts.map((k, j) => (
                  <div key={k} style={{ flex: r[k], background: ACTION_MARK[k], borderRadius: j === parts.length - 1 ? "0 4px 4px 0" : 0, minWidth: 2 }} />
                ))}
              </div>
              <span className="text-sm font-medium tabular-nums">{r.total}</span>
            </div>
          </div>
        );
      })}
      {rows.length > limit && <div className="text-xs text-muted-foreground">+{rows.length - limit} more controls</div>}
      <Tooltip tip={tip} />
    </div>
  );
}

/** 12-point trend in the de-emphasis hue, the latest point in the accent. */
export function Sparkline({ values, width = 96, height = 28 }: { values: number[]; width?: number; height?: number }) {
  if (values.length < 2) return null;
  const max = Math.max(1, ...values);
  const pts = values.map((v, i) => [(i / (values.length - 1)) * (width - 8) + 4, height - 4 - (v / max) * (height - 8)]);
  const last = pts[pts.length - 1];
  return (
    <svg width={width} height={height} aria-hidden className="overflow-visible">
      <polyline points={pts.map((p) => p.join(",")).join(" ")} fill="none" stroke="var(--ring)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={last[0]} cy={last[1]} r={4} fill="var(--primary)" stroke="var(--card)" strokeWidth={2} />
    </svg>
  );
}

/** Usage against a limit; the fill turns amber at 60% and red at 90%. */
export function Meter({ value, max, label }: { value: number; max: number; label: string }) {
  const f = max > 0 ? Math.min(1, value / max) : 0;
  const color = f >= 0.9 ? "var(--block)" : f >= 0.6 ? "var(--flag-mark)" : "var(--primary)";
  return (
    <div className="flex items-center gap-2" title={`${label}: ${value} of ${max}`}>
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-accent">
        <div className="h-full rounded-full" style={{ width: `${Math.max(f * 100, f > 0 ? 3 : 0)}%`, background: color }} />
      </div>
      <span className="w-10 text-right text-xs text-muted-foreground tabular-nums">{Math.round(f * 100)}%</span>
    </div>
  );
}
