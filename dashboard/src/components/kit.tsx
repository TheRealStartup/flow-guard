import { ChevronDown, Info } from "lucide-react";
import type { Action, AuditEvent, Outcome, Verdict } from "@/lib/api";
import { ACTION_HINT, ACTION_LABEL, OUTCOME_LABEL } from "@/lib/format";
import { cn } from "@/lib/utils";

// Small pieces shared by the Audit trail and Live demo pages, styled after the Figma designs.

export type Tone = "block" | "redact" | "flag" | "allow" | "neutral";

const TONE: Record<Tone, string> = {
  block: "bg-block-soft text-block",
  redact: "bg-redact-soft text-redact",
  flag: "bg-flag-soft text-flag",
  allow: "bg-allow-soft text-allow",
  neutral: "bg-muted text-muted-foreground",
};

export const TEXT: Record<Tone, string> = {
  block: "text-block",
  redact: "text-redact",
  flag: "text-flag",
  allow: "text-allow",
  neutral: "text-foreground",
};

export const outcomeTone = (o: Outcome): Tone =>
  ({ blocked: "block", redacted: "redact", flagged: "flag", allowed: "allow" })[o] as Tone;
export const actionTone = (a: Action): Tone =>
  ({ block: "block", redact: "redact", flag: "flag", allow: "allow" })[a] as Tone;

export function Pill({ tone, dot = true, children, className, title }: { tone: Tone; dot?: boolean; children: React.ReactNode; className?: string; title?: string }) {
  return (
    <span title={title} className={cn("inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-sm whitespace-nowrap", TONE[tone], className)}>
      {dot && <span className="size-1.5 rounded-full bg-current" />}
      {children}
    </span>
  );
}

export const OutcomePill = ({ outcome }: { outcome: Outcome }) => <Pill tone={outcomeTone(outcome)}>{OUTCOME_LABEL[outcome]}</Pill>;
// One badge per event, the same in the audit row, the event detail and the Overview (docs/ux-review.md, one term per concept).
export const VERDICT_TONE: Record<Verdict, Tone> = {
  attack: "block",
  blocked: "block",
  quarantined: "block",
  withheld: "redact",
  hidden: "redact",
  released: "neutral",
  flagged: "flag",
  allowed: "allow",
  policy: "neutral",
  rejected: "block",
};

export const VERDICT_HINT: Record<Verdict, string> = {
  attack: "An injection or an attempt to send data out was caught",
  blocked: "The request or a tool call was stopped",
  quarantined: "Injected text was removed before the model saw it",
  withheld: "Restricted content was kept back",
  hidden: "Sensitive values were replaced with reversible tokens (tokenized)",
  released: "Real values went only to a tool the policy approves",
  flagged: "Let through and recorded for review",
  allowed: "All checks passed",
  policy: "The policy file was loaded or changed",
  rejected: "A policy edit was invalid; the last good policy stays active",
};

/** The event's badge: the gateway's verdict, or the raw outcome for an entry without a summary. */
export function VerdictPill({ event }: { event: AuditEvent }) {
  const s = event.summary;
  if (s)
    return (
      <Pill tone={VERDICT_TONE[s.verdict]} title={VERDICT_HINT[s.verdict]}>
        {s.label}
      </Pill>
    );
  if (event.type === "policy_change") return <Pill tone={event.error ? "block" : "neutral"}>{event.error ? "Rejected" : "Policy"}</Pill>;
  return event.threats?.length ? <Pill tone="block">Attack caught</Pill> : <OutcomePill outcome={event.outcome} />;
}

export const ActionPill = ({ action }: { action: Action }) => (
  <Pill tone={actionTone(action)} dot={false} title={ACTION_HINT[action]}>
    {ACTION_LABEL[action]}
  </Pill>
);

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle: string; actions?: React.ReactNode }) {
  return (
    <div className="mb-8 flex items-start gap-6">
      <div className="flex-1">
        <h1 className="text-[32px] leading-tight font-normal">{title}</h1>
        <p className="mt-2 text-[17px] text-muted-foreground">{subtitle}</p>
      </div>
      <div className="flex shrink-0 gap-3">{actions}</div>
    </div>
  );
}

export function StatRow({ children }: { children: React.ReactNode }) {
  return <div className="mb-6 grid grid-cols-2 divide-border overflow-hidden rounded-lg border bg-card xl:grid-cols-4 xl:divide-x">{children}</div>;
}

export function Stat({ label, value, unit, note, tone }: { label: string; value: React.ReactNode; unit?: string; note: React.ReactNode; tone?: Tone }) {
  return (
    <div className="px-6 py-5">
      <div className="text-sm font-medium tracking-wide uppercase">{label}</div>
      <div className="mt-2 flex items-baseline gap-4">
        <span className={cn("text-[32px] leading-none font-medium tabular-nums", tone && TEXT[tone])}>{value}</span>
        {unit && <span className="text-sm tracking-wide text-muted-foreground uppercase">{unit}</span>}
      </div>
      <div className="mt-3 text-[15px] text-muted-foreground">{note}</div>
    </div>
  );
}

export function Panel({ children, className }: { children: React.ReactNode; className?: string }) {
  return <section className={cn("rounded-lg border bg-card", className)}>{children}</section>;
}

export function PanelHeader({ icon, title, count, children }: { icon?: React.ReactNode; title: string; count?: React.ReactNode; children?: React.ReactNode }) {
  return (
    <div className="flex min-h-[72px] items-center gap-3 border-b px-6 py-4">
      {icon}
      <h2 className="text-lg font-semibold">{title}</h2>
      {count !== undefined && <span className="rounded bg-muted px-2 py-0.5 font-mono text-xs text-muted-foreground">{count}</span>}
      <div className="ml-auto flex items-center gap-3">{children}</div>
    </div>
  );
}

export function SectionLabel({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("text-sm font-medium tracking-wide uppercase", className)}>{children}</div>;
}

export function Field({ label, children, className }: { label: string; children: React.ReactNode; className?: string }) {
  return (
    <label className={cn("flex min-w-0 flex-col gap-2 text-[15px]", className)}>
      <span>{label}</span>
      {children}
    </label>
  );
}

export function Select({
  value,
  onChange,
  options,
  className,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  className?: string;
}) {
  return (
    <div className={cn("relative", className)}>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="h-11 w-full appearance-none rounded-md border border-input bg-card pr-10 pl-3 text-[15px] outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <ChevronDown className="pointer-events-none absolute top-1/2 right-3 size-4 -translate-y-1/2 text-muted-foreground" />
    </div>
  );
}

export function Btn({
  children,
  variant = "outline",
  className,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "outline" }) {
  return (
    <button
      {...props}
      className={cn(
        "inline-flex h-11 items-center gap-2 rounded-md px-4 text-[15px] whitespace-nowrap disabled:opacity-50",
        variant === "primary" ? "bg-primary text-primary-foreground hover:bg-primary/90" : "border bg-card hover:bg-accent",
        className,
      )}
    >
      {children}
    </button>
  );
}

export function KV({ rows }: { rows: [string, React.ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[8.5rem_1fr] gap-x-4 gap-y-2 text-[15px]">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="min-w-0 font-mono text-sm break-all">{v ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}

/** An (i) with a definition: shown on hover and on keyboard focus. */
export function InfoTip({ text, className }: { text: string; className?: string }) {
  return (
    <span className={cn("group relative inline-flex normal-case", className)}>
      <span tabIndex={0} role="img" aria-label={text} className="rounded-full text-muted-foreground outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50">
        <Info className="size-4" />
      </span>
      <span
        role="tooltip"
        className="pointer-events-none absolute top-6 left-1/2 z-20 hidden w-64 -translate-x-1/2 rounded-md border bg-card px-3 py-2 text-left text-sm font-normal tracking-normal text-foreground shadow-lg group-focus-within:block group-hover:block"
      >
        {text}
      </span>
    </span>
  );
}
