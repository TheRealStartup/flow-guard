"use client";

import { useState } from "react";
import { CircleCheck, CircleX, Code, EyeOff, FileText, Flag, ListTree, ShieldAlert, ShieldCheck, X } from "lucide-react";
import type { Action, AuditEvent, ExchangeEvent, PolicyChangeEvent, Verify } from "@/lib/api";
import { controlName, eventId, eventLines, headline, shortHash, utcDate, utcTime, whereLabel } from "@/lib/format";
import { Btn, KV, Panel, PanelHeader, Pill, SectionLabel, TEXT, VERDICT_TONE, VerdictPill, actionTone, outcomeTone, type Tone } from "@/components/kit";
import { cn } from "@/lib/utils";

const BOX: Record<Tone, string> = {
  block: "bg-block-soft text-block",
  redact: "bg-redact-soft text-redact",
  flag: "bg-flag-soft text-flag",
  allow: "bg-allow-soft text-allow",
  neutral: "bg-muted text-foreground",
};

const ACTION_ICON: Record<Action, typeof CircleCheck> = { allow: CircleCheck, flag: Flag, redact: EyeOff, block: CircleX };

export function EventDetail({ event, verify, onSession }: { event: AuditEvent | null; verify: Verify | null; onSession: (s: string) => void }) {
  const [raw, setRaw] = useState(false);

  return (
    <Panel className="sticky top-6 flex max-h-[calc(100vh-3rem)] w-[400px] shrink-0 flex-col 2xl:w-[460px]">
      <PanelHeader icon={<FileText className="size-5" />} title="Event detail" />
      {!event ? (
        <div className="p-6 text-muted-foreground">Select an event to see its decisions.</div>
      ) : (
        <>
          <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">
            <div className="font-mono text-sm text-muted-foreground">{eventId(event)}</div>
            <h3 className="mt-1 text-xl leading-snug font-medium break-words">{eventLines(event).title}</h3>
            <div className="mt-1 text-[15px] text-muted-foreground">{eventLines(event).detail}</div>
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <VerdictPill event={event} />
              <span className="font-mono text-sm text-muted-foreground">
                {utcDate(event.ts)} · {utcTime(event.ts)} UTC
              </span>
            </div>
            {event.type === "exchange" ? <Exchange e={event} onSession={onSession} /> : <PolicyEvent e={event} />}
            <Integrity event={event} verify={verify} />
          </div>
          <div className="flex gap-3 border-t px-6 py-4">
            {event.type === "exchange" && event.session && (
              <Btn variant="primary" onClick={() => onSession(event.session!)}>
                <ListTree className="size-5" /> Show session
              </Btn>
            )}
            <Btn onClick={() => setRaw(true)}>
              <Code className="size-5" /> View raw event
            </Btn>
          </div>
        </>
      )}
      {raw && event && <RawDialog event={event} onClose={() => setRaw(false)} />}
    </Panel>
  );
}

function Exchange({ e, onSession }: { e: ExchangeEvent; onSession: (s: string) => void }) {
  const head = headline(e);
  const calls = e.tool_calls ?? [];
  // The callout says where it happened ("Blocked before it left"); the gateway's reason says what and why, in plain words.
  const tone: Tone = e.summary ? VERDICT_TONE[e.summary.verdict] : head ? (head.tone === "blocked" ? "block" : outcomeTone(head.tone)) : "neutral";
  return (
    <>
      {head && (
        <div className={cn("mt-5 rounded-md px-4 py-3", BOX[tone])}>
          <div className="font-semibold">{head.title}</div>
          <div className="mt-1 text-[15px] break-words">{e.summary?.reason ?? head.body}</div>
        </div>
      )}

      <Section title="Actor & request">
        <KV
          rows={[
            ["Agent ID", e.agent],
            ["Agent role", e.role],
            ["User ID", e.user],
            ["Purpose", e.purpose],
            [
              "Session",
              e.session ? (
                <button className="text-left underline decoration-dotted underline-offset-4" onClick={() => onSession(e.session!)}>
                  {e.session}
                </button>
              ) : null,
            ],
            ["Model", e.model_served && e.model_served !== e.model ? `${e.model} → ${e.model_served}` : e.model],
            ["Provider", e.provider],
            ["Policy", `${e.policy_version} · ${e.profile}`],
          ]}
        />
      </Section>

      {calls.length > 0 && (
        <Section title="Proposed tool calls">
          <div className="flex flex-col gap-3">
            {calls.map((c, i) => (
              <div key={i} className="rounded-md border px-3 py-2.5">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-medium">{c.name}</span>
                  <Pill className="ml-auto" tone={c.outcome === "blocked" ? "block" : c.outcome === "allowed" ? "allow" : "flag"}>
                    {c.outcome === "blocked" ? "Blocked" : c.outcome === "allowed" ? "Allowed" : "Released"}
                  </Pill>
                </div>
                {c.arguments && <div className="mt-1.5 font-mono text-xs break-all text-muted-foreground">{c.arguments}</div>}
                {c.control && <div className="mt-1 text-xs text-muted-foreground">Blocked before it ran · {controlName(c.control)}</div>}
                {c.outcome === "allowed_with_real_values" && <div className="mt-1 text-xs text-muted-foreground">Real values released to this approved tool</div>}
              </div>
            ))}
          </div>
        </Section>
      )}

      <Section title="Decision trace" aside={`${e.controls_ms.toFixed(0)} ms checks${e.upstream_ms != null ? ` · ${e.upstream_ms.toFixed(0)} ms model` : ""}`}>
        <ol className="flex flex-col gap-3">
          {e.decisions.map((d, i) => {
            const Icon = ACTION_ICON[d.action];
            const tone = actionTone(d.action);
            return (
              <li key={i} className="flex gap-3">
                <Icon className={cn("mt-0.5 size-5 shrink-0", d.action === "allow" ? "text-muted-foreground" : TEXT[tone])} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline gap-2">
                    <span className={cn(d.action === "block" && "text-block")}>{controlName(d.control)}</span>
                    <span className="ml-auto shrink-0 font-mono text-xs text-muted-foreground">{d.ms.toFixed(1)} ms</span>
                  </div>
                  <div className="text-sm break-words text-muted-foreground">
                    {whereLabel(d.where)} · {d.reason}
                  </div>
                  {d.excerpt && d.action !== "allow" && d.control !== "injection.jev" && (
                    <div className="mt-1 rounded bg-muted px-2 py-1 font-mono text-xs break-all">{d.excerpt}</div>
                  )}
                </div>
              </li>
            );
          })}
          {!e.decisions.length && <li className="text-sm text-muted-foreground">No control reported a finding.</li>}
        </ol>
      </Section>

      {(e.usage?.labels?.length ?? 0) > 0 && (
        <Section title="Data this session holds">
          <div className="flex flex-wrap gap-2">
            {e.usage.labels!.map((l) => (
              <Pill key={l} tone="redact" dot={false} className="font-mono text-xs">
                {l}
              </Pill>
            ))}
          </div>
        </Section>
      )}
    </>
  );
}

function PolicyEvent({ e }: { e: PolicyChangeEvent }) {
  return (
    <>
      {e.error && (
        <div className="mt-5 rounded-md bg-block-soft px-4 py-3 text-block">
          <div className="font-semibold">Edit rejected, last good policy stays active</div>
          <div className="mt-1 text-[15px] break-words">{e.error}</div>
        </div>
      )}
      <Section title="Version">
        <KV
          rows={[
            ["Now", e.version],
            ["Before", e.previous],
            ["Profile", e.profile],
          ]}
        />
      </Section>
      <Section title="What changed">
        {e.changes?.length ? (
          <ul className="flex flex-col gap-2">
            {e.changes.map((c, i) => (
              <li key={i} className="rounded-md border px-3 py-2">
                <div className="font-mono text-sm">{c.what}</div>
                <div className="mt-1 font-mono text-xs">
                  <span className="text-block line-through">{JSON.stringify(c.old)}</span> → <span className="text-allow">{JSON.stringify(c.new)}</span>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <div className="text-sm text-muted-foreground">No field-level changes recorded.</div>
        )}
      </Section>
    </>
  );
}

function Integrity({ event, verify }: { event: AuditEvent; verify: Verify | null }) {
  const broken = verify && !verify.ok && verify.broken_at !== undefined && event.seq >= verify.broken_at;
  return (
    <div className={cn("mt-6 flex gap-3 rounded-md px-4 py-3", broken ? "bg-block-soft text-block" : "bg-muted")}>
      {broken ? <ShieldAlert className="mt-0.5 size-5 shrink-0" /> : <ShieldCheck className="mt-0.5 size-5 shrink-0 text-allow" />}
      <div className="min-w-0 text-sm">
        <div>{broken ? "Hash chain broken at or before this entry" : verify ? `Hash-chained record · chain verified (${verify.entries} entries)` : "Hash-chained record"}</div>
        <div className="mt-1 font-mono text-xs text-muted-foreground">SHA-256 {shortHash(event.hash)}</div>
        <div className="font-mono text-xs text-muted-foreground">prev&nbsp;&nbsp;&nbsp; {shortHash(event.prev_hash)}</div>
      </div>
    </div>
  );
}

function Section({ title, aside, children }: { title: string; aside?: string; children: React.ReactNode }) {
  return (
    <div className="mt-6 border-t pt-5">
      <div className="mb-3 flex items-baseline">
        <SectionLabel>{title}</SectionLabel>
        {aside && <span className="ml-auto font-mono text-xs text-muted-foreground">{aside}</span>}
      </div>
      {children}
    </div>
  );
}

function RawDialog({ event, onClose }: { event: AuditEvent; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-primary/40 p-8" onClick={onClose}>
      <div className="flex max-h-full w-full max-w-3xl flex-col rounded-lg bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center border-b px-6 py-4">
          <h2 className="text-lg font-semibold">{eventId(event)} · raw audit entry</h2>
          <button className="ml-auto p-1 text-muted-foreground hover:text-foreground" onClick={onClose} aria-label="Close">
            <X className="size-5" />
          </button>
        </div>
        <pre className="overflow-auto p-6 font-mono text-xs leading-relaxed">{JSON.stringify(event, null, 2)}</pre>
      </div>
    </div>
  );
}
