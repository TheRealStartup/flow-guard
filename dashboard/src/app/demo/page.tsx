"use client";

import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import Link from "next/link";
import { ArrowRight, Bot, Check, CornerDownLeft, Database, FlaskConical, Info, ListTree, Loader2, Play, RotateCcw, ShieldAlert, ShieldCheck, User, X } from "lucide-react";
import { getJSON, type ExchangeEvent, type Policy, type TryResult } from "@/lib/api";
import { useAuditEvents, usePolicyLive } from "@/lib/stream";
import { CONTROLS, controlName, eventLines } from "@/lib/format";
import { ActionPill, Btn, Field, PageHeader, Panel, PanelHeader, Pill, SectionLabel, Select, Stat, TEXT, VERDICT_TONE, VerdictPill } from "@/components/kit";
import { cn } from "@/lib/utils";
import { analyse, type Analysis } from "./analyse";
import { EXAMPLES, MODELS, USERS } from "./scenarios";

export default function DemoPage() {
  const [example, setExample] = useState(EXAMPLES[1].id);
  const [user, setUser] = useState(EXAMPLES[1].user);
  const [prompt, setPrompt] = useState(EXAMPLES[1].prompt);
  const [model, setModel] = useState(MODELS[0].value);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ run: TryResult; a: Analysis; ms: number } | null>(null);
  // The run's session id, chosen here so its audit entries can be followed on the live stream while it runs.
  const [sid, setSid] = useState<string | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);
  const { data: events } = useAuditEvents(300);
  const steps = useMemo(
    () => (sid ? (events ?? []).filter((e): e is ExchangeEvent => e.type === "exchange" && e.session === sid).sort((x, y) => x.seq - y.seq) : []),
    [events, sid],
  );
  // When the run ends, bring its verdict into view (it sits below the fold on a laptop).
  useEffect(() => {
    if (result) resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [result]);

  // Refreshed when a policy change streams in; polls every 3 s only while the stream is down.
  const { policy } = usePolicyLive();

  const pick = (id: string) => {
    const ex = EXAMPLES.find((e) => e.id === id);
    setExample(id);
    if (ex) {
      setUser(ex.user);
      setPrompt(ex.prompt);
    }
  };

  async function run() {
    setBusy(true);
    setError(null);
    setResult(null);
    const session = `try-${user}-${Math.random().toString(36).slice(2, 8)}`;
    setSid(session);
    const t0 = performance.now();
    try {
      const r = await getJSON<TryResult>("/api/try", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user, prompt, model, scenario: USERS[user].scenario, session }),
      });
      setResult({ run: r, a: analyse(r), ms: performance.now() - t0 });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const a = result?.a;

  return (
    <>
      <PageHeader
        title="Live policy demo"
        subtitle="Run a real agent through FlowGuard and watch each check as it happens."
      />

      {/* Counts for this run only; each tile is one kind of action, in the colours used everywhere. */}
      <div className="mb-6 grid grid-cols-2 divide-border overflow-hidden rounded-lg border bg-card md:grid-cols-3 xl:grid-cols-5 xl:divide-x">
        <Stat label="Hidden" value={a ? a.hidden : "—"} unit="this run" tone={a?.hidden ? "redact" : undefined} note="Values replaced with tokens before the model saw them" />
        <Stat label="Quarantined" value={a ? a.quarantined : "—"} unit="this run" tone={a?.quarantined ? "block" : undefined} note="Hidden instructions removed from tool results" />
        <Stat label="Withheld" value={a ? a.withheld : "—"} unit="this run" tone={a?.withheld ? "redact" : undefined} note="Restricted content kept back" />
        <Stat label="Blocked" value={a ? a.blocked : "—"} unit="this run" tone={a?.blocked ? "block" : undefined} note="Requests or tool calls that never ran" />
        <Stat label="Released" value={a ? a.released.length : "—"} unit="this run" note="Real values put back for approved tools only" />
      </div>

      <FlowStrip a={a ?? null} ms={result?.ms ?? null} />

      <div className="flex flex-col gap-6">
        {/* One panel: pick a scenario or type your own request, run it, read the result underneath. */}
        <Panel>
          <PanelHeader icon={<FlaskConical className="size-5" />} title="Test a request">
            {result && <span className="font-mono text-sm text-muted-foreground">{result.run.session}</span>}
          </PanelHeader>
          <div className="px-6 pt-5 pb-5">
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.6fr_1fr_1.2fr]">
              <Field label="Example">
                <Select value={example} onChange={pick} options={[...EXAMPLES.map((e) => ({ value: e.id, label: e.label })), { value: "custom", label: "Custom prompt" }]} />
              </Field>
              <Field label="Acting as">
                <Select value={user} onChange={(v) => { setUser(v); setExample("custom"); }} options={Object.keys(USERS).map((u) => ({ value: u, label: `${u} · ${USERS[u].title}` }))} />
              </Field>
              <Field label="Model">
                <Select value={model} onChange={setModel} options={MODELS} />
              </Field>
            </div>

            <div className="mt-5 mb-2 flex items-baseline">
              <SectionLabel>User request</SectionLabel>
              <span className="ml-auto text-sm text-muted-foreground">{USERS[user].note}</span>
            </div>
            <div className="flex items-end gap-3">
              <textarea
                value={prompt}
                onChange={(e) => { setPrompt(e.target.value); setExample("custom"); }}
                onKeyDown={(e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) run(); }}
                rows={2}
                aria-label="User request"
                className="min-w-0 flex-1 resize-none rounded-md border border-input bg-muted px-4 py-3 text-[17px] outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
              />
              <div className="flex flex-col gap-2">
                <Btn variant="primary" onClick={run} disabled={busy || !prompt.trim()}>
                  <Play className="size-5" /> {busy ? "Running…" : "Run request"}
                </Btn>
                {result && !busy && (
                  <Btn onClick={() => setResult(null)}>
                    <RotateCcw className="size-5" /> Clear result
                  </Btn>
                )}
              </div>
            </div>
            <div className="mt-2 flex items-center gap-4 text-xs text-muted-foreground">
              <span>Pick an example or type your own request · Ctrl + Enter to run</span>
              <span className="ml-auto rounded bg-muted px-2 py-0.5">Fake customers and tools · no email or payment leaves this machine</span>
            </div>
            {error && <div className="mt-4 rounded-md bg-block-soft px-4 py-3 text-sm text-block">Run failed: {error}</div>}
          </div>
          {(busy || result) && <LiveSteps steps={steps} busy={busy} />}
          <div ref={resultRef} className="scroll-mt-6">
            {result && !busy && <Result result={result} />}
          </div>
        </Panel>

        <ControlsTable policy={policy} fired={a?.fired ?? null} />
      </div>
    </>
  );
}

/** One duration for the whole run, split into where the time went. */
function duration(a: Analysis, ms: number) {
  const sec = (x: number) => `${(x / 1000).toFixed(1)} s`;
  const judge = a.timing.judge >= 50 ? `, of which AI injection check ${sec(a.timing.judge)}` : "";
  return `Took ${sec(ms)}: model ${sec(a.timing.model)} · FlowGuard checks ${sec(a.timing.checks)}${judge}`;
}

function FlowStrip({ a, ms }: { a: Analysis | null; ms: number | null }) {
  const steps = [
    { icon: User, title: "User request", note: "Asks the agent for help" },
    { icon: Bot, title: "AI model", note: "Proposes tool calls" },
    { icon: ShieldCheck, title: "FlowGuard policy checks", note: "Allow, block or redact each step", focus: true },
    { icon: Database, title: "Bank tools", note: "Run only the calls that were allowed" },
  ];
  return (
    <Panel className="mb-6 px-6 py-5">
      <div className="mb-4 flex items-baseline">
        <h2 className="font-semibold">Every model request and tool call passes through FlowGuard</h2>
        <span className="ml-auto font-mono text-xs tracking-wide text-muted-foreground uppercase">Check before acting · Filter before the model · Block before leaving</span>
      </div>
      {/* Grid, not flex: every card gets the same width and the row's height, arrows sit in their own columns. */}
      <div className="grid grid-cols-[1fr_auto_1fr_auto_1fr_auto_1fr] items-stretch gap-3">
        {steps.map((s, i) => (
          <Fragment key={s.title}>
            <div className={cn("flex min-w-0 items-start gap-3 rounded-md border px-4 py-3", s.focus && "border-primary bg-selected ring-1 ring-primary")}>
              <s.icon className="mt-0.5 size-5 shrink-0" />
              <div className="min-w-0">
                <div className="font-medium">{s.title}</div>
                <div className="text-sm text-muted-foreground">{s.note}</div>
              </div>
            </div>
            {i < steps.length - 1 && <ArrowRight className="size-5 self-center text-muted-foreground" />}
          </Fragment>
        ))}
      </div>
      <div className="mt-3 flex items-center gap-2 text-sm text-muted-foreground">
        <CornerDownLeft className="size-4" />
        {a
          ? `This run: ${a.summary}. ${ms != null ? duration(a, ms) + "." : ""}`
          : "Tool → FlowGuard → model. Sensitive values never reach the model or the model provider."}
      </div>
    </Panel>
  );
}

const STATUS = {
  ran: { tone: "allow", label: "Ran", icon: Check },
  released: { tone: "neutral", label: "Ran with real values", icon: Check },
  stopped: { tone: "block", label: "Blocked before it ran", icon: X },
} as const;

function Result({ result }: { result: { run: TryResult; a: Analysis; ms: number } }) {
  const { a } = result;
  const BANNER = { block: "bg-block-soft text-block", redact: "bg-redact-soft text-redact", flag: "bg-flag-soft text-flag", allow: "bg-allow-soft text-allow", neutral: "bg-muted" };
  const stopped = a.actions.filter((x) => x.status === "stopped");

  return (
    <>
      {a.actions.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2 border-t px-6 py-3 text-sm">
          <span className="text-muted-foreground">AGENT ACTIONS</span>
          {a.actions.map((x, i) => {
            const s = STATUS[x.status];
            return (
              <span key={i} className="flex items-center gap-1.5 font-mono">
                <s.icon className={cn("size-4", TEXT[s.tone])} />
                {x.name}
              </span>
            );
          })}
        </div>
      )}

      <div className={cn("px-6 py-4", BANNER[a.verdict.tone])}>
        <div className="flex items-center gap-2 text-lg font-medium">
          <ShieldCheck className="size-5" /> {a.verdict.title}
        </div>
        <div className="mt-1 text-[15px]">{a.denied ? `${a.denied.status}: ${a.denied.message}` : a.summary.charAt(0).toUpperCase() + a.summary.slice(1) + "."}</div>
        <div className="mt-1 text-sm opacity-80">{duration(a, result.ms)}.</div>
      </div>

      {a.attackCaught && <AttackCallout a={a} model={result.run.model} />}

      {a.findings.length > 0 ? (
        <table className="w-full text-left text-[15px]">
          <thead className="border-b bg-muted text-sm text-muted-foreground">
            <tr>
              <th className="py-2.5 pl-6 font-normal">What was found</th>
              <th className="py-2.5 font-normal">Where</th>
              <th className="py-2.5 font-normal">Decision</th>
              <th className="py-2.5 font-normal">What the model saw instead</th>
              <th className="py-2.5 pr-6 font-normal">Rule</th>
            </tr>
          </thead>
          <tbody>
            {a.findings.map((f, i) => (
              <tr key={i} className="border-b align-top last:border-b-0" title={f.reason}>
                <td className="py-3 pl-6">{f.found}</td>
                <td className="py-3 pr-3 text-muted-foreground">
                  {f.where}
                  {f.source && <div className="font-mono text-xs break-all">{f.source}</div>}
                </td>
                <td className="py-3 pr-3">
                  <Pill tone={f.tone} dot={false}>
                    {f.decision}
                  </Pill>
                </td>
                <td className={cn("max-w-72 py-3 pr-3 font-mono text-sm break-all", f.tone === "block" && "text-block")}>{f.sawInstead}</td>
                <td className="py-3 pr-6 font-mono text-xs text-muted-foreground">{f.rule}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="border-t px-6 py-4 text-muted-foreground">No control reported a finding: everything passed unchanged.</div>
      )}

      {stopped.length > 0 && (
        <div className="border-t px-6 py-4">
          <SectionLabel className="mb-2">Blocked actions</SectionLabel>
          {stopped.map((x, i) => {
            const why = a.decisions.find((d) => d.action === "block" && d.where === `tool_call:${x.name}`);
            return (
              <div key={i} className="flex items-baseline gap-3 py-1 text-[15px]">
                <X className="size-4 shrink-0 translate-y-0.5 text-block" />
                <span className="font-mono">{x.name}</span>
                <span className="text-muted-foreground">blocked before it ran · {why ? `${controlName(why.control)}: ${why.reason.replace(/ \(mode=\w+\)/, "")}` : "blocked by policy"}</span>
              </div>
            );
          })}
        </div>
      )}

      <div className="grid grid-cols-4 gap-4 border-t bg-muted px-6 py-4 text-sm">
        <Checkpoint title="Actions checked" note={`${a.actions.filter((x) => x.status !== "stopped").length} allowed · ${a.stopped} blocked`} />
        <Checkpoint title="Results filtered" note={`${a.hidden} hidden · ${a.quarantined} quarantined${a.withheld ? ` · ${a.withheld} withheld` : ""}`} />
        <Checkpoint title="Answer checked" note={a.answerRedacted ? "Values in the answer hidden too" : "Nothing to hide in the answer"} />
        <Checkpoint title="Outbound" note={a.leftOrg.length ? `Sent via ${a.leftOrg.join(", ")}` : "Nothing left the organisation"} />
      </div>

      <div className="border-t px-6 py-5">
        <SectionLabel className="mb-2">AI response · as the model wrote it</SectionLabel>
        {a.answer ? <Markdown text={a.answer} /> : <p className="text-muted-foreground">No final answer (the run ended on a tool call or a block).</p>}
        <div className="mt-4 flex items-center gap-4">
          <p className="flex-1 text-sm text-muted-foreground">
            {a.hidden > 0 &&
              "The tool did read these values; the gateway kept them in its token vault and gave the model placeholders. Real values are only put back for tools the policy allows."}
          </p>
          <Link href={`/audit?session=${encodeURIComponent(result.run.session)}`}>
            <Btn>
              <ListTree className="size-5" /> View in audit trail
            </Btn>
          </Link>
        </div>
      </div>
    </>
  );
}

/** What a poisoned source wanted, in the scenario's hand-written words; never the injected text itself. */
function AttackCallout({ a, model }: { a: Analysis; model: string }) {
  return (
    <div className="flex gap-3 border-t bg-block-soft px-6 py-4 text-block">
      <ShieldAlert className="mt-0.5 size-5 shrink-0" />
      <div className="text-[15px]">
        <div className="font-semibold">What the attacker tried</div>
        {a.attacks.length ? (
          a.attacks.map((x) => (
            <p key={x.source} className="mt-1">
              {x.where} (<span className="font-mono text-sm">{x.source}</span>) contained hidden instructions telling the agent to{" "}
              <strong>{x.wants}</strong>.
            </p>
          ))
        ) : (
          <p className="mt-1">Text the agent read contained hidden instructions written to give it orders.</p>
        )}
        <p className="mt-1">
          {model.startsWith("mock/")
            ? "Without FlowGuard, the agent would have done it: this test model obeys every instruction it reads. "
            : "Without FlowGuard, the model would have read these orders as if they came from the user. "}
          With FlowGuard,{" "}
          {a.leftOrg.length ? "it still went out, see below." : "nothing left the organisation."}
        </p>
      </div>
    </div>
  );
}

/** The run's audit entries as they arrive on the live stream: one line per round trip through FlowGuard. */
function LiveSteps({ steps, busy }: { steps: ExchangeEvent[]; busy: boolean }) {
  return (
    <div className="border-t px-6 py-4">
      <SectionLabel className="mb-3">{busy ? "Live: what FlowGuard is doing" : "What FlowGuard did, step by step"}</SectionLabel>
      <ol className="flex flex-col gap-2" aria-live="polite">
        {steps.map((e, i) => {
          const tone = e.summary ? VERDICT_TONE[e.summary.verdict] : "neutral";
          const Icon = tone === "allow" ? Check : tone === "block" ? ShieldAlert : ShieldCheck;
          return (
            <li key={e.seq} className="flex items-start gap-3">
              <Icon className={cn("mt-0.5 size-5 shrink-0", tone === "neutral" ? "text-muted-foreground" : TEXT[tone])} />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline gap-x-3">
                  <span className="text-sm text-muted-foreground">Step {i + 1}</span>
                  <span className="font-medium" title={e.summary?.reason}>
                    {eventLines(e).title}
                  </span>
                  <VerdictPill event={e} />
                </div>
                <div className="text-sm text-muted-foreground">
                  {eventLines(e).detail} · checks {Math.round(e.controls_ms)} ms{e.upstream_ms != null ? ` · model ${(e.upstream_ms / 1000).toFixed(1)} s` : ""}
                </div>
              </div>
            </li>
          );
        })}
        {busy && (
          <li className="flex items-center gap-3 text-muted-foreground">
            <Loader2 className="size-5 animate-spin" />
            {steps.length ? "Running the allowed tool calls, then back through FlowGuard to the model…" : "Checking the request and asking the model…"}
          </li>
        )}
      </ol>
    </div>
  );
}

const Checkpoint = ({ title, note }: { title: string; note: string }) => (
  <div>
    <div className="font-medium">{title}</div>
    <div className="text-muted-foreground">{note}</div>
  </div>
);

function ControlsTable({ policy, fired }: { policy: Policy | null; fired: Set<string> | null }) {
  const rows = policy ? Object.entries(policy.controls) : [];
  return (
    <Panel className="overflow-hidden">
      <PanelHeader title="Active controls" count={rows.length}>
        <span className="text-sm text-muted-foreground">from policy/policy.yaml · profile {policy?.profile ?? "…"}</span>
      </PanelHeader>
      <table className="w-full text-left text-[15px]">
        <thead className="border-b bg-muted text-sm text-muted-foreground">
          <tr>
            <th className="py-2.5 pl-6 font-normal">Control</th>
            <th className="py-2.5 font-normal">Kind</th>
            <th className="py-2.5 font-normal">Outcome</th>
            <th className="py-2.5 pr-6 font-normal">Conditions & scope</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([id, c]) => {
            const meta = CONTROLS[id];
            const params = Object.entries(c)
              .filter(([k]) => k !== "action")
              // nested settings (e.g. the HR rules) are summarised, never printed as "[object Object]"
              .map(([k, v]) => `${k}: ${Array.isArray(v) ? `${v.length} entries` : v && typeof v === "object" ? `${Object.keys(v).length} settings` : v}`)
              .join(" · ");
            const hit = fired?.has(id);
            return (
              <tr key={id} className={cn("border-b border-l-2 border-l-transparent last:border-b-0", hit && "border-l-primary bg-selected")}>
                <td className="py-3 pl-6">
                  <div className="flex items-center gap-2">
                    {meta?.name ?? id}
                    {hit && <span className="rounded bg-primary px-1.5 py-0.5 text-[10px] tracking-wide text-primary-foreground uppercase">fired</span>}
                  </div>
                  <div className="font-mono text-xs text-muted-foreground">{id}</div>
                </td>
                <td className="py-3 pr-3 text-muted-foreground">{meta?.kind ?? "—"}</td>
                <td className="py-3 pr-3">
                  <ActionPill action={c.action} />
                </td>
                <td className="py-3 pr-6">
                  <div>{meta?.scope ?? ""}</div>
                  {params && <div className="font-mono text-xs text-muted-foreground">{params}</div>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <div className="flex items-center gap-2 border-t bg-muted px-6 py-3 text-sm text-muted-foreground">
        <Info className="size-4" /> Block beats redact beats flag. If a check fails or times out, the request is blocked (fail closed).
      </div>
    </Panel>
  );
}

/** The model's answer is Markdown (tables, lists, bold); render it instead of showing the raw syntax. */
const Markdown = ({ text }: { text: string }) => (
  <div
    className={cn(
      "text-[16px] leading-relaxed [&_code]:rounded [&_code]:bg-muted [&_code]:px-1 [&_code]:font-mono [&_code]:text-[14px] [&_h1]:mt-4 [&_h1]:text-xl [&_h1]:font-semibold",
      "[&_h2]:mt-4 [&_h2]:text-lg [&_h2]:font-semibold [&_h3]:mt-3 [&_h3]:font-semibold [&_li]:my-0.5 [&_ol]:my-2 [&_ol]:list-decimal [&_ol]:pl-6 [&_p]:my-2",
      "[&_pre]:my-2 [&_pre]:overflow-x-auto [&_pre]:rounded-md [&_pre]:bg-muted [&_pre]:p-3 [&_strong]:font-semibold [&_ul]:my-2 [&_ul]:list-disc [&_ul]:pl-6",
      "[&_table]:my-3 [&_table]:w-full [&_table]:border-collapse [&_table]:text-[15px] [&_td]:border-b [&_td]:px-2 [&_td]:py-1.5 [&_th]:border-b-2 [&_th]:px-2 [&_th]:py-1.5 [&_th]:text-left [&_th]:font-medium",
    )}
  >
    <ReactMarkdown remarkPlugins={[remarkGfm]}>{text}</ReactMarkdown>
  </div>
);
