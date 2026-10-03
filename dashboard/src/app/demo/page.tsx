"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowRight, Bot, Check, CornerDownLeft, Database, FlaskConical, History, Info, ListTree, Lock, Play, RotateCcw, ShieldCheck, User, X } from "lucide-react";
import { getJSON, usePoll, type Policy, type PolicyHistoryItem, type TryResult } from "@/lib/api";
import { CONTROLS, controlName, utcTime } from "@/lib/format";
import { ActionPill, Btn, Field, PageHeader, Panel, PanelHeader, Pill, SectionLabel, Select, Stat, StatRow, TEXT } from "@/components/kit";
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

  const { data: policy } = usePoll<Policy>("/api/policy", 3000);
  const { data: history } = usePoll<PolicyHistoryItem[]>("/api/policy/history", 3000);

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
    const t0 = performance.now();
    try {
      const r = await getJSON<TryResult>("/api/try", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user, prompt, model, scenario: USERS[user].scenario }),
      });
      setResult({ run: r, a: analyse(r), ms: performance.now() - t0 });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const a = result?.a;
  const enforced = policy ? Object.values(policy.controls).filter((c) => c.action !== "allow").length : null;

  return (
    <>
      <PageHeader
        title="Live policy demo"
        subtitle="Define what your AI agents can see. Stop sensitive data before it enters their context."
        actions={
          <>
            <Btn onClick={() => setResult(null)} disabled={!result || busy}>
              <RotateCcw className="size-5" /> Reset demo
            </Btn>
            <Btn variant="primary" onClick={run} disabled={busy || !prompt.trim()}>
              <Play className="size-5" /> {busy ? "Running…" : "Run request"}
            </Btn>
          </>
        }
      />

      <StatRow>
        <Stat label="Controls enforced" value={enforced ?? "…"} unit="live" note={policy ? `Profile ${policy.profile} · ${policy.version}` : "Loading policy…"} />
        <Stat label="Values hidden" value={a ? a.hidden : "—"} unit="this request" tone={a?.hidden ? "redact" : undefined} note="Tokenized before the model saw them" />
        <Stat label="Actions stopped" value={a ? a.stopped : "—"} unit="this request" tone={a?.stopped ? "block" : undefined} note="Removed from the model's answer, never ran" />
        <Stat label="Released to tools" value={a ? a.released.length : "—"} unit="this request" tone={a?.released.length ? "flag" : undefined} note="Real values put back for approved tools only" />
      </StatRow>

      <FlowStrip a={a ?? null} />

      <Panel className="mb-6 px-6 pt-5 pb-4">
        <div className="grid grid-cols-1 items-end gap-4 lg:grid-cols-[1.6fr_1fr_1.2fr_auto]">
          <Field label="Example">
            <Select value={example} onChange={pick} options={[...EXAMPLES.map((e) => ({ value: e.id, label: e.label })), { value: "custom", label: "Custom prompt" }]} />
          </Field>
          <Field label="Acting as">
            <Select value={user} onChange={(v) => { setUser(v); setExample("custom"); }} options={Object.keys(USERS).map((u) => ({ value: u, label: `${u} · ${USERS[u].scenario}` }))} />
          </Field>
          <Field label="Model">
            <Select value={model} onChange={setModel} options={MODELS} />
          </Field>
          <Btn variant="primary" onClick={run} disabled={busy || !prompt.trim()}>
            {busy ? "Running…" : "Run request"}
          </Btn>
        </div>
        <div className="mt-4 flex items-center gap-4 text-[15px] text-muted-foreground">
          <span>{USERS[user].note}</span>
          <span className="ml-auto rounded bg-muted px-2 py-0.5 text-sm">Fake customers and tools · no email or payment leaves this machine</span>
        </div>
      </Panel>

      <div className="flex items-start gap-6">
        <div className="flex min-w-0 flex-1 flex-col gap-6">
          <Panel>
            <PanelHeader icon={<FlaskConical className="size-5" />} title="Test a request">
              {result && (
                <span className="font-mono text-sm text-muted-foreground">
                  {result.run.session} · {Math.round(result.ms)} ms
                </span>
              )}
            </PanelHeader>
            <div className="px-6 pt-5 pb-6">
              <div className="mb-2 flex items-baseline">
                <SectionLabel>User request</SectionLabel>
                <span className="ml-auto text-sm text-muted-foreground">
                  {user} · {USERS[user].role}
                </span>
              </div>
              <textarea
                value={prompt}
                onChange={(e) => { setPrompt(e.target.value); setExample("custom"); }}
                onKeyDown={(e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) run(); }}
                rows={2}
                className="w-full resize-none rounded-md border border-input bg-muted px-4 py-3 text-[17px] outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
              />
              <div className="mt-1 text-xs text-muted-foreground">Ctrl + Enter to run</div>
              {error && <div className="mt-4 rounded-md bg-block-soft px-4 py-3 text-sm text-block">Run failed: {error}</div>}
            </div>
            {busy && <div className="border-t px-6 py-10 text-center text-muted-foreground">The agent is working through the gateway…</div>}
            {result && !busy && <Result result={result} />}
          </Panel>

          <ControlsTable policy={policy} fired={a?.fired ?? null} />
        </div>

        <LivePolicy policy={policy} history={history} />
      </div>
    </>
  );
}

function FlowStrip({ a }: { a: Analysis | null }) {
  const steps = [
    { icon: User, title: "User request", note: "Asks the agent for help" },
    { icon: Bot, title: "AI model", note: "Proposes tool calls" },
    { icon: ShieldCheck, title: "FlowGuard policy checks", note: "Check before acting · filter before the model · block before leaving", focus: true },
    { icon: Database, title: "Bank tools", note: "Run only the calls that were allowed" },
  ];
  return (
    <Panel className="mb-6 px-6 py-5">
      <div className="mb-4 flex items-baseline">
        <h2 className="font-semibold">Every model request and tool call passes through FlowGuard</h2>
        <span className="ml-auto font-mono text-xs tracking-wide text-muted-foreground uppercase">Check before acting · Filter before the model · Block before leaving</span>
      </div>
      <div className="flex items-stretch gap-3">
        {steps.map((s, i) => (
          <div key={s.title} className="flex flex-1 items-center gap-3">
            <div className={cn("flex flex-1 items-start gap-3 rounded-md border px-4 py-3", s.focus && "border-primary bg-selected ring-1 ring-primary")}>
              <s.icon className="mt-0.5 size-5 shrink-0" />
              <div>
                <div className="font-medium">{s.title}</div>
                <div className="text-sm text-muted-foreground">{s.note}</div>
              </div>
            </div>
            {i < steps.length - 1 && <ArrowRight className="size-5 shrink-0 text-muted-foreground" />}
          </div>
        ))}
      </div>
      <div className="mt-3 flex items-center gap-2 text-sm text-muted-foreground">
        <CornerDownLeft className="size-4" />
        {a
          ? `This run: ${a.decisions.length} checks in ${a.checksMs.toFixed(0)} ms. ${a.summary}.`
          : "Tool → FlowGuard → model. Sensitive values never reach the model or the model provider."}
      </div>
    </Panel>
  );
}

const STATUS = {
  ran: { tone: "allow", label: "Ran", icon: Check },
  released: { tone: "flag", label: "Ran with real values", icon: Check },
  stopped: { tone: "block", label: "Stopped before it ran", icon: X },
} as const;

function Result({ result }: { result: { run: TryResult; a: Analysis } }) {
  const { a } = result;
  const BANNER = { block: "bg-block-soft text-block", redact: "bg-redact-soft text-redact", flag: "bg-flag-soft text-flag", allow: "bg-allow-soft text-allow", neutral: "bg-muted" };
  const stopped = a.actions.filter((x) => x.status === "stopped");
  const tokenized = a.findings.filter((f) => f.decision === "Tokenized").length;

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
      </div>

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
                <td className="py-3 pr-3 text-muted-foreground">{f.where}</td>
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
          <SectionLabel className="mb-2">Stopped actions</SectionLabel>
          {stopped.map((x, i) => {
            const why = a.decisions.find((d) => d.action === "block" && d.where === `tool_call:${x.name}`);
            return (
              <div key={i} className="flex items-baseline gap-3 py-1 text-[15px]">
                <X className="size-4 shrink-0 translate-y-0.5 text-block" />
                <span className="font-mono">{x.name}</span>
                <span className="text-muted-foreground">stopped before it ran · {why ? `${controlName(why.control)}: ${why.reason}` : "blocked by policy"}</span>
              </div>
            );
          })}
        </div>
      )}

      <div className="grid grid-cols-4 gap-4 border-t bg-muted px-6 py-4 text-sm">
        <Checkpoint title="Actions checked" note={`${a.actions.filter((x) => x.status !== "stopped").length} allowed · ${a.stopped} stopped`} />
        <Checkpoint title="Results filtered" note={`${tokenized} tokenized · ${a.quarantined} quarantined`} />
        <Checkpoint title="Answer checked" note="Model text redacted too" />
        <Checkpoint title="Outbound" note={a.leftOrg.length ? `Sent via ${a.leftOrg.join(", ")}` : "Nothing left the organisation"} />
      </div>

      <div className="border-t px-6 py-5">
        <SectionLabel className="mb-2">AI response · as the model wrote it</SectionLabel>
        <p className="text-[16px] whitespace-pre-wrap">{a.answer ?? <span className="text-muted-foreground">No final answer (the run ended on a tool call or a block).</span>}</p>
        <div className="mt-4 flex items-center gap-4">
          <p className="flex-1 text-sm text-muted-foreground">
            The tool did read these values; the gateway kept them in its token vault and gave the model placeholders. Real values are only put back for tools the
            policy allows.
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
              .map(([k, v]) => `${k}: ${v}`)
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

function LivePolicy({ policy, history }: { policy: Policy | null; history: PolicyHistoryItem[] | null }) {
  const changes = (history ?? []).filter((h) => h.error || h.changes?.length).slice(0, 6);
  return (
    <Panel className="sticky top-6 w-[420px] shrink-0">
      <PanelHeader icon={<History className="size-5" />} title="Live policy">
        <span className="rounded bg-muted px-2 py-0.5 font-mono text-xs text-muted-foreground">{policy?.version ?? "…"}</span>
      </PanelHeader>
      <div className="px-6 py-5">
        <h3 className="text-xl font-medium">Change the rules while it runs</h3>
        <p className="mt-2 text-[15px] text-muted-foreground">
          Edit <span className="font-mono text-sm text-foreground">policy/policy.yaml</span>. The gateway reloads it within seconds, without a restart, and records
          every change in the audit trail.
        </p>

        <SectionLabel className="mt-5 mb-2">Try</SectionLabel>
        <pre className="rounded-md bg-muted px-4 py-3 font-mono text-sm leading-relaxed">
          {`active_profile: strict      # or permissive\n\ncontrols:\n  pii.iban: {action: flag}`}
        </pre>

        <SectionLabel className="mt-6 mb-3">Recent changes</SectionLabel>
        {changes.length ? (
          <ul className="flex flex-col gap-3">
            {changes.map((h, i) => (
              <li key={i} className={cn("rounded-md border px-3 py-2.5", h.error && "border-block/30 bg-block-soft")}>
                <div className="flex items-baseline gap-2 font-mono text-xs text-muted-foreground">
                  <span className="text-foreground">{h.version}</span>
                  <span>· {h.profile}</span>
                  {h.ts && <span className="ml-auto">{utcTime(h.ts, false)}</span>}
                </div>
                {h.error ? (
                  <div className="mt-1 text-sm text-block">Rejected, last good policy kept: {h.error}</div>
                ) : (
                  h.changes.map((c, j) => (
                    <div key={j} className="mt-1 font-mono text-xs">
                      {c.what}: <span className="text-block line-through">{JSON.stringify(c.old)}</span> → <span className="text-allow">{JSON.stringify(c.new)}</span>
                    </div>
                  ))
                )}
              </li>
            ))}
          </ul>
        ) : (
          <div className="text-sm text-muted-foreground">No edits since the gateway started.</div>
        )}

        <div className="mt-6 flex gap-3 rounded-md bg-muted px-4 py-3 text-sm text-muted-foreground">
          <Lock className="mt-0.5 size-4 shrink-0" />
          The dashboard is read-only. Rules live in one YAML file, and every decision in the audit trail names the policy version that made it.
        </div>
      </div>
    </Panel>
  );
}
