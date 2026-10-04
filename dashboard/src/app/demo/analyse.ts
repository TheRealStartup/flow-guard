import type { Decision, TryResult } from "@/lib/api";
import { controlName, whereLabel } from "@/lib/format";
import type { Tone } from "@/components/kit";
import { EXTERNAL_SINKS } from "./scenarios";

// Turns a Try-it run into the result card of docs/dashboard-demo-panel.md: verdict, findings, stopped actions.

export type Finding = { found: string; where: string; source: string | null; decision: string; tone: Tone; sawInstead: string; rule: string; reason: string };
export type Action = { name: string; arguments: string; status: "ran" | "stopped" | "released" };

/** The token of this kind in a decision's excerpt, e.g. [[IBAN#3f2a1b]]. Excerpts often hold several kinds. */
function tokenIn(excerpt: string | null, kind: string | undefined) {
  if (!excerpt) return null;
  const tokens = excerpt.match(/\[\[[^\]]+\]\]/g) ?? [];
  return tokens.find((t) => kind && t.startsWith(`[[${kind}`)) ?? tokens[0] ?? null;
}

function finding(d: Decision): Finding {
  const base = { where: whereLabel(d.where), source: d.source ?? null, rule: d.control, reason: d.reason };
  const found = d.reason.match(/^([A-Z]+) detected/)?.[1];
  const label = found ? { CARD: "Card number", IBAN: "IBAN", PESEL: "National ID (PESEL)", PASSPORT: "Passport number", DOB: "Date of birth", SECRET: "Secret" }[found] ?? found : controlName(d.control);

  if (d.control === "injection.jev" && d.action === "redact")
    return { ...base, found: "Text with hidden instructions", decision: `Quarantined${d.score != null ? ` (p = ${d.score.toFixed(2)})` : ""}`, tone: "block", sawInstead: "Content removed: suspected prompt injection" };
  if (d.control === "barrier.mnpi")
    return { ...base, found: "Restricted deal content", decision: "Withheld", tone: "block", sawInstead: "“Some results are outside your access.”" };
  if (d.control === "classification")
    return {
      ...base,
      found: "Data above the model's class limit",
      decision: d.action === "block" ? "Not sent to any model" : "Withheld",
      tone: "block",
      sawInstead: d.action === "block" ? "Nothing: the gateway answered itself" : "“Some results are outside your access.”",
    };
  if (d.action === "redact")
    return { ...base, found: label, decision: "Tokenized", tone: "redact", sawInstead: d.token ?? tokenIn(d.excerpt, found) ?? "Reversible token" };
  if (d.control === "pii.detokenize")
    return { ...base, found: "Token for a real value", decision: "Released to approved tool", tone: "flag", sawInstead: "Real value put back for this tool only" };
  if (d.action === "block") {
    const call = d.where.startsWith("tool_call:") ? d.where.slice(10) : null;
    const decision = d.control.startsWith("flow.") ? "Blocked before it left" : call ? "Stopped before it ran" : "Blocked";
    return { ...base, found: call ? `${call} call` : controlName(d.control), decision, tone: "block", sawInstead: "—" };
  }
  return { ...base, found: label, decision: "Flagged", tone: "flag", sawInstead: "Passed unchanged, recorded" };
}

export function analyse(r: TryResult) {
  const decisions: Decision[] = r.steps.flatMap((s) => (s.kind !== "tool" && s.acl ? s.acl.decisions : []));
  const findings = decisions.filter((d) => d.action !== "allow").map(finding);
  const denied = r.steps.find((s) => s.kind === "denied");

  const ran = new Set(r.steps.filter((s) => s.kind === "tool").map((s) => (s.kind === "tool" ? s.name : "")));
  const blocked = decisions.filter((d) => d.action === "block" && d.where.startsWith("tool_call:"));
  const released = decisions.filter((d) => d.control === "pii.detokenize").map((d) => d.where.slice(10));
  const actions: Action[] = r.steps.flatMap((s) =>
    s.kind === "model"
      ? s.tool_calls.map((c) => ({
          name: c.name,
          arguments: c.arguments,
          status: blocked.some((b) => b.where === `tool_call:${c.name}`) && !ran.has(c.name) ? "stopped" : released.includes(c.name) ? "released" : "ran",
        }))
      : [],
  );
  // The gateway removes blocked calls from the model's answer; list those too, even if the step shows none.
  for (const b of blocked) {
    const name = b.where.slice(10);
    if (!actions.some((a) => a.name === name && a.status === "stopped")) actions.push({ name, arguments: b.excerpt ?? "", status: "stopped" });
  }

  // A value the model's answer merely repeats as a token is not hidden twice: count each token once.
  const tokens = new Set(decisions.filter((d) => d.action === "redact" && d.token).map((d) => d.token));
  const hidden = tokens.size;
  const quarantined = decisions.filter((d) => d.action === "redact" && d.control === "injection.jev").length;
  const withheld = decisions.filter((d) => (d.control === "barrier.mnpi" || d.control === "classification") && d.action !== "allow").length;
  const answerRedacted = decisions.some((d) => d.where === "model_output" && d.action === "redact");
  const stopped = actions.filter((a) => a.status === "stopped").length;
  const leftOrg = [...ran].filter((t) => EXTERNAL_SINKS.includes(t));

  const flowBlock = decisions.find((d) => d.action === "block" && d.control.startsWith("flow."));
  const verdict: { tone: Tone; title: string } = flowBlock
    ? { tone: "block", title: "Blocked before it left" }
    : stopped
      ? { tone: "block", title: "Stopped before it ran" }
      : denied
        ? { tone: "block", title: "Denied at the door" }
        : hidden || quarantined || withheld
          ? { tone: "redact", title: "Removed before the model saw it" }
          : released.length
            ? { tone: "flag", title: "Released only to an approved tool" }
            : { tone: "allow", title: "Passed: nothing sensitive found" };

  const parts = [
    hidden && `${hidden} value${hidden === 1 ? "" : "s"} hidden from the model`,
    quarantined && `${quarantined} message${quarantined === 1 ? "" : "s"} quarantined`,
    withheld && `${withheld} restricted item${withheld === 1 ? "" : "s"} withheld`,
    stopped && `${stopped} action${stopped === 1 ? "" : "s"} stopped`,
    released.length && `${released.length} real value${released.length === 1 ? "" : "s"} released to ${[...new Set(released)].join(", ")}`,
    leftOrg.length ? `sent outside via ${leftOrg.join(", ")}` : "nothing left the organisation",
  ].filter(Boolean) as string[];

  const last = [...r.steps].reverse().find((s) => s.kind === "model" && s.content);
  const answer = last?.kind === "model" ? last.content : null;

  return {
    decisions,
    findings,
    actions,
    hidden,
    quarantined,
    withheld,
    answerRedacted,
    stopped,
    released,
    leftOrg,
    verdict,
    summary: parts.join(" · "),
    denied: denied?.kind === "denied" ? denied : null,
    answer,
    fired: new Set(decisions.filter((d) => d.action !== "allow").map((d) => d.control)),
    checksMs: decisions.reduce((s, d) => s + d.ms, 0),
  };
}

export type Analysis = ReturnType<typeof analyse>;
