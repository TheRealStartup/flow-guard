"use client";

import { usePathname } from "next/navigation";
import { ChevronRight, TriangleAlert } from "lucide-react";
import { usePoll, type Health } from "@/lib/api";
import { cn } from "@/lib/utils";

const TITLES: Record<string, string> = { "/audit": "Audit trail", "/demo": "Live demo" };

export function Topbar() {
  const path = usePathname();
  const { data: health, error } = usePoll<Health>("/api/health", 5000);

  return (
    <>
      <header className="flex h-16 items-center gap-4 border-b border-border bg-card px-9">
        <nav className="flex items-center gap-3 text-[15px]">
          <span className="text-muted-foreground">Oversight</span>
          <ChevronRight className="size-4 text-muted-foreground" />
          <span>{TITLES[path] ?? "Overview"}</span>
        </nav>
        <div className="ml-auto flex items-center gap-3">
          {health && (
            <>
              <Tag tone={health.judge === "demo" ? "warn" : "plain"} title="Which prompt-injection judge the gateway uses">
                {health.judge === "demo" ? "Demo judge" : `Judge · ${health.judge}`}
              </Tag>
              <Tag title="Active policy profile">{health.profile}</Tag>
            </>
          )}
          <span className="text-sm text-muted-foreground">All times in UTC</span>
        </div>
      </header>
      {(health?.policy_error || error) && (
        <div className="flex items-center gap-2 border-b border-block/20 bg-block-soft px-9 py-2 text-sm text-block">
          <TriangleAlert className="size-4 shrink-0" />
          {health?.policy_error
            ? `Policy edit rejected, the last good policy stays active: ${health.policy_error}`
            : "Gateway unreachable. Is `docker compose up` running?"}
        </div>
      )}
    </>
  );
}

function Tag({ children, tone = "plain", title }: { children: React.ReactNode; tone?: "plain" | "warn"; title?: string }) {
  return (
    <span
      title={title}
      className={cn(
        "rounded border px-2 py-1 font-mono text-xs tracking-wide uppercase",
        tone === "warn" ? "border-flag/30 bg-flag-soft text-flag" : "border-border bg-muted text-muted-foreground",
      )}
    >
      {children}
    </span>
  );
}
