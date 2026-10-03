"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { FlaskConical, Landmark, LayoutGrid, ListFilter, Lock, SlidersVertical, type LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { usePoll, type Health } from "@/lib/api";

type Item = { href: string; label: string; icon: LucideIcon; soon?: boolean };

const OVERSIGHT: Item[] = [
  { href: "/overview", label: "Overview", icon: LayoutGrid },
  { href: "/audit", label: "Audit trail", icon: ListFilter },
  { href: "/demo", label: "Live demo", icon: FlaskConical },
  { href: "/policies", label: "Policies", icon: SlidersVertical },
];

export function Sidebar() {
  const path = usePathname();
  const { data: health } = usePoll<Health>("/api/health", 5000);

  return (
    <aside className="sticky top-0 flex h-screen w-60 shrink-0 flex-col bg-sidebar text-sidebar-foreground">
      <div className="flex items-center gap-3 px-5 pt-6 pb-7">
        <Landmark className="size-8 text-white" strokeWidth={1.5} />
        <div>
          <div className="text-xl leading-tight text-white">FlowGuard</div>
          <div className="text-xs tracking-wide text-sidebar-muted uppercase">Control center</div>
        </div>
      </div>

      <div className="mx-3 mb-6 rounded-md border border-sidebar-border px-3 py-2.5">
        <div className="text-[11px] tracking-wide text-sidebar-muted uppercase">Gateway</div>
        <div className="flex items-center gap-2 text-sm text-white">
          <span className={cn("size-2 rounded-full", health?.ok ? "bg-emerald-400" : "bg-red-400")} />
          {health ? `localhost:8000 · ${health.profile}` : "connecting…"}
        </div>
      </div>

      <nav className="flex flex-col gap-1 px-3">
        <div className="px-2 pb-2 text-xs tracking-wide text-sidebar-muted uppercase">Oversight</div>
        {OVERSIGHT.map((item) => {
          const active = path === item.href || path.startsWith(item.href + "/");
          const Icon = item.icon;
          const body = (
            <>
              <Icon className="size-5" strokeWidth={1.75} />
              <span className="flex-1">{item.label}</span>
              {item.soon && <span className="text-[10px] tracking-wide text-sidebar-muted uppercase">soon</span>}
            </>
          );
          const cls = cn(
            "flex items-center gap-3 rounded-md px-3 py-3 text-[15px]",
            active && "bg-sidebar-accent font-semibold text-white",
            !active && !item.soon && "hover:bg-sidebar-accent/60",
            item.soon && "cursor-default opacity-55",
          );
          return item.soon ? (
            <div key={item.href} className={cls} aria-disabled>
              {body}
            </div>
          ) : (
            <Link key={item.href} href={item.href} className={cls}>
              {body}
            </Link>
          );
        })}
      </nav>

      <div className="mt-auto border-t border-sidebar-border px-5 py-4 text-sm">
        <div className="flex items-center gap-2 text-sidebar-foreground">
          <Lock className="size-4" /> Read-only audit access
        </div>
        <div className="mt-2 font-mono text-xs text-sidebar-muted">
          POLICY / {health?.policy_version ?? "…"}
        </div>
      </div>
    </aside>
  );
}
