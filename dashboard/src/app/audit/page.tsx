import { Suspense } from "react";
import { AuditTrail } from "./audit-trail";

export default function AuditPage() {
  return (
    <Suspense>
      <AuditTrail />
    </Suspense>
  );
}
