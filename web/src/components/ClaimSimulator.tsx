import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Loader2, CheckCircle2, XCircle, AlertCircle } from "lucide-react";
import { api } from "@/lib/api";
import type { ClaimFilter } from "./ClaimFilterEditor";
import type { RoleMappingRule } from "./RoleMappingEditor";

// FilterTraceRow mirrors internal/claims.FilterTrace.
type FilterTraceRow = {
  index: number;
  claim_path: string;
  operator: string;
  value: unknown;
  claim_value: unknown;
  claim_found: boolean;
  match: boolean;
};

type SimulateResponse = {
  allowed: boolean;
  filters_passed: boolean;
  filter_trace: FilterTraceRow[];
  email_verified_check: {
    required: boolean;
    claim_found: boolean;
    claim_value: unknown;
    passed: boolean;
  };
  sub_present: boolean;
  role: "user" | "admin";
  role_rule_index: number;
  identity: {
    sub: string;
    email: string;
    name: string;
  };
};

const EXAMPLE_CLAIMS = JSON.stringify(
  {
    sub: "u-1234",
    email: "ada@example.com",
    email_verified: true,
    name: "Ada Lovelace",
    given_name: "Ada",
    family_name: "Lovelace",
    groups: ["continuum-users", "engineering"],
    realm_access: { roles: ["operator"] },
  },
  null,
  2,
);

// ClaimSimulator lets the admin paste an arbitrary claims object and preview
// the gate decision against the *currently edited* (possibly unsaved) filters
// + role mapping + email_verified flag. It POSTs to /simulate-claims, passing
// the current page state as overrides so admins don't need to save before
// previewing.
export default function ClaimSimulator({
  filters,
  roleMapping,
  emailVerifiedRequired,
  seedClaims,
}: {
  filters: ClaimFilter[];
  roleMapping: RoleMappingRule[];
  emailVerifiedRequired: boolean;
  // seedClaims is an external (parent-supplied) claims object to prefill the
  // textarea from — usually the most recently decoded id_token claims from
  // DiagnosticsPanel. Updated via the "Use decoded claims" button there.
  seedClaims?: Record<string, unknown> | null;
}) {
  const [text, setText] = useState<string>(EXAMPLE_CLAIMS);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<SimulateResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadSeed = () => {
    if (!seedClaims) return;
    setText(JSON.stringify(seedClaims, null, 2));
  };

  const run = async () => {
    setError(null);
    setResult(null);
    let claims: Record<string, unknown>;
    try {
      claims = JSON.parse(text);
      if (typeof claims !== "object" || claims === null || Array.isArray(claims)) {
        throw new Error("Claims must be a JSON object");
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    setBusy(true);
    try {
      const r = await api.post<SimulateResponse>("/api/v1/admin/simulate-claims", {
        claims,
        filters,
        role_mapping: roleMapping,
        email_verified_required: emailVerifiedRequired,
      });
      setResult(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      <p className="text-muted-foreground text-xs">
        Paste a claims object (id_token + userinfo merged) to preview what
        would happen if a user with these claims tried to sign in. Uses the
        rules currently in the editors above (unsaved changes included).
      </p>
      <textarea
        rows={10}
        className="bg-background border-input w-full rounded-md border p-2 font-mono text-xs"
        value={text}
        onChange={(e) => setText(e.target.value)}
        spellCheck={false}
      />
      <div className="flex flex-wrap gap-2">
        <Button type="button" variant="outline" onClick={run} disabled={busy}>
          {busy && <Loader2 className="mr-2 size-4 animate-spin" />}
          Simulate
        </Button>
        {seedClaims && (
          <Button type="button" variant="ghost" onClick={loadSeed}>
            Use decoded claims from above
          </Button>
        )}
        <Button
          type="button"
          variant="ghost"
          onClick={() => setText(EXAMPLE_CLAIMS)}
        >
          Reset example
        </Button>
      </div>

      {error && (
        <div className="text-destructive flex items-center gap-2 text-sm">
          <AlertCircle className="size-4" /> {error}
        </div>
      )}

      {result && (
        <div className="bg-card border-border/70 space-y-3 rounded-md border p-4 text-sm">
          <Verdict result={result} />
          <FilterTraceTable trace={result.filter_trace} />
          <EmailCheckRow check={result.email_verified_check} />
          <SubCheckRow present={result.sub_present} />
          <RoleRow result={result} />
          <IdentityBlock identity={result.identity} />
        </div>
      )}
    </div>
  );
}

function Verdict({ result }: { result: SimulateResponse }) {
  if (result.allowed) {
    return (
      <div className="flex items-center gap-2 text-green-500">
        <CheckCircle2 className="size-4" /> Would sign in — assigned role{" "}
        <span className="font-mono">{result.role}</span>
      </div>
    );
  }
  const reasons: string[] = [];
  if (!result.filters_passed) reasons.push("claim filter rejected");
  if (!result.email_verified_check.passed) reasons.push("email_verified gate");
  if (!result.sub_present) reasons.push("missing sub");
  return (
    <div className="text-destructive flex items-center gap-2">
      <XCircle className="size-4" /> Would NOT sign in
      {reasons.length > 0 && ` — ${reasons.join(", ")}`}
    </div>
  );
}

function FilterTraceTable({ trace }: { trace: FilterTraceRow[] }) {
  if (trace.length === 0) {
    return (
      <div className="text-muted-foreground text-xs">
        No claim filters configured — no gating applied.
      </div>
    );
  }
  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="text-muted-foreground border-b text-left">
          <th className="py-1 pr-2">Filter</th>
          <th className="py-1 pr-2">Claim value</th>
          <th className="w-16 py-1 pr-2">Result</th>
        </tr>
      </thead>
      <tbody>
        {trace.map((row) => (
          <tr key={row.index} className="border-border/30 border-b last:border-b-0">
            <td className="py-1 pr-2 align-top">
              <span className="font-mono">{row.claim_path}</span>{" "}
              <span className="text-muted-foreground">{row.operator}</span>{" "}
              <span className="font-mono">{JSON.stringify(row.value)}</span>
            </td>
            <td className="py-1 pr-2 align-top">
              {row.claim_found ? (
                <span className="font-mono break-all">
                  {JSON.stringify(row.claim_value)}
                </span>
              ) : (
                <span className="text-destructive">claim not present</span>
              )}
            </td>
            <td className="py-1 pr-2 align-top">
              {row.match ? (
                <span className="text-green-500">pass</span>
              ) : (
                <span className="text-destructive">fail</span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function EmailCheckRow({
  check,
}: {
  check: SimulateResponse["email_verified_check"];
}) {
  if (!check.required) {
    return (
      <div className="text-muted-foreground text-xs">
        email_verified gate disabled.
      </div>
    );
  }
  return (
    <div className="text-xs">
      email_verified required:{" "}
      {check.passed ? (
        <span className="text-green-500">pass</span>
      ) : (
        <span className="text-destructive">
          fail (
          {check.claim_found
            ? `claim = ${JSON.stringify(check.claim_value)}`
            : "claim not present"}
          )
        </span>
      )}
    </div>
  );
}

function SubCheckRow({ present }: { present: boolean }) {
  if (present) return null;
  return (
    <div className="text-destructive text-xs">
      Missing <span className="font-mono">sub</span> — the host needs a stable
      external subject to track this identity.
    </div>
  );
}

function RoleRow({ result }: { result: SimulateResponse }) {
  if (result.role_rule_index < 0) {
    return (
      <div className="text-muted-foreground text-xs">
        No role-mapping rule matched — defaulting to{" "}
        <span className="font-mono">user</span>.
      </div>
    );
  }
  return (
    <div className="text-xs">
      Role assigned by rule #{result.role_rule_index + 1}:{" "}
      <span className="font-mono">{result.role}</span>
    </div>
  );
}

function IdentityBlock({
  identity,
}: {
  identity: SimulateResponse["identity"];
}) {
  return (
    <div className="border-border/40 border-t pt-2 text-xs">
      <div className="text-muted-foreground">Resolved identity:</div>
      <div className="mt-1 grid grid-cols-1 gap-1 sm:grid-cols-3">
        <Field label="sub" value={identity.sub} />
        <Field label="email" value={identity.email} />
        <Field label="display name" value={identity.name} />
      </div>
    </div>
  );
}

function Field({ label, value }: { label: string; value?: string }) {
  return (
    <div>
      <span className="text-muted-foreground">{label}: </span>
      <span className="font-mono break-all">{value || "—"}</span>
    </div>
  );
}
