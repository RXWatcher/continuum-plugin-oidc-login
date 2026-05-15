import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Loader2 } from "lucide-react";
import { api } from "@/lib/api";

type DecodeResult = {
  verified: boolean;
  claims?: Record<string, unknown>;
  error?: string;
};

// formatExpiry turns a JWT `exp` claim (numeric seconds since epoch) into a
// short human-readable countdown. Returns null if exp is missing/unparseable.
// No new dependency; mirrors the conservative formatting we use elsewhere.
function formatExpiry(exp: unknown): {
  label: string;
  expired: boolean;
} | null {
  const n = typeof exp === "number" ? exp : Number(exp);
  if (!Number.isFinite(n) || n <= 0) return null;
  const diffSec = Math.round(n - Date.now() / 1000);
  const abs = Math.abs(diffSec);
  const m = Math.floor(abs / 60);
  const s = abs % 60;
  const parts =
    abs >= 60 ? `${m}m ${s}s` : `${s}s`;
  if (diffSec < 0) {
    return { label: `expired ${parts} ago`, expired: true };
  }
  return { label: `expires in ${parts}`, expired: false };
}

// DiagnosticsPanel decodes a pasted id_token against the live JWKS. The
// per-claim "Filter" / "Role" buttons prefill a new row in the editors
// above via the onUseAsFilter / onUseAsRoleMapping callbacks.
export default function DiagnosticsPanel({
  onUseAsFilter,
  onUseAsRoleMapping,
}: {
  onUseAsFilter?: (claimPath: string) => void;
  onUseAsRoleMapping?: (claimPath: string) => void;
}) {
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<DecodeResult | null>(null);

  const decode = async () => {
    setBusy(true);
    try {
      const r = await api.post<DecodeResult>("/api/v1/admin/decode-id-token", {
        id_token: token,
      });
      setResult(r);
    } catch (e) {
      setResult({
        verified: false,
        error: e instanceof Error ? e.message : String(e),
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      <textarea
        rows={4}
        className="bg-background border-input w-full rounded-md border p-2 font-mono text-xs"
        placeholder="Paste an id_token here to decode + verify against the live JWKS"
        value={token}
        onChange={(e) => setToken(e.target.value)}
      />
      <Button type="button" variant="outline" onClick={decode} disabled={busy || !token}>
        {busy && <Loader2 className="mr-2 size-4 animate-spin" />}
        Decode
      </Button>
      {result && (
        <div className="bg-card border-border/70 rounded-md border p-4 text-sm">
          <div
            className={result.verified ? "text-green-500" : "text-destructive"}
          >
            {result.verified
              ? "Signature verified"
              : `Verification failed: ${result.error || "unknown"}`}
          </div>
          {result.claims &&
            (() => {
              const exp = formatExpiry(result.claims.exp);
              if (!exp) return null;
              return (
                <div
                  className={
                    "mt-1 text-xs " +
                    (exp.expired ? "text-destructive" : "text-muted-foreground")
                  }
                >
                  Token {exp.label}
                </div>
              );
            })()}
          {result.claims && (
            <div className="mt-3 space-y-2">
              <details>
                <summary className="text-muted-foreground cursor-pointer text-xs">
                  Raw claims JSON
                </summary>
                <pre className="bg-muted mt-2 max-h-64 overflow-auto rounded-md p-2 text-xs">
                  {JSON.stringify(result.claims, null, 2)}
                </pre>
              </details>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {Object.entries(result.claims).map(([key, val]) => (
                  <div
                    key={key}
                    className="border-border/70 rounded-md border p-2"
                  >
                    <div className="font-mono text-xs">{key}</div>
                    <div className="text-muted-foreground truncate text-xs">
                      {JSON.stringify(val)}
                    </div>
                    <div className="mt-1 flex gap-2">
                      {onUseAsFilter && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => onUseAsFilter(key)}
                        >
                          Filter
                        </Button>
                      )}
                      {onUseAsRoleMapping && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => onUseAsRoleMapping(key)}
                        >
                          Role
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
