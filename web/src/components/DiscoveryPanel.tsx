import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Loader2, CheckCircle2, XCircle, RefreshCw } from "lucide-react";
import { api } from "@/lib/api";

type JWKSKey = {
  kid: string;
  kty: string;
  alg: string;
  use: string;
};

type DiscoveryResult = {
  ok: boolean;
  error?: string;
  issuer?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
  scopes_supported?: string[];
  claims_supported?: string[];
  jwks_keys?: JWKSKey[];
};

// DiscoveryPanel triggers a live fetch of the configured issuer's discovery
// document and renders the result inline. Doubles as the JWKS rotation
// diagnostic: re-clicking refetches the signing keys, so admins can verify
// rotation took effect after rotating at the IdP.
export default function DiscoveryPanel() {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<DiscoveryResult | null>(null);
  const [fetchedAt, setFetchedAt] = useState<Date | null>(null);

  const test = async () => {
    setBusy(true);
    try {
      const r = await api.get<DiscoveryResult>("/api/v1/admin/discovery");
      setResult(r);
      setFetchedAt(new Date());
    } catch (e) {
      setResult({ ok: false, error: e instanceof Error ? e.message : String(e) });
      setFetchedAt(new Date());
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" variant="outline" onClick={test} disabled={busy}>
          {busy ? (
            <Loader2 className="mr-2 size-4 animate-spin" />
          ) : result ? (
            <RefreshCw className="mr-2 size-4" />
          ) : null}
          {result ? "Refresh discovery + JWKS" : "Test discovery"}
        </Button>
        {fetchedAt && (
          <span className="text-muted-foreground text-xs">
            last fetched {fetchedAt.toLocaleTimeString()}
          </span>
        )}
      </div>
      {result && (
        <div className="bg-card border-border/70 space-y-3 rounded-md border p-4 text-sm">
          {result.ok ? (
            <div className="flex items-center gap-2 text-green-500">
              <CheckCircle2 className="size-4" /> Discovery OK
            </div>
          ) : (
            <div className="text-destructive flex items-center gap-2">
              <XCircle className="size-4" /> {result.error}
            </div>
          )}
          {result.ok && (
            <dl className="grid grid-cols-1 gap-1 sm:grid-cols-2">
              <Field label="Issuer" value={result.issuer} />
              <Field
                label="Authorization endpoint"
                value={result.authorization_endpoint}
              />
              <Field label="Token endpoint" value={result.token_endpoint} />
              <Field
                label="UserInfo endpoint"
                value={result.userinfo_endpoint}
              />
              <Field label="JWKS URI" value={result.jwks_uri} />
              <Field
                label="Scopes supported"
                value={result.scopes_supported?.join(", ")}
              />
            </dl>
          )}
          {result.ok && (
            <JWKSTable keys={result.jwks_keys ?? []} />
          )}
        </div>
      )}
    </div>
  );
}

function JWKSTable({ keys }: { keys: JWKSKey[] }) {
  if (keys.length === 0) {
    return (
      <div className="text-muted-foreground text-xs">
        JWKS reported no keys — the IdP isn't advertising any signing keys at
        this URI, or the JWKS endpoint returned an error. Token verification
        will fail until at least one signing key is published.
      </div>
    );
  }
  return (
    <div className="space-y-1">
      <div className="text-muted-foreground text-xs">
        Signing keys ({keys.length})
      </div>
      <table className="w-full text-xs">
        <thead>
          <tr className="text-muted-foreground border-b text-left">
            <th className="py-1 pr-2">kid</th>
            <th className="w-16 py-1 pr-2">kty</th>
            <th className="w-20 py-1 pr-2">alg</th>
            <th className="w-16 py-1 pr-2">use</th>
          </tr>
        </thead>
        <tbody>
          {keys.map((k, i) => (
            <tr
              key={k.kid || `key-${i}`}
              className="border-border/30 border-b last:border-b-0"
            >
              <td className="py-1 pr-2 font-mono break-all">{k.kid || "—"}</td>
              <td className="py-1 pr-2 font-mono">{k.kty || "—"}</td>
              <td className="py-1 pr-2 font-mono">{k.alg || "—"}</td>
              <td className="py-1 pr-2 font-mono">{k.use || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="text-muted-foreground text-xs">
        After rotating keys at the IdP, click <em>Refresh</em> and confirm the
        kid set changed. Silo verifies id_tokens with whatever the JWKS
        endpoint advertises right now.
      </p>
    </div>
  );
}

function Field({ label, value }: { label: string; value?: string }) {
  if (!value) return null;
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="break-all font-mono">{value}</dd>
    </>
  );
}
