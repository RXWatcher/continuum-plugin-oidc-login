import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Loader2, CheckCircle2, XCircle } from "lucide-react";
import { api } from "@/lib/api";

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
  jwks_keys?: { kid: string; kty: string; alg: string; use: string }[];
};

// DiscoveryPanel triggers a live fetch of the configured issuer's discovery
// document and renders the result inline. Useful as a smoke test after
// changing the issuer URL.
export default function DiscoveryPanel() {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<DiscoveryResult | null>(null);

  const test = async () => {
    setBusy(true);
    try {
      const r = await api.get<DiscoveryResult>("/api/v1/admin/discovery");
      setResult(r);
    } catch (e) {
      setResult({ ok: false, error: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      <Button type="button" variant="outline" onClick={test} disabled={busy}>
        {busy && <Loader2 className="mr-2 size-4 animate-spin" />}
        Test discovery
      </Button>
      {result && (
        <div className="bg-card border-border/70 space-y-2 rounded-md border p-4 text-sm">
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
              <Field label="Authorization endpoint" value={result.authorization_endpoint} />
              <Field label="Token endpoint" value={result.token_endpoint} />
              <Field label="UserInfo endpoint" value={result.userinfo_endpoint} />
              <Field label="JWKS URI" value={result.jwks_uri} />
              <Field
                label="Scopes supported"
                value={result.scopes_supported?.join(", ")}
              />
              <Field
                label="JWKS keys"
                value={result.jwks_keys?.map((k) => `${k.kid}(${k.alg})`).join(", ")}
              />
            </dl>
          )}
        </div>
      )}
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
