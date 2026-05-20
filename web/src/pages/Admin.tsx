import { useEffect, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { api, installationID } from "@/lib/api";
import SettingsForm, { type SettingsState } from "@/components/SettingsForm";
import ClaimFilterEditor, {
  type ClaimFilter,
} from "@/components/ClaimFilterEditor";
import RoleMappingEditor, {
  type RoleMappingRule,
} from "@/components/RoleMappingEditor";
import DiagnosticsPanel from "@/components/DiagnosticsPanel";
import ClaimSimulator from "@/components/ClaimSimulator";

type ConfigSummary = {
  issuer_url: string;
  client_id: string;
  has_client_secret: boolean;
  scopes: string;
  display_name: string;
  icon_url_path: string;
  claim_filters: ClaimFilter[];
  claim_role_mapping: RoleMappingRule[];
  email_verified_required: boolean;
  link_by_email: boolean;
  available_icons: string[];
};

// Admin page composes the three card sections + Diagnostics + a single Save
// button at the bottom. All state lives here; sub-components are pure
// controlled inputs. Save PATCHes the plugin admin endpoint, which stores the
// settings in the plugin database and rebuilds the OIDC provider.
export default function Admin() {
  const qc = useQueryClient();
  const cfgQ = useQuery({
    queryKey: ["config-summary"],
    queryFn: () => api.get<ConfigSummary>("/api/v1/admin/config-summary"),
  });

  const [settings, setSettings] = useState<SettingsState>({
    issuer_url: "",
    client_id: "",
    client_secret: "",
    has_client_secret: false,
    scopes: "openid profile email",
    display_name: "",
    icon_url_path: "generic-key.svg",
    email_verified_required: true,
    link_by_email: false,
  });
  const [filters, setFilters] = useState<ClaimFilter[]>([]);
  const [mapping, setMapping] = useState<RoleMappingRule[]>([]);
  // Decoded claims from the last successful DiagnosticsPanel verification.
  // Lifted up here so ClaimSimulator can offer a "Use decoded claims" shortcut.
  const [decodedClaims, setDecodedClaims] = useState<Record<
    string,
    unknown
  > | null>(null);

  useEffect(() => {
    if (!cfgQ.data) return;
    setSettings({
      issuer_url: cfgQ.data.issuer_url ?? "",
      client_id: cfgQ.data.client_id ?? "",
      client_secret: "",
      has_client_secret: cfgQ.data.has_client_secret,
      scopes: cfgQ.data.scopes || "openid profile email",
      display_name: cfgQ.data.display_name ?? "",
      icon_url_path: cfgQ.data.icon_url_path || "generic-key.svg",
      email_verified_required: cfgQ.data.email_verified_required,
      link_by_email: cfgQ.data.link_by_email,
    });
    setFilters(cfgQ.data.claim_filters ?? []);
    setMapping(cfgQ.data.claim_role_mapping ?? []);
  }, [cfgQ.data]);

  const save = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = {
        issuer_url: settings.issuer_url,
        client_id: settings.client_id,
        scopes: settings.scopes,
        display_name: settings.display_name,
        icon_url_path: settings.icon_url_path,
        email_verified_required: settings.email_verified_required,
        link_by_email: settings.link_by_email,
        claim_filters: filters,
        claim_role_mapping: mapping,
      };
      if (settings.client_secret) {
        body.client_secret = settings.client_secret;
      }
      await api.patch("/api/v1/admin/config", body);
      const id = installationID();
      if (id) {
        await api.hostPut(`/api/v1/admin/plugins/installations/${id}/auth-binding`, {
          capability_id: "oidc",
          enabled: true,
          display_order: 100,
          auto_provision: true,
          default_login: false,
          display_name: settings.display_name.trim(),
          icon_url_path: settings.icon_url_path.trim(),
        });
      }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["config-summary"] });
      qc.invalidateQueries({ queryKey: ["config-summary-for-brand"] });
      toast.success("Saved");
      setSettings((s) => ({ ...s, client_secret: "" }));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  if (cfgQ.isLoading || !cfgQ.data) {
    return <Skeleton className="h-[600px] w-full" />;
  }

  const useAsFilter = (claim_path: string) =>
    setFilters((f) => [
      ...f,
      { claim_path, operator: "contains", value: "" },
    ]);
  const useAsRoleMapping = (claim_path: string) =>
    setMapping((m) => [
      ...m,
      { claim_path, operator: "contains", value: "", role: "admin" },
    ]);

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Settings</CardTitle>
        </CardHeader>
        <CardContent>
          <SettingsForm
            state={settings}
            setState={setSettings}
            availableIcons={cfgQ.data.available_icons}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Claim Filters</CardTitle>
        </CardHeader>
        <CardContent>
          <ClaimFilterEditor value={filters} onChange={setFilters} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Role Mapping</CardTitle>
        </CardHeader>
        <CardContent>
          <RoleMappingEditor value={mapping} onChange={setMapping} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Diagnostics</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <section className="space-y-2">
            <h3 className="text-sm font-medium">Decode id_token</h3>
            <p className="text-muted-foreground text-xs">
              Paste a real id_token to verify it against the live JWKS and
              browse its claims. Use the per-claim buttons to seed a filter
              or role-mapping rule.
            </p>
            <DiagnosticsPanel
              onUseAsFilter={useAsFilter}
              onUseAsRoleMapping={useAsRoleMapping}
              onClaimsDecoded={setDecodedClaims}
            />
          </section>
          <section className="space-y-2">
            <h3 className="text-sm font-medium">Simulate sign-in</h3>
            <ClaimSimulator
              filters={filters}
              roleMapping={mapping}
              emailVerifiedRequired={settings.email_verified_required}
              seedClaims={decodedClaims}
            />
          </section>
        </CardContent>
      </Card>

      <div className="flex justify-end">
        <Button onClick={() => save.mutate()} disabled={save.isPending}>
          Save
        </Button>
      </div>
    </div>
  );
}
