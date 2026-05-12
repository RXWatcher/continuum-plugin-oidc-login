import { useEffect, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { api, patchPluginConfig } from "@/lib/api";
import { installID } from "@/lib/identity";
import SettingsForm, { type SettingsState } from "@/components/SettingsForm";
import ClaimFilterEditor, {
  type ClaimFilter,
} from "@/components/ClaimFilterEditor";
import RoleMappingEditor, {
  type RoleMappingRule,
} from "@/components/RoleMappingEditor";
import DiagnosticsPanel from "@/components/DiagnosticsPanel";

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
// controlled inputs. Save PATCHes continuum's host config endpoint with
// every key — the host writes them back into plugin_installation_config and
// pushes a Configure RPC at the plugin, which rebuilds the OIDC provider.
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
      const entries: Record<string, { value: unknown }> = {
        issuer_url: { value: settings.issuer_url },
        client_id: { value: settings.client_id },
        scopes: { value: settings.scopes },
        display_name: { value: settings.display_name },
        icon_url_path: { value: settings.icon_url_path },
        email_verified_required: { value: settings.email_verified_required },
        link_by_email: { value: settings.link_by_email },
        claim_filters: { value: filters },
        claim_role_mapping: { value: mapping },
      };
      if (settings.client_secret) {
        entries.client_secret = { value: settings.client_secret };
      }
      await patchPluginConfig(installID(), entries);
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

      <details className="bg-card border-border/70 rounded-md border p-4">
        <summary className="cursor-pointer text-sm font-medium">
          Diagnostics
        </summary>
        <div className="mt-3">
          <DiagnosticsPanel
            onUseAsFilter={useAsFilter}
            onUseAsRoleMapping={useAsRoleMapping}
          />
        </div>
      </details>

      <div className="flex justify-end">
        <Button onClick={() => save.mutate()} disabled={save.isPending}>
          Save
        </Button>
      </div>
    </div>
  );
}
