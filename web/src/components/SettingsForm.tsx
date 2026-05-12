import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import IconPicker from "./IconPicker";
import DiscoveryPanel from "./DiscoveryPanel";

export type SettingsState = {
  issuer_url: string;
  client_id: string;
  /** Only populated when the admin types into the password field. */
  client_secret: string;
  has_client_secret: boolean;
  scopes: string;
  display_name: string;
  icon_url_path: string;
  email_verified_required: boolean;
  link_by_email: boolean;
};

// SettingsForm renders the spec Layer 7.2 Settings section: the seven config
// inputs plus the IconPicker and the Test-discovery panel. State is owned by
// the parent (Admin page) so all sections can be saved in one PATCH.
export default function SettingsForm({
  state,
  setState,
  availableIcons,
}: {
  state: SettingsState;
  setState: (updater: (prev: SettingsState) => SettingsState) => void;
  availableIcons: string[];
}) {
  return (
    <div className="space-y-5">
      <div className="space-y-2">
        <Label>Issuer URL</Label>
        <Input
          value={state.issuer_url}
          onChange={(e) =>
            setState((s) => ({ ...s, issuer_url: e.target.value }))
          }
          placeholder="https://auth.example.com"
        />
        <DiscoveryPanel />
      </div>
      <div className="space-y-2">
        <Label>Client ID</Label>
        <Input
          value={state.client_id}
          onChange={(e) =>
            setState((s) => ({ ...s, client_id: e.target.value }))
          }
        />
      </div>
      <div className="space-y-2">
        <Label>Client secret</Label>
        <Input
          type="password"
          value={state.client_secret}
          placeholder={state.has_client_secret ? "(unchanged)" : "enter secret"}
          onChange={(e) =>
            setState((s) => ({ ...s, client_secret: e.target.value }))
          }
        />
      </div>
      <div className="space-y-2">
        <Label>Scopes</Label>
        <Input
          value={state.scopes}
          onChange={(e) => setState((s) => ({ ...s, scopes: e.target.value }))}
          placeholder="openid profile email"
        />
      </div>
      <div className="space-y-2">
        <Label>Display name (login button label)</Label>
        <Input
          value={state.display_name}
          onChange={(e) =>
            setState((s) => ({ ...s, display_name: e.target.value }))
          }
        />
      </div>
      <div className="space-y-2">
        <Label>Icon</Label>
        <IconPicker
          available={availableIcons}
          value={state.icon_url_path}
          onChange={(v) => setState((s) => ({ ...s, icon_url_path: v }))}
        />
      </div>
      <div className="space-y-2">
        <label className="flex items-center gap-2">
          <Checkbox
            checked={state.email_verified_required}
            onCheckedChange={(v) =>
              setState((s) => ({ ...s, email_verified_required: !!v }))
            }
          />
          <span>Require verified email</span>
        </label>
        <label className="flex items-center gap-2">
          <Checkbox
            checked={state.link_by_email}
            onCheckedChange={(v) =>
              setState((s) => ({ ...s, link_by_email: !!v }))
            }
          />
          <span>
            Auto-link to existing user by email (less safe — only enable if
            you trust the IdP)
          </span>
        </label>
      </div>
    </div>
  );
}
