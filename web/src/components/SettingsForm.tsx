import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import IconPicker from "./IconPicker";
import DiscoveryPanel from "./DiscoveryPanel";
import { Button } from "@/components/ui/button";
import { copyText } from "@/lib/copyText";
import { currentOAuthCallbackUrl } from "@/lib/oauthCallbackUrl";
import { toast } from "sonner";
import { AlertTriangle } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

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
  const callbackUrl = currentOAuthCallbackUrl();
  const copyCallbackUrl = async () => {
    if (await copyText(callbackUrl)) {
      toast.success("Callback URL copied");
    } else {
      toast.error("Copy failed. Select the URL and copy it manually.");
    }
  };
  const [confirmLinkOpen, setConfirmLinkOpen] = useState(false);
  // Toggle handler for link_by_email. Disabling is unconditional; enabling
  // pops a confirmation modal so the security implication is explicit.
  const toggleLinkByEmail = (next: boolean) => {
    if (!next) {
      setState((s) => ({ ...s, link_by_email: false }));
      return;
    }
    setConfirmLinkOpen(true);
  };
  const confirmEnableLink = () => {
    setState((s) => ({ ...s, link_by_email: true }));
    setConfirmLinkOpen(false);
  };

  return (
    <div className="space-y-5">
      <div className="space-y-2">
        <Label>Callback URL</Label>
        <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto]">
          <Input readOnly value={callbackUrl} />
          <Button type="button" variant="outline" onClick={copyCallbackUrl}>
            Copy
          </Button>
        </div>
        <p className="text-muted-foreground text-xs">
          Paste this as the redirect or callback URL in your OIDC client.
        </p>
      </div>
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
            onCheckedChange={(v) => toggleLinkByEmail(!!v)}
          />
          <span>Auto-link to existing user by email</span>
        </label>
        {state.link_by_email && (
          <div className="border-destructive/30 bg-destructive/10 text-destructive flex gap-2 rounded-md border p-3 text-xs">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <div className="space-y-1">
              <div className="font-medium">Account-linking enabled</div>
              <p>
                Silo will merge a sign-in into an existing local account
                whenever the IdP's <span className="font-mono">email</span>{" "}
                claim matches. If the IdP doesn't strictly verify email
                addresses, anyone able to claim a Silo user's email at
                the IdP can take over that account. Only keep this on when you
                trust the IdP to enforce email ownership.
              </p>
            </div>
          </div>
        )}
      </div>

      <Dialog open={confirmLinkOpen} onOpenChange={setConfirmLinkOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="text-destructive size-5" />
              Enable account-linking by email?
            </DialogTitle>
            <DialogDescription>
              When enabled, a sign-in is merged into an existing Silo
              account whenever the IdP's email matches. If the IdP doesn't
              strictly verify email addresses, an attacker who controls the
              matching email at the IdP can take over that account.
            </DialogDescription>
          </DialogHeader>
          <ul className="text-muted-foreground list-disc pl-5 text-sm">
            <li>Only enable for IdPs that verify email ownership.</li>
            <li>
              Keep <span className="font-mono">Require verified email</span>{" "}
              checked above unless you understand the trade-off.
            </li>
            <li>
              Disable this if you don't need the existing-account merge
              behavior.
            </li>
          </ul>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setConfirmLinkOpen(false)}
            >
              Cancel
            </Button>
            <Button variant="destructive" onClick={confirmEnableLink}>
              Enable anyway
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
