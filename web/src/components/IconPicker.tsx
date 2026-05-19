import { cn } from "@/lib/utils";
import { mountPath } from "@/lib/api";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

// IconPicker renders the bundled icon SVGs as a selectable grid. The admin
// picks one; the selected filename becomes the icon_url_path config value.
// Selected card has a primary-coloured border.
export default function IconPicker({
  available,
  value,
  onChange,
}: {
  available: string[];
  value: string;
  onChange: (v: string) => void;
}) {
  const selectedURL = iconURL(value);
  const customValue = available.includes(value) ? "" : value;

  return (
    <div className="space-y-4">
      <div className="border-border/70 bg-surface flex items-center gap-3 rounded-md border p-3">
        <span
          data-testid="selected-icon-tile"
          className="grid size-16 shrink-0 place-items-center rounded-md border border-slate-200 bg-white"
        >
          <img src={selectedURL} alt="Selected icon preview" className="max-h-12 max-w-12" />
        </span>
        <div className="min-w-0">
          <div className="text-sm font-medium">Selected icon</div>
          <div className="text-muted-foreground truncate text-xs">{value || "No icon selected"}</div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-3 sm:grid-cols-4 lg:grid-cols-6">
        {available.map((name) => {
          const isSelected = name === value;
          const url = iconURL(name);
          return (
            <button
              key={name}
              data-testid={`icon-${name}`}
              type="button"
              onClick={() => onChange(name)}
              className={cn(
                "hover:bg-surface-hover flex min-h-28 flex-col items-center justify-center gap-2 rounded-md border p-3 text-xs transition-colors",
                isSelected ? "border-primary bg-primary/10 ring-primary/30 ring-2" : "border-border/70 bg-background",
              )}
            >
              <span
                data-testid={`icon-artwork-${name}`}
                className="grid size-14 place-items-center rounded-md border border-slate-200 bg-white"
              >
                <img src={url} alt="" className="max-h-10 max-w-10" />
              </span>
              <span className="text-muted-foreground w-full truncate text-center">
                {name.replace(".svg", "")}
              </span>
            </button>
          );
        })}
      </div>

      <div className="space-y-2">
        <Label htmlFor="custom-icon-url">Custom icon URL or path</Label>
        <Input
          id="custom-icon-url"
          value={customValue}
          onChange={(e) => onChange(e.target.value)}
          placeholder="https://example.com/icon.svg or /assets/custom.svg"
        />
        <p className="text-muted-foreground text-xs">
          Use a hosted HTTPS icon or a root-relative path served by Continuum.
        </p>
      </div>
    </div>
  );
}

function iconURL(value: string): string {
  if (!value) return "";
  if (/^https?:\/\//i.test(value) || value.startsWith("/")) return value;
  return mountPath() + "/assets/" + value;
}
