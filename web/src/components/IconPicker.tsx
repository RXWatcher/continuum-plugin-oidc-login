import { cn } from "@/lib/utils";
import { mountPath } from "@/lib/api";

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
  return (
    <div className="grid grid-cols-4 gap-3 sm:grid-cols-8">
      {available.map((name) => {
        const isSelected = name === value;
        const url = mountPath() + "/assets/" + name;
        return (
          <button
            key={name}
            data-testid={`icon-${name}`}
            type="button"
            onClick={() => onChange(name)}
            className={cn(
              "hover:bg-surface-hover flex flex-col items-center gap-1 rounded-md border p-2 text-xs transition-colors",
              isSelected ? "border-primary bg-surface" : "border-border/70",
            )}
          >
            <img src={url} alt="" className="size-8" />
            <span className="text-muted-foreground w-full truncate text-center">
              {name.replace(".svg", "")}
            </span>
          </button>
        );
      })}
    </div>
  );
}
