import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Plus, X } from "lucide-react";

export type Operator = "equals" | "contains" | "starts_with" | "regex";

export type ClaimFilter = {
  claim_path: string;
  operator: Operator;
  value: unknown;
};

// ClaimFilterEditor renders the claim_filters array as a small table editor:
// one row per filter, columns Claim path / Operator / Value / Delete.
// The Value column special-cases email_verified to a Yes/No select that
// emits a real boolean (the gate evaluates equals on the JSON-typed value).
export default function ClaimFilterEditor({
  value,
  onChange,
}: {
  value: ClaimFilter[];
  onChange: (v: ClaimFilter[]) => void;
}) {
  const update = (idx: number, patch: Partial<ClaimFilter>) => {
    const next = value.map((row, i) => (i === idx ? { ...row, ...patch } : row));
    onChange(next);
  };
  const add = () =>
    onChange([...value, { claim_path: "", operator: "equals", value: "" }]);
  const del = (idx: number) => onChange(value.filter((_, i) => i !== idx));

  return (
    <div className="space-y-2">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-muted-foreground border-b text-left">
            <th className="py-1 pr-2">Claim path</th>
            <th className="w-32 py-1 pr-2">Operator</th>
            <th className="py-1 pr-2">Value</th>
            <th className="w-8 py-1"></th>
          </tr>
        </thead>
        <tbody>
          {value.map((row, i) => (
            <tr key={i}>
              <td className="py-1 pr-2">
                <Input
                  value={row.claim_path}
                  onChange={(e) => update(i, { claim_path: e.target.value })}
                  className="font-mono"
                />
              </td>
              <td className="py-1 pr-2">
                <select
                  className="bg-background border-input h-9 w-full rounded-md border px-2"
                  value={row.operator}
                  onChange={(e) =>
                    update(i, { operator: e.target.value as Operator })
                  }
                >
                  <option value="equals">equals</option>
                  <option value="contains">contains</option>
                  <option value="starts_with">starts with</option>
                  <option value="regex">regex</option>
                </select>
              </td>
              <td className="py-1 pr-2">
                {row.claim_path === "email_verified" ? (
                  <select
                    className="bg-background border-input h-9 w-full rounded-md border px-2"
                    value={String(row.value)}
                    onChange={(e) =>
                      update(i, { value: e.target.value === "true" })
                    }
                  >
                    <option value="true">true</option>
                    <option value="false">false</option>
                  </select>
                ) : (
                  <Input
                    value={String(row.value ?? "")}
                    onChange={(e) => update(i, { value: e.target.value })}
                  />
                )}
              </td>
              <td className="py-1">
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label="Delete row"
                  onClick={() => del(i)}
                >
                  <X className="size-4" />
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <Button variant="outline" size="sm" onClick={add}>
        <Plus className="mr-1 size-4" /> Add filter
      </Button>
      <p className="text-muted-foreground text-xs">
        All filters must pass for a user to sign in. Empty list = no gating.
      </p>
    </div>
  );
}
