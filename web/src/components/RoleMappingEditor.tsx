import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Plus, X } from "lucide-react";
import type { Operator } from "./ClaimFilterEditor";

export type Role = "user" | "admin";

export type RoleMappingRule = {
  claim_path: string;
  operator: Operator;
  value: unknown;
  role: Role;
};

// RoleMappingEditor adds a Role column to the ClaimFilterEditor shape.
// Rules are evaluated by continuum host (and exported ResolveRole in the
// claims package) in order, with the first match winning. Default: user.
export default function RoleMappingEditor({
  value,
  onChange,
}: {
  value: RoleMappingRule[];
  onChange: (v: RoleMappingRule[]) => void;
}) {
  const update = (idx: number, patch: Partial<RoleMappingRule>) => {
    onChange(value.map((row, i) => (i === idx ? { ...row, ...patch } : row)));
  };
  const add = () =>
    onChange([
      ...value,
      { claim_path: "", operator: "contains", value: "", role: "admin" },
    ]);
  const del = (idx: number) => onChange(value.filter((_, i) => i !== idx));

  return (
    <div className="space-y-2">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-muted-foreground border-b text-left">
            <th className="py-1 pr-2">Claim path</th>
            <th className="w-32 py-1 pr-2">Operator</th>
            <th className="py-1 pr-2">Value</th>
            <th className="w-24 py-1 pr-2">Role</th>
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
                <Input
                  value={String(row.value ?? "")}
                  onChange={(e) => update(i, { value: e.target.value })}
                />
              </td>
              <td className="py-1 pr-2">
                <select
                  className="bg-background border-input h-9 w-full rounded-md border px-2"
                  value={row.role}
                  onChange={(e) =>
                    update(i, { role: e.target.value as Role })
                  }
                >
                  <option value="user">user</option>
                  <option value="admin">admin</option>
                </select>
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
        <Plus className="mr-1 size-4" /> Add rule
      </Button>
      <p className="text-muted-foreground text-xs">
        First matching rule wins. Default role: user.
      </p>
    </div>
  );
}
