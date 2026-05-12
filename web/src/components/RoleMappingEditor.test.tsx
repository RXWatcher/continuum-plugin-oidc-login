import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import RoleMappingEditor, { type RoleMappingRule } from "./RoleMappingEditor";

describe("RoleMappingEditor", () => {
  it("adds a new rule defaulting to role=admin", () => {
    let curr: RoleMappingRule[] = [];
    render(
      <RoleMappingEditor
        value={curr}
        onChange={(v) => {
          curr = v;
        }}
      />,
    );
    fireEvent.click(screen.getByText("Add rule"));
    expect(curr).toHaveLength(1);
    expect(curr[0].role).toBe("admin");
    expect(curr[0].operator).toBe("contains");
  });

  it("deletes a row", () => {
    let curr: RoleMappingRule[] = [
      { claim_path: "g", operator: "contains", value: "x", role: "admin" },
    ];
    render(
      <RoleMappingEditor
        value={curr}
        onChange={(v) => {
          curr = v;
        }}
      />,
    );
    fireEvent.click(screen.getByLabelText(/Delete row/i));
    expect(curr).toHaveLength(0);
  });

  it("changes role via the role select", () => {
    let curr: RoleMappingRule[] = [
      { claim_path: "g", operator: "contains", value: "x", role: "admin" },
    ];
    render(
      <RoleMappingEditor
        value={curr}
        onChange={(v) => {
          curr = v;
        }}
      />,
    );
    const sel = screen.getByDisplayValue("admin");
    fireEvent.change(sel, { target: { value: "user" } });
    expect(curr[0].role).toBe("user");
  });
});
