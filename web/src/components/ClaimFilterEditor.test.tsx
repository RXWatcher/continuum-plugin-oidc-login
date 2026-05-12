import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import ClaimFilterEditor, { type ClaimFilter } from "./ClaimFilterEditor";

describe("ClaimFilterEditor", () => {
  it("adds a new filter row when Add filter is clicked", () => {
    let curr: ClaimFilter[] = [];
    render(
      <ClaimFilterEditor
        value={curr}
        onChange={(v) => {
          curr = v;
        }}
      />,
    );
    fireEvent.click(screen.getByText("Add filter"));
    expect(curr).toHaveLength(1);
    expect(curr[0]).toEqual({ claim_path: "", operator: "equals", value: "" });
  });

  it("deletes a row when the trash button is clicked", () => {
    let curr: ClaimFilter[] = [
      { claim_path: "groups", operator: "contains", value: "a" },
    ];
    render(
      <ClaimFilterEditor
        value={curr}
        onChange={(v) => {
          curr = v;
        }}
      />,
    );
    fireEvent.click(screen.getByLabelText(/Delete row/i));
    expect(curr).toHaveLength(0);
  });

  it("updates a row on input change", () => {
    let curr: ClaimFilter[] = [
      { claim_path: "g", operator: "equals", value: "x" },
    ];
    render(
      <ClaimFilterEditor
        value={curr}
        onChange={(v) => {
          curr = v;
        }}
      />,
    );
    fireEvent.change(screen.getByDisplayValue("g"), {
      target: { value: "groups" },
    });
    expect(curr[0].claim_path).toBe("groups");
  });

  it("renders a yes/no select when claim_path is email_verified", () => {
    let curr: ClaimFilter[] = [
      { claim_path: "email_verified", operator: "equals", value: true },
    ];
    render(
      <ClaimFilterEditor
        value={curr}
        onChange={(v) => {
          curr = v;
        }}
      />,
    );
    expect(screen.getByRole("option", { name: "true" })).toBeDefined();
    expect(screen.getByRole("option", { name: "false" })).toBeDefined();
  });
});
