import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import IconPicker from "./IconPicker";

describe("IconPicker", () => {
  it("renders all available icons", () => {
    render(
      <IconPicker
        available={["authentik.svg", "keycloak.svg"]}
        value="authentik.svg"
        onChange={() => {}}
      />,
    );
    expect(screen.getByTestId("icon-authentik.svg")).toBeDefined();
    expect(screen.getByTestId("icon-keycloak.svg")).toBeDefined();
  });

  it("calls onChange when an icon is clicked", () => {
    let picked = "";
    render(
      <IconPicker
        available={["authentik.svg", "keycloak.svg"]}
        value="authentik.svg"
        onChange={(v) => {
          picked = v;
        }}
      />,
    );
    fireEvent.click(screen.getByTestId("icon-keycloak.svg"));
    expect(picked).toBe("keycloak.svg");
  });

  it("marks the selected icon visually", () => {
    render(
      <IconPicker
        available={["authentik.svg", "keycloak.svg"]}
        value="keycloak.svg"
        onChange={() => {}}
      />,
    );
    const selected = screen.getByTestId("icon-keycloak.svg");
    expect(selected.className).toMatch(/border-primary/);
  });
});
