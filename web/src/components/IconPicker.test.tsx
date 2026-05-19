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

  it("shows the selected icon in a larger preview", () => {
    render(
      <IconPicker
        available={["authentik.svg", "keycloak.svg"]}
        value="keycloak.svg"
        onChange={() => {}}
      />,
    );

    expect(screen.getByAltText("Selected icon preview").getAttribute("src")).toBe(
      "/assets/keycloak.svg",
    );
  });

  it("renders icon artwork on white preview tiles", () => {
    render(
      <IconPicker
        available={["authentik.svg"]}
        value="authentik.svg"
        onChange={() => {}}
      />,
    );

    expect(screen.getByTestId("selected-icon-tile").className).toContain("bg-white");
    expect(screen.getByTestId("icon-artwork-authentik.svg").className).toContain("bg-white");
  });

  it("allows a custom icon URL or path", () => {
    let picked = "";
    render(
      <IconPicker
        available={["authentik.svg"]}
        value="authentik.svg"
        onChange={(v) => {
          picked = v;
        }}
      />,
    );

    fireEvent.change(screen.getByLabelText("Custom icon URL or path"), {
      target: { value: "https://example.com/icon.svg" },
    });

    expect(picked).toBe("https://example.com/icon.svg");
  });
});
