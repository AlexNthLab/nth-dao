// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { LangProvider, useLang } from "../i18n";

afterEach(cleanup);
beforeEach(() => localStorage.clear());

function Probe() {
  const { lang, setLang, t } = useLang();
  return (
    <div>
      <span data-testid="out">{t("发布", "Publish")}</span>
      <span data-testid="fallback">{t("仅中文")}</span>
      <span data-testid="lang">{lang}</span>
      <button onClick={() => setLang("en")}>en</button>
      <button onClick={() => setLang("zh")}>zh</button>
    </div>
  );
}

describe("i18n", () => {
  it("defaults to English", () => {
    render(<LangProvider><Probe /></LangProvider>);
    expect(screen.getByTestId("lang").textContent).toBe("en");
    expect(screen.getByTestId("out").textContent).toBe("Publish");
  });

  it("uses English by default and falls back when a translation is missing", () => {
    render(<LangProvider><Probe /></LangProvider>);
    expect(screen.getByTestId("out").textContent).toBe("Publish");
    // A missing English value falls back to the source text, never blank.
    expect(screen.getByTestId("fallback").textContent).toBe("仅中文");
  });

  it("persists an explicit language selection across remounts", () => {
    const first = render(<LangProvider><Probe /></LangProvider>);
    fireEvent.click(screen.getByRole("button", { name: "zh" }));
    expect(localStorage.getItem("nth.v2.lang")).toBe("zh");
    first.unmount();
    render(<LangProvider><Probe /></LangProvider>);
    expect(screen.getByTestId("lang").textContent).toBe("zh");
  });
});
