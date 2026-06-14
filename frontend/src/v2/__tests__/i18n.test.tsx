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
  it("默认中文,t() 返回中文参", () => {
    render(<LangProvider><Probe /></LangProvider>);
    expect(screen.getByTestId("lang").textContent).toBe("zh");
    expect(screen.getByTestId("out").textContent).toBe("发布");
  });

  it("切到 en 后 t() 返回英文参,缺译回退中文", () => {
    render(<LangProvider><Probe /></LangProvider>);
    fireEvent.click(screen.getByText("en"));
    expect(screen.getByTestId("out").textContent).toBe("Publish");
    // 没给英文 → 回退中文,不显示空。
    expect(screen.getByTestId("fallback").textContent).toBe("仅中文");
  });

  it("选择持久化到 localStorage,重挂载后恢复", () => {
    const first = render(<LangProvider><Probe /></LangProvider>);
    fireEvent.click(screen.getByText("en"));
    expect(localStorage.getItem("nth.v2.lang")).toBe("en");
    first.unmount();
    render(<LangProvider><Probe /></LangProvider>);
    expect(screen.getByTestId("lang").textContent).toBe("en");
  });
});
