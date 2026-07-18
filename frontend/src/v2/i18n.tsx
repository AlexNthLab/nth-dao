/**
 * 轻量 i18n —— 中/英切换,零依赖。
 *
 * 设计:inline `t("中文","English")`。
 *   - lang=zh → 返回第一参(中文恒为全集、永不缺译);
 *   - lang=en → 返回第二参,缺省则回退中文(优雅降级,半铺开也不崩)。
 * 选择持久化到 localStorage(复用页签持久化同款套路),刷新不丢。
 *
 * 框架层(Topbar/IconNav/StatusBar)本就英文,翻译面集中在各 View 正文,
 * 按使用频次逐步铺开;未译处 en 模式回退中文,不影响功能。
 */
import {
  createContext, useCallback, useContext, useEffect, useState,
} from "react";
import type { ReactNode } from "react";

export type Lang = "zh" | "en";

/** 语言选择的 localStorage 键(每 origin 私有)。 */
const LANG_KEY = "nth.v2.lang";

/** 翻译函数:t(中文, 英文?)。en 缺译回退中文。 */
export type TFn = (zh: string, en?: string) => string;

interface LangContextValue {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: TFn;
}

const LangContext = createContext<LangContextValue | null>(null);

/** 从 localStorage 读回上次语言;无值/脏值/禁读一律降级中文。 */
function loadLang(): Lang {
  try {
    const v = localStorage.getItem(LANG_KEY);
    if (v === "zh" || v === "en") return v;
  } catch {
    /* Private browsing may block storage; retain the English default. */
  }
  return "en";
}

export function LangProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(loadLang);
  useEffect(() => {
    try {
      localStorage.setItem(LANG_KEY, lang);
    } catch {
      /* 配额满 / 隐私模式禁写 —— 静默降级,不影响切换本身 */
    }
  }, [lang]);

  const setLang = useCallback((l: Lang) => setLangState(l), []);
  const t = useCallback<TFn>(
    (zh, en) => (lang === "en" ? en ?? zh : zh),
    [lang],
  );

  return (
    <LangContext.Provider value={{ lang, setLang, t }}>
      {children}
    </LangContext.Provider>
  );
}

/** 取语言上下文。必须在 LangProvider 内调用。 */
export function useLang(): LangContextValue {
  const ctx = useContext(LangContext);
  if (!ctx) throw new Error("useLang must be used within LangProvider");
  return ctx;
}
