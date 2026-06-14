/**
 * Topbar — brand, identity slug, Cmd+K trigger.
 *
 * 48px tall, single row. The identity slug is the user's stable
 * anchor across the whole UI ("this is you signing"). The Cmd+K
 * hint stays visible always so the keyboard contract is taught
 * passively.
 */

import { BrandLogo } from "./BrandLogo";
import { BrandMark } from "./BrandMark";
import type { IdentityHeader } from "../types-v2";
import { useLang } from "../i18n";

export interface TopbarProps {
  identity: IdentityHeader | null;
  onCmdK: () => void;
}

export function Topbar({ identity, onCmdK }: TopbarProps) {
  const { lang, setLang, t } = useLang();
  return (
    <header className="topbar">
      <div className="topbar-brand">
        <BrandLogo size={24} className="topbar-logo-mark" />
        <BrandMark />
      </div>

      {identity && (
        <div className="topbar-identity" title={identity.did}>
          <strong>{identity.agent_id}</strong>
          <code>{identity.code}</code>
        </div>
      )}

      <div className="topbar-spacer" />

      {/* 语言切换:中 / EN,持久化在 localStorage,刷新不丢 */}
      <div
        className="lang-toggle"
        role="group"
        aria-label={t("语言", "Language")}
      >
        <button
          type="button"
          className={`lang-toggle-btn ${lang === "zh" ? "active" : ""}`}
          aria-pressed={lang === "zh"}
          onClick={() => setLang("zh")}
        >
          中
        </button>
        <button
          type="button"
          className={`lang-toggle-btn ${lang === "en" ? "active" : ""}`}
          aria-pressed={lang === "en"}
          onClick={() => setLang("en")}
        >
          EN
        </button>
      </div>

      <button type="button" className="cmdk-trigger" onClick={onCmdK}>
        <span>{t("搜索或命令", "Search or command")}</span>
        <kbd>⌘K</kbd>
      </button>
    </header>
  );
}
