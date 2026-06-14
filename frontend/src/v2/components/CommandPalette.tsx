/**
 * Cmd+K command palette.
 *
 * Single-tier list (no groups in v1 — flat is faster to scan when
 * the keyboard contract is the main thing). Substring match on
 * lower-cased title; arrow keys to navigate; Enter to run; Esc to
 * close. The palette traps focus while open.
 *
 * Why no fuzzy match: substring + smart ordering of commands
 * (recent / frequent first) outperforms naive fuzzy in keyboard-
 * heavy workflows. We can add fuzzy when the command list exceeds
 * ~30.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { IconSearch } from "./Icons";
import { useLang } from "../i18n";
import type { CommandItem } from "../types-v2";

export interface CommandPaletteProps {
  open: boolean;
  items: CommandItem[];
  onClose: () => void;
}

export function CommandPalette({ open, items, onClose }: CommandPaletteProps) {
  const { t } = useLang();
  const [query, setQuery] = useState("");
  const [highlight, setHighlight] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter(
      (it) =>
        it.title.toLowerCase().includes(q) ||
        (it.hint || "").toLowerCase().includes(q),
    );
  }, [query, items]);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setHighlight(0);
    // Defer focus to next tick so the input mounts first.
    const focusTimer = setTimeout(() => inputRef.current?.focus(), 0);
    return () => clearTimeout(focusTimer);
  }, [open]);

  useEffect(() => {
    setHighlight(0);
  }, [query]);

  if (!open) return null;

  function handleKey(e: React.KeyboardEvent) {
    if (e.key === "Escape") {
      e.preventDefault();
      onClose();
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setHighlight((h) => Math.min(h + 1, filtered.length - 1));
      return;
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      setHighlight((h) => Math.max(h - 1, 0));
      return;
    }
    if (e.key === "Enter") {
      e.preventDefault();
      const item = filtered[highlight];
      if (item) {
        void item.run();
        onClose();
      }
    }
  }

  /* Focus trap (audit review#2, 2026-06-10): the input element is
   * the only natural tab stop inside the palette, so Tab from the
   * input lets focus escape to the page behind the overlay. ARIA
   * aria-modal="true" requires the implementation to confine
   * focus. We trap by intercepting Tab at the panel level and
   * routing it back to the input — single tab stop = simplest
   * possible trap. */
  function handleTrapTab(e: React.KeyboardEvent) {
    if (e.key !== "Tab") return;
    e.preventDefault();
    inputRef.current?.focus();
  }

  /* A11y wiring (audit fix 2026-06-10, finding C2 a11y batch
   *   + review#N1 self-rebound 2026-06-10):
   *   - role="dialog" + aria-modal="true" announces the modal
   *   - The result list is a listbox; each item has role="option"
   *     and aria-selected on the highlighted row, so arrow-key
   *     navigation reads the focused command aloud
   *   - Critical (N1): the overlay div MUST NOT carry
   *     aria-hidden="true". aria-hidden propagates to ALL
   *     descendants per ARIA spec, which would have masked the
   *     dialog, listbox, and every option underneath — making
   *     the entire palette invisible to screen readers. The
   *     overlay's only purpose is the click-to-dismiss target;
   *     it doesn't need to opt out of accessibility because the
   *     <div> isn't focusable to begin with.
   */
  return (
    <div
      className="cmdk-overlay"
      onClick={onClose}
    >
      <div
        className="cmdk-panel"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleTrapTab}
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        tabIndex={-1}
      >
        <div style={{ position: "relative" }}>
          <div
            style={{
              position: "absolute",
              left: 16,
              top: "50%",
              transform: "translateY(-50%)",
              color: "var(--fg-tertiary)",
              pointerEvents: "none",
            }}
          >
            <IconSearch size={14} />
          </div>
          <input
            ref={inputRef}
            className="cmdk-input"
            style={{ paddingLeft: 40 }}
            placeholder={t("输入命令或搜索…", "Type a command or search…")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKey}
            role="combobox"
            aria-expanded="true"
            aria-controls="cmdk-results"
            aria-autocomplete="list"
            aria-activedescendant={
              filtered[highlight]
                ? `cmdk-item-${filtered[highlight].id}`
                : undefined
            }
          />
        </div>
        <div
          id="cmdk-results"
          className="cmdk-list"
          role="listbox"
          aria-label="Matching commands"
        >
          {filtered.length === 0 && (
            <div className="cmdk-empty">{t("没有匹配的命令。", "No matching command.")}</div>
          )}
          {filtered.map((it, i) => (
            <button
              key={it.id}
              id={`cmdk-item-${it.id}`}
              role="option"
              aria-selected={i === highlight}
              className={`cmdk-item ${i === highlight ? "active" : ""}`}
              onMouseEnter={() => setHighlight(i)}
              onClick={() => {
                void it.run();
                onClose();
              }}
            >
              <span>{it.title}</span>
              {it.hint && (
                <span style={{ color: "var(--fg-tertiary)", marginLeft: 8 }}>
                  {it.hint}
                </span>
              )}
              {it.shortcut && (
                <span className="cmdk-item-shortcut">{it.shortcut}</span>
              )}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
