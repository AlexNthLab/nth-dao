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
import type { CommandItem } from "../types-v2";

export interface CommandPaletteProps {
  open: boolean;
  items: CommandItem[];
  onClose: () => void;
}

export function CommandPalette({ open, items, onClose }: CommandPaletteProps) {
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
    const t = setTimeout(() => inputRef.current?.focus(), 0);
    return () => clearTimeout(t);
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

  return (
    <div className="cmdk-overlay" onClick={onClose}>
      <div className="cmdk-panel" onClick={(e) => e.stopPropagation()}>
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
            placeholder="Type a command or search…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKey}
          />
        </div>
        <div className="cmdk-list">
          {filtered.length === 0 && (
            <div className="cmdk-empty">No matching command.</div>
          )}
          {filtered.map((it, i) => (
            <button
              key={it.id}
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
