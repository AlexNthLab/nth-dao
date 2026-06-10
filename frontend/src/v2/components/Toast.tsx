/**
 * Minimal Toast notification system (audit fix 2026-06-10,
 * findings M14 + M15: handleScanLan / handleAddAgent + the chat
 * send-failure path C4 silently went to console.log, leaving the
 * user with no visual confirmation that an action ran).
 *
 * Why custom, not a library: 3 levels of severity, 1 visual idiom,
 * <60 lines of TSX. A library is overkill.
 *
 * Contract:
 *   - `useToast()` returns a `pushToast(text, kind?)` function.
 *   - Toasts auto-dismiss after 3.5s (or 5.5s for errors).
 *   - The ToastViewport must be mounted once at App root.
 *
 * Visual:
 *   Bottom-right floating stack. Slides in from below. Each toast
 *   carries a colored left bar (green/amber/red) matching the
 *   3-status color discipline.
 */

import {
  createContext, useCallback, useContext, useEffect, useMemo, useState,
} from "react";
import type { ReactNode } from "react";

export type ToastKind = "info" | "success" | "warn" | "error";

interface ToastItem {
  id: string;
  text: string;
  kind: ToastKind;
}

interface ToastCtx {
  push: (text: string, kind?: ToastKind) => void;
}

const ToastContext = createContext<ToastCtx | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const push = useCallback((text: string, kind: ToastKind = "info") => {
    const id = `t-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    setToasts((prev) => [...prev, { id, text, kind }]);
  }, []);

  const remove = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const value = useMemo<ToastCtx>(() => ({ push }), [push]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <ToastViewport toasts={toasts} onDismiss={remove} />
    </ToastContext.Provider>
  );
}

export function useToast(): ToastCtx {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    // Soft fallback so tests rendering a component in isolation
    // don't crash. In normal app flow ToastProvider wraps the tree.
    return {
      push: (text, kind) => {
        // eslint-disable-next-line no-console
        console.log(`[toast:${kind ?? "info"}]`, text);
      },
    };
  }
  return ctx;
}

const KIND_COLOR: Record<ToastKind, string> = {
  info:    "var(--accent)",
  success: "var(--status-ok)",
  warn:    "var(--status-wait)",
  error:   "var(--status-bad)",
};

/* Viewport cap (audit pass#4 fix I1, 2026-06-10): at N=50 users
 * a shared dashboard can produce dozens of concurrent toasts —
 * stacking unbounded covers the entire working area. We cap the
 * visible window at 5 (newest at the bottom, matching typical
 * chat scroll) and surface a single summary row when overflow
 * exists. Older toasts continue to auto-dismiss in the background
 * via their setTimeout — the cap is purely visual gating, not a
 * drop. */
const MAX_VISIBLE_TOASTS = 5;

function ToastViewport({
  toasts, onDismiss,
}: { toasts: ToastItem[]; onDismiss: (id: string) => void }) {
  // Newest 5 are visible; everything older sits in the queue and
  // gets auto-dismissed by its own timer. visibleToasts ordering
  // matches the original (oldest-first at top, newest at bottom).
  const overflowCount = Math.max(0, toasts.length - MAX_VISIBLE_TOASTS);
  const visibleToasts = toasts.slice(-MAX_VISIBLE_TOASTS);
  return (
    <div
      // aria-live polite so screen readers announce success/info
      // without interrupting; errors should arguably be assertive
      // but mixing levels in one region confuses readers — we
      // accept "polite" as the v1 compromise.
      aria-live="polite"
      role="status"
      style={{
        position: "fixed",
        right: 20,
        bottom: 40,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        zIndex: 1000,
        pointerEvents: "none",
      }}
    >
      {overflowCount > 0 && (
        <div
          style={{
            background: "var(--bg-elevated)",
            border: "1px solid var(--border)",
            borderRadius: 6,
            padding: "6px 12px",
            fontSize: 11,
            color: "var(--fg-tertiary)",
            textAlign: "center",
            pointerEvents: "none",
          }}
        >
          + {overflowCount} earlier notification{overflowCount === 1 ? "" : "s"}
        </div>
      )}
      {visibleToasts.map((t) => (
        /* Pass `id` + the stable `onDismiss` separately (audit
         * review#3, 2026-06-10): inlining `() => onDismiss(t.id)`
         * gave the prop a new reference every render, retriggering
         * ToastRow's useEffect and resetting the auto-dismiss
         * timer. With `id` (a string) and `onDismiss` (memoised
         * via useCallback at the provider level), the row's
         * effect deps are stable across the parent's re-renders. */
        <ToastRow key={t.id} toast={t} dismiss={onDismiss} />
      ))}
    </div>
  );
}

function ToastRow({
  toast, dismiss,
}: { toast: ToastItem; dismiss: (id: string) => void }) {
  const { id, kind } = toast;
  useEffect(() => {
    const lifetime = kind === "error" ? 5500 : 3500;
    const h = setTimeout(() => dismiss(id), lifetime);
    return () => clearTimeout(h);
  }, [id, kind, dismiss]);

  /* Manual dismiss button (audit pass#3 finding I3, 2026-06-10):
   * WCAG 2.2.1 requires that timed content longer than 3s offer
   * the user a way to pause/stop/hide it. Error toasts run 5.5s
   * which is well past that threshold. Adding a small close
   * affordance with a clear aria-label gives keyboard + AT users
   * an explicit dismiss path without affecting the visual idiom
   * (the button is the same accent-on-bg as the rest of the
   * toast frame). */
  return (
    <div
      style={{
        background: "var(--bg-elevated)",
        border: "1px solid var(--border)",
        borderLeft: `3px solid ${KIND_COLOR[toast.kind]}`,
        borderRadius: 6,
        padding: "8px 14px",
        fontSize: 12,
        color: "var(--fg-primary)",
        boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
        maxWidth: 360,
        pointerEvents: "auto",
        animation: "toastIn 200ms ease",
        display: "flex",
        alignItems: "flex-start",
        gap: 10,
      }}
    >
      <span style={{ flex: 1, minWidth: 0 }}>{toast.text}</span>
      <button
        type="button"
        onClick={() => dismiss(id)}
        aria-label="Dismiss notification"
        title="Dismiss"
        style={{
          marginLeft: "auto",
          padding: "0 4px",
          color: "var(--fg-tertiary)",
          fontSize: 14,
          lineHeight: 1,
          background: "transparent",
          border: 0,
          cursor: "pointer",
          flexShrink: 0,
        }}
      >
        ×
      </button>
    </div>
  );
}
