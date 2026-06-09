/**
 * Bottom 28px status bar — ambient state, always visible.
 *
 * Inspired by VS Code's and Claude Code's status lines: a single
 * row of high-signal facts the user shouldn't have to dig for.
 *
 * Fields shown:
 *   - identity dot + DID short + handle
 *   - active cap_tokens (+ expiring-soon highlight)
 *   - chain head short hash
 *   - mission count
 *   - pending decisions (right-aligned, accent-tinted if > 0)
 */

import type { StatusBarState } from "../types-v2";

export interface StatusBarProps {
  state: StatusBarState | null;
}

export function StatusBar({ state }: StatusBarProps) {
  if (!state) {
    return (
      <div className="statusbar">
        <span className="muted">Loading workspace…</span>
      </div>
    );
  }

  const capLabel =
    state.caps_expiring_soon > 0
      ? `${state.active_caps} active · ${state.caps_expiring_soon} expiring`
      : `${state.active_caps} active`;

  return (
    <div className="statusbar">
      <div className="statusbar-item" title={state.did}>
        <span className="statusbar-dot" />
        <span>{state.agent_id}</span>
        <code>{state.code}</code>
      </div>

      <div className="statusbar-item" title="Active cap_tokens">
        <span>cap_tokens</span>
        <code>{capLabel}</code>
      </div>

      <div className="statusbar-item" title="Latest chain head content_hash">
        <span>chain head</span>
        <code>{state.chain_head_short || "—"}</code>
      </div>

      <div className="statusbar-item">
        <span>missions</span>
        <code>{state.active_missions}</code>
      </div>

      <div className="statusbar-spacer" />

      <div
        className="statusbar-item"
        style={
          state.pending_decisions > 0
            ? { color: "var(--accent)" }
            : undefined
        }
      >
        <span>pending</span>
        <code>{state.pending_decisions}</code>
      </div>
    </div>
  );
}
