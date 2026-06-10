/**
 * Top-level ErrorBoundary (audit fix 2026-06-10, finding M4).
 *
 * Without this, any uncaught error in any v2 component white-
 * screens the entire app — the user loses context on what went
 * wrong, can't approve a queued decision, can't see what state
 * the chain is in. We can't return to a no-render-tree state
 * silently; we replace the broken subtree with an inert recovery
 * panel.
 *
 * Class component (not hook) because React 19's hooks-based error
 * surface is still proposal-stage. The class API is stable.
 *
 * Why one big boundary at App's root, not per-view: when the v2
 * surfaces have settled, we'll route per-view boundaries so a
 * crash in Chat doesn't kill Decisions. For v1 a single boundary
 * is the right MVP — at least we stop white-screen-of-death.
 */

import { Component } from "react";
import type { ErrorInfo, ReactNode } from "react";

export interface ErrorBoundaryProps {
  children: ReactNode;
  /** Optional renderer for the fallback UI. Defaults to the
   *  built-in recovery panel. */
  fallback?: (err: Error, reset: () => void) => ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // In dev this surfaces in the console alongside React's own
    // overlay. In prod (no overlay) this is the only signal.
    // TODO: post to /api/client_errors when telemetry lands.
    // eslint-disable-next-line no-console
    console.error("[v2] ErrorBoundary caught:", error, info);
  }

  reset = () => this.setState({ error: null });

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    if (this.props.fallback) return this.props.fallback(error, this.reset);

    return (
      <div
        role="alert"
        style={{
          padding: 32,
          minHeight: "100vh",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          background: "var(--bg-root)",
          color: "var(--fg-primary)",
        }}
      >
        <div
          style={{
            maxWidth: 520,
            border: "1px solid var(--status-bad)",
            borderRadius: 12,
            padding: 24,
            background: "var(--bg-panel)",
          }}
        >
          <h2
            style={{
              margin: "0 0 8px",
              fontSize: 18,
              fontWeight: 600,
              color: "var(--status-bad)",
            }}
          >
            Something broke in the console.
          </h2>
          <p
            style={{
              margin: "0 0 16px",
              fontSize: 13,
              color: "var(--fg-secondary)",
            }}
          >
            Your work is safe — receipts persist in the ledger
            regardless of UI state. Use the button below to retry
            the surface that failed, or refresh the page.
          </p>
          <pre
            style={{
              margin: "0 0 16px",
              padding: 12,
              fontSize: 12,
              fontFamily: "var(--t-mono)",
              color: "var(--fg-tertiary)",
              background: "var(--bg-elevated)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              maxHeight: 160,
              overflow: "auto",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
            }}
          >
            {error.message}
          </pre>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              type="button"
              className="btn btn-primary"
              onClick={this.reset}
            >
              Retry
            </button>
            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => window.location.reload()}
            >
              Reload page
            </button>
          </div>
        </div>
      </div>
    );
  }
}
