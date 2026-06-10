/**
 * Shared time + status helpers for v2 components.
 *
 * History (audit fix 2026-06-10, finding M3): `relativeTime` was
 * duplicated across DecisionCard / BlackboardView / ChatView /
 * AgentDirectoryView with THREE different format conventions
 * ("just now" / "now", "2h ago" / "2h", "5d ago" / "5d"). Each
 * copy drifted independently — drift is a bug temptation. This
 * module is the single source of truth.
 *
 * Format rules (chosen for keyboard-driven dense UI):
 *   - <60s    → "just now"
 *   - <60m    → "{n}m ago" (e.g. "5m ago")
 *   - <24h    → "{n}h ago"
 *   - <30d    → "{n}d ago"
 *   - ≥30d    → locale date string
 *
 * `relativeFuture` is the same shape but for cap_token expiry —
 * "in 5m", "in 2h", "in 3d", "expired".
 */

/* Invalid-input handling (audit pass#3 fix 2026-06-10, finding I1):
 * `new Date("not-iso")` returns an Invalid Date object — getTime()
 * yields NaN, every comparison falls through, and the function
 * ended up rendering the literal string "Invalid Date" via
 * toLocaleDateString. Backends sending malformed timestamps would
 * have silently leaked that string into the UI. Each entry point
 * now guards: malformed in → "—" out. */

function safeTime(iso: string): number | null {
  const t = new Date(iso).getTime();
  return Number.isFinite(t) ? t : null;
}

export function relativeTime(iso: string): string {
  const t = safeTime(iso);
  if (t === null) return "—";
  const diff = (Date.now() - t) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 86400 * 30) return `${Math.floor(diff / 86400)}d ago`;
  return new Date(t).toLocaleDateString();
}

export function relativeFuture(iso: string | number): string {
  const t = typeof iso === "string" ? safeTime(iso) : iso;
  if (t === null || !Number.isFinite(t)) return "—";
  const diff = (t - Date.now()) / 1000;
  if (diff < 0) return "expired";
  if (diff < 3600) return `in ${Math.floor(diff / 60)}m`;
  if (diff < 86400) return `in ${Math.floor(diff / 3600)}h`;
  return `in ${Math.floor(diff / 86400)}d`;
}

/** Optional convenience for callers that want a non-suffixed
 *  variant (e.g. badge slots where "ago" is implied). Same
 *  underlying buckets — preserves consistency across formats. */
export function relativeTimeShort(iso?: string): string {
  if (!iso) return "—";
  const t = safeTime(iso);
  if (t === null) return "—";
  const diff = (Date.now() - t) / 1000;
  if (diff < 60) return "now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h`;
  if (diff < 86400 * 30) return `${Math.floor(diff / 86400)}d`;
  return new Date(t).toLocaleDateString();
}
