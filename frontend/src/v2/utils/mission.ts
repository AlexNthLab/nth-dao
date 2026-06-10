/**
 * Mission-related shared helpers (audit fix 2026-06-10, finding L4):
 * progress-bar color logic was inlined inside MissionList's JSX.
 * Centralizing means the same color contract applies anywhere the
 * progress visualisation appears (cockpit detail view, future
 * dashboard widgets).
 */

import type { MissionSummary } from "../types-v2";

/** CSS var name to use for the progress bar fill. Failed missions
 *  go red regardless of completion %. Everything else uses the
 *  brand accent (cyan). */
export function progressColor(m: MissionSummary): string {
  if (m.status === "failed") return "var(--status-bad)";
  return "var(--accent)";
}

/** Progress percentage as an integer 0..100. Total=0 short-circuits
 *  to 0 (the case for fresh "planning"-state missions whose driver
 *  hasn't enumerated steps yet).
 *
 *  Clamped to [0, 100] (audit pass#3 bonus 2026-06-10): a buggy
 *  backend could send steps_done > steps_total (re-runs counted
 *  twice, optimistic completion before terminal step records).
 *  Without the clamp the bar overflows its container, breaking
 *  the visual rhythm. We clamp instead of throwing because the
 *  point of the bar is "roughly how done" — visual saturation at
 *  100% is the honest depiction. */
export function progressPct(m: MissionSummary): number {
  // Defensive: TypeScript says number but a loose backend can leak
  // null/undefined/"" which divide-by-zero to NaN. Also catches
  // Infinity (steps_total=0.0001 etc). The follow-up clamp would
  // otherwise pass NaN through (NaN<0 and NaN>100 are both false).
  if (!m.steps_total || !Number.isFinite(m.steps_total)) return 0;
  if (!Number.isFinite(m.steps_done)) return 0;
  const raw = Math.round((m.steps_done / m.steps_total) * 100);
  if (raw < 0) return 0;
  if (raw > 100) return 100;
  return raw;
}
