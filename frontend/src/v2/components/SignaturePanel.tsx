/**
 * Signature inspector — `{}` panel that shows the raw JSON of a
 * receipt / cap_token / agent card.
 *
 * The cryptographic claim of NTH DAO is that every action is signed
 * and inspectable. This panel is the literal manifestation of that
 * claim: any signed material can be displayed verbatim, with light
 * JSON syntax highlighting.
 *
 * Highlighting strategy: tiny inline tokenizer (no Prism / no
 * react-syntax-highlighter dependency). JSON's grammar is small
 * enough to colorize without a library.
 */

import { useMemo } from "react";

export interface SignaturePanelProps {
  /** The object to inspect. Will be ``JSON.stringify``'d. */
  value: unknown;
  /** Optional title above the JSON; defaults to "Signed material". */
  title?: string;
}

interface Span {
  kind: "key" | "string" | "number" | "bool" | "null" | "plain";
  text: string;
}

/** Walks the already-stringified canonical JSON one match at a time
 *  using ``String.prototype.matchAll`` (no exec/RegExp lookahead
 *  involved). */
function colorize(json: string): Span[] {
  const pattern = /("(?:\\.|[^"\\])*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)|(true|false)|(null)/g;
  const spans: Span[] = [];
  let cursor = 0;
  for (const m of json.matchAll(pattern)) {
    const start = m.index ?? 0;
    if (start > cursor) {
      spans.push({ kind: "plain", text: json.slice(cursor, start) });
    }
    if (m[1] !== undefined) {
      spans.push({ kind: m[2] ? "key" : "string", text: m[1] });
      if (m[2]) spans.push({ kind: "plain", text: m[2] });
    } else if (m[3] !== undefined) {
      spans.push({ kind: "number", text: m[3] });
    } else if (m[4] !== undefined) {
      spans.push({ kind: "bool", text: m[4] });
    } else if (m[5] !== undefined) {
      spans.push({ kind: "null", text: m[5] });
    }
    cursor = start + m[0].length;
  }
  if (cursor < json.length) {
    spans.push({ kind: "plain", text: json.slice(cursor) });
  }
  return spans;
}

const kindClass: Record<Span["kind"], string> = {
  key: "json-key",
  string: "json-string",
  number: "json-number",
  bool: "json-bool",
  null: "json-null",
  plain: "",
};

export function SignaturePanel({ value, title = "Signed material" }: SignaturePanelProps) {
  const { json, spans } = useMemo(() => {
    let raw: string;
    try {
      raw = JSON.stringify(value, null, 2);
    } catch {
      raw = String(value);
    }
    return { json: raw, spans: colorize(raw) };
  }, [value]);

  return (
    <div className="detail-section">
      <div
        className="detail-section-label"
        style={{ display: "flex", alignItems: "center", gap: 6 }}
      >
        <span>{title}</span>
        <span className="muted" style={{ fontFamily: "var(--t-mono)", fontSize: 10 }}>
          {json.length} bytes
        </span>
      </div>
      <pre className="signature-panel">
        {spans.map((s, i) =>
          s.kind === "plain" ? (
            <span key={i}>{s.text}</span>
          ) : (
            <span key={i} className={kindClass[s.kind]}>{s.text}</span>
          ),
        )}
      </pre>
    </div>
  );
}
