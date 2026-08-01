import { describe, expect, it } from "vitest";

import vectors from "../../../nth_dao/trade_rules/vectors/rule-recognition-v1.json";
import {
  recognitionSigningInput,
  tradeCanonicalBytes,
  validateRuleRecognitionAuditPayload,
  verifyRuleRecognitionSignature,
} from "./conformance";

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

async function sha256Digest(value: unknown): Promise<string> {
  const canonical = tradeCanonicalBytes(value);
  const input = canonical.slice().buffer as ArrayBuffer;
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    input
  );
  return `sha256:${hex(new Uint8Array(digest))}`;
}

describe("Trade Rule Recognition v1 cross-implementation conformance", () => {
  it("reproduces Python canonical and signing bytes", () => {
    expect(hex(tradeCanonicalBytes(vectors.recognized))).toBe(
      vectors.expected_recognized_canonical_hex
    );
    expect(hex(recognitionSigningInput(vectors.recognized))).toBe(
      vectors.expected_recognized_signing_input_hex
    );
  });

  it("verifies Python signatures and domain separation", async () => {
    await expect(
      verifyRuleRecognitionSignature(vectors.recognized)
    ).resolves.toBe(true);
    await expect(
      verifyRuleRecognitionSignature(vectors.revoked)
    ).resolves.toBe(true);
    await expect(
      verifyRuleRecognitionSignature(
        vectors.recognized,
        globalThis.crypto.subtle,
        "another-protocol"
      )
    ).resolves.toBe(false);
  });

  it("separates source signatures from semantic validity", async () => {
    await expect(
      verifyRuleRecognitionSignature(
        vectors.invalid.tampered_decision
      )
    ).resolves.toBe(false);
    await expect(
      verifyRuleRecognitionSignature(
        vectors.invalid.missing_reason
      )
    ).resolves.toBe(true);
  });

  it("binds Spine audit payloads to exact signed statements", async () => {
    const expectedFields = [
      "decision",
      "issued_at",
      "issuer_did",
      "not_after",
      "package_digest",
      "protocol_version",
      "recognition_digest",
      "recognition_id",
      "rule_id",
      "sequence",
    ];
    const cases = [
      [vectors.recognized, vectors.recognized_audit_payload],
      [vectors.revoked, vectors.revoked_audit_payload],
    ] as const;

    for (const [statement, payload] of cases) {
      expect(validateRuleRecognitionAuditPayload(payload)).toEqual(payload);
      expect(Object.keys(payload).sort()).toEqual(expectedFields);
      expect(payload.protocol_version).toBe("1");
      expect(payload.recognition_digest).toBe(
        await sha256Digest(statement)
      );
      expect(payload.recognition_id).toBe(statement.recognition_id);
      expect(payload.rule_id).toBe(statement.rule_id);
      expect(payload.package_digest).toBe(statement.package_digest);
      expect(payload.issuer_did).toBe(statement.issuer_did);
      expect(payload.sequence).toBe(statement.sequence);
      expect(payload.decision).toBe(statement.decision);
      expect(payload.issued_at).toBe(statement.issued_at);
      expect(payload.not_after).toBe(statement.not_after);
    }
  });

  it("rejects semantic audit payload attacks", () => {
    for (const payload of Object.values(vectors.invalid_audit_payloads)) {
      expect(() =>
        validateRuleRecognitionAuditPayload(payload)
      ).toThrow();
    }
  });
});
