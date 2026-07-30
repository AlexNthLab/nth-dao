import { describe, expect, it } from "vitest";

import vectors from "../../../nth_dao/trade_rules/vectors/rule-recognition-v1.json";
import {
  recognitionSigningInput,
  tradeCanonicalBytes,
  verifyRuleRecognitionSignature,
} from "./conformance";

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
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
});
