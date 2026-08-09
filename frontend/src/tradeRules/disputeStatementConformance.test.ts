import { describe, expect, it } from "vitest";

import vectors from "../../../nth_dao/trade_rules/vectors/agreement-v1.json";
import {
  disputeStatementSigningInput,
  tradeCanonicalBytes,
  verifyTradeDisputeStatement,
  verifyTradeDisputeStatementSignature,
} from "./conformance";

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

describe("Trade Dispute Statement v1 cross-implementation conformance", () => {
  it("reproduces Python canonical and signing bytes", () => {
    expect(hex(tradeCanonicalBytes(vectors.trade_dispute_statement))).toBe(
      vectors.trade_dispute_statement_canonical_hex
    );
    expect(
      hex(disputeStatementSigningInput(vectors.trade_dispute_statement))
    ).toBe(vectors.trade_dispute_statement_signing_input_hex);
  });

  it("verifies the Python signature and domain separation", async () => {
    await expect(
      verifyTradeDisputeStatementSignature(vectors.trade_dispute_statement)
    ).resolves.toBe(true);
    await expect(
      verifyTradeDisputeStatementSignature(
        vectors.trade_dispute_statement,
        globalThis.crypto.subtle,
        "another-protocol"
      )
    ).resolves.toBe(false);
  });

  it("keeps source attribution separate from semantic validity", async () => {
    for (const testCase of vectors.trade_dispute_statement_signed_negative_cases) {
      expect(testCase.expected_valid).toBe(false);
      await expect(
        verifyTradeDisputeStatementSignature(testCase.document)
      ).resolves.toBe(true);
    }
    const tampered = vectors.negative_cases.find(
      (testCase) =>
        testCase.case === "trade-dispute-statement-signature-tamper"
    );
    expect(tampered).toBeDefined();
    await expect(
      verifyTradeDisputeStatementSignature(tampered!.document)
    ).resolves.toBe(false);
  });

  it("independently verifies bindings, roles, time, and the resolved Rule Package", async () => {
    for (const testCase of vectors.trade_dispute_statement_verification_cases) {
      const result = await verifyTradeDisputeStatement(
        vectors.trade_dispute_statement,
        {
          order: vectors.order,
          receipt: vectors.execution_receipt,
          review: vectors.disputed_receipt_review,
          observedAt: testCase.at,
          clockSkewSeconds: testCase.clock_skew_seconds,
          resolvedRulePackage: vectors.rule_package,
        }
      );
      expect(result.valid, `${testCase.case}: ${result.reason}`).toBe(
        testCase.expected_valid
      );
    }
  });

  it("rejects correctly signed statements under the wrong semantic context", async () => {
    for (const testCase of vectors.trade_dispute_statement_signed_negative_cases) {
      const signedContext = await verifyTradeDisputeStatement(testCase.document, {
        order: vectors.order,
        receipt: vectors.execution_receipt,
        review: testCase.signed_review,
        observedAt: testCase.document.created_at,
        clockSkewSeconds: 0,
      });
      expect(signedContext, `${testCase.case} signed context`).toEqual({
        valid: true,
        reason: "ok",
      });

      const verification = await verifyTradeDisputeStatement(testCase.document, {
        order: vectors.order,
        receipt: vectors.execution_receipt,
        review: testCase.verification_review,
        observedAt: testCase.at,
        clockSkewSeconds: testCase.clock_skew_seconds,
      });
      expect(verification.valid, testCase.case).toBe(false);
      expect(verification.reason).toContain(testCase.expected_reason);
    }
  });

  it("fails closed when a resolved Rule Package is absent or corrupt", async () => {
    const context = {
      order: vectors.order,
      receipt: vectors.execution_receipt,
      review: vectors.disputed_receipt_review,
      observedAt: "2026-08-01T02:04:00Z",
      clockSkewSeconds: 300,
    };
    await expect(
      verifyTradeDisputeStatement(vectors.trade_dispute_statement, context)
    ).resolves.toMatchObject({ valid: false, reason: expect.stringContaining("resolved Rule Package") });

    const corruptPackage = structuredClone(vectors.rule_package);
    corruptPackage.resources[0]!.bytes_hex = "00";
    const verification = await verifyTradeDisputeStatement(
      vectors.trade_dispute_statement,
      { ...context, resolvedRulePackage: corruptPackage }
    );
    expect(verification.valid).toBe(false);
    expect(verification.reason).toContain("resource bytes");
  });
});
