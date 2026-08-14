import { beforeAll, describe, expect, it } from "vitest";

import vectors from "../../../nth_dao/trade_rules/vectors/agreement-v1.json";
import {
  disputeStatementAcknowledgementSigningInput,
  createVerifiedTradeDisputeArtifacts,
  disputeStatementDeliverySigningInput,
  disputeStatementSigningInput,
  tradeCanonicalBytes,
  verifyTradeDisputeStatement,
  verifyTradeDisputeStatementAcknowledgement,
  verifyTradeDisputeStatementAcknowledgementBinding,
  verifyTradeDisputeStatementDelivery,
  verifyTradeDisputeStatementSignature,
} from "./conformance";

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

async function verifiedArtifacts(review: unknown = vectors.disputed_receipt_review) {
  return createVerifiedTradeDisputeArtifacts(
    {
      order: vectors.order,
      receipt: vectors.execution_receipt,
      review,
    }
  );
}

let baseArtifacts: Awaited<ReturnType<typeof verifiedArtifacts>>;

beforeAll(async () => {
  baseArtifacts = await verifiedArtifacts();
});

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
          artifacts: baseArtifacts,
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

  it("bounds Statement clock skew without numeric overflow", async () => {
    const context = {
      artifacts: baseArtifacts,
      observedAt: vectors.trade_dispute_statement.created_at,
      resolvedRulePackage: vectors.rule_package,
    };
    await expect(
      verifyTradeDisputeStatement(vectors.trade_dispute_statement, {
        ...context,
        clockSkewSeconds: 86_400,
      })
    ).resolves.toEqual({ valid: true, reason: "ok" });

    for (const clockSkewSeconds of [86_400.000_001, 1e300]) {
      await expect(
        verifyTradeDisputeStatement(vectors.trade_dispute_statement, {
          ...context,
          clockSkewSeconds,
        })
      ).resolves.toEqual({
        valid: false,
        reason: "clockSkewSeconds must be finite and between 0 and 86400",
      });
    }
  });

  it("rejects correctly signed statements under the wrong semantic context", async () => {
    for (const testCase of vectors.trade_dispute_statement_signed_negative_cases) {
      const signedArtifacts = await verifiedArtifacts(testCase.signed_review);
      const signedContext = await verifyTradeDisputeStatement(testCase.document, {
        artifacts: signedArtifacts,
        observedAt: testCase.document.created_at,
        clockSkewSeconds: 0,
      });
      expect(signedContext, `${testCase.case} signed context`).toEqual({
        valid: true,
        reason: "ok",
      });

      const verificationArtifacts = await verifiedArtifacts(
        testCase.verification_review
      );
      const verification = await verifyTradeDisputeStatement(testCase.document, {
        artifacts: verificationArtifacts,
        observedAt: testCase.at,
        clockSkewSeconds: testCase.clock_skew_seconds,
      });
      expect(verification.valid, testCase.case).toBe(false);
      expect(verification.reason).toContain(testCase.expected_reason);
    }
  });

  it("fails closed when a resolved Rule Package is absent or corrupt", async () => {
    const context = {
      artifacts: baseArtifacts,
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

  it("reproduces Delivery and Acknowledgement canonical signing bytes", () => {
    expect(hex(tradeCanonicalBytes(vectors.trade_dispute_statement_delivery))).toBe(
      vectors.trade_dispute_statement_delivery_canonical_hex
    );
    expect(
      hex(disputeStatementDeliverySigningInput(vectors.trade_dispute_statement_delivery))
    ).toBe(vectors.trade_dispute_statement_delivery_signing_input_hex);
    expect(
      hex(
        disputeStatementAcknowledgementSigningInput(
          vectors.trade_dispute_statement_acknowledgement
        )
      )
    ).toBe(vectors.trade_dispute_statement_acknowledgement_signing_input_hex);
  });

  it("independently verifies Delivery destination, TTL, bindings, and signature", async () => {
    for (const testCase of vectors.trade_dispute_statement_delivery_verification_cases) {
      const result = await verifyTradeDisputeStatementDelivery(
        vectors.trade_dispute_statement_delivery,
        {
          artifacts: baseArtifacts,
          recipientDid: testCase.recipient_did,
          observedAt: testCase.at,
          maxTtlSeconds: testCase.max_ttl_seconds,
          clockSkewSeconds: testCase.clock_skew_seconds,
          resolvedRulePackage: vectors.rule_package,
        }
      );
      expect(result.valid, `${testCase.case}: ${result.reason}`).toBe(
        testCase.expected_valid
      );
    }
    const wrongDomain = await verifyTradeDisputeStatementDelivery(
      vectors.trade_dispute_statement_delivery,
      {
        artifacts: baseArtifacts,
        recipientDid: vectors.trade_dispute_statement_delivery.recipient_did,
        observedAt: "2026-08-01T02:06:00Z",
        resolvedRulePackage: vectors.rule_package,
      },
      globalThis.crypto.subtle,
      "another-protocol"
    );
    expect(wrongDomain.valid).toBe(false);
  });

  it("independently verifies receiver ACK bindings, chronology, and signature", async () => {
    await expect(verifyTradeDisputeStatementAcknowledgementBinding(
      vectors.trade_dispute_statement_acknowledgement,
      vectors.trade_dispute_statement_delivery,
    )).resolves.toEqual({ valid: true, reason: "ok" });
    const tampered = structuredClone(
      vectors.trade_dispute_statement_acknowledgement
    );
    tampered.statement_digest = `sha256:${"0".repeat(64)}`;
    const rejected = await verifyTradeDisputeStatementAcknowledgementBinding(
      tampered,
      vectors.trade_dispute_statement_delivery,
    );
    expect(rejected.valid).toBe(false);
    expect(rejected.reason).toContain("statement_digest does not match Delivery");

    for (const testCase of vectors.trade_dispute_statement_acknowledgement_verification_cases) {
      const result = await verifyTradeDisputeStatementAcknowledgement(
        vectors.trade_dispute_statement_acknowledgement,
        vectors.trade_dispute_statement_delivery,
        {
          artifacts: baseArtifacts,
          recipientDid: vectors.trade_dispute_statement_delivery.recipient_did,
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

  it("keeps a historical ACK verifiable after its Delivery expires", async () => {
    const result = await verifyTradeDisputeStatementAcknowledgement(
      vectors.trade_dispute_statement_acknowledgement,
      vectors.trade_dispute_statement_delivery,
      {
        artifacts: baseArtifacts,
        recipientDid: vectors.trade_dispute_statement_delivery.recipient_did,
        observedAt: "2026-09-01T00:00:00Z",
        resolvedRulePackage: vectors.rule_package,
      }
    );
    expect(result).toEqual({ valid: true, reason: "ok" });
  });

  it("applies the same explicit Delivery TTL policy to ACK verification", async () => {
    const context = {
      artifacts: baseArtifacts,
      recipientDid: vectors.trade_dispute_statement_delivery.recipient_did,
      observedAt: "2026-08-01T02:07:00Z",
      clockSkewSeconds: 0,
      resolvedRulePackage: vectors.rule_package,
    };
    const defaultPolicy = await verifyTradeDisputeStatementAcknowledgement(
      vectors.trade_dispute_statement_overlong_acknowledgement,
      vectors.trade_dispute_statement_overlong_delivery,
      context
    );
    expect(defaultPolicy.valid).toBe(false);
    expect(defaultPolicy.reason).toContain("lifetime exceeds limit");

    const explicitPolicy = await verifyTradeDisputeStatementAcknowledgement(
      vectors.trade_dispute_statement_overlong_acknowledgement,
      vectors.trade_dispute_statement_overlong_delivery,
      { ...context, maxTtlSeconds: 86_400 }
    );
    expect(explicitPolicy).toEqual({ valid: true, reason: "ok" });
  });

  it("rejects Python Delivery and ACK tamper vectors", async () => {
    for (const testCase of vectors.negative_cases.filter((item) =>
      item.target === "trade_dispute_statement_delivery" ||
      item.target === "trade_dispute_statement_acknowledgement"
    )) {
      const context = {
        artifacts: baseArtifacts,
        recipientDid: vectors.trade_dispute_statement_delivery.recipient_did,
        observedAt: "2026-08-01T02:07:00Z",
        resolvedRulePackage: vectors.rule_package,
      };
      const result = testCase.target === "trade_dispute_statement_delivery"
        ? await verifyTradeDisputeStatementDelivery(testCase.document, context)
        : await verifyTradeDisputeStatementAcknowledgement(
            testCase.document,
            vectors.trade_dispute_statement_delivery,
            context
          );
      expect(result.valid, `${testCase.case}: ${result.reason}`).toBe(false);
    }
  });

  it("fails closed for an unverified artifact bundle", async () => {
    const result = await verifyTradeDisputeStatement(
      vectors.trade_dispute_statement,
      {
        artifacts: {
          order: vectors.order,
          receipt: vectors.execution_receipt,
          review: vectors.disputed_receipt_review,
        },
        observedAt: "2026-08-01T02:04:00Z",
      } as never
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("createVerifiedTradeDisputeArtifacts");
  });

  it("does not let a caller mint a bundle for a forged upstream artifact", async () => {
    const forgedOrder = structuredClone(vectors.order);
    forgedOrder.snapshot.offer.proof.proof_value = "A".repeat(86);
    await expect(
      createVerifiedTradeDisputeArtifacts(
        {
          order: forgedOrder,
          receipt: vectors.execution_receipt,
          review: vectors.disputed_receipt_review,
        }
      )
    ).rejects.toThrow("Order Offer signature is invalid");
  });

  it.each([
    {
      label: "Proposal",
      build: () => {
        const order = structuredClone(vectors.order);
        order.snapshot.proposal.proof.proof_value = "A".repeat(86);
        return { order, receipt: vectors.execution_receipt, review: vectors.disputed_receipt_review };
      },
    },
    {
      label: "Acceptance",
      build: () => {
        const order = structuredClone(vectors.order);
        order.snapshot.acceptance.proof.proof_value = "A".repeat(86);
        return { order, receipt: vectors.execution_receipt, review: vectors.disputed_receipt_review };
      },
    },
    {
      label: "Execution Receipt",
      build: () => {
        const receipt = structuredClone(vectors.execution_receipt);
        receipt.proof.proof_value = "A".repeat(86);
        return { order: vectors.order, receipt, review: vectors.disputed_receipt_review };
      },
    },
    {
      label: "Receipt Review",
      build: () => {
        const review = structuredClone(vectors.disputed_receipt_review);
        review.proof.proof_value = "A".repeat(86);
        return { order: vectors.order, receipt: vectors.execution_receipt, review };
      },
    },
  ])("rejects a forged $label signature before branding", async ({ build }) => {
    await expect(createVerifiedTradeDisputeArtifacts(build())).rejects.toThrow(
      "artifact signature is invalid"
    );
  });
});
