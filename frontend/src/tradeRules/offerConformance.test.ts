import { describe, expect, it } from "vitest";

import vectors from "../../../nth_dao/trade_rules/vectors/offer-v2.json";
import {
  evaluateTradeOffer,
  offerDigest,
  offerSigningInput,
  tradeCanonicalBytes,
  validateTradeOffer,
  verifyOffer,
  verifyOfferSourceSignature,
} from "./conformance";

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("Trade Offer v2 cross-implementation conformance", () => {
  it("reproduces the Python offer bytes and signing input", () => {
    expect(hex(tradeCanonicalBytes(vectors.offer))).toBe(
      vectors.expected_offer_canonical_hex
    );
    expect(hex(offerSigningInput(vectors.offer))).toBe(
      vectors.expected_signing_input_hex
    );
  });

  it("reproduces the Python signed offer digest", async () => {
    await expect(offerDigest(vectors.offer)).resolves.toBe(
      vectors.expected_offer_digest
    );
  });

  it("does not issue a trusted digest for a tampered offer", async () => {
    const tampered = structuredClone(vectors.offer);
    tampered.summary = "tampered";
    await expect(offerDigest(tampered)).rejects.toThrow("signature invalid");
  });

  it("verifies Python Ed25519 and rejects another protocol domain", async () => {
    const validated = validateTradeOffer(vectors.offer);
    expect(validated.offer_id).toBe(
      "org.nthdao.reference/btc-for-solana-token"
    );
    expect(Object.isFrozen(validated)).toBe(true);
    expect(Object.isFrozen(validated.provides)).toBe(true);
    await expect(verifyOffer(vectors.offer)).resolves.toBe(true);
    await expect(verifyOfferSourceSignature(vectors.offer)).resolves.toBe(true);
    await expect(
      verifyOfferSourceSignature(
        vectors.offer,
        globalThis.crypto.subtle,
        "OTHER-PROTOCOL"
      )
    ).resolves.toBe(false);
  });

  it("separates signature integrity from current activity", async () => {
    await expect(
      evaluateTradeOffer(vectors.offer, new Date("2026-07-29T00:00:02Z"))
    ).resolves.toEqual({ active: true, reason: "active" });
    await expect(
      evaluateTradeOffer(vectors.offer, new Date("2026-07-28T23:59:59Z"))
    ).resolves.toEqual({ active: false, reason: "not_yet_active" });
    await expect(
      evaluateTradeOffer(vectors.offer, new Date("2027-07-29T00:00:00Z"))
    ).resolves.toEqual({ active: false, reason: "expired" });
    await expect(verifyOffer(vectors.withdrawal_offer)).resolves.toBe(true);
    await expect(offerDigest(vectors.withdrawal_offer)).resolves.toBe(
      vectors.expected_withdrawal_digest
    );
    await expect(
      evaluateTradeOffer(
        vectors.withdrawal_offer,
        new Date("2026-07-30T00:00:02Z")
      )
    ).resolves.toEqual({ active: false, reason: "withdrawn" });
  });

  it("separates source attribution from protocol validity", async () => {
    for (const testCase of vectors.negative_offers) {
      await expect(verifyOfferSourceSignature(testCase.document)).resolves.toBe(
        testCase.expected_signature_valid
      );
      await expect(verifyOffer(testCase.document)).resolves.toBe(false);
    }
  });

  it("does not issue trusted digests for signed semantic-invalid offers", async () => {
    for (const testCase of vectors.negative_offers.filter(
      (item) => item.expected_signature_valid
    )) {
      await expect(offerDigest(testCase.document)).rejects.toThrow(
        "semantics invalid"
      );
    }
  });

  it("covers selected rule digests with the publisher signature", async () => {
    const tampered = structuredClone(vectors.offer);
    tampered.rule_refs[0].digest = `sha256:${"0".repeat(64)}`;
    await expect(verifyOfferSourceSignature(tampered)).resolves.toBe(false);
  });
});
