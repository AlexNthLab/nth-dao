import { describe, expect, it } from "vitest";

import vectors from "../../../nth_dao/trade_rules/vectors/manifest-v1.json";
import {
  manifestDigest,
  manifestSigningInput,
  tradeCanonicalBytes,
  verifyManifestSignature,
} from "./conformance";

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("Trade Rule Manifest v1 cross-implementation conformance", () => {
  it("reproduces Python canonical vectors without calling Python code", () => {
    for (const testCase of vectors.canonical_cases) {
      expect(hex(tradeCanonicalBytes(testCase.input))).toBe(testCase.expected_hex);
    }
  });

  it("reproduces the frozen manifest bytes and signing input", () => {
    expect(hex(tradeCanonicalBytes(vectors.manifest))).toBe(
      vectors.expected_manifest_canonical_hex
    );
    expect(hex(manifestSigningInput(vectors.manifest))).toBe(
      vectors.expected_signing_input_hex
    );
  });

  it("reproduces the signed manifest digest", async () => {
    await expect(manifestDigest(vectors.manifest)).resolves.toBe(
      vectors.expected_manifest_digest
    );
  });

  it("verifies the Python Ed25519 signature and rejects another domain", async () => {
    await expect(verifyManifestSignature(vectors.manifest)).resolves.toBe(true);
    await expect(
      verifyManifestSignature(vectors.manifest, globalThis.crypto.subtle, "OTHER-PROTOCOL")
    ).resolves.toBe(false);
  });

  it("verifies the immutable call-time snapshot across WebCrypto awaits", async () => {
    const document = structuredClone(vectors.manifest);
    const verification = verifyManifestSignature(document);
    document.summary = "mutated after verification started";
    await expect(verification).resolves.toBe(true);
  });

  it("rejects every tampered Python negative vector", async () => {
    for (const testCase of vectors.negative_manifests) {
      await expect(verifyManifestSignature(testCase.document)).resolves.toBe(false);
    }
  });

  it("rejects a non-canonical base64url spelling of the same signature bytes", async () => {
    const document = structuredClone(vectors.manifest);
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const signature = document.proof.proof_value;
    const lastIndex = alphabet.indexOf(signature[signature.length - 1] ?? "");
    expect(lastIndex % 4).toBe(0);
    document.proof.proof_value = `${signature.slice(0, -1)}${alphabet[lastIndex + 1]}`;
    await expect(verifyManifestSignature(document)).resolves.toBe(false);
  });
});
