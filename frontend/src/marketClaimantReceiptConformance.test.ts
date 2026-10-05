import { describe, expect, it } from "vitest";

import vector from "../../nth_dao/market/vectors/claimant-source-receipt-observed-v1.json";
import { canonicalJSON } from "./crypto";

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function decodeDidKey(did: string): Uint8Array {
  if (!did.startsWith("did:key:z")) throw new Error("unsupported DID");
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let value = 0n;
  const encoded = did.slice("did:key:z".length);
  for (const char of encoded) {
    const digit = alphabet.indexOf(char);
    if (digit < 0) throw new Error("invalid DID encoding");
    value = value * 58n + BigInt(digit);
  }
  const bytes: number[] = [];
  while (value > 0n) {
    bytes.unshift(Number(value % 256n));
    value /= 256n;
  }
  const leading = encoded.match(/^1*/)?.[0].length ?? 0;
  const decoded = new Uint8Array([...Array(leading).fill(0), ...bytes]);
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error("DID is not an Ed25519 did:key");
  }
  return decoded.slice(2);
}

function decodeSignature(value: string): Uint8Array {
  const encoded = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(encoded.padEnd(Math.ceil(encoded.length / 4) * 4, "=")),
    (char) => char.charCodeAt(0));
}

describe("Claimant source receipt observation wire conformance", () => {
  it("verifies Python canonical bytes and Ed25519 event with WebCrypto", async () => {
    const subtle = globalThis.crypto.subtle;
    const payload = canonicalJSON(vector.payload);
    expect(payload).toBe(vector.payload_canonical_json);
    const payloadHash = new Uint8Array(await subtle.digest("SHA-256", new TextEncoder().encode(payload)));
    expect(`sha256:${hex(payloadHash)}`).toBe(vector.payload_sha256);

    const { content_hash, sig, ...core } = vector.event;
    expect(core.payload).toEqual(vector.payload);
    const coreBytes = new TextEncoder().encode(canonicalJSON(core));
    expect(new TextDecoder().decode(coreBytes)).toBe(vector.event_core_canonical_json);
    const coreHash = new Uint8Array(await subtle.digest("SHA-256", coreBytes));
    expect(hex(coreHash)).toBe(content_hash);

    const pubkey = decodeDidKey(core.author_did);
    const key = await subtle.importKey("raw", asArrayBuffer(pubkey), "Ed25519", false, ["verify"]);
    const signature = decodeSignature(sig);
    expect(await subtle.verify("Ed25519", key, asArrayBuffer(signature), asArrayBuffer(coreHash))).toBe(true);
    const changed = { ...core, payload: { ...core.payload, accepted: true } };
    const changedHash = new Uint8Array(await subtle.digest(
      "SHA-256", new TextEncoder().encode(canonicalJSON(changed)),
    ));
    expect(await subtle.verify("Ed25519", key, asArrayBuffer(signature), asArrayBuffer(changedHash))).toBe(false);
  });
});
