import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test } from "vitest";
import { canonicalJSON } from "./src/crypto";

const vector = JSON.parse(
  readFileSync(resolve(process.cwd(), "../nth_dao/market/vectors/source-completion-receipt-crypto-v1.json"), "utf8")
);
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function publicKeyFromDid(did) {
  if (!did.startsWith("did:key:z")) throw new Error("invalid DID method");
  let value = 0n;
  for (const character of did.slice(9)) {
    const digit = BASE58.indexOf(character);
    if (digit < 0) throw new Error("invalid base58 DID");
    value = value * 58n + BigInt(digit);
  }
  const multicodec = Buffer.from(value.toString(16).padStart(68, "0"), "hex");
  if (multicodec.length !== 34 || multicodec[0] !== 0xed || multicodec[1] !== 0x01) {
    throw new Error("DID is not an Ed25519 key");
  }
  return multicodec.subarray(2);
}

function validSignature(did, message, signature) {
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  const key = createPublicKey({
    key: Buffer.concat([prefix, publicKeyFromDid(did)]),
    format: "der",
    type: "spki",
  });
  return verify(null, message, key, signature);
}

function validRotationPath(chain, pinnedDid, signerDid) {
  let candidate = pinnedDid;
  const visited = new Set([candidate]);
  for (const row of chain) {
    const { previous_sig, successor_sig, ...body } = row;
    if (row.previous_did !== candidate || visited.has(row.successor_did)) return false;
    const bytes = Buffer.from(canonicalJSON(body), "utf8");
    if (!validSignature(candidate, bytes, Buffer.from(previous_sig, "hex"))) return false;
    if (!validSignature(row.successor_did, bytes, Buffer.from(successor_sig, "hex"))) return false;
    candidate = row.successor_did;
    visited.add(candidate);
  }
  return candidate === signerDid;
}

test("Python source receipt and rotation signatures verify independently in Node", () => {
  const { content_hash, sig, ...core } = vector.event;
  const bytes = canonicalJSON(core);
  expect(bytes).toBe(vector.event_core_canonical_json);
  expect(createHash("sha256").update(bytes, "utf8").digest("hex")).toBe(content_hash);
  expect(validSignature(core.author_did, Buffer.from(content_hash, "hex"), Buffer.from(sig, "base64url"))).toBe(true);

  const { previous_sig: _previous, successor_sig: _successor, ...rotationBody } = vector.rotation_chain[0];
  expect(canonicalJSON(rotationBody)).toBe(vector.rotation_body_canonical_json);
  expect(validRotationPath(vector.rotation_chain, vector.pinned_source_did, core.author_did)).toBe(true);
  expect(validRotationPath([], vector.pinned_source_did, core.author_did)).toBe(false);
  expect(
    validRotationPath(
      [{ ...vector.rotation_chain[0], previous_sig: "0".repeat(128) }],
      vector.pinned_source_did,
      core.author_did
    )
  ).toBe(false);

  const tamperedCore = { ...core, payload: { ...core.payload, accepted: true } };
  const tamperedHash = createHash("sha256").update(canonicalJSON(tamperedCore)).digest();
  expect(validSignature(core.author_did, tamperedHash, Buffer.from(sig, "base64url"))).toBe(false);
});
