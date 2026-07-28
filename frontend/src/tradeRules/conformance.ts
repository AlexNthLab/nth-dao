const MAX_SAFE_INTEGER = 9_007_199_254_740_991;
const MAX_BYTES = 262_144;
const MAX_DEPTH = 32;
const MAX_NODES = 10_000;
const MAX_STRING_BYTES = 65_536;
const MAX_KEY_BYTES = 256;

export const TRADE_RULE_MANIFEST_DOMAIN = "NTH-TRADE-RULE-MANIFEST-V1";

type JsonObject = { [key: string]: JsonValue };
type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function canonicalString(
  value: unknown,
  path: string,
  depth: number,
  state: { nodes: number },
  ancestors: Set<object>
): string {
  state.nodes += 1;
  if (state.nodes > MAX_NODES) throw new Error("trade JSON exceeds node limit");
  if (depth > MAX_DEPTH) throw new Error("trade JSON exceeds depth limit");

  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") {
    if (hasLoneSurrogate(value)) throw new Error(`invalid Unicode string at ${path}`);
    if (utf8(value).byteLength > MAX_STRING_BYTES) {
      throw new Error(`string too large at ${path}`);
    }
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Math.abs(value) > MAX_SAFE_INTEGER) {
      throw new Error(`unsafe or non-integer number at ${path}`);
    }
    return JSON.stringify(value);
  }
  if (typeof value !== "object" || value === undefined) {
    throw new Error(`unsupported value at ${path}`);
  }

  if (ancestors.has(value)) throw new Error(`cyclic value at ${path}`);
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return (
        "[" +
        value
          .map((item, index) =>
            canonicalString(item, `${path}[${index}]`, depth + 1, state, ancestors)
          )
          .join(",") +
        "]"
      );
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error(`non-plain object at ${path}`);
    }
    const object = value as Record<string, unknown>;
    const ownKeys = Reflect.ownKeys(object);
    if (
      ownKeys.some((key) => typeof key !== "string") ||
      ownKeys.length !== Object.keys(object).length
    ) {
      throw new Error(`non-string key at ${path}`);
    }
    const keys = Object.keys(object).sort();
    for (const key of keys) {
      if (
        key.length === 0 ||
        key.length > MAX_KEY_BYTES ||
        [...key].some((character) => {
          const code = character.charCodeAt(0);
          return code < 0x21 || code > 0x7e;
        })
      ) {
        throw new Error(`invalid ASCII key at ${path}`);
      }
    }
    return (
      "{" +
      keys
        .map(
          (key) =>
            `${JSON.stringify(key)}:${canonicalString(
              object[key],
              `${path}.${key}`,
              depth + 1,
              state,
              ancestors
            )}`
        )
        .join(",") +
      "}"
    );
  } finally {
    ancestors.delete(value);
  }
}

export function tradeCanonicalBytes(value: unknown): Uint8Array {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("trade JSON root must be an object");
  }
  const encoded = utf8(canonicalString(value, "$", 0, { nodes: 0 }, new Set()));
  if (encoded.byteLength > MAX_BYTES) throw new Error("trade JSON exceeds byte limit");
  return encoded;
}

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.byteLength, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function asArrayBuffer(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy.buffer;
}

export function manifestSigningInput(
  manifest: unknown,
  domain = TRADE_RULE_MANIFEST_DOMAIN
): Uint8Array {
  const document = asObject(manifest, "manifest");
  const proof = asObject(document.proof, "proof");
  if (typeof proof.proof_value !== "string") {
    throw new Error("proof.proof_value must be a string");
  }
  const signingProof = { ...proof };
  delete signingProof.proof_value;
  const signingBody = { ...document, proof: signingProof };
  return concatBytes(utf8(domain), new Uint8Array([0]), tradeCanonicalBytes(signingBody));
}

function decodeBase58(value: string): Uint8Array {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let number = 0n;
  for (const character of value) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("invalid base58btc");
    number = number * 58n + BigInt(index);
  }
  const body: number[] = [];
  while (number > 0n) {
    body.push(Number(number % 256n));
    number /= 256n;
  }
  body.reverse();
  let leadingZeros = 0;
  while (value[leadingZeros] === "1") leadingZeros += 1;
  return new Uint8Array([...new Array(leadingZeros).fill(0), ...body]);
}

function decodeDidKey(value: string): Uint8Array {
  const prefix = "did:key:z";
  if (!value.startsWith(prefix)) throw new Error("unsupported DID");
  const decoded = decodeBase58(value.slice(prefix.length));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error("DID is not an Ed25519 did:key");
  }
  return decoded.slice(2);
}

function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]{86}$/.test(value)) throw new Error("invalid signature encoding");
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "==";
  const binary = atob(base64);
  const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (decoded.byteLength !== 64) throw new Error("invalid Ed25519 signature length");
  const canonical = btoa(String.fromCharCode(...decoded))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  if (canonical !== value) throw new Error("non-canonical signature encoding");
  return decoded;
}

export async function verifyManifestSignature(
  manifest: unknown,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
  domain = TRADE_RULE_MANIFEST_DOMAIN
): Promise<boolean> {
  try {
    const document = asObject(
      JSON.parse(new TextDecoder().decode(tradeCanonicalBytes(manifest))),
      "manifest"
    );
    const proof = asObject(document.proof, "proof");
    if (
      document.kind !== "org.nthdao.trade.rule-manifest" ||
      document.protocol_version !== "1.0" ||
      proof.type !== "NthEd25519SignatureV1" ||
      proof.proof_purpose !== "assertionMethod" ||
      typeof document.publisher_did !== "string" ||
      typeof proof.verification_method !== "string" ||
      proof.verification_method !==
        `${document.publisher_did}#${document.publisher_did.slice("did:key:".length)}` ||
      typeof proof.proof_value !== "string"
    ) {
      return false;
    }
    const keyBytes = decodeDidKey(document.publisher_did);
    const signature = decodeBase64Url(proof.proof_value);
    const key = await subtle.importKey(
      "raw",
      asArrayBuffer(keyBytes),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    return await subtle.verify(
      { name: "Ed25519" },
      key,
      asArrayBuffer(signature),
      asArrayBuffer(manifestSigningInput(document, domain))
    );
  } catch {
    return false;
  }
}

export async function manifestDigest(
  manifest: unknown,
  subtle: SubtleCrypto = globalThis.crypto.subtle
): Promise<string> {
  const digest = new Uint8Array(
    await subtle.digest("SHA-256", asArrayBuffer(tradeCanonicalBytes(manifest)))
  );
  return `sha256:${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}
