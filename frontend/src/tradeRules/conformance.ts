const MAX_SAFE_INTEGER = 9_007_199_254_740_991;
const MAX_BYTES = 262_144;
const MAX_DEPTH = 32;
const MAX_NODES = 10_000;
const MAX_STRING_BYTES = 65_536;
const MAX_KEY_BYTES = 256;

export const TRADE_RULE_MANIFEST_DOMAIN = "NTH-TRADE-RULE-MANIFEST-V1";
export const TRADE_OFFER_DOMAIN = "NTH-TRADE-OFFER-V2";
export const TRADE_RULE_RECOGNITION_DOMAIN =
  "nth-dao/trade-rule-recognition/v1";

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

function exactObject(
  value: unknown,
  expected: readonly string[],
  label: string
): Record<string, unknown> {
  const object = asObject(value, label);
  const actual = Object.keys(object).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new Error(`${label} fields invalid`);
  }
  return object;
}

function boundedString(
  value: unknown,
  label: string,
  minimum: number,
  maximum: number
): string {
  if (
    typeof value !== "string" ||
    [...value].length < minimum ||
    [...value].length > maximum ||
    hasLoneSurrogate(value)
  ) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

const TOKEN = /^[a-z0-9][a-z0-9._:/-]*$/;
const OFFER_ID =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+(?:\/[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?)?$/;
const RULE_ID =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+(?:\/[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?)?$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const RESOURCE_ID =
  /^([a-z][a-z0-9+.-]{0,31}):[A-Za-z0-9._~!$&'()*+,;=:@%/?#\[\]-]+$/;
const QUANTITY = /^(?:[1-9][0-9]*(?:\.[0-9]*[1-9])?|0\.[0-9]*[1-9])$/;
const EXTENSION_ID =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\/[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?$/;
const TIMESTAMP =
  /^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z$/;
const UNSAFE_RESOURCE_SCHEMES = new Set(["data", "file", "javascript", "vbscript"]);

const OFFER_FIELDS = [
  "kind",
  "protocol_version",
  "offer_id",
  "revision",
  "previous_offer_digest",
  "state",
  "publisher_did",
  "title",
  "summary",
  "provides",
  "requests",
  "rule_refs",
  "published_at",
  "not_after",
  "extensions",
  "proof",
] as const;
const LEG_FIELDS = [
  "leg_id",
  "resource_type",
  "resource_id",
  "quantity",
  "unit",
  "descriptor_digest",
] as const;
const RULE_REF_FIELDS = ["rule_id", "digest"] as const;
const PROOF_FIELDS = [
  "type",
  "created",
  "verification_method",
  "proof_purpose",
  "proof_value",
] as const;

function token(value: unknown, label: string, maximum: number): string {
  const text = boundedString(value, label, 1, maximum);
  if (!TOKEN.test(text)) throw new Error(`${label} is not a namespaced token`);
  return text;
}

function digest(value: unknown, label: string): string {
  const text = boundedString(value, label, 71, 71);
  if (!DIGEST.test(text)) throw new Error(`${label} is not a sha256 digest`);
  return text;
}

function timestampNanos(value: unknown, label: string): bigint {
  const text = boundedString(value, label, 1, 35);
  const match = TIMESTAMP.exec(text);
  if (!match) throw new Error(`${label} is not a UTC RFC3339 timestamp`);
  const base = match[1] ?? "";
  if (Number(base.slice(0, 4)) < 1) {
    throw new Error(`${label} is not a real timestamp`);
  }
  const date = new Date(`${base}Z`);
  if (
    Number.isNaN(date.getTime()) ||
    date.toISOString().slice(0, 19) !== base
  ) {
    throw new Error(`${label} is not a real timestamp`);
  }
  const nanos = BigInt((match[2] ?? "").padEnd(9, "0") || "0");
  return BigInt(date.getTime()) * 1_000_000n + nanos;
}

function asArray(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

function validateLegs(value: unknown, label: string, minimum: number): Set<string> {
  const legs = asArray(value, label);
  if (legs.length < minimum || legs.length > 32) {
    throw new Error(`${label} must contain ${minimum}..32 entries`);
  }
  const ids: string[] = [];
  for (const [index, raw] of legs.entries()) {
    const leg = exactObject(raw, LEG_FIELDS, `${label}[${index}]`);
    const legId = token(leg.leg_id, `${label}[${index}].leg_id`, 64);
    token(leg.resource_type, `${label}[${index}].resource_type`, 160);
    const resourceId = boundedString(
      leg.resource_id,
      `${label}[${index}].resource_id`,
      1,
      512
    );
    const resourceMatch = RESOURCE_ID.exec(resourceId);
    if (!resourceMatch || UNSAFE_RESOURCE_SCHEMES.has(resourceMatch[1] ?? "")) {
      throw new Error(`${label}[${index}].resource_id is invalid`);
    }
    const quantity = boundedString(
      leg.quantity,
      `${label}[${index}].quantity`,
      1,
      80
    );
    if (
      !QUANTITY.test(quantity) ||
      quantity.replace(".", "").length > 78 ||
      (quantity.includes(".") && (quantity.split(".")[1]?.length ?? 0) > 30)
    ) {
      throw new Error(`${label}[${index}].quantity is invalid`);
    }
    token(leg.unit, `${label}[${index}].unit`, 80);
    digest(leg.descriptor_digest, `${label}[${index}].descriptor_digest`);
    ids.push(legId);
  }
  if (new Set(ids).size !== ids.length) {
    throw new Error(`${label} contains duplicate leg_id values`);
  }
  if (ids.some((value, index) => value !== [...ids].sort()[index])) {
    throw new Error(`${label} must be sorted by leg_id`);
  }
  return new Set(ids);
}

function validateRuleRefs(value: unknown): void {
  const refs = asArray(value, "rule_refs");
  if (refs.length > 32) throw new Error("rule_refs exceeds 32 entries");
  const order: string[] = [];
  for (const [index, raw] of refs.entries()) {
    const ref = exactObject(raw, RULE_REF_FIELDS, `rule_refs[${index}]`);
    const ruleId = boundedString(ref.rule_id, `rule_refs[${index}].rule_id`, 3, 160);
    if (!RULE_ID.test(ruleId)) throw new Error(`rule_refs[${index}].rule_id is invalid`);
    order.push(`${ruleId}\0${digest(ref.digest, `rule_refs[${index}].digest`)}`);
  }
  if (new Set(order).size !== order.length) {
    throw new Error("rule_refs contains duplicate entries");
  }
  if (order.some((value, index) => value !== [...order].sort()[index])) {
    throw new Error("rule_refs must be sorted");
  }
}

function validateOfferSnapshot(document: Record<string, unknown>): void {
  exactObject(document, OFFER_FIELDS, "offer");
  if (
    document.kind !== "org.nthdao.trade.offer" ||
    document.protocol_version !== "2.0"
  ) {
    throw new Error("unsupported offer protocol");
  }
  const offerId = boundedString(document.offer_id, "offer_id", 3, 256);
  if (!OFFER_ID.test(offerId)) throw new Error("offer_id is invalid");
  const revision = document.revision;
  if (
    typeof revision !== "number" ||
    !Number.isInteger(revision) ||
    revision < 1 ||
    revision > 2_147_483_647
  ) {
    throw new Error("revision is invalid");
  }
  if (revision === 1) {
    if (document.previous_offer_digest !== null) {
      throw new Error("revision 1 cannot bind a previous offer");
    }
  } else {
    digest(document.previous_offer_digest, "previous_offer_digest");
  }
  if (document.state !== "active" && document.state !== "withdrawn") {
    throw new Error("state is invalid");
  }
  if (revision === 1 && document.state === "withdrawn") {
    throw new Error("an initial offer cannot be withdrawn");
  }
  boundedString(document.publisher_did, "publisher_did", 1, 256);
  boundedString(document.title, "title", 1, 160);
  const summary = boundedString(document.summary, "summary", 0, 2_000);
  if (utf8(summary).byteLength > 8_000) throw new Error("summary is too large");
  const provides = validateLegs(document.provides, "provides", 1);
  const requests = validateLegs(document.requests, "requests", 0);
  if ([...provides].some((legId) => requests.has(legId))) {
    throw new Error("leg_id values overlap");
  }
  validateRuleRefs(document.rule_refs);
  const published = timestampNanos(document.published_at, "published_at");
  if (
    document.not_after !== null &&
    timestampNanos(document.not_after, "not_after") <= published
  ) {
    throw new Error("not_after must be later than published_at");
  }
  const extensions = asObject(document.extensions, "extensions");
  if (Object.keys(extensions).length > 32) throw new Error("extensions exceeds 32 entries");
  for (const [key, value] of Object.entries(extensions)) {
    if (!EXTENSION_ID.test(key)) throw new Error(`extension id ${key} is invalid`);
    asObject(value, `extension ${key}`);
  }

  const proof = exactObject(document.proof, PROOF_FIELDS, "proof");
  if (
    proof.type !== "NthEd25519SignatureV1" ||
    proof.proof_purpose !== "assertionMethod"
  ) {
    throw new Error("proof options are invalid");
  }
  const proofCreated = timestampNanos(proof.created, "proof.created");
  if (proofCreated < published) throw new Error("proof predates publication");
  if (
    document.not_after !== null &&
    timestampNanos(document.not_after, "not_after") <= proofCreated
  ) {
    throw new Error("offer expires before its proof");
  }
  if (
    typeof document.publisher_did !== "string" ||
    proof.verification_method !==
      `${document.publisher_did}#${document.publisher_did.slice("did:key:".length)}`
  ) {
    throw new Error("verification_method does not match publisher_did");
  }
  decodeDidKey(document.publisher_did);
  decodeBase64Url(boundedString(proof.proof_value, "proof.proof_value", 86, 86));
}

export function validateTradeOffer(offer: unknown): Record<string, unknown> {
  const snapshot = asObject(
    JSON.parse(new TextDecoder().decode(tradeCanonicalBytes(offer))),
    "offer"
  );
  validateOfferSnapshot(snapshot);
  return deepFreezeJson(snapshot);
}

function deepFreezeJson<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value as Record<string, unknown>)) {
      deepFreezeJson(child);
    }
    Object.freeze(value);
  }
  return value;
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

export function offerSigningInput(
  offer: unknown,
  domain = TRADE_OFFER_DOMAIN
): Uint8Array {
  return manifestSigningInput(offer, domain);
}

export function recognitionSigningInput(
  recognition: unknown,
  domain = TRADE_RULE_RECOGNITION_DOMAIN
): Uint8Array {
  return manifestSigningInput(recognition, domain);
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

export async function verifyOfferSourceSignature(
  offer: unknown,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
  domain = TRADE_OFFER_DOMAIN
): Promise<boolean> {
  try {
    const document = asObject(
      JSON.parse(new TextDecoder().decode(tradeCanonicalBytes(offer))),
      "offer"
    );
    const proof = asObject(document.proof, "proof");
    if (
      document.kind !== "org.nthdao.trade.offer" ||
      document.protocol_version !== "2.0" ||
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
      asArrayBuffer(offerSigningInput(document, domain))
    );
  } catch {
    return false;
  }
}

export async function verifyRuleRecognitionSignature(
  recognition: unknown,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
  domain = TRADE_RULE_RECOGNITION_DOMAIN
): Promise<boolean> {
  try {
    const document = asObject(
      JSON.parse(new TextDecoder().decode(tradeCanonicalBytes(recognition))),
      "recognition"
    );
    const proof = asObject(document.proof, "proof");
    if (
      document.kind !== "nth.dao.trade.rule-recognition" ||
      document.protocol_version !== "1" ||
      proof.type !== "NthEd25519SignatureV1" ||
      proof.proof_purpose !== "tradeRuleRecognition" ||
      typeof document.issuer_did !== "string" ||
      typeof proof.verification_method !== "string" ||
      proof.verification_method !==
        `${document.issuer_did}#${document.issuer_did.slice("did:key:".length)}` ||
      typeof proof.proof_value !== "string"
    ) {
      return false;
    }
    const keyBytes = decodeDidKey(document.issuer_did);
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
      asArrayBuffer(recognitionSigningInput(document, domain))
    );
  } catch {
    return false;
  }
}

async function verifyOfferSnapshotSignature(
  document: Record<string, unknown>,
  subtle: SubtleCrypto,
  domain: string
): Promise<boolean> {
  const proof = asObject(document.proof, "proof");
  if (
    typeof document.publisher_did !== "string" ||
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
    asArrayBuffer(offerSigningInput(document, domain))
  );
}

export async function verifyOffer(
  offer: unknown,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
  domain = TRADE_OFFER_DOMAIN
): Promise<boolean> {
  try {
    const snapshot = validateTradeOffer(offer);
    return await verifyOfferSnapshotSignature(snapshot, subtle, domain);
  } catch {
    return false;
  }
}

export type OfferActivity =
  | "active"
  | "expired"
  | "not_yet_active"
  | "withdrawn"
  | "invalid";

export async function evaluateTradeOffer(
  offer: unknown,
  at: Date = new Date(),
  subtle: SubtleCrypto = globalThis.crypto.subtle
): Promise<{ active: boolean; reason: OfferActivity }> {
  if (Number.isNaN(at.getTime())) return { active: false, reason: "invalid" };
  try {
    const snapshot = validateTradeOffer(offer);
    if (!(await verifyOfferSnapshotSignature(snapshot, subtle, TRADE_OFFER_DOMAIN))) {
      return { active: false, reason: "invalid" };
    }
    const moment = BigInt(at.getTime()) * 1_000_000n;
    if (moment < timestampNanos(snapshot.published_at, "published_at")) {
      return { active: false, reason: "not_yet_active" };
    }
    if (
      snapshot.not_after !== null &&
      moment >= timestampNanos(snapshot.not_after, "not_after")
    ) {
      return { active: false, reason: "expired" };
    }
    if (snapshot.state === "withdrawn") {
      return { active: false, reason: "withdrawn" };
    }
    return { active: true, reason: "active" };
  } catch {
    return { active: false, reason: "invalid" };
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

export async function offerDigest(
  offer: unknown,
  subtle: SubtleCrypto = globalThis.crypto.subtle
): Promise<string> {
  const canonical = tradeCanonicalBytes(offer);
  const snapshot = JSON.parse(new TextDecoder().decode(canonical));
  try {
    validateOfferSnapshot(asObject(snapshot, "offer"));
  } catch {
    throw new Error("offer semantics invalid");
  }
  if (!(await verifyOfferSnapshotSignature(snapshot, subtle, TRADE_OFFER_DOMAIN))) {
    throw new Error("offer signature invalid");
  }
  const digest = new Uint8Array(
    await subtle.digest("SHA-256", asArrayBuffer(canonical))
  );
  return `sha256:${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}
