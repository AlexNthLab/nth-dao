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
export const TRADE_DISPUTE_STATEMENT_DOMAIN =
  "nth-dao/trade-dispute-statement/v1";

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
const RECOGNITION_AUDIT_TIMESTAMP =
  /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{6})?Z$/;
const RECOGNITION_ID = /^nth-trade-recognition-sha256:[0-9a-f]{64}$/;
const RECOGNITION_AUDIT_FIELDS = [
  "protocol_version",
  "recognition_id",
  "recognition_digest",
  "rule_id",
  "package_digest",
  "issuer_did",
  "sequence",
  "decision",
  "issued_at",
  "not_after",
] as const;
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

const DISPUTE_STATEMENT_FIELDS = [
  "kind",
  "protocol_version",
  "statement_id",
  "dispute_id",
  "order_digest",
  "receipt_digest",
  "review_digest",
  "review_id",
  "author_did",
  "author_role",
  "statement_type",
  "parent_statement_digests",
  "reason_codes",
  "claim",
  "evidence",
  "rule_action",
  "created_at",
  "proof",
] as const;
const DISPUTE_CLAIM_FIELDS = [
  "claim_type",
  "media_type",
  "digest",
  "size",
  "schema_digest",
] as const;
const DISPUTE_EVIDENCE_FIELDS = [
  "purpose",
  "media_type",
  "digest",
  "size",
] as const;
const DISPUTE_RULE_ACTION_FIELDS = [
  "rule_id",
  "digest",
  "hook",
  "hook_version",
] as const;
const DISPUTE_PACKAGE_FIELDS = ["digest", "manifest", "resources"] as const;
const DISPUTE_PACKAGE_RESOURCE_FIELDS = ["bytes_hex", "digest"] as const;
const DISPUTE_TIMESTAMP =
  /^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{6}))?Z$/;
const DISPUTE_STATEMENT_ID =
  /^nth-trade-dispute-statement-sha256:[0-9a-f]{64}$/;
const DISPUTE_ID = /^nth-trade-dispute-sha256:[0-9a-f]{64}$/;
const DISPUTE_REVIEW_ID = /^nth-trade-review-sha256:[0-9a-f]{64}$/;
const DISPUTE_REASON = /^[a-z][a-z0-9._:-]{0,127}$/;
const DISPUTE_TOKEN = /^[a-z][a-z0-9._:/-]{0,127}$/;
const DISPUTE_HOOK = /^[a-z0-9][a-z0-9._:/-]{0,127}$/;
const DISPUTE_HOOK_VERSION = /^[a-z0-9][a-z0-9._:/-]{0,31}$/;
const DISPUTE_MEDIA_TYPE = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;
const MAX_DISPUTE_CONTENT_BYTES = 16 * 1024 * 1024;
const MAX_DISPUTE_TOTAL_EVIDENCE_BYTES = 64 * 1024 * 1024;

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

export function disputeStatementSigningInput(
  statement: unknown,
  domain = TRADE_DISPUTE_STATEMENT_DOMAIN
): Uint8Array {
  return manifestSigningInput(statement, domain);
}

export function validateRuleRecognitionAuditPayload(
  value: unknown
): Record<string, unknown> {
  const payload = exactObject(
    value,
    RECOGNITION_AUDIT_FIELDS,
    "Recognition Spine payload"
  );
  if (payload.protocol_version !== "1") {
    throw new Error("Recognition Spine payload protocol version is unsupported");
  }
  if (
    typeof payload.recognition_id !== "string" ||
    !RECOGNITION_ID.test(payload.recognition_id)
  ) {
    throw new Error("Recognition Spine payload recognition_id is invalid");
  }
  digest(payload.recognition_digest, "recognition_digest");
  digest(payload.package_digest, "package_digest");
  if (typeof payload.rule_id !== "string" || !RULE_ID.test(payload.rule_id)) {
    throw new Error("Recognition Spine payload rule_id is invalid");
  }
  if (typeof payload.issuer_did !== "string") {
    throw new Error("Recognition Spine payload issuer_did is invalid");
  }
  decodeDidKey(payload.issuer_did);
  if (
    typeof payload.sequence !== "number" ||
    !Number.isSafeInteger(payload.sequence) ||
    payload.sequence < 1 ||
    payload.sequence > 2_147_483_647
  ) {
    throw new Error("Recognition Spine payload sequence is invalid");
  }
  if (
    payload.decision !== "recognized" &&
    payload.decision !== "deprecated" &&
    payload.decision !== "revoked"
  ) {
    throw new Error("Recognition Spine payload decision is invalid");
  }
  for (const field of ["issued_at", "not_after"] as const) {
    if (
      typeof payload[field] !== "string" ||
      !RECOGNITION_AUDIT_TIMESTAMP.test(payload[field]) ||
      payload[field].endsWith(".000000Z")
    ) {
      throw new Error(`Recognition Spine payload ${field} is invalid`);
    }
  }
  const issuedAt = timestampNanos(payload.issued_at, "issued_at");
  const notAfter = timestampNanos(payload.not_after, "not_after");
  if (notAfter <= issuedAt) {
    throw new Error(
      "Recognition Spine payload not_after must follow issued_at"
    );
  }
  return payload;
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

export async function verifyTradeDisputeStatementSignature(
  statement: unknown,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
  domain = TRADE_DISPUTE_STATEMENT_DOMAIN
): Promise<boolean> {
  try {
    const document = asObject(
      JSON.parse(new TextDecoder().decode(tradeCanonicalBytes(statement))),
      "trade dispute statement"
    );
    const proof = asObject(document.proof, "proof");
    if (
      document.kind !== "nth.dao.trade.dispute-statement" ||
      document.protocol_version !== "1" ||
      proof.type !== "Ed25519Signature2020" ||
      proof.proof_purpose !== "tradeDisputeStatement" ||
      proof.created !== document.created_at ||
      typeof document.author_did !== "string" ||
      typeof proof.verification_method !== "string" ||
      proof.verification_method !==
        `${document.author_did}#${document.author_did.slice("did:key:".length)}` ||
      typeof proof.proof_value !== "string"
    ) {
      return false;
    }
    const keyBytes = decodeDidKey(document.author_did);
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
      asArrayBuffer(disputeStatementSigningInput(document, domain))
    );
  } catch {
    return false;
  }
}

export type TradeDisputeStatementVerificationContext = {
  /** These artifacts must first pass their own protocol validators. */
  order: unknown;
  receipt: unknown;
  review: unknown;
  observedAt: string;
  clockSkewSeconds?: number;
  resolvedRulePackage?: unknown;
};

export type TradeDisputeStatementVerificationResult = {
  valid: boolean;
  reason: string;
};

function disputeTimestampMicros(value: unknown, label: string): bigint {
  const text = boundedString(value, label, 1, 35);
  const match = DISPUTE_TIMESTAMP.exec(text);
  if (!match || match[2] === "000000") {
    throw new Error(`${label} must be a canonical UTC RFC3339 timestamp`);
  }
  const base = match[1] ?? "";
  if (Number(base.slice(0, 4)) < 1) {
    throw new Error(`${label} is not a real timestamp`);
  }
  const date = new Date(`${base}Z`);
  if (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 19) !== base) {
    throw new Error(`${label} is not a real timestamp`);
  }
  const micros = BigInt(match[2] ?? "0");
  return BigInt(date.getTime()) * 1_000n + micros;
}

function disputeSize(value: unknown, label: string): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > MAX_DISPUTE_CONTENT_BYTES
  ) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function sortedUniqueStrings(
  value: unknown,
  label: string,
  limit: number,
  validator: RegExp
): string[] {
  const items = asArray(value, label);
  if (
    items.length > limit ||
    items.some((item) => typeof item !== "string" || !validator.test(item))
  ) {
    throw new Error(`${label} must be bounded, sorted, and unique`);
  }
  const strings = items as string[];
  const sorted = [...new Set(strings)].sort();
  if (
    sorted.length !== strings.length ||
    strings.some((item, index) => item !== sorted[index])
  ) {
    throw new Error(`${label} must be bounded, sorted, and unique`);
  }
  return strings;
}

type DisputeContentBinding = {
  digest: string;
  mediaType: string;
  size: number;
};

function validateDisputeClaim(
  value: unknown,
  statementType: string
): DisputeContentBinding | null {
  if (value === null) {
    if (statementType !== "evidence") {
      throw new Error("response and remedy statements require a typed claim");
    }
    return null;
  }
  if (statementType === "evidence") {
    throw new Error("evidence statements cannot contain a claim");
  }
  const claim = exactObject(value, DISPUTE_CLAIM_FIELDS, "claim");
  const claimType = boundedString(claim.claim_type, "claim.claim_type", 1, 128);
  if (!DISPUTE_TOKEN.test(claimType)) throw new Error("claim.claim_type is invalid");
  const mediaType = boundedString(claim.media_type, "claim.media_type", 1, 127);
  if (!DISPUTE_MEDIA_TYPE.test(mediaType)) {
    throw new Error("claim.media_type is invalid");
  }
  const claimDigest = digest(claim.digest, "claim.digest");
  const size = disputeSize(claim.size, "claim.size");
  if (claim.schema_digest !== null) digest(claim.schema_digest, "claim.schema_digest");
  return { digest: claimDigest, mediaType, size };
}

type DisputeEvidenceBinding = DisputeContentBinding & { purpose: string };

function compareEvidence(
  left: DisputeEvidenceBinding,
  right: DisputeEvidenceBinding
): number {
  for (const pair of [
    [left.purpose, right.purpose],
    [left.digest, right.digest],
    [left.mediaType, right.mediaType],
  ] as const) {
    if (pair[0] < pair[1]) return -1;
    if (pair[0] > pair[1]) return 1;
  }
  return left.size - right.size;
}

function validateDisputeEvidence(value: unknown): DisputeEvidenceBinding[] {
  const items = asArray(value, "evidence");
  if (items.length > 32) throw new Error("evidence must be a bounded list");
  const bindings = items.map((raw, index) => {
    const item = exactObject(raw, DISPUTE_EVIDENCE_FIELDS, `evidence[${index}]`);
    const purpose = boundedString(
      item.purpose,
      `evidence[${index}].purpose`,
      1,
      128
    );
    if (!DISPUTE_TOKEN.test(purpose)) {
      throw new Error(`evidence[${index}].purpose is invalid`);
    }
    const mediaType = boundedString(
      item.media_type,
      `evidence[${index}].media_type`,
      1,
      127
    );
    if (!DISPUTE_MEDIA_TYPE.test(mediaType)) {
      throw new Error(`evidence[${index}].media_type is invalid`);
    }
    return {
      purpose,
      digest: digest(item.digest, `evidence[${index}].digest`),
      mediaType,
      size: disputeSize(item.size, `evidence[${index}].size`),
    };
  });
  const sorted = [...bindings].sort(compareEvidence);
  if (
    bindings.some((item, index) => compareEvidence(item, sorted[index]!) !== 0) ||
    bindings.some(
      (item, index) => index > 0 && compareEvidence(item, bindings[index - 1]!) === 0
    )
  ) {
    throw new Error("evidence must be sorted and contain no duplicate entries");
  }
  const metadata = new Map<string, string>();
  let totalSize = 0;
  for (const item of bindings) {
    totalSize += item.size;
    if (totalSize > MAX_DISPUTE_TOTAL_EVIDENCE_BYTES) {
      throw new Error("declared dispute evidence exceeds its total byte limit");
    }
    const current = `${item.mediaType}\0${item.size}`;
    const previous = metadata.get(item.digest);
    if (previous !== undefined && previous !== current) {
      throw new Error("one evidence digest cannot declare conflicting metadata");
    }
    metadata.set(item.digest, current);
  }
  return bindings;
}

function validateTradeDisputeStatementShape(
  value: unknown
): Record<string, unknown> {
  const document = exactObject(
    JSON.parse(new TextDecoder().decode(tradeCanonicalBytes(value))),
    DISPUTE_STATEMENT_FIELDS,
    "trade dispute statement"
  );
  if (
    document.kind !== "nth.dao.trade.dispute-statement" ||
    document.protocol_version !== "1"
  ) {
    throw new Error("unsupported trade dispute statement protocol");
  }
  if (typeof document.statement_id !== "string" || !DISPUTE_STATEMENT_ID.test(document.statement_id)) {
    throw new Error("statement_id is invalid");
  }
  if (typeof document.dispute_id !== "string" || !DISPUTE_ID.test(document.dispute_id)) {
    throw new Error("dispute_id is invalid");
  }
  for (const field of ["order_digest", "receipt_digest", "review_digest"] as const) {
    digest(document[field], field);
  }
  if (typeof document.review_id !== "string" || !DISPUTE_REVIEW_ID.test(document.review_id)) {
    throw new Error("review_id is invalid");
  }
  if (typeof document.author_did !== "string") throw new Error("author_did is invalid");
  decodeDidKey(document.author_did);
  if (document.author_role !== "maker" && document.author_role !== "taker") {
    throw new Error("author_role is invalid");
  }
  if (
    document.statement_type !== "response" &&
    document.statement_type !== "evidence" &&
    document.statement_type !== "remedy-proposal"
  ) {
    throw new Error("statement_type is invalid");
  }
  sortedUniqueStrings(
    document.parent_statement_digests,
    "parent_statement_digests",
    64,
    DIGEST
  );
  const reasons = sortedUniqueStrings(
    document.reason_codes,
    "reason_codes",
    32,
    DISPUTE_REASON
  );
  const claim = validateDisputeClaim(document.claim, document.statement_type);
  const evidence = validateDisputeEvidence(document.evidence);
  if (document.statement_type === "evidence" && evidence.length === 0) {
    throw new Error("evidence statements require at least one evidence reference");
  }
  if (document.statement_type !== "evidence" && reasons.length === 0) {
    throw new Error("response and remedy statements require a reason code");
  }
  if (claim !== null) {
    for (const item of evidence) {
      if (
        item.digest === claim.digest &&
        (item.mediaType !== claim.mediaType || item.size !== claim.size)
      ) {
        throw new Error("claim and evidence metadata conflict for one digest");
      }
    }
  }
  if (document.rule_action !== null) {
    const action = exactObject(
      document.rule_action,
      DISPUTE_RULE_ACTION_FIELDS,
      "rule_action"
    );
    if (typeof action.rule_id !== "string" || !RULE_ID.test(action.rule_id)) {
      throw new Error("rule_action.rule_id is invalid");
    }
    digest(action.digest, "rule_action.digest");
    if (typeof action.hook !== "string" || !DISPUTE_HOOK.test(action.hook)) {
      throw new Error("rule_action.hook is invalid");
    }
    if (
      typeof action.hook_version !== "string" ||
      !DISPUTE_HOOK_VERSION.test(action.hook_version)
    ) {
      throw new Error("rule_action.hook_version is invalid");
    }
  }
  disputeTimestampMicros(document.created_at, "created_at");
  const proof = exactObject(document.proof, PROOF_FIELDS, "proof");
  if (
    proof.type !== "Ed25519Signature2020" ||
    proof.proof_purpose !== "tradeDisputeStatement" ||
    proof.created !== document.created_at ||
    proof.verification_method !==
      `${document.author_did}#${document.author_did.slice("did:key:".length)}` ||
    typeof proof.proof_value !== "string"
  ) {
    throw new Error("trade dispute statement proof is invalid");
  }
  decodeBase64Url(proof.proof_value);
  return document;
}

async function sha256Digest(
  value: unknown,
  subtle: SubtleCrypto
): Promise<string> {
  const hash = new Uint8Array(
    await subtle.digest("SHA-256", asArrayBuffer(tradeCanonicalBytes(value)))
  );
  return `sha256:${Array.from(hash, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("")}`;
}

async function validateResolvedDisputePackage(
  value: unknown,
  action: Record<string, unknown>,
  subtle: SubtleCrypto
): Promise<void> {
  const rulePackage = exactObject(value, DISPUTE_PACKAGE_FIELDS, "resolved Rule Package");
  if (rulePackage.digest !== action.digest) {
    throw new Error("rule_action package digest mismatch");
  }
  const manifest = asObject(rulePackage.manifest, "resolved Rule Package manifest");
  if (!(await verifyManifestSignature(manifest, subtle))) {
    throw new Error("rule_action package manifest signature is invalid");
  }
  if ((await sha256Digest(manifest, subtle)) !== action.digest) {
    throw new Error("rule_action package manifest digest mismatch");
  }
  if (manifest.rule_id !== action.rule_id) {
    throw new Error("rule_action rule_id does not match the resolved package");
  }
  const declarations = asArray(manifest.resources, "resolved Rule Package manifest.resources");
  const declared = new Map<string, number>();
  for (const [index, raw] of declarations.entries()) {
    const item = asObject(raw, `resolved Rule Package manifest.resources[${index}]`);
    const resourceDigest = digest(item.digest, `manifest.resources[${index}].digest`);
    const size = item.size;
    if (typeof size !== "number" || !Number.isSafeInteger(size) || size < 0) {
      throw new Error(`manifest.resources[${index}].size is invalid`);
    }
    const previous = declared.get(resourceDigest);
    if (previous !== undefined && previous !== size) {
      throw new Error("resolved Rule Package declares conflicting resource sizes");
    }
    declared.set(resourceDigest, size);
  }
  const supplied = new Set<string>();
  for (const [index, raw] of asArray(rulePackage.resources, "resolved Rule Package resources").entries()) {
    const item = exactObject(raw, DISPUTE_PACKAGE_RESOURCE_FIELDS, `resources[${index}]`);
    const resourceDigest = digest(item.digest, `resources[${index}].digest`);
    if (supplied.has(resourceDigest)) throw new Error("resolved Rule Package repeats a resource");
    if (typeof item.bytes_hex !== "string" || !/^(?:[0-9a-f]{2})*$/.test(item.bytes_hex)) {
      throw new Error(`resources[${index}].bytes_hex is invalid`);
    }
    const payload = Uint8Array.from(
      item.bytes_hex.match(/.{2}/g) ?? [],
      (pair) => Number.parseInt(pair, 16)
    );
    const hash = new Uint8Array(await subtle.digest("SHA-256", asArrayBuffer(payload)));
    const actual = `sha256:${Array.from(hash, (byte) =>
      byte.toString(16).padStart(2, "0")
    ).join("")}`;
    if (actual !== resourceDigest || declared.get(resourceDigest) !== payload.byteLength) {
      throw new Error("resolved Rule Package resource bytes do not match the manifest");
    }
    supplied.add(resourceDigest);
  }
  if (supplied.size !== declared.size || [...declared.keys()].some((key) => !supplied.has(key))) {
    throw new Error("resolved Rule Package resources are incomplete");
  }
  const hooks = asArray(manifest.hook_contracts, "resolved Rule Package hook_contracts");
  if (
    !hooks.some((raw) => {
      const hook = asObject(raw, "resolved Rule Package hook contract");
      return hook.name === action.hook && hook.version === action.hook_version;
    })
  ) {
    throw new Error("rule_action hook name/version is absent from the package");
  }
}

export async function verifyTradeDisputeStatement(
  statement: unknown,
  context: TradeDisputeStatementVerificationContext,
  subtle: SubtleCrypto = globalThis.crypto.subtle
): Promise<TradeDisputeStatementVerificationResult> {
  try {
    const document = validateTradeDisputeStatementShape(statement);
    if (!(await verifyTradeDisputeStatementSignature(document, subtle))) {
      throw new Error("trade dispute statement signature is invalid");
    }
    const binding = { ...document };
    delete binding.statement_id;
    delete binding.proof;
    const expectedStatementId =
      "nth-trade-dispute-statement-sha256:" +
      (await sha256Digest(binding, subtle)).slice("sha256:".length);
    if (document.statement_id !== expectedStatementId) {
      throw new Error("statement_id does not match the statement binding");
    }

    const order = asObject(context.order, "verified Order");
    const receipt = asObject(context.receipt, "verified Execution Receipt");
    const review = asObject(context.review, "verified Receipt Review");
    const expectedDisputeId =
      "nth-trade-dispute-sha256:" +
      (await sha256Digest({ review_id: review.review_id }, subtle)).slice("sha256:".length);
    const bindings = [
      ["dispute_id", expectedDisputeId],
      ["order_digest", await sha256Digest(order, subtle)],
      ["receipt_digest", await sha256Digest(receipt, subtle)],
      ["review_digest", await sha256Digest(review, subtle)],
      ["review_id", review.review_id],
    ] as const;
    for (const [field, expected] of bindings) {
      if (document[field] !== expected) {
        throw new Error(`trade dispute statement ${field} binding mismatch`);
      }
    }
    if (review.decision !== "disputed") {
      throw new Error("trade dispute statements require a disputed Receipt Review");
    }
    const role = document.author_role as "maker" | "taker";
    if (document.author_did !== order[`${role}_did`]) {
      throw new Error("author_did does not match author_role in the signed Order");
    }
    if (document.statement_type === "response" && role !== receipt.executor_role) {
      throw new Error("a response must be signed by the Receipt executor");
    }
    if (
      disputeTimestampMicros(document.created_at, "created_at") <
      disputeTimestampMicros(review.reviewed_at, "review.reviewed_at")
    ) {
      throw new Error("trade dispute statement predates the disputed Review");
    }
    const skew = context.clockSkewSeconds ?? 300;
    if (!Number.isFinite(skew) || skew < 0 || skew * 1_000_000 > Number.MAX_SAFE_INTEGER) {
      throw new Error("clockSkewSeconds must be a finite non-negative number");
    }
    const observed = disputeTimestampMicros(context.observedAt, "observedAt");
    const created = disputeTimestampMicros(document.created_at, "created_at");
    if (created > observed + BigInt(Math.round(skew * 1_000_000))) {
      throw new Error("trade dispute statement is too far in the future");
    }

    if (document.rule_action !== null) {
      const action = asObject(document.rule_action, "rule_action");
      const signedBindings = asArray(order.rule_bindings, "Order rule_bindings");
      const bound = signedBindings.some((raw) => {
        const item = asObject(raw, "Order rule binding");
        return item.rule_id === action.rule_id && item.digest === action.digest;
      });
      if (!bound) throw new Error("rule_action is outside the signed Order rule bindings");
      if (context.resolvedRulePackage === undefined) {
        throw new Error("rule_action requires an exact-digest resolved Rule Package");
      }
      await validateResolvedDisputePackage(
        context.resolvedRulePackage,
        action,
        subtle
      );
    }
    return { valid: true, reason: "ok" };
  } catch (error) {
    return {
      valid: false,
      reason: error instanceof Error ? error.message : "invalid trade dispute statement",
    };
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
