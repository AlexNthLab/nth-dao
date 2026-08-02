// Browser-side Ed25519 keystore + canonical-JSON signer.
//
// Mirrors `nth_dao.identity.canonical_json` (sort_keys=True,
// separators=(",", ":"), ensure_ascii=False, UTF-8 bytes) so signatures
// produced here verify on the Python side and vice versa.
//
// Uses WebCrypto's native Ed25519 (Chrome 137+, Firefox 130+, Safari 17.4+).
// The private key is a non-extractable CryptoKey in IndexedDB. The UI never
// sees raw private-key bytes; only the public key is exported as hex.
// in localStorage for quick read access.

const DB_NAME = "nth-dao-wallet";
const STORE = "keys";
const KEY_NAME = "ed25519-main";
const PUBKEY_LS = "nth-dao-pubkey-hex";

export type JSONValue = null | boolean | number | string | JSONValue[] | { [key: string]: JSONValue };

function assertJSONValue(value: unknown, path = "$"): asserts value is JSONValue {
  if (value === null) return;
  const t = typeof value;
  if (t === "string" || t === "boolean") return;
  if (t === "number") {
    if (!Number.isFinite(value)) throw new Error(`cannot sign non-finite number at ${path}`);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertJSONValue(item, `${path}[${index}]`));
    return;
  }
  if (t === "object") {
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      throw new Error(`cannot sign non-plain object at ${path}`);
    }
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (item === undefined) throw new Error(`cannot sign undefined at ${path}.${key}`);
      assertJSONValue(item, `${path}.${key}`);
    }
    return;
  }
  throw new Error(`cannot sign ${t} at ${path}`);
}

// Stable, deterministic JSON encoding - sorted keys, no whitespace, recursive.
export function canonicalJSON(value: unknown): string {
  assertJSONValue(value);
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJSON).join(",") + "]";
  const obj = value as Record<string, JSONValue>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJSON(obj[k])).join(",") + "}";
}

function toHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function dbGet(key: string): Promise<CryptoKeyPair | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly").objectStore(STORE).get(key);
    tx.onsuccess = () => resolve((tx.result as CryptoKeyPair | undefined) ?? null);
    tx.onerror = () => reject(tx.error);
  });
}

async function dbPut(key: string, value: CryptoKeyPair): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite").objectStore(STORE).put(value, key);
    tx.onsuccess = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export interface BrowserWallet {
  pubkeyHex: string;
  sign: (payload: unknown) => Promise<string>;
}

/**
 * Load the local Ed25519 keypair, generating + persisting one on first use.
 * Throws if WebCrypto Ed25519 isn't available in this browser.
 */
export async function loadOrCreateWallet(): Promise<BrowserWallet> {
  if (!("subtle" in crypto)) throw new Error("WebCrypto unavailable");
  let pair = await dbGet(KEY_NAME);
  if (!pair) {
    pair = (await crypto.subtle.generateKey(
      { name: "Ed25519" } as AlgorithmIdentifier,
      false, // non-extractable private key
      ["sign", "verify"]
    )) as CryptoKeyPair;
    await dbPut(KEY_NAME, pair);
  }
  const raw = await crypto.subtle.exportKey("raw", pair.publicKey);
  const pubkeyHex = toHex(raw);
  window.localStorage.setItem(PUBKEY_LS, pubkeyHex);
  const sign = async (payload: unknown): Promise<string> => {
    const msg = new TextEncoder().encode(canonicalJSON(payload));
    const sig = await crypto.subtle.sign({ name: "Ed25519" } as AlgorithmIdentifier, pair!.privateKey, msg);
    return toHex(sig);
  };
  return { pubkeyHex, sign };
}
