'use strict';

// Independent Node crypto check of the public Python wire fixture. This
// verifies signatures and addresses, not local claim retention or acceptance.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(key => {
      assert.match(key, /^[\x20-\x7e]+$/, 'fixture object keys must be ASCII');
      return JSON.stringify(key) + ':' + canonical(value[key]);
    }).join(',') + '}';
  }
  throw new Error('unsupported canonical value');
}

function losslessJSON(text) {
  let supported = false;
  JSON.parse('0', (_key, value, context) => {
    supported = typeof context?.source === 'string';
    return value;
  });
  assert(supported, 'Node with JSON.parse reviver source support is required');
  return JSON.parse(text, (_key, value, context) => {
    if (typeof value !== 'number') return value;
    assert.match(context.source, /^-?(0|[1-9][0-9]*)$/, 'floats are outside this fixture');
    const integer = BigInt(context.source);
    return Number.isSafeInteger(value) ? value : integer;
  });
}

function hash(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function publicKey(hex) {
  assert.match(hex, /^[0-9a-f]{64}$/);
  return crypto.createPublicKey({
    key: Buffer.from('302a300506032b6570032100' + hex, 'hex'),
    format: 'der', type: 'spki',
  });
}

function verify(signature, bytes, key) {
  assert.equal(crypto.verify(null, Buffer.from(bytes), key, Buffer.from(signature, 'base64url')), true);
}

const filename = process.argv[2] || path.join(
  __dirname, '../nth_dao/market/vectors/source-receipt-delivery-v1.json',
);
const fixture = JSON.parse(fs.readFileSync(filename, 'utf8'));
assert.equal(fixture.format, 'nth-market-source-receipt-delivery-v1');
const envelope = fixture.envelope;
const { signature, ...body } = envelope;
body.routing = { hop_limit: envelope.routing.hop_limit };
const { message_id, ...content } = body;
assert.equal(envelope.message_id, 'sha256:' + hash(canonical(content)));
assert.equal(envelope.payload_hash, 'sha256:' + hash(canonical(envelope.payload)));
assert.equal(fixture.envelope_sha256, 'sha256:' + hash(canonical(envelope)));
assert.equal(envelope.sender_did, fixture.expected_source_did);
assert.equal(envelope.recipient, fixture.expected_recipient_did);
const sourceKey = publicKey(fixture.source_pubkey_hex);
verify(signature, canonical(body), sourceKey);

const response = losslessJSON(envelope.payload.source_receipt_json);
assert.equal(canonical(response), envelope.payload.source_receipt_json);
const { sig, content_hash, ...core } = response.source_receipt_event;
assert.equal(core.seq, 9007199254740993n);
assert.equal(content_hash, hash(canonical(core)));
assert.equal(response.audit_event_id, content_hash);
assert.equal(core.author_did, envelope.sender_did);
assert.equal(core.payload.claimant_did, envelope.recipient);
for (const field of ['source_claim_id', 'completion_head_digest', 'proof_digest']) {
  assert.equal(envelope.payload[field], core.payload[field]);
}
verify(sig, Buffer.from(content_hash, 'hex'), sourceKey);

const { signature: ackSignature, ...ackBody } = fixture.ack;
assert.equal(ackBody.receiver_did, envelope.recipient);
assert.equal(ackBody.message_id, envelope.message_id);
assert.equal(ackBody.envelope_sha256, fixture.envelope_sha256);
verify(ackSignature, canonical(ackBody), publicKey(fixture.claimant_pubkey_hex));
assert.equal(fixture.clock_skew_ms, 300000);
for (const item of fixture.ack_time_cases) {
  const receiptTime = (item.boundary === 'created'
    ? envelope.created_at_ms : envelope.expires_at_ms) + item.offset_ms;
  const accepted = envelope.created_at_ms - fixture.clock_skew_ms <= receiptTime
    && receiptTime < envelope.expires_at_ms;
  assert.equal(accepted, item.accepted, 'ACK time boundary');
}
console.log('PASS: envelope address/signature, lossless receipt event signature, receiver ACK, clock boundaries');
