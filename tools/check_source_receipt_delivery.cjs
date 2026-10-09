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

function verify(signature, bytes, key, label = 'signature') {
  assert.equal(crypto.verify(null, Buffer.from(bytes), key, Buffer.from(signature, 'base64url')), true, label);
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

function didKey(hex) {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let value = BigInt('0xed01' + hex);
  let encoded = '';
  while (value > 0n) {
    encoded = alphabet[Number(value % 58n)] + encoded;
    value /= 58n;
  }
  return 'did:key:z' + encoded;
}

function verifyEnvelope(value, pubkeyHex) {
  const { signature: sig, ...signed } = value;
  signed.routing = { hop_limit: value.routing.hop_limit };
  const { message_id: id, ...addressed } = signed;
  assert.equal(value.protocol, 'nth-transport-envelope');
  assert.equal(value.version, 1);
  assert.equal(value.sender_did, didKey(pubkeyHex));
  assert.equal(id, 'sha256:' + hash(canonical(addressed)));
  assert.equal(value.payload_hash, 'sha256:' + hash(canonical(value.payload)));
  verify(sig, canonical(signed), publicKey(pubkeyHex), 'outer-signature');
}

function verifyAckReturn(vector) {
  assert.equal(vector.format, 'nth-delivery-ack-envelope-v1');
  assert.equal(vector.synthetic, true);
  assert.equal(vector.verification_scope, 'wire_binding_only_not_local_source_authorization');
  const original = vector.original_envelope;
  const returned = vector.return_envelope;
  verifyEnvelope(original, vector.source_pubkey_hex);
  verifyEnvelope(returned, vector.receiver_pubkey_hex);
  assert.equal(returned.kind, 'delivery.ack');
  assert.equal(returned.recipient, original.sender_did, 'recipient-binding');
  assert.deepEqual(returned.routing, { hop_limit: 0, hop_count: 0 });
  assert.deepEqual(Object.keys(returned.payload), ['ack']);
  const { signature: sig, ...ack } = returned.payload.ack;
  assert.equal(ack.protocol, 'nth-delivery-ack');
  assert.equal(ack.version, 1);
  assert.equal(ack.kind, 'delivery.ack');
  assert.equal(ack.status, 'received');
  assert.equal(ack.receiver_did, original.recipient, 'receiver-binding');
  assert.equal(ack.receiver_did, returned.sender_did, 'receiver-binding');
  assert.equal(ack.message_id, original.message_id);
  assert.equal(ack.envelope_sha256, 'sha256:' + hash(canonical(original)), 'digest-binding');
  assert(ack.received_at_ms >= original.created_at_ms - 300000);
  assert(ack.received_at_ms < original.expires_at_ms);
  verify(sig, canonical(ack), publicKey(vector.receiver_pubkey_hex), 'inner-signature');
  for (const item of vector.time_cases) {
    const valid = returned.created_at_ms <= item.now_ms + 300000
      && item.now_ms < returned.expires_at_ms && ack.received_at_ms <= item.now_ms + 300000;
    assert.equal(valid, item.expected_valid, item.id);
  }
}

const returnFilename = process.argv[3] || path.join(
  __dirname, '../nth_dao/market/vectors/ack-return-envelope-v1.json',
);
const returnFixture = JSON.parse(fs.readFileSync(returnFilename, 'utf8'));
verifyAckReturn(returnFixture);

function signTestEnvelope(value, key) {
  const { signature: ignoredSignature, message_id: ignoredAddress, ...content } = value;
  content.payload_hash = 'sha256:' + hash(canonical(value.payload));
  content.routing = { hop_limit: value.routing.hop_limit };
  value.payload_hash = content.payload_hash;
  value.message_id = 'sha256:' + hash(canonical(content));
  value.signature = crypto.sign(null, Buffer.from(canonical({ ...content, message_id: value.message_id })), key)
    .toString('base64url');
}

function signTestAck(ack, key) {
  const { signature: ignored, ...body } = ack;
  ack.signature = crypto.sign(null, Buffer.from(canonical(body)), key).toString('base64url');
}

// Ephemeral test keys are never serialized. Every inner negative has a valid
// outer signature/address so it must reach the intended inner/binding check.
const sourcePair = crypto.generateKeyPairSync('ed25519');
const receiverPair = crypto.generateKeyPairSync('ed25519');
const hostileBase = structuredClone(returnFixture);
hostileBase.source_pubkey_hex = sourcePair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
hostileBase.receiver_pubkey_hex = receiverPair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
const testOriginal = hostileBase.original_envelope;
testOriginal.sender_did = didKey(hostileBase.source_pubkey_hex);
testOriginal.recipient = didKey(hostileBase.receiver_pubkey_hex);
testOriginal.kind = 'chat.message';
testOriginal.payload = { text: 'synthetic ACK signature boundary' };
signTestEnvelope(testOriginal, sourcePair.privateKey);
const testReturn = hostileBase.return_envelope;
testReturn.sender_did = testOriginal.recipient;
testReturn.recipient = testOriginal.sender_did;
Object.assign(testReturn.payload.ack, {
  message_id: testOriginal.message_id, envelope_sha256: 'sha256:' + hash(canonical(testOriginal)),
  receiver_did: testOriginal.recipient,
});
signTestAck(testReturn.payload.ack, receiverPair.privateKey);
signTestEnvelope(testReturn, receiverPair.privateKey);
verifyAckReturn(hostileBase);

for (const tamper of ['outer-signature', 'inner-signature', 'receiver', 'recipient', 'digest']) {
  const changed = structuredClone(hostileBase);
  const returned = changed.return_envelope;
  const ack = returned.payload.ack;
  if (tamper === 'inner-signature') ack.signature = '';
  if (tamper === 'receiver') ack.receiver_did = changed.original_envelope.sender_did;
  if (tamper === 'recipient') returned.recipient = changed.original_envelope.recipient;
  if (tamper === 'digest') ack.envelope_sha256 = 'sha256:' + '0'.repeat(64);
  if (tamper === 'receiver' || tamper === 'digest') signTestAck(ack, receiverPair.privateKey);
  signTestEnvelope(returned, receiverPair.privateKey);
  if (tamper === 'outer-signature') returned.signature = '';
  else verifyEnvelope(returned, changed.receiver_pubkey_hex);
  const expected = ['receiver', 'recipient', 'digest'].includes(tamper) ? tamper + '-binding' : tamper;
  assert.throws(() => verifyAckReturn(changed), error => error.message.includes(expected), tamper);
}
console.log('PASS: directed ACK return, both signatures, DID/key binding, TTL boundaries, five isolated tamper cases');
