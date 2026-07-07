// KV store adapter: same contract as memoryStore, backed by a (mock) KV namespace.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { kvStore } from '../src/oid4vci.mjs';

function mockKV() {
  const m = new Map();
  return {
    _m: m,
    async put(k, v, opts) { m.set(k, { v, ttl: opts?.expirationTtl }); },
    async get(k) { return m.has(k) ? m.get(k).v : null; },
    async delete(k) { m.delete(k); },
  };
}

test('kvStore: set/get round-trips JSON and applies a TTL floor of 60s', async () => {
  const kv = mockKV();
  const s = kvStore(kv);
  await s.set('at:abc', { ids: ['pid_mdoc'], userId: 'u_001' }, 600);
  assert.deepEqual(await s.get('at:abc'), { ids: ['pid_mdoc'], userId: 'u_001' });
  await s.set('nonce:x', { v: 1 }, 5); // below floor
  assert.equal(kv._m.get('nonce:x').ttl, 60);
});

test('kvStore: get returns null for missing key; del removes', async () => {
  const s = kvStore(mockKV());
  assert.equal(await s.get('missing'), null);
  await s.set('k', { a: 1 });
  await s.del('k');
  assert.equal(await s.get('k'), null);
});

test('kvStore is drop-in for IssuerService (pre-auth issuance works on KV)', async () => {
  const { IssuerService } = await import('../src/oid4vci.mjs');
  const svc = new IssuerService({ store: kvStore(mockKV()) });
  const { credential_offer, preAuthorizedCode } = await svc.createOffer(['pid_mdoc']);
  assert.ok(credential_offer.credential_issuer);
  const tok = await svc.token({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': preAuthorizedCode });
  assert.ok(tok.access_token);
});
