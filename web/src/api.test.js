import test from 'node:test';
import assert from 'node:assert/strict';
import { api } from './api.ts';

test('api returns JSON and reports API errors', async () => {
  const original = globalThis.fetch;
  globalThis.document = { cookie: '' };
  try {
    globalThis.fetch = async () => new Response(JSON.stringify({ status: 'ok' }), { status: 200 });
    assert.deepEqual(await api('/healthz'), { status: 'ok' });
    globalThis.fetch = async () => new Response(JSON.stringify({ message: 'Not allowed' }), { status: 403 });
    await assert.rejects(api('/api/v1/test'), /Not allowed/);
  } finally { globalThis.fetch = original; delete globalThis.document; }
});
