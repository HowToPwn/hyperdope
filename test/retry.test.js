import { test } from 'node:test';
import assert from 'node:assert/strict';
import { withRetry } from '../src/retry.js';

// Speed up tests — override delays via a tiny patch approach.
// We'll use maxAttempts and mock fns that resolve/reject synchronously.
// To avoid waiting on real setTimeout delays, we use baseDelayMs=0.

test('succeeds on first attempt — calls fn exactly once', async () => {
  let calls = 0;
  const result = await withRetry(() => { calls++; return Promise.resolve('ok'); }, { maxAttempts: 3, baseDelayMs: 0 });
  assert.equal(result, 'ok');
  assert.equal(calls, 1);
});

test('succeeds on 3rd attempt after 2 network failures', async () => {
  let calls = 0;
  const result = await withRetry(() => {
    calls++;
    if (calls < 3) {
      const err = new Error('Network error');
      // no status → treated as network error → retried
      return Promise.reject(err);
    }
    return Promise.resolve('success');
  }, { maxAttempts: 3, baseDelayMs: 0 });
  assert.equal(result, 'success');
  assert.equal(calls, 3);
});

test('throws after maxAttempts exhausted', async () => {
  let calls = 0;
  await assert.rejects(
    withRetry(() => {
      calls++;
      const err = new Error('always fails');
      return Promise.reject(err);
    }, { maxAttempts: 3, baseDelayMs: 0 }),
    /always fails/
  );
  assert.equal(calls, 3);
});

test('does NOT retry on 400 (client error)', async () => {
  let calls = 0;
  const err400 = Object.assign(new Error('Bad Request'), { status: 400 });
  await assert.rejects(
    withRetry(() => {
      calls++;
      return Promise.reject(err400);
    }, { maxAttempts: 3, baseDelayMs: 0 }),
    { status: 400 }
  );
  assert.equal(calls, 1);
});

test('does NOT retry on 401', async () => {
  let calls = 0;
  const err = Object.assign(new Error('Unauthorized'), { status: 401 });
  await assert.rejects(
    withRetry(() => { calls++; return Promise.reject(err); }, { maxAttempts: 3, baseDelayMs: 0 })
  );
  assert.equal(calls, 1);
});

test('does NOT retry on 403', async () => {
  let calls = 0;
  const err = Object.assign(new Error('Forbidden'), { status: 403 });
  await assert.rejects(
    withRetry(() => { calls++; return Promise.reject(err); }, { maxAttempts: 3, baseDelayMs: 0 })
  );
  assert.equal(calls, 1);
});

test('DOES retry on 429 (rate limited)', async () => {
  let calls = 0;
  const result = await withRetry(() => {
    calls++;
    if (calls < 3) {
      return Promise.reject(Object.assign(new Error('Rate limited'), { status: 429 }));
    }
    return Promise.resolve('ok after retry');
  }, { maxAttempts: 3, baseDelayMs: 0 });
  assert.equal(result, 'ok after retry');
  assert.equal(calls, 3);
});

test('DOES retry on 500 (server error)', async () => {
  let calls = 0;
  const result = await withRetry(() => {
    calls++;
    if (calls < 2) {
      return Promise.reject(Object.assign(new Error('Internal Server Error'), { status: 500 }));
    }
    return Promise.resolve('recovered');
  }, { maxAttempts: 3, baseDelayMs: 0 });
  assert.equal(result, 'recovered');
  assert.equal(calls, 2);
});

test('also checks statusCode property (Anthropic SDK style)', async () => {
  let calls = 0;
  const err = Object.assign(new Error('Bad Request'), { statusCode: 400 });
  await assert.rejects(
    withRetry(() => { calls++; return Promise.reject(err); }, { maxAttempts: 3, baseDelayMs: 0 })
  );
  assert.equal(calls, 1);
});
