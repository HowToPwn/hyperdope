import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractJson, extractJsonArray } from '../src/extract.js';

test('clean JSON string', () => {
  const result = extractJson('{"key": "value", "n": 42}');
  assert.deepEqual(result, { key: 'value', n: 42 });
});

test('JSON inside ```json fence', () => {
  const raw = 'Some prose.\n```json\n{"score": 9.8, "severity": "Critical"}\n```\nMore text.';
  const result = extractJson(raw);
  assert.deepEqual(result, { score: 9.8, severity: 'Critical' });
});

test('JSON inside plain ``` fence (no lang tag)', () => {
  const raw = 'Output:\n```\n{"id": "AUDIT-001"}\n```';
  const result = extractJson(raw);
  assert.deepEqual(result, { id: 'AUDIT-001' });
});

test('JSON with surrounding prose (brace counting)', () => {
  const raw = 'Here is the result: {"phase": "profile", "status": "complete"} — end.';
  const result = extractJson(raw);
  assert.deepEqual(result, { phase: 'profile', status: 'complete' });
});

test('nested JSON objects — brace counting handles depth correctly', () => {
  const raw = 'Result: {"outer": {"inner": {"deep": true}, "sibling": 1}}';
  const result = extractJson(raw);
  assert.deepEqual(result, { outer: { inner: { deep: true }, sibling: 1 } });
});

test('JSON with escaped quotes inside strings', () => {
  const raw = '{"message": "He said \\"hello\\" to me", "ok": true}';
  const result = extractJson(raw);
  assert.deepEqual(result, { message: 'He said "hello" to me', ok: true });
});

test('returns null for non-JSON string', () => {
  assert.equal(extractJson('This is just plain text with no JSON.'), null);
});

test('returns null for empty string', () => {
  assert.equal(extractJson(''), null);
});

test('returns null for null input', () => {
  assert.equal(extractJson(null), null);
});

test('extractJsonArray returns array from fenced block', () => {
  const raw = '```json\n[{"id": 1}, {"id": 2}]\n```';
  const result = extractJsonArray(raw);
  assert.deepEqual(result, [{ id: 1 }, { id: 2 }]);
});

test('extractJsonArray returns findings array from wrapped object', () => {
  const raw = '```json\n{"findings": [{"id": "AUDIT-001"}, {"id": "AUDIT-002"}]}\n```';
  const result = extractJsonArray(raw);
  assert.deepEqual(result, [{ id: 'AUDIT-001' }, { id: 'AUDIT-002' }]);
});

test('extractJsonArray returns empty array for non-JSON', () => {
  const result = extractJsonArray('No JSON here.');
  assert.deepEqual(result, []);
});

test('extractJsonArray wraps single object in array', () => {
  const raw = '{"id": "AUDIT-001", "title": "RCE"}';
  const result = extractJsonArray(raw);
  assert.deepEqual(result, [{ id: 'AUDIT-001', title: 'RCE' }]);
});
