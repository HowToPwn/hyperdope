import { test } from 'node:test';
import assert from 'node:assert/strict';
import { calculateScore, severity, extractVector, parseVector } from '../src/cvss.js';

// Known-good vectors verified against the CVSS v3.1 formula from FIRST.org spec.
// Note: AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N = 3.3 (directive stated 2.5 which
// conflicts with the spec — the math gives 3.3 and that is correct).

test('9.8 Critical — Log4Shell-class, all-network no-auth', () => {
  const score = calculateScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  assert.equal(score, 9.8);
  assert.equal(severity(score), 'Critical');
});

test('6.5 Medium — network, authenticated read-only', () => {
  const score = calculateScore('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N');
  assert.equal(score, 6.5);
  assert.equal(severity(score), 'Medium');
});

test('3.3 Low — local, high-complexity, user interaction', () => {
  const score = calculateScore('CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N');
  assert.equal(score, 3.3);
  assert.equal(severity(score), 'Low');
});

test('10.0 Critical — Scope:Changed, full CIA impact', () => {
  const score = calculateScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
  assert.equal(score, 10.0);
  assert.equal(severity(score), 'Critical');
});

test('8.1 High — network, high complexity, no auth', () => {
  const score = calculateScore('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H');
  assert.equal(score, 8.1);
  assert.equal(severity(score), 'High');
});

test('severity thresholds', () => {
  assert.equal(severity(0.0),  'None');
  assert.equal(severity(0.1),  'Low');
  assert.equal(severity(3.9),  'Low');
  assert.equal(severity(4.0),  'Medium');
  assert.equal(severity(6.9),  'Medium');
  assert.equal(severity(7.0),  'High');
  assert.equal(severity(8.9),  'High');
  assert.equal(severity(9.0),  'Critical');
  assert.equal(severity(10.0), 'Critical');
});

test('parseVector throws on missing metric', () => {
  assert.throws(
    () => parseVector('CVSS:3.1/AV:N/AC:L'),
    /missing metric/
  );
});

test('parseVector throws on invalid metric value', () => {
  assert.throws(
    () => parseVector('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    /Invalid AV/
  );
});

test('parseVector throws on non-CVSS-3 string', () => {
  assert.throws(
    () => parseVector('CVSS:2.0/AV:N/AC:L'),
    /Not a CVSS v3/
  );
});

test('extractVector finds vector in surrounding text', () => {
  const text = 'Our assessment: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — classified Critical.';
  const found = extractVector(text);
  assert.equal(found, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
});

test('extractVector returns null when no vector present', () => {
  assert.equal(extractVector('No CVSS data here.'), null);
});

test('ISC=0 gives score=0 (all None impacts)', () => {
  const score = calculateScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N');
  assert.equal(score, 0.0);
  assert.equal(severity(score), 'None');
});
