import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { ROOT, runApp } from '../lib/harness.mjs';
import { parseHandle } from '../../test-keeper/handles.mjs';

const file = path.join(ROOT, 'crates/proto/vectors/handles.json');
const { vectors } = JSON.parse(fs.readFileSync(file, 'utf8'));

test('the Node shim recognises exactly the valid vectors (as strings and as bytes)', () => {
  const r = runApp('recognise.mjs', { handles: false, env: { VECTORS: file } }).results;
  vectors.forEach((v, i) => {
    for (const got of [r.out[i], r.outBytes[i]]) {
      if (!v.valid) { assert.equal(got, null, v.note); continue; }
      assert.ok(got, v.note);
      assert.equal(got.handle, v.handle, v.note);
      assert.equal(got.prefix, v.prefix, v.note);
      assert.equal(got.keyEncoding, v.key_encoding, v.note);
    }
  });
});

test('the test keeper parses the handle of every valid vector to the same ids', () => {
  for (const v of vectors.filter((x) => x.valid)) assert.deepEqual(parseHandle(v.handle), v.ids, v.note);
});
