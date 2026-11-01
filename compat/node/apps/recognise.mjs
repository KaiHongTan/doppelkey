// Ask the shim which vector inputs it recognises as handles.
import fs from 'node:fs';
import { results, finish } from './_finish.mjs';
const { vectors } = JSON.parse(fs.readFileSync(process.env.VECTORS, 'utf8'));
const shim = globalThis[Symbol.for('doppelkey.shim')];
results.out = vectors.map((v) => shim.recognise(v.input));
results.outBytes = vectors.map((v) => shim.recognise(Buffer.from(v.input, 'latin1')));
finish();
