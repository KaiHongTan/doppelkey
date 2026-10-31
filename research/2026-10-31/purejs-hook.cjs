// PoC: wrap pure-JS HMAC packages at load time with module.registerHooks (Node >= 22.15).
// fast-sha256 (CJS, used by svix/standardwebhooks): append a wrapper to module.exports.hmac.
const { registerHooks } = require('node:module');
globalThis.__dkPure = {
  isHandle: (k) => Buffer.from(k.buffer, k.byteOffset, k.byteLength).toString('latin1').startsWith('KH1:'),
  hmac: (k, d) => new Uint8Array(require('node:crypto').createHmac('sha256', Buffer.from(k)).update(Buffer.from(d)).digest()),
};
registerHooks({
  load(url, context, nextLoad) {
    const r = nextLoad(url, context);
    if (/\/node_modules\/fast-sha256\/sha256\.js$/.test(url)) {
      const src = String(r.source ?? require('fs').readFileSync(new URL(url)));
      return { ...r, format: 'commonjs', source: src + `\n;(function(){var o=module.exports.hmac;module.exports.hmac=function(k,d){return globalThis.__dkPure.isHandle(k)?globalThis.__dkPure.hmac(k,d):o(k,d)};if(module.exports.default)module.exports.default.hmac=module.exports.hmac})();` };
    }
    return r;
  },
});
