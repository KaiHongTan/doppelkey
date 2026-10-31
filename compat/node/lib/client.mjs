// Minimal wire-protocol v1 client for tests: frame = 4-byte big-endian length + JSON.
import net from 'node:net';

export async function connect(sock) {
  const c = net.createConnection(sock);
  await new Promise((res, rej) => { c.once('connect', res); c.once('error', rej); });
  let buf = Buffer.alloc(0), id = 0;
  const waiting = new Map();
  c.on('data', (d) => {
    buf = Buffer.concat([buf, d]);
    while (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) {
      const n = buf.readUInt32BE(0);
      const msg = JSON.parse(buf.subarray(4, 4 + n).toString());
      buf = buf.subarray(4 + n);
      waiting.get(msg.id)?.(msg);
      waiting.delete(msg.id);
    }
  });
  const sendRaw = (bytes) => { const h = Buffer.alloc(4); h.writeUInt32BE(bytes.length); c.write(Buffer.concat([h, bytes])); };
  return {
    request(body) {
      const rid = body.id ?? ++id;
      return new Promise((res) => { waiting.set(rid, res); sendRaw(Buffer.from(JSON.stringify({ v: 1, ...body, id: rid }))); });
    },
    raw(bytes, expectId = 0) { return new Promise((res) => { waiting.set(expectId, res); sendRaw(bytes); }); },
    close: () => c.end(),
  };
}
