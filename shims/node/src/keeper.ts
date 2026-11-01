// Synchronous calls to the keeper. A worker thread owns the socket; the calling thread
// blocks on Atomics.wait until the worker posts the reply, then reads it with
// receiveMessageOnPort. This is what lets createHmac(...).digest() stay synchronous.
import os from 'node:os';
import path from 'node:path';
import { Worker, MessageChannel, MessagePort, receiveMessageOnPort } from 'node:worker_threads';

export const WORKER_MARK = '__doppelkeyWorker';

export class DoppelkeyError extends Error {
  code: string;
  hint?: string;
  /** `hint` is either a command ("doppelkey doctor") or a sentence of advice. */
  constructor(code: string, message: string, hint?: string) {
    const advice = !hint ? '' : hint.startsWith('doppelkey ') ? ` Run "${hint}".` : ` ${hint}`;
    super(`doppelkey: ${message.replace(/[.\s]+$/, '')}.${advice}`);
    this.name = 'DoppelkeyError';
    this.code = code;
    this.hint = hint;
  }
}

export function socketPath(env: NodeJS.ProcessEnv = process.env): string {
  if (env.DOPPELKEY_SOCK) return env.DOPPELKEY_SOCK;
  if (env.XDG_RUNTIME_DIR) return path.join(env.XDG_RUNTIME_DIR, 'doppelkey', 'doppelkeyd.sock');
  const uid = typeof process.getuid === 'function' ? process.getuid() : 'user';
  return path.join(os.tmpdir(), `doppelkey-${uid}`, 'doppelkeyd.sock');
}

// Runs inside the worker. Must be self-contained: it is serialised with Function#toString.
function workerMain() {
  /* eslint-disable */
  const { workerData } = require('node:worker_threads');
  const net = require('node:net');
  const { port, signal, sock } = workerData;
  let conn: any = null;
  let connected = false;
  let rbuf: Buffer = Buffer.alloc(0);
  let queue: Buffer[] = [];
  const inflight = new Set<number>();
  const deliver = (msg: unknown) => {
    port.postMessage(msg);
    Atomics.add(signal, 0, 1);
    Atomics.notify(signal, 0);
  };
  const failAll = (code: string, message: string) => {
    for (const id of inflight) deliver({ v: 1, id, ok: false, error: { code, message } });
    inflight.clear();
    queue = [];
  };
  const connect = () => {
    connected = false;
    rbuf = Buffer.alloc(0);
    const c = net.createConnection(sock);
    conn = c;
    c.on('connect', () => {
      connected = true;
      for (const f of queue) c.write(f);
      queue = [];
    });
    c.on('data', (chunk: Buffer) => {
      rbuf = rbuf.length ? Buffer.concat([rbuf, chunk]) : chunk;
      while (rbuf.length >= 4) {
        const n = rbuf.readUInt32BE(0);
        if (rbuf.length < 4 + n) break;
        let msg: any;
        try { msg = JSON.parse(rbuf.subarray(4, 4 + n).toString('utf8')); } catch { msg = null; }
        rbuf = rbuf.subarray(4 + n);
        if (msg && typeof msg.id === 'number') { inflight.delete(msg.id); deliver(msg); }
      }
    });
    // Bun emits 'close' before 'error' for a missing socket, so decide by whether we ever connected.
    const down = (e?: any) => {
      if (conn === c) conn = null;
      if (!inflight.size) return;
      if (!connected) failAll('keeper_unreachable', `keeper not running (no keeper at ${sock})`);
      else failAll('keeper_unreachable', e ? `keeper connection failed: ${e.message}` : 'keeper closed the connection');
    };
    c.on('error', (e: any) => down(e));
    c.on('close', () => down());
  };
  port.on('message', (req: any) => {
    const body = Buffer.from(JSON.stringify(req), 'utf8');
    const head = Buffer.alloc(4);
    head.writeUInt32BE(body.length, 0);
    const frame = Buffer.concat([head, body]);
    inflight.add(req.id);
    if (!conn) connect();
    if (connected) conn.write(frame);
    else queue.push(frame);
  });
}

let worker: Worker | null = null;
let port: MessagePort;
let signal: Int32Array;
let seq = 0;
let workerStarted = false;

function start() {
  const ch = new MessageChannel();
  port = ch.port1;
  signal = new Int32Array(new SharedArrayBuffer(4));
  worker = new Worker(`(${workerMain.toString()})()`, {
    eval: true,
    execArgv: [],
    workerData: { port: ch.port2, signal, sock: socketPath(), [WORKER_MARK]: true },
    transferList: [ch.port2],
  });
  worker.unref();
  worker.on('error', () => { worker = null; });
  worker.on('exit', () => { worker = null; });
  workerStarted = true;
}

export const keeperStats = () => ({ workerStarted, calls: seq });

const timeoutMs = () => Number(process.env.DOPPELKEY_TIMEOUT_MS) || 30000;

export interface KeeperError { code: string; message: string; hint?: string }

/** Send one request and block until the keeper answers. Throws DoppelkeyError on failure. */
export function call(op: string, params: Record<string, unknown>): any {
  if (!worker) start();
  const id = ++seq;
  port.postMessage({ v: 1, id, op, ...params });
  const deadline = Date.now() + timeoutMs();
  for (;;) {
    const seen = Atomics.load(signal, 0);
    const m = receiveMessageOnPort(port);
    if (m) {
      const msg = m.message;
      if (msg.id !== id) continue; // a late reply to an earlier, timed-out request
      if (msg.ok) return msg.result;
      const e: KeeperError = msg.error || { code: 'bad_reply', message: 'malformed keeper reply' };
      const hint = e.hint ?? (e.code === 'keeper_unreachable' || e.code === 'unknown_handle' || e.code === 'version_mismatch' ? 'doppelkey doctor' : undefined);
      throw new DoppelkeyError(e.code, e.message, hint);
    }
    const left = deadline - Date.now();
    if (left <= 0) throw new DoppelkeyError('keeper_timeout', `keeper did not answer within ${timeoutMs()} ms`, 'doppelkey doctor');
    Atomics.wait(signal, 0, seen, left);
  }
}
