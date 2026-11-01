package dev.doppelkey;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

/** Blocking wire-protocol v1 client: 4-byte big-endian length + JSON over a Unix socket. */
final class Keeper {
    private static SocketChannel conn;
    private static long seq;

    private Keeper() {}

    static String socketPath() {
        String s = System.getenv("DOPPELKEY_SOCK");
        if (s != null && !s.isEmpty()) return s;
        String x = System.getenv("XDG_RUNTIME_DIR");
        if (x != null && !x.isEmpty()) return Path.of(x, "doppelkey", "doppelkeyd.sock").toString();
        String tmp = System.getenv("TMPDIR") != null ? System.getenv("TMPDIR") : "/tmp";
        String uid = System.getProperty("doppelkey.uid", uid());
        return Path.of(tmp, "doppelkey-" + uid, "doppelkeyd.sock").toString();
    }

    private static String uid() {
        try {
            Object u = java.nio.file.Files.getAttribute(Path.of(System.getProperty("user.home")), "unix:uid");
            return String.valueOf(u);
        } catch (Exception e) {
            return "user";
        }
    }

    private static void readFully(ByteBuffer b) throws IOException {
        while (b.hasRemaining()) if (conn.read(b) < 0) throw new IOException("keeper closed the connection");
        b.flip();
    }

    /** Send one request and return its result object. Throws DoppelkeyException. */
    static synchronized Json.Obj call(String op, Json.Obj params) {
        String path = socketPath();
        try {
            if (conn == null || !conn.isOpen()) {
                try {
                    conn = SocketChannel.open(StandardProtocolFamily.UNIX);
                    conn.connect(UnixDomainSocketAddress.of(path));
                } catch (IOException e) {
                    conn = null;
                    throw new DoppelkeyException("keeper_unreachable", "keeper not running (no keeper at " + path + ")", "doppelkey doctor");
                }
            }
            long id = ++seq;
            Json.Obj req = new Json.Obj().put("v", 1).put("id", id).put("op", op).putAll(params);
            byte[] body = Json.write(req).getBytes(StandardCharsets.UTF_8);
            ByteBuffer out = ByteBuffer.allocate(4 + body.length).putInt(body.length).put(body);
            out.flip();
            while (out.hasRemaining()) conn.write(out);
            while (true) {
                ByteBuffer len = ByteBuffer.allocate(4);
                readFully(len);
                ByteBuffer msg = ByteBuffer.allocate(len.getInt());
                readFully(msg);
                Json.Obj reply = (Json.Obj) Json.parse(StandardCharsets.UTF_8.decode(msg).toString());
                if (!(reply.get("id") instanceof Long) || (Long) reply.get("id") != id) continue;
                if (Boolean.TRUE.equals(reply.get("ok"))) {
                    Json.Obj r = reply.obj("result");
                    return r == null ? new Json.Obj() : r;
                }
                Json.Obj e = reply.obj("error");
                String code = e == null ? "error" : e.str("code");
                String hint = e == null ? null : e.str("hint");
                if (hint == null && ("unknown_handle".equals(code) || "version_mismatch".equals(code))) hint = "doppelkey doctor";
                throw new DoppelkeyException(code, e == null ? "keeper error" : e.str("message"), hint);
            }
        } catch (IOException e) {
            try { if (conn != null) conn.close(); } catch (IOException ignored) { }
            conn = null;
            throw new DoppelkeyException("keeper_unreachable", "keeper connection failed: " + e.getMessage(), "doppelkey doctor");
        }
    }
}
