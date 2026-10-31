package dev.doppelkey;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Handle format v1 (docs/protocol.md). Mirrors shims/node/src/handle.ts. */
final class Handle {
    static final String LABEL = "NOT-A-SECRET-load-doppelkey-shim";
    static final int MAX_PREFIX = 8;
    private static final String CORE = "dk1:(?:" + LABEL + ":[0-9a-f]{12}:|[0-9a-f]{12})[0-9a-f]{4}";
    private static final Pattern KEY = Pattern.compile("^([\\s\\S]{0," + MAX_PREFIX + "}?)((?:" + CORE + "\\.*)+)$");
    private static final Pattern CORE_RE = Pattern.compile("dk1:(?:" + LABEL + ":([0-9a-f]{12}):|([0-9a-f]{12}))([0-9a-f]{4})");

    /** A key that is (or encodes) a handle. */
    static final class Ref {
        final String handle;
        final byte[] prefix;
        final String keyEncoding;
        final int length;

        Ref(String handle, byte[] prefix, String keyEncoding, int length) {
            this.handle = handle;
            this.prefix = prefix;
            this.keyEncoding = keyEncoding;
            this.length = length;
        }

        Json.Obj fields() {
            Json.Obj f = new Json.Obj().put("handle", handle);
            if (prefix.length > 0) f.put("prefix", Base64.getEncoder().encodeToString(prefix));
            if (keyEncoding != null) f.put("key_encoding", keyEncoding);
            return f;
        }
    }

    private Handle() {}

    static String crc(String id) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(("dk1:" + id).getBytes(StandardCharsets.US_ASCII));
            return String.format("%02x%02x", d[0] & 0xff, d[1] & 0xff);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String[] parse(String latin1) {
        Matcher m = KEY.matcher(latin1);
        if (!m.matches()) return null;
        Matcher c = CORE_RE.matcher(m.group(2));
        while (c.find()) {
            String id = c.group(1) != null ? c.group(1) : c.group(2);
            if (!crc(id).equals(c.group(3))) return null;
        }
        return new String[] {m.group(1), m.group(2)};
    }

    /** Ref if the key bytes are a doppelkey handle (raw, prefixed, or hex/base64 encoded), else null. */
    static Ref recognise(byte[] key) {
        if (key == null || key.length < 20) return null;
        String s = new String(key, StandardCharsets.ISO_8859_1);
        if (s.contains("dk1:")) {
            String[] p = parse(s);
            return p == null ? null : new Ref(p[1], p[0].getBytes(StandardCharsets.ISO_8859_1), null, key.length);
        }
        int h = s.indexOf("646b313a"), b = s.indexOf("ZGsxO");
        int start = -1;
        if (h >= 0 && h <= MAX_PREFIX) start = h;
        if (b >= 0 && b <= MAX_PREFIX && (start < 0 || b < start)) start = b;
        if (start < 0) return null;
        String body = s.substring(start);
        byte[] decoded;
        String enc;
        try {
            if (body.startsWith("646b313a") && body.matches("[0-9a-f]+") && body.length() % 2 == 0) {
                enc = "hex";
                decoded = new byte[body.length() / 2];
                for (int i = 0; i < decoded.length; i++) decoded[i] = (byte) Integer.parseInt(body.substring(2 * i, 2 * i + 2), 16);
            } else if (body.startsWith("ZGsxO") && body.matches("[A-Za-z0-9+/]+={0,2}")) {
                enc = "base64";
                decoded = Base64.getDecoder().decode(body);
            } else {
                return null;
            }
        } catch (IllegalArgumentException e) {
            return null;
        }
        String[] p = parse(new String(decoded, StandardCharsets.ISO_8859_1));
        if (p == null || !p[0].isEmpty()) return null;
        return new Ref(p[1], s.substring(0, start).getBytes(StandardCharsets.ISO_8859_1), enc, key.length);
    }
}
