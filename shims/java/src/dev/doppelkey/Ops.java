package dev.doppelkey;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Typed calls to keeper ops. */
final class Ops {
    private Ops() {}

    static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }

    static byte[] hmac(Handle.Ref ref, String alg, byte[] data) {
        Json.Obj r = Keeper.call("hmac", ref.fields().put("alg", alg).put("data", b64(data)));
        return r.has("handle") ? r.str("handle").getBytes(StandardCharsets.ISO_8859_1) : Base64.getDecoder().decode(r.str("digest"));
    }

    static byte[] pbkdf2(Handle.Ref ref, String hash, byte[] salt, int iterations, int length) {
        Json.Obj r = Keeper.call("pbkdf2", ref.fields().put("hash", hash).put("salt", b64(salt)).put("iterations", iterations).put("length", length));
        byte[] out = r.str("handle").getBytes(StandardCharsets.ISO_8859_1);
        if (out.length != length) throw new DoppelkeyException("bad_reply", "keeper returned a " + out.length + "-byte handle, expected " + length, "doppelkey doctor");
        return out;
    }

    static byte[] aes(String op, Handle.Ref ref, String mode, byte[] iv, byte[] data, byte[] aad, Integer keyBits, Boolean padding) {
        Json.Obj p = ref.fields().put("mode", mode).put("iv", b64(iv)).put("data", b64(data));
        if (aad != null && aad.length > 0) p.put("aad", b64(aad));
        if (keyBits != null) p.put("key_bits", keyBits);
        if (padding != null && !padding) p.put("padding", false);
        return Base64.getDecoder().decode(Keeper.call(op, p).str("out"));
    }
}
