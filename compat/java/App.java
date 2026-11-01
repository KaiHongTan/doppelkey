// Unmodified JCA usage (what Spring Security, jjwt and friends do underneath), with handles in
// the environment. Prints one JSON object of results.
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class App {
    interface Op { Object run() throws Exception; }
    static final Map<String, Object> out = new LinkedHashMap<>();
    static final Map<String, String> errors = new LinkedHashMap<>();
    static void attempt(String name, Op op) {
        try { out.put(name, op.run()); } catch (Throwable e) { errors.put(name, e.getClass().getSimpleName() + ": " + e.getMessage()); }
    }
    static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    static byte[] env(String k) { return System.getenv(k).getBytes(StandardCharsets.UTF_8); }
    static byte[] hex(String s) { byte[] b = new byte[s.length() / 2]; for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16); return b; }
    static String hmac(String alg, byte[] key, String data) throws Exception {
        Mac m = Mac.getInstance(alg);
        m.init(new SecretKeySpec(key, alg));
        return b64(m.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    public static void main(String[] args) throws Exception {
        attempt("jwt", () -> {
            Base64.Encoder u = Base64.getUrlEncoder().withoutPadding();
            String signingInput = u.encodeToString("{\"alg\":\"HS256\"}".getBytes()) + "." + u.encodeToString("{\"sub\":\"user1\"}".getBytes());
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(env("JWT_SECRET"), "HmacSHA256"));
            return signingInput + "." + u.encodeToString(m.doFinal(signingInput.getBytes(StandardCharsets.UTF_8)));
        });
        attempt("hmac512", () -> hmac("HmacSHA512", env("COOKIE_SECRET"), "hello"));
        attempt("provider", () -> { Mac m = Mac.getInstance("HmacSHA256"); m.init(new SecretKeySpec(env("JWT_SECRET"), "HmacSHA256")); return m.getProvider().getName(); });
        attempt("plainHmac", () -> hmac("HmacSHA256", "not-a-handle".getBytes(), "hello"));
        attempt("plainProvider", () -> { Mac m = Mac.getInstance("HmacSHA256"); m.init(new SecretKeySpec("not-a-handle".getBytes(), "HmacSHA256")); return m.getProvider().getName(); });
        attempt("pbkdf2Gcm", () -> {
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] k = f.generateSecret(new PBEKeySpec(System.getenv("SESSION_PASSWORD").toCharArray(), "salt".getBytes(), 1000, 256)).getEncoded();
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"), new GCMParameterSpec(128, new byte[12]));
            return b64(c.doFinal("derived".getBytes()));
        });
        attempt("gcm", () -> {
            SecretKeySpec key = new SecretKeySpec(env("ENCRYPTION_KEY"), "AES");
            byte[] iv = new byte[12]; iv[0] = 7;
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            c.updateAAD("hdr".getBytes());
            byte[] part = c.update("field ".getBytes());
            byte[] rest = c.doFinal("secret".getBytes());
            byte[] ct = new byte[part.length + rest.length];
            System.arraycopy(part, 0, ct, 0, part.length);
            System.arraycopy(rest, 0, ct, part.length, rest.length);
            Cipher d = Cipher.getInstance("AES/GCM/NoPadding");
            d.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            d.updateAAD("hdr".getBytes());
            String back = new String(d.doFinal(ct));
            String tamper;
            try {
                ct[0] ^= 1;
                d.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
                d.updateAAD("hdr".getBytes());
                d.doFinal(ct);
                tamper = "accepted";
            } catch (javax.crypto.AEADBadTagException e) { tamper = "AEADBadTagException"; }
            ct[0] ^= 1;
            return Map.of("ct", b64(ct), "back", back, "tamper", tamper);
        });
        attempt("cbc", () -> {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(hex(System.getenv("ENCRYPTION_KEY_HEX")), "AES"), new IvParameterSpec(new byte[16]));
            return b64(c.doFinal("java cbc".getBytes()));
        });
        attempt("plainGcm", () -> {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new GCMParameterSpec(128, new byte[12]));
            return b64(c.doFinal("x".getBytes()));
        });
        attempt("policy", () -> hmac("HmacSHA256", env("AUTH_SECRET"), "x"));
        StringBuilder sb = new StringBuilder("{");
        for (Map.Entry<String, Object> e : out.entrySet()) sb.append(q(e.getKey())).append(':').append(val(e.getValue())).append(',');
        sb.append("\"errors\":{");
        boolean first = true;
        for (Map.Entry<String, String> e : errors.entrySet()) { if (!first) sb.append(','); first = false; sb.append(q(e.getKey())).append(':').append(q(e.getValue())); }
        sb.append("}}");
        System.out.println(sb);
    }
    static String q(String s) { return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""; }
    static String val(Object v) {
        if (v instanceof Map) { StringBuilder sb = new StringBuilder("{"); boolean f = true; for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) { if (!f) sb.append(','); f = false; sb.append(q(e.getKey().toString())).append(':').append(q(e.getValue().toString())); } return sb.append('}').toString(); }
        return q(String.valueOf(v));
    }
}
