package dev.doppelkey;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * PBKDF2 from a handle returns a key whose bytes are a new handle (the derived key stays in the
 * keeper). Other passwords are delegated to the JDK's own implementation.
 */
public abstract class DoppelkeyPBKDF2 extends SecretKeyFactorySpi {
    private final String alg;
    private final String hash;

    DoppelkeyPBKDF2(String alg, String hash) {
        this.alg = alg;
        this.hash = hash;
    }

    private SecretKeyFactory delegate() throws InvalidKeySpecException {
        try {
            return SecretKeyFactory.getInstance(alg, "SunJCE");
        } catch (Exception e) {
            throw new InvalidKeySpecException(e);
        }
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec spec) throws InvalidKeySpecException {
        if (spec instanceof PBEKeySpec) {
            PBEKeySpec p = (PBEKeySpec) spec;
            char[] pw = p.getPassword();
            Handle.Ref ref = Handle.recognise(new String(pw).getBytes(StandardCharsets.UTF_8));
            if (ref != null) {
                if (p.getSalt() == null || p.getKeyLength() <= 0) throw new InvalidKeySpecException("salt and key length are required");
                return new SecretKeySpec(Ops.pbkdf2(ref, hash, p.getSalt(), p.getIterationCount(), p.getKeyLength() / 8), alg);
            }
        }
        return delegate().generateSecret(spec);
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> spec) throws InvalidKeySpecException {
        return delegate().getKeySpec(key, spec);
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        try {
            return delegate().translateKey(key);
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(e);
        }
    }

    public static final class SHA1 extends DoppelkeyPBKDF2 { public SHA1() { super("PBKDF2WithHmacSHA1", "sha1"); } }
    public static final class SHA256 extends DoppelkeyPBKDF2 { public SHA256() { super("PBKDF2WithHmacSHA256", "sha256"); } }
    public static final class SHA384 extends DoppelkeyPBKDF2 { public SHA384() { super("PBKDF2WithHmacSHA384", "sha384"); } }
    public static final class SHA512 extends DoppelkeyPBKDF2 { public SHA512() { super("PBKDF2WithHmacSHA512", "sha512"); } }
}
