package dev.doppelkey;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.MacSpi;

/**
 * HMAC whose key is a handle. For any other key, init throws InvalidKeyException so the JDK's
 * delayed provider selection falls through to the normal provider: non-handle keys are untouched.
 */
public abstract class DoppelkeyMac extends MacSpi {
    private final String alg;
    private final int len;
    private Handle.Ref ref;
    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

    DoppelkeyMac(String alg, int len) {
        this.alg = alg;
        this.len = len;
    }

    @Override protected int engineGetMacLength() { return len; }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params) throws InvalidKeyException {
        ref = key == null ? null : Handle.recognise(key.getEncoded());
        if (ref == null) throw new InvalidKeyException("not a doppelkey handle");
        buf.reset();
    }

    @Override protected void engineUpdate(byte input) { buf.write(input); }
    @Override protected void engineUpdate(byte[] input, int offset, int length) { buf.write(input, offset, length); }

    @Override
    protected byte[] engineDoFinal() {
        byte[] out = Ops.hmac(ref, alg, buf.toByteArray());
        buf.reset();
        return out;
    }

    @Override protected void engineReset() { buf.reset(); }

    public static final class SHA1 extends DoppelkeyMac { public SHA1() { super("sha1", 20); } }
    public static final class SHA256 extends DoppelkeyMac { public SHA256() { super("sha256", 32); } }
    public static final class SHA384 extends DoppelkeyMac { public SHA384() { super("sha384", 48); } }
    public static final class SHA512 extends DoppelkeyMac { public SHA512() { super("sha512", 64); } }
}
