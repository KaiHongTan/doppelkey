package dev.doppelkey;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * AES-GCM / AES-CBC whose key is a handle. Input is buffered and the keeper produces the output
 * in doFinal (JCA allows update() to buffer). Non-handle keys: InvalidKeyException at init, so
 * the JDK falls through to its normal provider.
 */
public abstract class DoppelkeyCipher extends CipherSpi {
    private final boolean gcm;
    private final boolean padding;
    private int opmode;
    private Handle.Ref ref;
    private int keyBits;
    private byte[] iv;
    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
    private final ByteArrayOutputStream aad = new ByteArrayOutputStream();

    DoppelkeyCipher(boolean gcm, boolean padding) {
        this.gcm = gcm;
        this.padding = padding;
    }

    @Override protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!mode.equalsIgnoreCase(gcm ? "GCM" : "CBC")) throw new NoSuchAlgorithmException(mode);
    }
    @Override protected void engineSetPadding(String p) throws NoSuchPaddingException {
        String want = gcm || !padding ? "NoPadding" : "PKCS5Padding";
        if (!p.equalsIgnoreCase(want)) throw new NoSuchPaddingException(p);
    }
    @Override protected int engineGetBlockSize() { return 16; }
    @Override protected int engineGetOutputSize(int inputLen) { return buf.size() + inputLen + 32; }
    @Override protected byte[] engineGetIV() { return iv == null ? null : iv.clone(); }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (iv == null) return null;
        try {
            AlgorithmParameters p = AlgorithmParameters.getInstance(gcm ? "GCM" : "AES");
            p.init(gcm ? new GCMParameterSpec(128, iv) : new IvParameterSpec(iv));
            return p;
        } catch (Exception e) {
            return null;
        }
    }

    private void start(int opmode, Key key, byte[] iv) throws InvalidKeyException {
        Handle.Ref r = key == null ? null : Handle.recognise(key.getEncoded());
        if (r == null) throw new InvalidKeyException("not a doppelkey handle");
        int bits = key.getEncoded().length * 8;
        if (r.keyEncoding == null && bits != 128 && bits != 192 && bits != 256) throw new InvalidKeyException("Invalid AES key length: " + bits / 8 + " bytes");
        if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) throw DoppelkeyException.unsupported("Cipher wrap/unwrap");
        this.opmode = opmode;
        this.ref = r;
        this.keyBits = bits;
        this.iv = iv;
        buf.reset();
        aad.reset();
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if (key == null || Handle.recognise(key.getEncoded()) == null) throw new InvalidKeyException("not a doppelkey handle");
        if (opmode != Cipher.ENCRYPT_MODE) throw new InvalidKeyException("parameters (IV) are required for decryption");
        byte[] fresh = new byte[gcm ? 12 : 16];
        (random != null ? random : new SecureRandom()).nextBytes(fresh);
        start(opmode, key, fresh);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (key == null || Handle.recognise(key.getEncoded()) == null) throw new InvalidKeyException("not a doppelkey handle");
        if (params == null) { engineInit(opmode, key, random); return; }
        byte[] v;
        if (gcm) {
            if (!(params instanceof GCMParameterSpec)) throw new InvalidAlgorithmParameterException("GCMParameterSpec required");
            GCMParameterSpec g = (GCMParameterSpec) params;
            if (g.getTLen() != 128) throw DoppelkeyException.unsupported("AES-GCM with a " + g.getTLen() + "-bit tag (only 128-bit tags)");
            v = g.getIV();
            if (v.length != 12) throw DoppelkeyException.unsupported("AES-GCM with a " + v.length + "-byte IV (only 12-byte IVs)");
        } else {
            if (!(params instanceof IvParameterSpec)) throw new InvalidAlgorithmParameterException("IvParameterSpec required");
            v = ((IvParameterSpec) params).getIV();
            if (v.length != 16) throw new InvalidAlgorithmParameterException("Wrong IV length: must be 16 bytes long");
        }
        start(opmode, key, v);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        try {
            AlgorithmParameterSpec spec = null;
            if (params != null) spec = gcm ? params.getParameterSpec(GCMParameterSpec.class) : params.getParameterSpec(IvParameterSpec.class);
            engineInit(opmode, key, spec, random);
        } catch (java.security.spec.InvalidParameterSpecException e) {
            throw new InvalidAlgorithmParameterException(e);
        }
    }

    @Override protected void engineUpdateAAD(byte[] src, int offset, int len) { aad.write(src, offset, len); }

    @Override
    protected byte[] engineUpdate(byte[] input, int offset, int len) {
        if (input != null) buf.write(input, offset, len);
        return new byte[0];
    }

    @Override
    protected int engineUpdate(byte[] input, int offset, int len, byte[] output, int outOffset) {
        if (input != null) buf.write(input, offset, len);
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int offset, int len) throws BadPaddingException {
        if (input != null) buf.write(input, offset, len);
        String mode = opmode == Cipher.ENCRYPT_MODE ? "encrypt" : "decrypt";
        Integer bits = ref.keyEncoding == null ? keyBits : null;
        try {
            return gcm
                ? Ops.aes("aes_gcm", ref, mode, iv, buf.toByteArray(), aad.toByteArray(), bits, null)
                : Ops.aes("aes_cbc", ref, mode, iv, buf.toByteArray(), null, bits, padding);
        } catch (DoppelkeyException e) {
            if ("crypto_error".equals(e.code())) throw gcm ? new AEADBadTagException("Tag mismatch") : new BadPaddingException("Given final block not properly padded");
            throw e;
        } finally {
            buf.reset();
            aad.reset();
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int offset, int len, byte[] output, int outOffset) throws BadPaddingException, javax.crypto.ShortBufferException {
        byte[] out = engineDoFinal(input, offset, len);
        if (output.length - outOffset < out.length) throw new javax.crypto.ShortBufferException();
        System.arraycopy(out, 0, output, outOffset, out.length);
        return out.length;
    }

    public static final class GCM extends DoppelkeyCipher { public GCM() { super(true, false); } }
    public static final class CBCPKCS5 extends DoppelkeyCipher { public CBCPKCS5() { super(false, true); } }
    public static final class CBCNoPadding extends DoppelkeyCipher { public CBCNoPadding() { super(false, false); } }
}
