package dev.doppelkey;

import java.security.Provider;

/** JCA provider that performs crypto for handle keys in the doppelkey keeper. */
public final class DoppelkeyProvider extends Provider {
    public DoppelkeyProvider() {
        super("Doppelkey", "0.1", "doppelkey: crypto with doppelkey handle keys runs in the doppelkey keeper");
        String p = "dev.doppelkey.";
        put("Mac.HmacSHA1", p + "DoppelkeyMac$SHA1");
        put("Mac.HmacSHA256", p + "DoppelkeyMac$SHA256");
        put("Mac.HmacSHA384", p + "DoppelkeyMac$SHA384");
        put("Mac.HmacSHA512", p + "DoppelkeyMac$SHA512");
        put("Cipher.AES/GCM/NoPadding", p + "DoppelkeyCipher$GCM");
        put("Cipher.AES/CBC/PKCS5Padding", p + "DoppelkeyCipher$CBCPKCS5");
        put("Cipher.AES/CBC/NoPadding", p + "DoppelkeyCipher$CBCNoPadding");
        put("SecretKeyFactory.PBKDF2WithHmacSHA1", p + "DoppelkeyPBKDF2$SHA1");
        put("SecretKeyFactory.PBKDF2WithHmacSHA256", p + "DoppelkeyPBKDF2$SHA256");
        put("SecretKeyFactory.PBKDF2WithHmacSHA384", p + "DoppelkeyPBKDF2$SHA384");
        put("SecretKeyFactory.PBKDF2WithHmacSHA512", p + "DoppelkeyPBKDF2$SHA512");
    }
}
