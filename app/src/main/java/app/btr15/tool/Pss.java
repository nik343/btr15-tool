package app.btr15.tool;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * RSA-PSS (SHA-256, MGF1-SHA256, salt length 222) implemented with
 * BigInteger so it runs on every supported Android API level.  This mirrors
 * the exact padding the QCC upgrade library verifies: salt 222 with SHA-256
 * fills the encoded message (222 + 32 + 2 + 0 pad bytes) for a 2048-bit
 * modulus, which is the padding FiiO's production images use.
 */
final class Pss {
    static final int SALT_LENGTH = 222;
    private static final int EM_LEN = 256;
    private static final int H_LEN = 32;

    private Pss() { }

    static byte[] sign(DevKey key, byte[] content) {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        byte[] em = encodePss(sha256(content), salt);
        BigInteger m = new BigInteger(1, em);
        BigInteger s = m.modPow(key.privateExponent, key.modulus);
        return DevKey.toFixed(s, EM_LEN);
    }

    static boolean verify(BigInteger modulus, byte[] signature, byte[] content) {
        if (signature == null || signature.length != EM_LEN) {
            return false;
        }
        try {
            BigInteger sInt = new BigInteger(1, signature);
            if (sInt.compareTo(modulus) >= 0) {
                return false;
            }
            BigInteger mInt = sInt.modPow(DevKey.EXPONENT, modulus);
            byte[] em = DevKey.toFixed(mInt, EM_LEN);
            return verifyEncoded(em, sha256(content));
        } catch (RuntimeException error) {
            return false;
        }
    }

    /** PSS-VERIFY (RFC 8017 §9.1.2) against an already-hashed message. */
    static boolean verifyEncoded(byte[] em, byte[] mHash) {
        if (em.length != EM_LEN || mHash.length != H_LEN) {
            return false;
        }
        if ((em[EM_LEN - 1] & 0xFF) != 0xBC) {
            return false;
        }
        int dbLen = EM_LEN - H_LEN - 1;
        byte[] maskedDb = new byte[dbLen];
        System.arraycopy(em, 0, maskedDb, 0, dbLen);
        byte[] h = new byte[H_LEN];
        System.arraycopy(em, dbLen, h, 0, H_LEN);
        // emBits = 8*emLen - 1: the top bit must be zero.
        if ((maskedDb[0] & 0x80) != 0) {
            return false;
        }
        byte[] dbMask = mgf1(h, dbLen);
        byte[] db = new byte[dbLen];
        for (int i = 0; i < dbLen; i++) {
            db[i] = (byte) (maskedDb[i] ^ dbMask[i]);
        }
        // RFC 8017 §9.1.2 step 7: with emBits = 8*emLen-1 the encoder masks the
        // top bit of maskedDB away, so a recovered db[0] whose top bit returns
        // via dbMask is legitimate; the spec mandates masking, not rejection.
        db[0] &= 0x7F;
        int padLen = dbLen - SALT_LENGTH - 1;
        for (int i = 0; i < padLen; i++) {
            if (db[i] != 0x00) {
                return false;
            }
        }
        if (db[padLen] != 0x01) {
            return false;
        }
        byte[] salt = new byte[SALT_LENGTH];
        System.arraycopy(db, padLen + 1, salt, 0, SALT_LENGTH);
        byte[] check = encodeHash(mHash, salt);
        for (int i = 0; i < H_LEN; i++) {
            if (check[i] != h[i]) {
                return false;
            }
        }
        return true;
    }

    /** PSS-ENCODE (RFC 8017 §9.1.1) for a 2048-bit modulus. */
    static byte[] encodePss(byte[] mHash, byte[] salt) {
        byte[] h = encodeHash(mHash, salt);
        int dbLen = EM_LEN - H_LEN - 1;
        byte[] db = new byte[dbLen];
        db[dbLen - SALT_LENGTH - 1] = 0x01;
        System.arraycopy(salt, 0, db, dbLen - SALT_LENGTH, SALT_LENGTH);
        byte[] dbMask = mgf1(h, dbLen);
        byte[] maskedDb = new byte[dbLen];
        for (int i = 0; i < dbLen; i++) {
            maskedDb[i] = (byte) (db[i] ^ dbMask[i]);
        }
        maskedDb[0] = (byte) (maskedDb[0] & 0x7F);
        byte[] em = new byte[EM_LEN];
        System.arraycopy(maskedDb, 0, em, 0, dbLen);
        System.arraycopy(h, 0, em, dbLen, H_LEN);
        em[EM_LEN - 1] = (byte) 0xBC;
        return em;
    }

    private static byte[] encodeHash(byte[] mHash, byte[] salt) {
        MessageDigest digest = sha();
        digest.update(new byte[8]);
        digest.update(mHash);
        digest.update(salt);
        return digest.digest();
    }

    static byte[] mgf1(byte[] seed, int length) {
        byte[] out = new byte[length];
        byte[] counter = new byte[4];
        int produced = 0;
        int block = 0;
        while (produced < length) {
            MessageDigest digest = sha();
            digest.update(seed);
            counter[0] = (byte) (block >>> 24);
            counter[1] = (byte) (block >>> 16);
            counter[2] = (byte) (block >>> 8);
            counter[3] = (byte) block;
            digest.update(counter);
            byte[] chunk = digest.digest();
            int take = Math.min(chunk.length, length - produced);
            System.arraycopy(chunk, 0, out, produced, take);
            produced += take;
            block++;
        }
        return out;
    }

    private static byte[] sha256(byte[] value) {
        return sha().digest(value);
    }

    private static MessageDigest sha() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (Exception error) {
            throw new IllegalStateException("SHA-256 unavailable", error);
        }
    }
}
