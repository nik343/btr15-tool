package app.btr15.tool;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * BDKD-v1: deterministic BTR15 developer-key derivation from a BIP-39 mnemonic
 * (RSA-2048, e = 65537).  This is the Java mirror of
 * {@code tools/btr15_devkey_derive.py}; the two must produce byte-identical
 * output for the pinned test vectors, so every constant here is frozen.  Any
 * behavioural change requires a new algorithm version tag — never mutate v1.
 *
 * <p>The QCC constant block layout is M || M_dash || R^2 mod M, each 256-bit
 * half stored in XAP uint16 (byte-swapped) form with M_dash as a uint16
 * little-endian value between them, exactly matching the FiiO firmware block
 * the developer key replaces.</p>
 */
final class DevKey {
    static final String ALGORITHM = "BDKD-v1";
    static final BigInteger EXPONENT = BigInteger.valueOf(65537L);
    private static final int PRIME_BITS = 1024;
    private static final BigInteger QUANTUM_BOUND = BigInteger.ONE.shiftLeft(512);
    private static final byte[] PERSONALIZATION =
            sha256("BTR15-DEVKEY-DERIVE-V1".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    private static final int[] TRIAL_PRIMES = firstNPrimes(200);
    private static final int[] MR_BASES = firstNPrimes(64);

    final BigInteger modulus;
    final BigInteger privateExponent;
    final BigInteger p;
    final BigInteger q;
    final int mDash;
    final byte[] qccBlock;
    final String fingerprint;

    private DevKey(BigInteger modulus, BigInteger privateExponent, BigInteger p, BigInteger q,
                   int mDash, byte[] qccBlock, String fingerprint) {
        this.modulus = modulus;
        this.privateExponent = privateExponent;
        this.p = p;
        this.q = q;
        this.mDash = mDash;
        this.qccBlock = qccBlock;
        this.fingerprint = fingerprint;
    }

    static DevKey derive(String mnemonic) {
        if (!Bip39.isValid(mnemonic)) {
            throw new IllegalArgumentException("mnemonic is not valid BIP-39");
        }
        byte[] seed = Bip39.toSeed(mnemonic, "");
        HmacDrbg drbg = new HmacDrbg(seed, PERSONALIZATION);
        BigInteger p = generatePrime(drbg);
        BigInteger q;
        while (true) {
            q = generatePrime(drbg);
            if (!p.equals(q) && p.subtract(q).abs().compareTo(QUANTUM_BOUND) > 0) {
                break;
            }
        }
        if (p.compareTo(q) < 0) {
            BigInteger t = p;
            p = q;
            q = t;
        }
        BigInteger modulus = p.multiply(q);
        BigInteger p1 = p.subtract(BigInteger.ONE);
        BigInteger q1 = q.subtract(BigInteger.ONE);
        BigInteger lambda = p1.multiply(q1).divide(p1.gcd(q1));
        BigInteger privateExponent = EXPONENT.modInverse(lambda);
        byte[] modulusBe = toFixed(modulus, 256);
        int low16 = ((modulusBe[254] & 0xFF) << 8) | (modulusBe[255] & 0xFF);
        int mDash = BigInteger.valueOf(low16).modInverse(BigInteger.valueOf(1L << 16))
                .negate().mod(BigInteger.valueOf(1L << 16)).intValue();
        BigInteger rSquared = BigInteger.valueOf(2).modPow(BigInteger.valueOf(4096), modulus);
        byte[] rSquaredBe = toFixed(rSquared, 256);
        byte[] block = new byte[256 + 2 + 256];
        byte[] modSwap = swapUint16(modulusBe);
        byte[] rSwap = swapUint16(rSquaredBe);
        System.arraycopy(modSwap, 0, block, 0, 256);
        block[256] = (byte) (mDash & 0xFF);
        block[257] = (byte) ((mDash >>> 8) & 0xFF);
        System.arraycopy(rSwap, 0, block, 258, 256);
        String fingerprint = hex(sha256(modulusBe));
        return new DevKey(modulus, privateExponent, p, q, mDash, block, fingerprint);
    }

    byte[] modulusBigEndian() {
        return toFixed(modulus, 256);
    }

    /**
     * Prove this key is arithmetically usable before a package is trusted to it.
     * The derivation is deterministic, so these can only fail through a real
     * defect (or a forged/edited vector): a 2047-bit modulus, a broken CRT pair,
     * a d that does not invert e, a QCC block that does not describe the key, or
     * a sign/verify roundtrip that disagrees.  Cheap next to a 2 MB flash.
     */
    void selfCheck() {
        if (modulus.bitLength() != 2048) {
            throw new IllegalStateException("derived modulus is " + modulus.bitLength()
                    + " bit, not 2048");
        }
        if (!p.multiply(q).equals(modulus)) {
            throw new IllegalStateException("derived p*q does not equal the modulus");
        }
        BigInteger p1 = p.subtract(BigInteger.ONE);
        BigInteger q1 = q.subtract(BigInteger.ONE);
        BigInteger lambda = p1.multiply(q1).divide(p1.gcd(q1));
        if (!EXPONENT.multiply(privateExponent).mod(lambda).equals(BigInteger.ONE)) {
            throw new IllegalStateException("derived private exponent does not invert e mod lambda");
        }
        long low16 = modulus.and(BigInteger.valueOf(0xFFFFL)).longValue();
        if ((mDash * low16) % 0x10000L != 0xFFFFL) {
            throw new IllegalStateException("m_dash does not invert the modulus mod 2^16");
        }
        if (qccBlock.length != 514) {
            throw new IllegalStateException("QCC block is " + qccBlock.length + " bytes, not 514");
        }
        if (!Arrays.equals(swapUint16(modulusBigEndian()),
                Arrays.copyOfRange(qccBlock, 0, 256))) {
            throw new IllegalStateException("QCC block does not carry this modulus");
        }
        byte[] probe = sha256("BTR15-DEVKEY-SELFCHECK".getBytes(
                java.nio.charset.StandardCharsets.UTF_8));
        byte[] signature = signPss(probe);
        if (signature.length != 256 || !Pss.verify(modulus, signature, probe)) {
            throw new IllegalStateException("PSS sign/verify roundtrip failed for this key");
        }
    }

    /** RSA-PSS (SHA-256, MGF1-SHA256, salt length 222) over arbitrary content. */
    byte[] signPss(byte[] content) {
        return Pss.sign(this, content);
    }

    private static BigInteger generatePrime(HmacDrbg drbg) {
        int bytes = PRIME_BITS / 8;
        while (true) {
            byte[] raw = drbg.generate(bytes);
            raw[0] = (byte) (raw[0] | 0xC0);
            raw[bytes - 1] = (byte) (raw[bytes - 1] | 0x01);
            BigInteger candidate = new BigInteger(1, raw);
            if (candidate.subtract(BigInteger.ONE).gcd(EXPONENT).equals(BigInteger.ONE)
                    && millerRabin(candidate)) {
                return candidate;
            }
        }
    }

    private static boolean millerRabin(BigInteger n) {
        for (int prime : TRIAL_PRIMES) {
            BigInteger small = BigInteger.valueOf(prime);
            if (n.equals(small)) {
                return true;
            }
            if (n.mod(small).equals(BigInteger.ZERO)) {
                return false;
            }
        }
        BigInteger d = n.subtract(BigInteger.ONE);
        int r = d.getLowestSetBit();
        d = d.shiftRight(r);
        BigInteger nMinusOne = n.subtract(BigInteger.ONE);
        for (int base : MR_BASES) {
            BigInteger a = BigInteger.valueOf(base);
            if (a.compareTo(nMinusOne) >= 0) {
                continue;
            }
            BigInteger x = a.modPow(d, n);
            if (x.equals(BigInteger.ONE) || x.equals(nMinusOne)) {
                continue;
            }
            boolean witness = true;
            for (int i = 1; i < r; i++) {
                x = x.modPow(BigInteger.valueOf(2L), n);
                if (x.equals(nMinusOne)) {
                    witness = false;
                    break;
                }
            }
            if (witness) {
                return false;
            }
        }
        return true;
    }

    static byte[] swapUint16(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i + 1 < data.length; i += 2) {
            out[i] = data[i + 1];
            out[i + 1] = data[i];
        }
        return out;
    }

    static byte[] toFixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[length];
        int offset = Math.max(0, raw.length - length);
        int len = Math.min(raw.length, length);
        System.arraycopy(raw, offset, out, length - len, len);
        return out;
    }

    private static int[] firstNPrimes(int count) {
        List<Integer> primes = new ArrayList<>();
        int candidate = 2;
        while (primes.size() < count) {
            boolean prime = true;
            int limit = (int) Math.sqrt(candidate);
            for (int p : primes) {
                if (p > limit) {
                    break;
                }
                if (candidate % p == 0) {
                    prime = false;
                    break;
                }
            }
            if (prime) {
                primes.add(candidate);
            }
            candidate++;
        }
        int[] out = new int[count];
        for (int i = 0; i < count; i++) {
            out[i] = primes.get(i);
        }
        return out;
    }

    static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (Exception error) {
            throw new IllegalStateException("SHA-256 unavailable", error);
        }
    }

    static String hex(byte[] value) {
        StringBuilder out = new StringBuilder(value.length * 2);
        for (byte b : value) {
            out.append(Character.forDigit((b >> 4) & 0xF, 16));
            out.append(Character.forDigit(b & 0xF, 16));
        }
        return out.toString();
    }

    /** NIST SP 800-90A HMAC_DRBG (SHA-256), fixed instantiate + no reseeding. */
    private static final class HmacDrbg {
        private byte[] k;
        private byte[] v;

        HmacDrbg(byte[] entropy, byte[] personalization) {
            k = new byte[32];
            v = new byte[32];
            java.util.Arrays.fill(v, (byte) 0x01);
            byte[] seedMaterial = concat(entropy, personalization);
            k = hmac(k, concat(concat(v, new byte[] {0x00}), seedMaterial));
            v = hmac(k, v);
            k = hmac(k, concat(concat(v, new byte[] {0x01}), seedMaterial));
            v = hmac(k, v);
        }

        byte[] generate(int count) {
            byte[] out = new byte[count];
            int produced = 0;
            while (produced < count) {
                v = hmac(k, v);
                int take = Math.min(v.length, count - produced);
                System.arraycopy(v, 0, out, produced, take);
                produced += take;
            }
            k = hmac(k, concat(v, new byte[] {0x00}));
            v = hmac(k, v);
            return out;
        }
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception error) {
            throw new IllegalStateException("HmacSHA256 unavailable", error);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
