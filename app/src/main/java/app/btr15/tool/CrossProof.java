package app.btr15.tool;

import java.nio.charset.Charset;

/**
 * Platform cross-proof.  Runs on any JVM — the build PC and the phone — with
 * no arguments and no files, and prints XPROOF lines.  The pinned digests
 * below were produced by the frozen BDKD-v1 derivation; a PASS on both
 * machines proves they compute bit-identical keys and RSA-PSS signatures,
 * which is everything the flashing path inherits from the platform.
 *
 * The phone prints the same lines to logcat (tag System.out) via
 * MainActivity's run_selftest mode; proof.ps1 diffs them.
 */
public final class CrossProof {
    static final String V1_MNEMONIC = "abandon abandon abandon abandon abandon"
            + " abandon abandon abandon abandon abandon abandon about";
    private static final byte[] PROOF_CONTENT =
            "btr15 clockwork cross-proof".getBytes(Charset.forName("UTF-8"));

    // Pinned from the frozen BDKD-v1 derivation (PC run, JDK 21).  Any JVM
    // that prints MATCH on all three derives bit-identical developer keys.
    static final String PIN_MODULUS_SHA256 =
            "0ac6fc60f002d28f61295d79ac8cfa7c68a309daa1fb677a6887cfa6fe7370c2";
    static final String PIN_QCC_BLOCK_SHA256 =
            "a80cafe50bef38160f45bf903dd79271bf4f1d020fa33cfe75d2f47be59b2be9";
    static final String PIN_FINGERPRINT =
            "0ac6fc60f002d28f61295d79ac8cfa7c68a309daa1fb677a6887cfa6fe7370c2";

    public static void main(String[] args) {
        String report = run();
        System.out.print(report);
        if (report.contains("=FAIL") || report.contains("MISMATCH")) {
            System.exit(1);
        }
    }

    /** Returns a human-readable report; every line starts with XPROOF. */
    public static String run() {
        StringBuilder out = new StringBuilder();
        DevKey key = DevKey.derive(V1_MNEMONIC);
        String modulusSha = Util.sha256Hex(key.modulusBigEndian());
        String qccSha = Util.sha256Hex(key.qccBlock);
        line(out, "modulus-sha256", modulusSha, PIN_MODULUS_SHA256);
        line(out, "qcc-block-sha256", qccSha, PIN_QCC_BLOCK_SHA256);
        line(out, "fingerprint", key.fingerprint, PIN_FINGERPRINT);
        line(out, "modulus-bitlength",
                String.valueOf(key.modulus.bitLength()), "2048");
        byte[] signature = key.signPss(PROOF_CONTENT);
        boolean roundtrip = Pss.verify(key.modulus, signature, PROOF_CONTENT);
        byte[] tampered = PROOF_CONTENT.clone();
        tampered[0] ^= 0x01;
        boolean rejectsTamper = !Pss.verify(key.modulus, signature, tampered);
        byte[] wrongSignature = signature.clone();
        wrongSignature[wrongSignature.length - 1] ^= 0x01;
        boolean rejectsBadSignature = !Pss.verify(key.modulus, wrongSignature, PROOF_CONTENT);
        line(out, "pss-roundtrip", roundtrip ? "PASS" : "FAIL", "PASS");
        line(out, "pss-rejects-tampered-message", rejectsTamper ? "PASS" : "FAIL", "PASS");
        line(out, "pss-rejects-tampered-signature",
                rejectsBadSignature ? "PASS" : "FAIL", "PASS");
        return out.toString();
    }

    private static void line(StringBuilder out, String name, String value, String expected) {
        boolean pinned = expected != null && expected.length() > 0 && !"PENDING".equals(expected);
        out.append("XPROOF ").append(name).append('=').append(value);
        if (pinned) {
            out.append(expected.equals(value) ? " MATCH" : " MISMATCH");
        }
        out.append('\n');
    }
}
