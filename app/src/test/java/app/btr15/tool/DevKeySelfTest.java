package app.btr15.tool;

/**
 * Pinned regression test for BDKD-v1 derivation and the BigInteger RSA-PSS
 * port.  Vectors are the permanent ones from
 * work/btr15_devkey_vectors/bdkd_v1_vectors.json and pss_crosscheck.json
 * (produced by tools/btr15_devkey_derive.py).  Run:
 *   javac -encoding UTF-8 -d build\tests src\app\btr15\tool\*.java tests\app\btr15\tool\DevKeySelfTest.java
 *   java -cp build\tests app.btr15.tool.DevKeySelfTest
 */
public final class DevKeySelfTest {
    private static final String V1_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    private static final String V2_MNEMONIC =
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
    private static final String V3_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    private static final String V1_MODULUS_SHA = "0ac6fc60f002d28f61295d79ac8cfa7c68a309daa1fb677a6887cfa6fe7370c2";
    private static final String V2_MODULUS_SHA = "821756cdb9ae1f5f546ae26ac175af31111009d79124b861748c8d53f418152d";
    private static final String V3_MODULUS_SHA = "0238152cc25871f8d355ba02536141e4dfe09e0b93507bb9d01d7057b38cdf2d";
    private static final String V1_BLOCK_SHA = "a80cafe50bef38160f45bf903dd79271bf4f1d020fa33cfe75d2f47be59b2be9";
    private static final String V2_BLOCK_SHA = "d75ff27165a1d48bd1d7bc1ee7a17980cd64f7eea1d45476983661ca46a25f6d";
    private static final String V3_BLOCK_SHA = "cd8b5a1f66cf6c36dbe987c9a400665e9dc2d2196b2d156e60b4a858ab3a1ee0";
    private static final String V1_P = "dc42f15a2247271316c4a06456a105beb0870ec647e0c3ff108539cc7293c764149316dd5bd5417f7247d507980464effb0d2c11d2776e1d860b68ba6219d9ded8003abd39689c20d9ddc9c8814682f5efcfbdaf6100ec097b967f282f7d9909987d795238ada17dd3c7a15c1e51a0894a45c5f5cea1a9c218561027fb57907d";
    private static final String V1_Q = "d8c827012eaacdf77c51c71e413770e85121f394355afe315e7918942a119a07e6521e30172e2b068b43d40535708bceae01c854f9037dff4d3495fdade0c2fc3f9ce7f4493fb67285cf7051e1885d7461f6a68082e2217d0b5c8edd4d2e8dd6d1efdf34db119bf2409dab223144b828f16733b9aa55291bfb9203f2ccae5583";
    private static final String V2_P = "e63c500205d09dcf6cbb7a95d4dc1d65657c9624d0745715543d06ea395f1c87116d6a46a3236ece67bcf75c44780b4f0fddf9767b2833cd11f8424442103ea1a51dc69f4b774fbfe7df0fdcd5b08b31583e02de9f60878387e5119a0acb61175774cd3ce45b269f44e65f2029b4808ca5d12cd9deaad71ec005528956373d9d";
    private static final String V2_Q = "e56a04ec074161513977c26ee8da5b81d1e08e4e7276b6f8b21abcb8ce6242cf6e16d44d1e616f3df0e946f67124022b9b2692bd794ed4281a08c51aabe7df6b2d8ba3e971a2973b7f7e9f6493dde5e33ede9aa10184bc0b8ff0157a803c2a8c7fdfe3f6adaac737943b87fbf7cb66d4d01411b804d496f1c80b5c13dd2dc6af";
    private static final String V3_P = "f6cdd25dfb7861329d96a0b20a4063060e64434428f67a51b4abf244ef054f57bede2154ae0a65b56d4bf435339a3453f9fef0ff5f1b267c65a9940a431c813d0aad0a27d0276f85f37e0d3254c49646be464029151d0366341983ded214d0ed369109e67826efd23400ab104b5b8b2a938c6415d7907fd41062b482c73bafc7";
    private static final String V3_Q = "e6fc020b1c58234a6dacb4c2da78f0867ea60328ce77129cdcef435cecc7d0c3bd8d167425163c30fc116dada2b21ec61237b511249453e8c04aaef4ab40f398cf7a792f6b5b774ef8b65d77d7377acc13c1ba73f07ab05e2f348cfd8ec1e6b11534a60bea2e64b9a0092f4f2563ee072ddd6097567a9f5a5ccf9b1d1227fa8f";
    private static final String V1_M_DASH = "af39";
    private static final String V2_M_DASH = "6825";
    private static final String V3_M_DASH = "89e7";
    private static final String V1_SEED_SHA = "62a772f85e4be6226108b56c0b1cf935c2490e434adec864fe47b189f1ed517d";
    private static final String V2_SEED_SHA = "f7b66042adf5a23189e2235045752f22b46af06c483d925c298cbeeb4534da1a";
    private static final String V3_SEED_SHA = "89c4a8ef3af3a5aff8421e632e8430f295088836e135beb86001b4e3d61da1fe";

    // pss_crosscheck.json: signature over the oracle's message produced by
    // the Python oracle under V1's key; Java must verify the exact bytes.
    private static final String PSS_MESSAGE_HEX =
            "4254523135205053532063726f73732d636865636b206d65737361676520666f722074686520416e64726f696420706f72742e";
    private static final String PSS_SIGNATURE_HEX =
            "148ceabc25e95a48b9ebba6d0efd6d25cb0acf56a08111df9b4c7620b191cafb"
            + "3ad734aed0fdb566da80352c7d5a87cbdf5b8bd677693426aea095b92976a2de"
            + "ea283b3a8582c5988ac5deb53d30efd04d1b973d5b3488abcf97d790a291af5a"
            + "55246b27aeebe98a66ebf09c5b59c6404a1fb6a4922bf4654b24adf7f9edde22"
            + "7bd8c49699c0f533c136b8c368452dfe06d3fce5822e390208764ba5c2dde929"
            + "04115fe5a84a96ee91c6e2422f69f558d4f731cb866f60e3bbbab37fa47cf684"
            + "974908ebd9f59906866b6e986be53e20b14acd4168de7d8756ac78c980798366"
            + "9d121cf06bf0b1820c0db5c3243cf86e8940562353a911feb8037f40d8fcba9c";
    private static final String PSS_SIGNATURE_SHA =
            "c89c54fab8e9a6f40e0cd1be19ea20db10999575b69bbe14e59b0b381c9b2483";

    private static int checks = 0;

    public static void main(String[] args) {
        trezorSeedVector();
        checkVector("v1", V1_MNEMONIC, V1_MODULUS_SHA, V1_BLOCK_SHA, V1_M_DASH, V1_SEED_SHA, V1_P, V1_Q);
        checkVector("v2", V2_MNEMONIC, V2_MODULUS_SHA, V2_BLOCK_SHA, V2_M_DASH, V2_SEED_SHA, V2_P, V2_Q);
        checkVector("v3", V3_MNEMONIC, V3_MODULUS_SHA, V3_BLOCK_SHA, V3_M_DASH, V3_SEED_SHA, V3_P, V3_Q);
        pssRoundTripAndCrossCheck();
        selfCheckEveryVector();
        System.out.println("DevKeySelfTest: PASS (" + checks + " checks)");
    }

    /** The runtime guard the app runs before signing must pass for real keys. */
    private static void selfCheckEveryVector() {
        for (String mnemonic : new String[] {V1_MNEMONIC, V2_MNEMONIC, V3_MNEMONIC}) {
            DevKey key = DevKey.derive(mnemonic);
            key.selfCheck();
            expect(true, "selfCheck passes (p*q, e*d mod lambda, m_dash, block, PSS roundtrip)");
        }
    }

    private static void trezorSeedVector() {
        byte[] seed = Bip39.toSeed(V1_MNEMONIC, "TREZOR");
        String hex = DevKey.hex(seed);
        String expected = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
                + "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
        expect(hex.equals(expected), "TREZOR BIP-39 seed vector");
    }

    private static void checkVector(String name, String mnemonic, String modulusSha, String blockSha,
                                    String mDash, String seedSha, String pHex, String qHex) {
        expect(Bip39.isValid(mnemonic), name + " mnemonic is valid BIP-39");
        byte[] seed = Bip39.toSeed(mnemonic, "");
        expect(seed.length == 64, name + " seed is 64 bytes");
        expect(DevKey.hex(DevKey.sha256(seed)).equals(seedSha), name + " BIP-39 seed digest");
        DevKey key = DevKey.derive(mnemonic);
        expect(DevKey.hex(DevKey.sha256(key.modulusBigEndian())).equals(modulusSha),
                name + " modulus digest");
        expect(DevKey.hex(DevKey.sha256(key.qccBlock)).equals(blockSha), name + " QCC block digest");
        expect(String.format("%04x", key.mDash).equals(mDash), name + " m_dash");
        expect(DevKey.hex(DevKey.toFixed(key.p, 128)).equals(pHex), name + " p");
        expect(DevKey.hex(DevKey.toFixed(key.q, 128)).equals(qHex), name + " q");
        expect(key.modulus.bitLength() == 2048, name + " modulus is 2048-bit");
        expect(key.p.multiply(key.q).equals(key.modulus), name + " p*q == n");
        expect(key.qccBlock.length == 514, name + " QCC block is 514 bytes");
    }

    private static void pssRoundTripAndCrossCheck() {
        DevKey key = DevKey.derive(V1_MNEMONIC);
        byte[] message = new byte[600_000];
        for (int i = 0; i < message.length; i++) {
            message[i] = (byte) (i * 31 + 7);
        }
        byte[] signature = key.signPss(message);
        expect(signature.length == 256, "PSS signature is 256 bytes");
        expect(Pss.verify(key.modulus, signature, message), "PSS Java sign -> Java verify");
        byte[] tamperedMessage = message.clone();
        tamperedMessage[12345] ^= 0x01;
        expect(!Pss.verify(key.modulus, signature, tamperedMessage), "PSS rejects tampered message");
        // Cross-verification against the pinned Python-oracle signature.
        byte[] crossMessage = hexToBytes(PSS_MESSAGE_HEX);
        byte[] sig = hexToBytes(PSS_SIGNATURE_HEX);
        expect(DevKey.hex(DevKey.sha256(sig)).equals(PSS_SIGNATURE_SHA), "PSS vector signature digest");
        expect(Pss.verify(key.modulus, sig, crossMessage), "PSS Python sign -> Java verify");
        byte[] em = DevKey.toFixed(new java.math.BigInteger(1, sig)
                .modPow(DevKey.EXPONENT, key.modulus), 256);
        expect(Pss.verifyEncoded(em, DevKey.sha256(crossMessage)), "PSS encoded-message verify");
        expect(!Pss.verify(key.modulus, tamper(sig), crossMessage), "PSS rejects tampered signature");
    }

    private static byte[] tamper(byte[] value) {
        byte[] copy = value.clone();
        copy[copy.length / 2] ^= 0x01;
        return copy;
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static void expect(boolean condition, String label) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAIL: " + label);
        }
        System.out.println("ok: " + label);
    }
}
