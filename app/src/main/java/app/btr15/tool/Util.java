package app.btr15.tool;

import java.security.MessageDigest;

/**
 * Pure-JVM byte helpers shared by the offline firmware engine and its tests.
 *
 * <p>Base64 is decoded by hand rather than {@code java.util.Base64} (API 26)
 * or {@code android.util.Base64} because these constants and the firmware
 * engine must also run unmodified on a plain JVM during the regression
 * self-tests.
 */
final class Util {
    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private static final int[] BASE64 = buildBase64Table();

    private Util() { }

    static String hex(byte[] value) {
        char[] out = new char[value.length * 2];
        for (int i = 0; i < value.length; i++) {
            int b = value[i] & 0xFF;
            out[i * 2] = HEX[b >>> 4];
            out[i * 2 + 1] = HEX[b & 0x0F];
        }
        return new String(out);
    }

    static byte[] hex(String text) {
        int length = text.length();
        if ((length & 1) != 0) {
            throw new IllegalArgumentException("hex string has odd length");
        }
        byte[] out = new byte[length / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(text.charAt(i * 2), 16);
            int low = Character.digit(text.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("invalid hex digit");
            }
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }

    static byte[] unbase64(String text) {
        String body = text.replaceAll("\\s", "");
        int padding = 0;
        while (body.endsWith("=")) {
            padding++;
            body = body.substring(0, body.length() - 1);
        }
        int outLength = body.length() * 3 / 4;
        byte[] out = new byte[outLength];
        int accumulator = 0;
        int bits = 0;
        int produced = 0;
        for (int i = 0; i < body.length(); i++) {
            int value = body.charAt(i);
            int sextet = value < BASE64.length ? BASE64[value] : -1;
            if (sextet < 0) {
                throw new IllegalArgumentException("invalid base64 character");
            }
            accumulator = (accumulator << 6) | sextet;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out[produced++] = (byte) ((accumulator >>> bits) & 0xFF);
            }
        }
        if (produced != outLength) {
            throw new IllegalArgumentException("truncated base64 input");
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

    static String sha256Hex(byte[] value) {
        return hex(sha256(value));
    }

    /**
     * The one sanctioned way to compare two hex digests: case-insensitive,
     * because FirmwareInspector prints %02X while hex() prints lowercase.
     * Any code tempted to write hash .equals(hash) is a bug waiting to happen.
     */
    static boolean sameHash(String first, String second) {
        return first != null && second != null && first.equalsIgnoreCase(second);
    }

    private static int[] buildBase64Table() {
        int[] table = new int[128];
        java.util.Arrays.fill(table, -1);
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < alphabet.length(); i++) {
            table[alphabet.charAt(i)] = i;
        }
        return table;
    }
}
