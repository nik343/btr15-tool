package app.btr15.tool;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

public final class FirmwareInspectorSelfTest {
    private static final String V38_SHA256 =
            "26B21C1779BD9229B7256A055B1D1E55834A0EE48E500B6E0C952206911FDB39";

    public static void main(String[] args) throws Exception {
        require(args.length >= 2, "expected stock firmware and invalid file paths");
        Path stock = Paths.get(args[0]);
        Path invalid = Paths.get(args[1]);

        FirmwareInspector.Result result;
        try (FileInputStream input = new FileInputStream(stock.toFile())) {
            result = FirmwareInspector.inspect(input);
        }
        require(result.hash.equals(V38_SHA256), "stock SHA-256 mismatch");
        require(result.bytes == Files.size(stock), "stock size mismatch");
        require(result.partitions == 7, "stock partition count mismatch");

        for (int index = 2; index < args.length; index++) {
            try (FileInputStream input = new FileInputStream(args[index])) {
                FirmwareInspector.Result additional = FirmwareInspector.inspect(input);
                require(additional.partitions > 0, "additional firmware has no partitions");
            }
        }

        expectInvalid(Files.readAllBytes(invalid));
        byte[] stockBytes = Files.readAllBytes(stock);
        // Regression guard: FirmwareInspector prints %02X, Util.hex lowercase.
        // They must always agree case-insensitively — every cross-layer hash
        // comparison relies on Util.sameHash, and this pin makes drift fatal.
        require(Util.sameHash(result.hash, Util.sha256Hex(stockBytes)),
                "hash format drift: inspector and Util digests disagree");
        require(result.hash.equals(result.hash.toUpperCase(java.util.Locale.US))
                        && !Util.sha256Hex(stockBytes).equals(
                                Util.sha256Hex(stockBytes).toUpperCase(java.util.Locale.US)),
                "hash casing convention changed silently");
        expectInvalid(Arrays.copyOf(stockBytes, stockBytes.length - 1));
        byte[] trailing = Arrays.copyOf(stockBytes, stockBytes.length + 1);
        expectInvalid(trailing);
        readCap(stockBytes);
        System.out.println("Firmware inspector self-test passed");
    }

    /**
     * A wrong pick is refused while streaming: the reader stops at the cap
     * instead of buffering a hundreds-of-megabytes file whole, and a real
     * package passes untouched.
     */
    private static void readCap(byte[] stockBytes) throws Exception {
        require(Arrays.equals(FirmwareRead.all(new ByteArrayInputStream(stockBytes)), stockBytes),
                "a package below the cap is read whole");
        require(FirmwareRead.all(new ByteArrayInputStream(
                        new byte[(int) FirmwareRead.MAX_BYTES])).length == FirmwareRead.MAX_BYTES,
                "a file exactly at the cap is still read");
        try {
            FirmwareRead.all(new ByteArrayInputStream(
                    new byte[(int) FirmwareRead.MAX_BYTES + 1]));
            throw new AssertionError("a file over the cap was buffered anyway");
        } catch (FirmwareException expected) {
            require(expected.getMessage().contains("8 MB"),
                    "the refusal names the limit: " + expected.getMessage());
        }
        // The cap is counted, not trusted: a stream that reports more than it
        // hands over must not slip past it.
        try {
            FirmwareRead.all(new EndlessStream(FirmwareRead.MAX_BYTES + 4096L));
            throw new AssertionError("an oversized stream slipped through");
        } catch (FirmwareException expected) {
            require(expected.getMessage().contains("larger than"), "oversized stream refused");
        }
    }

    /** A filler stream that hands out bytes in awkward, uneven pieces. */
    private static final class EndlessStream extends java.io.InputStream {
        private long left;

        EndlessStream(long bytes) {
            this.left = bytes;
        }

        @Override
        public int read() {
            if (left <= 0) {
                return -1;
            }
            left--;
            return 0x5A;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) {
            if (left <= 0) {
                return -1;
            }
            int count = (int) Math.min(left, Math.min(length, 3001L));
            for (int index = 0; index < count; index++) {
                buffer[offset + index] = 0x5A;
            }
            left -= count;
            return count;
        }
    }

    private static void expectInvalid(byte[] value) throws Exception {
        try {
            FirmwareInspector.inspect(new ByteArrayInputStream(value));
            throw new AssertionError("invalid file accepted");
        } catch (FirmwareInspector.InvalidFirmwareException expected) {
            // Expected.
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
