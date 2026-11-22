package app.btr15.tool;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;

/** Streaming structural validation for Qualcomm APPUHDR5 update containers. */
final class FirmwareInspector {
    private static final byte[] CONTAINER = ascii("APPUHDR5");
    private static final byte[] PLATFORM = ascii("QCC512Xx");
    private static final byte[] PARTITION = ascii("PARTDATA");
    private static final byte[] FOOTER = ascii("APPUPFTR");
    private static final long MAX_HEADER = 1024L * 1024L;
    private static final long MAX_RECORD = 64L * 1024L * 1024L;

    static final class Result {
        final String hash;
        final long bytes;
        final int partitions;

        Result(String hash, long bytes, int partitions) {
            this.hash = hash;
            this.bytes = bytes;
            this.partitions = partitions;
        }
    }

    static final class InvalidFirmwareException extends IOException {
        InvalidFirmwareException(String message) {
            super(message);
        }
    }

    private FirmwareInspector() { }

    static Result inspect(InputStream input) throws Exception {
        try {
            return inspectComplete(input);
        } catch (EOFException error) {
            throw invalid();
        }
    }

    private static Result inspectComplete(InputStream input) throws Exception {
        if (input == null) {
            throw new IOException("Firmware could not be opened");
        }
        Reader reader = new Reader(input);
        byte[] outer = reader.readExact(12);
        if (!Arrays.equals(Arrays.copyOfRange(outer, 0, 8), CONTAINER)) {
            throw invalid();
        }
        long headerSize = u32(outer, 8);
        if (headerSize < PLATFORM.length || headerSize > MAX_HEADER) {
            throw invalid();
        }
        byte[] header = reader.readExact((int) headerSize);
        if (!Arrays.equals(Arrays.copyOfRange(header, 0, PLATFORM.length), PLATFORM)) {
            throw invalid();
        }

        int partitions = 0;
        boolean footerSeen = false;
        while (!footerSeen) {
            byte[] magic;
            try {
                magic = reader.readExact(8);
            } catch (EOFException error) {
                throw invalid();
            }
            if (Arrays.equals(magic, PARTITION)) {
                byte[] record = reader.readExact(8);
                long recordSize = u32(record, 0);
                if (recordSize < 4 || recordSize > MAX_RECORD) {
                    throw invalid();
                }
                reader.discard(recordSize - 4);
                partitions++;
                continue;
            }
            if (Arrays.equals(magic, FOOTER)) {
                byte[] size = reader.readExact(4);
                long footerSize = u32(size, 0);
                if (footerSize == 0 || footerSize > MAX_HEADER) {
                    throw invalid();
                }
                reader.discard(footerSize);
                footerSeen = true;
                continue;
            }
            throw invalid();
        }
        if (partitions == 0 || reader.readOne() != -1) {
            throw invalid();
        }
        return new Result(reader.hash(), reader.total, partitions);
    }

    private static InvalidFirmwareException invalid() {
        return new InvalidFirmwareException("This file is not a BTR15 firmware image.");
    }

    private static long u32(byte[] value, int offset) {
        return ((long) (value[offset] & 0xFF) << 24)
                | ((long) (value[offset + 1] & 0xFF) << 16)
                | ((long) (value[offset + 2] & 0xFF) << 8)
                | (long) (value[offset + 3] & 0xFF);
    }

    private static byte[] ascii(String value) {
        try {
            return value.getBytes("US-ASCII");
        } catch (Exception impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static final class Reader {
        final InputStream input;
        final MessageDigest digest;
        long total;

        Reader(InputStream input) throws Exception {
            this.input = input;
            this.digest = MessageDigest.getInstance("SHA-256");
        }

        byte[] readExact(int length) throws IOException {
            byte[] result = new byte[length];
            int offset = 0;
            while (offset < length) {
                int count = input.read(result, offset, length - offset);
                if (count < 0) {
                    throw new EOFException("Truncated firmware image");
                }
                if (count == 0) {
                    continue;
                }
                digest.update(result, offset, count);
                total += count;
                offset += count;
            }
            return result;
        }

        void discard(long length) throws IOException {
            byte[] buffer = new byte[65536];
            long remaining = length;
            while (remaining > 0) {
                int wanted = (int) Math.min(buffer.length, remaining);
                int count = input.read(buffer, 0, wanted);
                if (count < 0) {
                    throw new EOFException("Truncated firmware image");
                }
                if (count == 0) {
                    continue;
                }
                digest.update(buffer, 0, count);
                total += count;
                remaining -= count;
            }
        }

        int readOne() throws IOException {
            int value = input.read();
            if (value >= 0) {
                digest.update((byte) value);
                total++;
            }
            return value;
        }

        String hash() {
            StringBuilder result = new StringBuilder(64);
            for (byte value : digest.digest()) {
                result.append(String.format(Locale.US, "%02X", value & 0xFF));
            }
            return result.toString();
        }
    }
}
