package app.btr15.tool;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Structural parse and rebuild of Qualcomm APPUHDR5 upgrade packages.
 *
 * <p>Layout: {@code APPUHDR5} + u32be header size + header, then a sequence
 * of {@code PARTDATA} + u32be record size (counting the size field itself) +
 * u16be partition type + u16be partition number + payload, and one closing
 * {@code APPUPFTR} + u32be footer size + exactly 256 bytes of RSA-PSS
 * signature with nothing after it.  The signed content is every PARTDATA
 * payload concatenated in record order; the device's upgrade id is the last
 * four bytes of the file (the tail of the signature).
 */
final class AppPackage {
    static final int SIGNATURE_SIZE = 256;
    private static final byte[] CONTAINER = Util.hex("4150505548445235"); // APPUHDR5
    private static final byte[] PARTITION = Util.hex("5041525444415441"); // PARTDATA
    private static final byte[] FOOTER = Util.hex("4150505550465452"); // APPUPFTR

    static final class Partition {
        final int type;
        final int number;
        final byte[] payload;

        Partition(int type, int number, byte[] payload) {
            this.type = type;
            this.number = number;
            this.payload = payload;
        }

        String sha256Hex() {
            return Util.sha256Hex(payload);
        }
    }

    final byte[] header;
    final List<Partition> partitions;
    final byte[] signature;

    private AppPackage(byte[] header, List<Partition> partitions, byte[] signature) {
        this.header = header;
        this.partitions = Collections.unmodifiableList(partitions);
        this.signature = signature;
    }

    static AppPackage parse(byte[] blob) throws FirmwareException {
        if (blob.length < 12 || !Arrays.equals(Arrays.copyOf(blob, 8), CONTAINER)) {
            throw new FirmwareException("input is not an APPUHDR5 container");
        }
        long headerSize = unsigned32(blob, 8);
        long headerEnd = 12 + headerSize;
        if (headerSize < 4 || headerEnd > blob.length) {
            throw new FirmwareException("truncated or absurd APPUHDR5 header");
        }
        List<Partition> partitions = new ArrayList<>();
        byte[] signature = null;
        long cursor = headerEnd;
        while (cursor < blob.length) {
            if (cursor + 8 > blob.length) {
                throw new FirmwareException("truncated record magic");
            }
            byte[] magic = Arrays.copyOfRange(blob, (int) cursor, (int) cursor + 8);
            cursor += 8;
            if (Arrays.equals(magic, PARTITION)) {
                if (signature != null) {
                    throw new FirmwareException("PARTDATA found after APPUPFTR");
                }
                if (cursor + 8 > blob.length) {
                    throw new FirmwareException("truncated PARTDATA header");
                }
                long recordSize = unsigned32(blob, (int) cursor);
                int type = unsigned16(blob, (int) cursor + 4);
                int number = unsigned16(blob, (int) cursor + 6);
                if (recordSize < 4) {
                    throw new FirmwareException("invalid PARTDATA size");
                }
                long payloadSize = recordSize - 4;
                long payloadStart = cursor + 8;
                long payloadEnd = payloadStart + payloadSize;
                if (payloadEnd > blob.length) {
                    throw new FirmwareException("truncated PARTDATA payload");
                }
                partitions.add(new Partition(type, number,
                        Arrays.copyOfRange(blob, (int) payloadStart, (int) payloadEnd)));
                cursor = payloadEnd;
                continue;
            }
            if (Arrays.equals(magic, FOOTER)) {
                if (signature != null) {
                    throw new FirmwareException("duplicate APPUPFTR");
                }
                if (cursor + 4 > blob.length) {
                    throw new FirmwareException("truncated APPUPFTR header");
                }
                long footerSize = unsigned32(blob, (int) cursor);
                long footerStart = cursor + 4;
                long footerEnd = footerStart + footerSize;
                if (footerSize != SIGNATURE_SIZE || footerEnd > blob.length) {
                    throw new FirmwareException("APPUPFTR footer must hold one 256-byte signature");
                }
                signature = Arrays.copyOfRange(blob, (int) footerStart, (int) footerEnd);
                cursor = footerEnd;
                break;
            }
            throw new FirmwareException("unknown record magic inside container");
        }
        if (signature == null) {
            throw new FirmwareException("container has no APPUPFTR");
        }
        if (cursor != blob.length) {
            throw new FirmwareException("container has trailing bytes");
        }
        if (partitions.isEmpty()) {
            throw new FirmwareException("container has no PARTDATA records");
        }
        return new AppPackage(Arrays.copyOfRange(blob, 12, (int) headerEnd), partitions, signature);
    }

    /** All PARTDATA payloads concatenated in record order: the signed content. */
    byte[] signedContent() {
        int total = 0;
        for (Partition partition : partitions) {
            total += partition.payload.length;
        }
        byte[] content = new byte[total];
        int cursor = 0;
        for (Partition partition : partitions) {
            System.arraycopy(partition.payload, 0, content, cursor, partition.payload.length);
            cursor += partition.payload.length;
        }
        return content;
    }

    /** The device-visible upgrade id: the last four bytes of the file. */
    long upgradeId() throws FirmwareException {
        return unsigned32(signature, SIGNATURE_SIZE - 4);
    }

    Partition partition(int number) throws FirmwareException {
        Partition found = null;
        for (Partition partition : partitions) {
            if (partition.number == number) {
                if (found != null) {
                    throw new FirmwareException("duplicate partition number " + number);
                }
                found = partition;
            }
        }
        if (found == null) {
            throw new FirmwareException("container lacks partition " + number);
        }
        return found;
    }

    /** Re-serialize with a new payload set and signature; header bytes unchanged. */
    static byte[] assemble(byte[] header, List<Partition> newPartitions, byte[] signature)
            throws FirmwareException {
        if (signature.length != SIGNATURE_SIZE) {
            throw new FirmwareException("signature must be 256 bytes");
        }
        long total = 12 + header.length + 8 + 4 + SIGNATURE_SIZE;
        for (Partition partition : newPartitions) {
            total += 8 + 8 + (long) partition.payload.length;
        }
        if (total > Integer.MAX_VALUE) {
            throw new FirmwareException("assembled package too large");
        }
        byte[] out = new byte[(int) total];
        int cursor = 0;
        System.arraycopy(CONTAINER, 0, out, cursor, 8);
        cursor += 8;
        writeUnsigned32(out, cursor, header.length);
        cursor += 4;
        System.arraycopy(header, 0, out, cursor, header.length);
        cursor += header.length;
        for (Partition partition : newPartitions) {
            System.arraycopy(PARTITION, 0, out, cursor, 8);
            cursor += 8;
            writeUnsigned32(out, cursor, partition.payload.length + 4);
            writeUnsigned16(out, cursor + 4, partition.type);
            writeUnsigned16(out, cursor + 6, partition.number);
            cursor += 8;
            System.arraycopy(partition.payload, 0, out, cursor, partition.payload.length);
            cursor += partition.payload.length;
        }
        System.arraycopy(FOOTER, 0, out, cursor, 8);
        cursor += 8;
        writeUnsigned32(out, cursor, SIGNATURE_SIZE);
        cursor += 4;
        System.arraycopy(signature, 0, out, cursor, SIGNATURE_SIZE);
        return out;
    }

    private static long unsigned32(byte[] value, int offset) throws FirmwareException {
        if (offset + 4 > value.length) {
            throw new FirmwareException("truncated uint32");
        }
        return ((long) (value[offset] & 0xFF) << 24)
                | ((long) (value[offset + 1] & 0xFF) << 16)
                | ((long) (value[offset + 2] & 0xFF) << 8)
                | (long) (value[offset + 3] & 0xFF);
    }

    private static int unsigned16(byte[] value, int offset) {
        return ((value[offset] & 0xFF) << 8) | (value[offset + 1] & 0xFF);
    }

    private static void writeUnsigned32(byte[] out, int offset, long value) {
        out[offset] = (byte) (value >>> 24);
        out[offset + 1] = (byte) (value >>> 16);
        out[offset + 2] = (byte) (value >>> 8);
        out[offset + 3] = (byte) value;
    }

    private static void writeUnsigned16(byte[] out, int offset, int value) {
        out[offset] = (byte) (value >>> 8);
        out[offset + 1] = (byte) value;
    }
}
