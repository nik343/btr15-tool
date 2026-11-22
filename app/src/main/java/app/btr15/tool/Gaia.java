package app.btr15.tool;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * GAIA v1 transport framing for the Qualcomm QTIL vendor channel, exactly as
 * FiiO Control 3.45.0 and the QCC5125 Apps image speak it on SPP:
 * {@code FF 01 flags len vendor16be command16be payload [xor]} with a trailing
 * XOR of every preceding byte whenever flag bit 0 is set.
 *
 * <p>The stream decoder resynchronises on 0xFF markers so stray bytes from a
 * half-opened RFCOMM session can never wedge the protocol engine.
 */
final class Gaia {
    static final int VENDOR_QTIL = 0x000A;
    static final int ACK_MASK = 0x8000;
    static final int FLAG_XOR = 0x01;

    static final int REGISTER_NOTIFICATION = 0x4001;
    static final int EVENT_NOTIFICATION = 0x4003;
    static final int UPGRADE_CONNECT = 0x0640;
    static final int UPGRADE_DISCONNECT = 0x0641;
    static final int UPGRADE_CONTROL = 0x0642;
    static final int RETRIEVE_PS_KEY = 0x0710;
    static final int RETRIEVE_PS_KEY_FULL = 0x0711;
    static final int STORE_PS_KEY = 0x0712;
    static final int SEND_APPLICATION_MESSAGE = 0x0721;
    static final int FIIO_GETTER = 0x0400;

    static final int EVENT_VM_UPGRADE = 0x12;
    static final int EVENT_SYS_REBOOT = 0x478F;

    private Gaia() { }

    /** One immutable GAIA v1 packet. */
    static final class Frame {
        final int vendor;
        final int command;
        final int flags;
        final byte[] payload;

        Frame(int vendor, int command, byte[] payload, int flags) {
            this.vendor = vendor;
            this.command = command;
            this.payload = payload;
            this.flags = flags;
        }

        Frame(int vendor, int command, byte[] payload) {
            this(vendor, command, payload, 0);
        }

        boolean isAck() {
            return (command & ACK_MASK) != 0;
        }

        /** Zero GAIA status byte, if present. */
        int status() throws FirmwareException {
            if (payload.length == 0) {
                throw new FirmwareException("GAIA acknowledgement has no status byte");
            }
            return payload[0] & 0xFF;
        }

        byte[] encode() throws FirmwareException {
            if (payload.length > 0xFF) {
                throw new FirmwareException("GAIA v1 payload exceeds one-byte length");
            }
            if (vendor > 0xFFFF || command > 0xFFFF) {
                throw new FirmwareException("GAIA identifier exceeds uint16");
            }
            byte[] packet = new byte[8 + payload.length + ((flags & FLAG_XOR) != 0 ? 1 : 0)];
            packet[0] = (byte) 0xFF;
            packet[1] = 0x01;
            packet[2] = (byte) flags;
            packet[3] = (byte) payload.length;
            packet[4] = (byte) (vendor >>> 8);
            packet[5] = (byte) vendor;
            packet[6] = (byte) (command >>> 8);
            packet[7] = (byte) command;
            System.arraycopy(payload, 0, packet, 8, payload.length);
            if ((flags & FLAG_XOR) != 0) {
                byte check = 0;
                for (int i = 0; i < packet.length - 1; i++) {
                    check ^= packet[i];
                }
                packet[packet.length - 1] = check;
            }
            return packet;
        }

        String describe() {
            return String.format("%s0x%04x %d byte(s)", isAck() ? "ACK " : "",
                    command & ~ACK_MASK, payload.length);
        }
    }

    static Frame decode(byte[] packet) throws FirmwareException {
        if (packet.length < 8 || (packet[0] & 0xFF) != 0xFF || packet[1] != 0x01) {
            throw new FirmwareException("not a GAIA v1 packet");
        }
        int flags = packet[2] & 0xFF;
        int payloadLength = packet[3] & 0xFF;
        int expected = 8 + payloadLength + ((flags & FLAG_XOR) != 0 ? 1 : 0);
        if (packet.length != expected) {
            throw new FirmwareException("GAIA length mismatch: got " + packet.length
                    + ", expected " + expected);
        }
        if ((flags & FLAG_XOR) != 0) {
            byte check = 0;
            for (byte value : packet) {
                check ^= value;
            }
            if (check != 0) {
                throw new FirmwareException("GAIA XOR check failed");
            }
        }
        return new Frame(((packet[4] & 0xFF) << 8) | (packet[5] & 0xFF),
                ((packet[6] & 0xFF) << 8) | (packet[7] & 0xFF),
                Arrays.copyOfRange(packet, 8, 8 + payloadLength), flags);
    }

    /** Incremental SPP framing: yields every complete frame and resyncs on junk. */
    static final class StreamDecoder {
        private byte[] buffer = new byte[0];

        List<Frame> feed(byte[] data) {
            byte[] joined = Arrays.copyOf(buffer, buffer.length + data.length);
            System.arraycopy(data, 0, joined, buffer.length, data.length);
            buffer = joined;
            List<Frame> frames = new ArrayList<>();
            while (true) {
                int start = indexOf(ff(), 1);
                if (start < 0) {
                    buffer = new byte[0];
                    break;
                }
                if (start > 0) {
                    buffer = Arrays.copyOfRange(buffer, start, buffer.length);
                }
                if (buffer.length < 4) {
                    break;
                }
                if (buffer[1] != 0x01) {
                    buffer = Arrays.copyOfRange(buffer, 1, buffer.length);
                    continue;
                }
                int expected = 8 + (buffer[3] & 0xFF)
                        + ((buffer[2] & FLAG_XOR) != 0 ? 1 : 0);
                if (buffer.length < expected) {
                    break;
                }
                byte[] candidate = Arrays.copyOf(buffer, expected);
                try {
                    frames.add(decode(candidate));
                    buffer = Arrays.copyOfRange(buffer, expected, buffer.length);
                } catch (FirmwareException broken) {
                    buffer = Arrays.copyOfRange(buffer, 1, buffer.length);
                }
            }
            return frames;
        }

        private static byte ff() {
            return (byte) 0xFF;
        }

        private int indexOf(byte value, int from) {
            for (int i = from - 1; i < buffer.length; i++) {
                if (buffer[i] == value) {
                    return i;
                }
            }
            return -1;
        }
    }

    static byte[] qtil(int command, byte[] payload) throws FirmwareException {
        return new Frame(VENDOR_QTIL, command, payload == null ? new byte[0] : payload).encode();
    }

    static byte[] qtil(int command) throws FirmwareException {
        return qtil(command, new byte[0]);
    }

    /** QTIL control channel carrying one Upgrade message. */
    static byte[] control(int messageId, byte[] body) throws FirmwareException {
        return qtil(UPGRADE_CONTROL, Upgrade.message(messageId, body).encode());
    }

    static byte[] control(int messageId) throws FirmwareException {
        return control(messageId, new byte[0]);
    }

    /** Decode the Upgrade message carried by a QTIL EVENT_NOTIFICATION frame. */
    static Upgrade.Message upgradeNotification(Frame frame) throws FirmwareException {
        if (frame.vendor != VENDOR_QTIL || frame.command != EVENT_NOTIFICATION) {
            throw new FirmwareException("not a QTIL event-notification frame");
        }
        if (frame.payload.length < 1 || (frame.payload[0] & 0xFF) != EVENT_VM_UPGRADE) {
            throw new FirmwareException("not a VM Upgrade notification");
        }
        return Upgrade.Message.decode(Arrays.copyOfRange(frame.payload, 1, frame.payload.length));
    }

    static Frame expectAck(byte[] packet, int expectedCommand) throws FirmwareException {
        Frame frame = decode(packet);
        if (frame.vendor != VENDOR_QTIL) {
            throw new FirmwareException("acknowledgement from unexpected GAIA vendor");
        }
        if (frame.command != (expectedCommand | ACK_MASK)) {
            throw new FirmwareException("acknowledged 0x"
                    + Integer.toHexString(frame.command) + " but awaited 0x"
                    + Integer.toHexString(expectedCommand | ACK_MASK));
        }
        return frame;
    }
}
