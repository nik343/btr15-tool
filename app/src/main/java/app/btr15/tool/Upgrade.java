package app.btr15.tool;

import java.util.Arrays;

/**
 * Qualcomm Upgrade library messaging carried over the GAIA QTIL control
 * channel, plus the PS-key-4 upgrade context with FiiO's shipped PS-store
 * quirks.  Message shapes mirror the recovered ADK 6.3 semantics proven on
 * the BTR15: {@code id || u16be length || body}.
 */
final class Upgrade {
    static final int START_REQ = 1;
    static final int START_CFM = 2;
    static final int DATA_BYTES_REQ = 3;
    static final int DATA = 4;
    static final int ABORT_REQ = 7;
    static final int ABORT_CFM = 8;
    static final int TRANSFER_COMPLETE_IND = 11;
    static final int TRANSFER_COMPLETE_RES = 12;
    static final int IN_PROGRESS_IND = 13;
    static final int IN_PROGRESS_RES = 14;
    static final int COMMIT_REQ = 15;
    static final int COMMIT_CFM = 16;
    static final int ERRORWARN_IND = 17;
    static final int COMPLETE_IND = 18;
    static final int SYNC_REQ = 19;
    /** Highest Upgrade protocol version the proven client accepts (mock answers 5). */
    static final int UPGRADE_PROTOCOL_VERSION = 5;
    static final int SYNC_CFM = 20;
    static final int START_DATA_REQ = 21;
    static final int IS_CSR_VALID_DONE_REQ = 22;
    static final int IS_CSR_VALID_DONE_CFM = 23;
    static final int ERRORWARN_RES = 31;

    /** PS key 4: the Upgrade library context, eighteen uint16 words. */
    static final int CONTEXT_PS_KEY = 4;
    static final int CONTEXT_WORDS = 19;
    static final int RESUME_WORD = 13;
    static final int RESUME_PRE_VALIDATE = 1;
    /**
     * The staged image validated and the copy ran, but the host never
     * acknowledged the transfer — no reboot, no trial, no commit yet.  Field
     * capture 2026-11-20: a jailbreak staging on a device that already trusted
     * the key waited passively for a message a passing footer only sends when
     * polled, timed out, and left the device here.
     */
    static final int RESUME_VALIDATED = 2;
    static final int RESUME_POST_REBOOT = 3;
    static final int RESUME_ERROR = 6;
    static final int RESUME_IN_PROGRESS = 8;
    static final int RESUME_COMPLETE = 12;
    static final int STAGED_ID_LOW_WORD = 11;
    static final int STAGED_ID_HIGH_WORD = 12;

    /** Footer signature digest mismatch: the stock trust rejection jailbreak rides on. */
    static final int FOOTER_VALIDATION_FAILED = 0x003D;

    /**
     * Word 0 of the Upgrade context belongs to the sink application, not to the
     * upgrade library (which journals from word 1).  ADK's sink_upgrade.c gives
     * its layout exactly: bits 0-7 are the last GAIA transport that ran
     * UPGRADE_CONNECT ({@code SINK_UPGRADE_TRANSPORT_MASK 0xFF}), bit 15 is the
     * config-reset flag ({@code SINK_UPGRADE_CONFIG_RESET_BIT}), bits 8-14 are
     * unused.  So it is a live state marker with a small enum in it, never a
     * constant: 0x0001 and 0x8001 (SPP, as this tool connects) and 0x8003
     * (GATT, a unit last upgraded over BLE) are all the same clean state.
     */
    static final int TRANSPORT_MASK = 0xFF;
    static final int CONFIG_RESET_BIT = 0x8000;
    /** gaia_transport_type: none, spp, rfcomm, gatt, accessory. */
    static final int TRANSPORT_ACCESSORY = 4;

    /** The transport recorded in context word 0 (gaia_transport_type value). */
    static int contextTransport(int word) {
        return word & TRANSPORT_MASK;
    }

    /** True when context word 0 carries the config-reset flag. */
    static boolean isConfigReset(int word) {
        return (word & CONFIG_RESET_BIT) != 0;
    }

    /** Whether word 0 names a transport the firmware can actually record. */
    static boolean isValidContextPrefix(int word) {
        return contextTransport(word) <= TRANSPORT_ACCESSORY;
    }

    /** Human name for the transport in word 0, for logs and refusals. */
    static String transportName(int word) {
        switch (contextTransport(word)) {
            case 0: return "none";
            case 1: return "spp";
            case 2: return "rfcomm";
            case 3: return "gatt";
            case 4: return "accessory";
            default: return "unknown(" + contextTransport(word) + ")";
        }
    }

    /**
     * Idle Upgrade context proven by verify_clean_v38: a valid sink prefix,
     * active version/config fields (1, 1, 2) and a fully zeroed journal.
     */
    static int[] cleanBaseline(int prefix) throws FirmwareException {
        requireValidPrefix(prefix);
        int[] words = new int[CONTEXT_WORDS];
        words[0] = prefix;
        words[1] = 1;
        words[2] = 1;
        words[3] = 2;
        return words;
    }

    /**
     * Exact key-4 journal the BTR15 leaves after staging a complete image,
     * pinned by the live flows: (prefix, 1, 1, 2, 0, 0, 1, 1, 1, 2, 0,
     * id-low, id-high, resume, 0x000A, 0, 0, 0, 0).  The ERROR variant is the
     * footer-failure state and the POST_REBOOT variant is the trial bank.
     */
    static int[] journalContext(int prefix, long upgradeId, int resumeWord)
            throws FirmwareException {
        requireValidPrefix(prefix);
        int[] words = new int[] {
            prefix, 0x0001, 0x0001, 0x0002,
            0x0000, 0x0000, 0x0001,
            0x0001, 0x0001, 0x0002,
            0x0000,
            (int) (upgradeId & 0xFFFFL),
            (int) ((upgradeId >>> 16) & 0xFFFFL),
            resumeWord,
            0x000A,
            0x0000, 0x0000, 0x0000, 0x0000,
        };
        return words;
    }

    private static void requireValidPrefix(int prefix) throws FirmwareException {
        if (!isValidContextPrefix(prefix)) {
            throw new FirmwareException("unsupported sink context prefix 0x"
                    + Integer.toHexString(prefix));
        }
    }

    /** Conservative 240-byte data bodies keep every GAIA packet at 252 bytes. */
    static final int DEFAULT_CHUNK = 240;

    /**
     * Everything one encoded DATA packet carries besides firmware bytes: the
     * eight-byte GAIA v1 header, the three-byte Upgrade message header
     * (id, uint16 length) and the one-byte last-image flag.
     */
    static final int DATA_FRAME_OVERHEAD = 8 + 3 + 1;

    private Upgrade() { }

    static String name(int messageId) {
        switch (messageId) {
            case START_REQ: return "START_REQ";
            case START_CFM: return "START_CFM";
            case DATA_BYTES_REQ: return "DATA_BYTES_REQ";
            case DATA: return "DATA";
            case ABORT_REQ: return "ABORT_REQ";
            case ABORT_CFM: return "ABORT_CFM";
            case TRANSFER_COMPLETE_IND: return "TRANSFER_COMPLETE_IND";
            case TRANSFER_COMPLETE_RES: return "TRANSFER_COMPLETE_RES";
            case IN_PROGRESS_IND: return "IN_PROGRESS_IND";
            case IN_PROGRESS_RES: return "IN_PROGRESS_RES";
            case COMMIT_REQ: return "COMMIT_REQ";
            case COMMIT_CFM: return "COMMIT_CFM";
            case ERRORWARN_IND: return "ERRORWARN_IND";
            case COMPLETE_IND: return "COMPLETE_IND";
            case SYNC_REQ: return "SYNC_REQ";
            case SYNC_CFM: return "SYNC_CFM";
            case START_DATA_REQ: return "START_DATA_REQ";
            case IS_CSR_VALID_DONE_REQ: return "IS_CSR_VALID_DONE_REQ";
            case IS_CSR_VALID_DONE_CFM: return "IS_CSR_VALID_DONE_CFM";
            case ERRORWARN_RES: return "ERRORWARN_RES";
            default: return "UNKNOWN_" + messageId;
        }
    }

    /** One Upgrade library message. */
    static final class Message {
        final int id;
        final byte[] body;

        Message(int id, byte[] body) {
            this.id = id;
            this.body = body;
        }

        byte[] encode() throws FirmwareException {
            if (id < 0 || id > 0xFF) {
                throw new FirmwareException("Upgrade message id exceeds one byte");
            }
            if (body.length > 0xFFFF) {
                throw new FirmwareException("Upgrade message body exceeds uint16 length");
            }
            byte[] out = new byte[3 + body.length];
            out[0] = (byte) id;
            out[1] = (byte) (body.length >>> 8);
            out[2] = (byte) body.length;
            System.arraycopy(body, 0, out, 3, body.length);
            return out;
        }

        static Message decode(byte[] packet) throws FirmwareException {
            if (packet.length < 3) {
                throw new FirmwareException("truncated Upgrade message");
            }
            int bodyLength = ((packet[1] & 0xFF) << 8) | (packet[2] & 0xFF);
            if (packet.length != 3 + bodyLength) {
                throw new FirmwareException("Upgrade message length mismatch");
            }
            return new Message(packet[0] & 0xFF, Arrays.copyOfRange(packet, 3, packet.length));
        }

        /** u32be fields: for DATA_BYTES_REQ these are requested bytes and start offset. */
        long unsigned32At(int word) throws FirmwareException {
            int at = word * 4;
            if (at + 4 > body.length) {
                throw new FirmwareException("Upgrade body too short for uint32 " + word);
            }
            return ((long) (body[at] & 0xFF) << 24) | ((long) (body[at + 1] & 0xFF) << 16)
                    | ((long) (body[at + 2] & 0xFF) << 8) | (long) (body[at + 3] & 0xFF);
        }

        /**
         * SYNC_CFM layout proven by the live client (btr15_qcc_ota_client.py
         * parse_sync_cfm): resume point (u8), upgrade id (4 bytes big endian),
         * protocol version (u8) — six bytes exactly.
         */
        int syncResumeWord() throws FirmwareException {
            requireSyncCfm();
            return body[0] & 0xFF;
        }

        long syncUpgradeId() throws FirmwareException {
            requireSyncCfm();
            return ((long) (body[1] & 0xFF) << 24) | ((long) (body[2] & 0xFF) << 16)
                    | ((long) (body[3] & 0xFF) << 8) | (long) (body[4] & 0xFF);
        }

        int syncProtocol() throws FirmwareException {
            requireSyncCfm();
            int protocol = body[5] & 0xFF;
            if (protocol < 1 || protocol > UPGRADE_PROTOCOL_VERSION) {
                throw new FirmwareException("unsupported Upgrade protocol " + protocol);
            }
            return protocol;
        }

        private void requireSyncCfm() throws FirmwareException {
            if (id != SYNC_CFM) {
                throw new FirmwareException("message is not SYNC_CFM");
            }
            if (body.length != 6) {
                throw new FirmwareException("SYNC_CFM body is not six bytes");
            }
        }

        /** START_CFM layout proven by require_success_start: status u8, battery mV u16be. */
        int startBatteryMillivolts() throws FirmwareException {
            if (id != START_CFM || body.length != 3 || body[0] != 0) {
                throw new FirmwareException("START_CFM was malformed or unsuccessful");
            }
            return ((body[1] & 0xFF) << 8) | (body[2] & 0xFF);
        }

        String describe() {
            return name(id) + " (" + body.length + " byte body)";
        }
    }

    static Message message(int id, byte[] body) {
        return new Message(id, body == null ? new byte[0] : body);
    }

    /** The u32be upgrade id is literally the last four bytes of the package file. */
    static byte[] upgradeIdBytes(byte[] image) throws FirmwareException {
        if (image.length < 4) {
            throw new FirmwareException("image shorter than an upgrade id");
        }
        return Arrays.copyOfRange(image, image.length - 4, image.length);
    }

    /** The same four bytes for an id that came from a journal, not from bytes. */
    static byte[] upgradeIdBytes(long upgradeId) {
        return new byte[] {
            (byte) (upgradeId >>> 24), (byte) (upgradeId >>> 16),
            (byte) (upgradeId >>> 8), (byte) upgradeId
        };
    }

    static byte[] big32(long value) {
        return new byte[] {(byte) (value >>> 24), (byte) (value >>> 16),
                (byte) (value >>> 8), (byte) value};
    }

    // ---- PS key 4 -----------------------------------------------------------

    /**
     * Word count FiiO's shipped 0x0712 handler really stores: it applies the
     * byte-to-word conversion twice, so a payload of length L stores
     * (((L-2)/2)+1)/2 words and silently ignores the rest.
     */
    static int storedWordCount(int payloadLength) throws FirmwareException {
        if (payloadLength < 2 || payloadLength > 0xFF || (payloadLength & 1) != 0) {
            throw new FirmwareException("PS-store payload length must be even and in 2..254");
        }
        return (((payloadLength - 2) / 2) + 1) / 2;
    }

    /**
     * RETRIEVE_PS_KEY acknowledgement body: u16be status then key and words.
     * Returns the key's words (without the leading key id).
     */
    static int[] parseRetrieveAck(Gaia.Frame frame) throws FirmwareException {
        if (frame.vendor != Gaia.VENDOR_QTIL
                || frame.command != (Gaia.RETRIEVE_PS_KEY | Gaia.ACK_MASK)) {
            throw new FirmwareException("not a RETRIEVE_PS_KEY acknowledgement");
        }
        if (frame.payload.length < 3 || frame.payload[0] != 0) {
            throw new FirmwareException("PS retrieve failed, GAIA status="
                    + (frame.payload.length > 0 ? (frame.payload[0] & 0xFF) : "none"));
        }
        byte[] data = Arrays.copyOfRange(frame.payload, 1, frame.payload.length);
        if ((data.length & 1) != 0) {
            throw new FirmwareException("PS retrieve response has an odd uint16 payload");
        }
        int[] words = new int[data.length / 2];
        for (int i = 0; i < words.length; i++) {
            words[i] = ((data[2 * i] & 0xFF) << 8) | (data[2 * i + 1] & 0xFF);
        }
        if (words.length == 0 || words[0] != CONTEXT_PS_KEY) {
            throw new FirmwareException("PS response key mismatch");
        }
        return Arrays.copyOfRange(words, 1, words.length);
    }

    /**
     * PS-store frame for the shipped handler: key and words stay meaningful,
     * zero padding expands an N-word write to the minimum 4N-byte payload so
     * the double size adjustment passes exactly N words to PsStore.
     */
    static byte[] storeFrame(int key, int[] words) throws FirmwareException {
        byte[] meaningful = new byte[2 + 2 * words.length];
        meaningful[0] = (byte) (key >>> 8);
        meaningful[1] = (byte) key;
        for (int i = 0; i < words.length; i++) {
            meaningful[2 + 2 * i] = (byte) (words[i] >>> 8);
            meaningful[2 + 2 * i + 1] = (byte) words[i];
        }
        byte[] payload;
        if (words.length == 0) {
            payload = meaningful;
        } else {
            int target = 4 * words.length;
            if (target > 0xFF) {
                throw new FirmwareException("PS key cannot fit in one padded GAIA v1 payload");
            }
            payload = Arrays.copyOf(meaningful, target);
        }
        int stored = storedWordCount(payload.length);
        if (stored != words.length) {
            throw new IllegalStateException("PS-store payload would persist " + stored
                    + " words instead of " + words.length);
        }
        for (int i = 0; i < words.length; i++) {
            int at = 2 + 2 * i;
            int got = ((payload[at] & 0xFF) << 8) | (payload[at + 1] & 0xFF);
            if (got != words[i]) {
                throw new IllegalStateException("PS-store payload does not round-trip");
            }
        }
        return Gaia.qtil(Gaia.STORE_PS_KEY, payload);
    }

    /** Rewrite exactly one resume state word, proving nothing else moves. */
    static int[] withResumeWord(int[] words, int expectedCurrent, int replacement)
            throws FirmwareException {
        if (words.length < RESUME_WORD + 6) {
            throw new FirmwareException("upgrade context has " + words.length
                    + " words, expected at least " + (RESUME_WORD + 6));
        }
        if (words[RESUME_WORD] != expectedCurrent) {
            throw new FirmwareException("resume word is " + words[RESUME_WORD] + ", expected "
                    + expectedCurrent + "; refusing to touch an unexpected state");
        }
        int[] copy = words.clone();
        copy[RESUME_WORD] = replacement;
        for (int i = 0; i < words.length; i++) {
            if (i != RESUME_WORD && copy[i] != words[i]) {
                throw new IllegalStateException("context rewrite moved word " + i);
            }
        }
        return copy;
    }

    /** The upgrade id the device has staged, from the two little-endian halves. */
    static long stagedId(int[] words) throws FirmwareException {
        if (words.length < STAGED_ID_HIGH_WORD + 1) {
            throw new FirmwareException("upgrade context too short to name a staged id");
        }
        return (words[STAGED_ID_LOW_WORD] & 0xFFFFL)
                | ((words[STAGED_ID_HIGH_WORD] & 0xFFFFL) << 16);
    }

    /**
     * A journal with nothing staged: a transport word the firmware could have
     * written, the active version/config words, and a zeroed transaction area.
     * The transport itself is not compared — SPP (1) and GATT (3) are both
     * ordinary, and which one a unit remembers only says how its last upgrade
     * client connected.
     */
    static boolean isCleanContext(int[] words) {
        if (words.length != CONTEXT_WORDS) {
            return false;
        }
        if (!isValidContextPrefix(words[0])) {
            return false;
        }
        if (words[1] != 1 || words[2] != 1 || words[3] != 2) {
            return false;
        }
        for (int i = 4; i < words.length; i++) {
            if (words[i] != 0) {
                return false;
            }
        }
        return true;
    }

    /** "transport gatt, config reset set" — how word 0 reads in a log. */
    static String describeContextWord(int word) {
        return "transport " + transportName(word)
                + (isConfigReset(word) ? ", config reset set" : "");
    }

    /**
     * The whole context as space-separated four-digit words.  A refusal to stage
     * has to name the field that stopped it, otherwise "not idle" covers an
     * absent key, a short answer and a genuinely busy device with one sentence.
     */
    static String contextHex(int[] words) {
        StringBuilder out = new StringBuilder(words.length * 5);
        for (int i = 0; i < words.length; i++) {
            if (i > 0) {
                out.append(' ');
            }
            String hex = Integer.toHexString(words[i] & 0xFFFF);
            for (int pad = hex.length(); pad < 4; pad++) {
                out.append('0');
            }
            out.append(hex);
        }
        return out.toString();
    }

    // ---- data pump ----------------------------------------------------------

    /**
     * Device-driven data pump: the BTR15 asks for {@code requested} bytes at
     * {@code offset}; each DATA message carries a last-image flag byte and at
     * most {@code chunk} bytes, and the cursor tracks the image absolutely.
     */
    static final class Sender {
        private final byte[] image;
        private final int chunk;
        private int cursor;
        /** Image offset after each packet of the last batch, in send order. */
        private int[] batchOffsets = new int[0];

        Sender(byte[] image, int chunk) throws FirmwareException {
            if (chunk < 1 || chunk > 250) {
                throw new FirmwareException("chunk size must be in range 1..250");
            }
            this.image = image;
            this.chunk = chunk;
        }

        int cursor() {
            return cursor;
        }

        /**
         * How much of the image the device holds once the pump has transmitted
         * packet {@code index} of the batch the last {@link #satisfy} returned.
         * The pump sends exactly those packets, in that order, so this is the
         * honest "bytes on the device" the status line is built from — a single
         * large request would otherwise jump 0% to 100% in one step.
         */
        int offsetAfter(int index) {
            if (index < 0 || index >= batchOffsets.length) {
                throw new IllegalArgumentException("no packet " + index + " in the current batch");
            }
            return batchOffsets[index];
        }

        /** Satisfy one DATA_BYTES_REQ; returns raw GAIA packets to transmit. */
        byte[][] satisfy(long requested, long startOffset) throws FirmwareException {
            if (requested < 0 || startOffset < 0) {
                throw new FirmwareException("device request fields cannot be negative");
            }
            long target = cursor + startOffset;
            if (target > image.length) {
                throw new FirmwareException("device startOffset runs past the end of the image");
            }
            cursor = (int) target;
            int remaining = (int) Math.min(requested, (long) image.length - cursor);
            byte[][] packets = new byte[(remaining + chunk - 1) / chunk][];
            int[] offsets = new int[packets.length];
            int produced = 0;
            while (remaining > 0) {
                int count = Math.min(remaining, chunk);
                byte[] chunkBytes = Arrays.copyOfRange(image, cursor, cursor + count);
                cursor += count;
                remaining -= count;
                byte last = cursor == image.length ? (byte) 1 : (byte) 0;
                byte[] packet = Gaia.control(DATA, concat(last, chunkBytes));
                if (packet.length > 262) {
                    throw new IllegalStateException("generated DATA packet exceeds GAIA v1 bounds");
                }
                offsetCheck(cursor);
                offsets[produced] = cursor;
                packets[produced++] = packet;
            }
            batchOffsets = Arrays.copyOf(offsets, produced);
            return Arrays.copyOf(packets, produced);
        }

        /** The cursor only ever moves forward inside the image; prove it per packet. */
        private void offsetCheck(int offset) {
            if (offset < 0 || offset > image.length) {
                throw new IllegalStateException("data pump cursor left the image");
            }
        }

        private static byte[] concat(byte head, byte[] tail) {
            byte[] out = new byte[tail.length + 1];
            out[0] = head;
            System.arraycopy(tail, 0, out, 1, tail.length);
            return out;
        }
    }
}
