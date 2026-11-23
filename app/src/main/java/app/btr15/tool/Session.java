package app.btr15.tool;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;

/**
 * One live GAIA/Upgrade conversation with a BTR15 over a {@link Transport}.
 *
 * <p>The engine reproduces the exact behaviour proven against the physical
 * device and the strict mock: acknowledgements may arrive before or after an
 * interleaved VM-Upgrade notification; every notification is acknowledged with
 * the 0x8000-masked event and a zero status; the host interlock makes it
 * impossible to emit ABORT_REQ or ERRORWARN_RES, because the jailbreak and
 * stock flows depend on the device sitting in its footer-failure state
 * untouched.  Frames are logged as hex for exported transcripts — never any
 * key material or mnemonic.
 */
final class Session {
    static final long DEFAULT_ACK_TIMEOUT_MS = 6_000L;
    /** Live ImageUpgradeCopy validation can take minutes; proven budget 180 s. */
    static final long DEFAULT_VALIDATION_BUDGET_MS = 180_000L;

    private final Transport transport;
    private final Gaia.StreamDecoder decoder = new Gaia.StreamDecoder();
    private final Deque<Gaia.Frame> inbox = new ArrayDeque<>();
    private final Deque<Upgrade.Message> upgradeQueue = new ArrayDeque<>();
    private final List<String> transcript = new ArrayList<>();
    /** Set by the last key-4 read: true when the device answered "absent" (status 5). */
    private boolean upgradeContextAbsent;
    private final long ackTimeoutMs;
    private long dataFramesSent;
    private long firmwareBytesSent;
    private boolean closed;
    /** Last device-side Upgrade error code seen, or -1 while none has been seen. */
    private int upgradeErrorCode = -1;

    Session(Transport transport, long ackTimeoutMs) {
        this.transport = transport;
        this.ackTimeoutMs = ackTimeoutMs;
    }

    Session(Transport transport) {
        this(transport, DEFAULT_ACK_TIMEOUT_MS);
    }

    long dataFramesSent() {
        return dataFramesSent;
    }

    long firmwareBytesSent() {
        return firmwareBytesSent;
    }

    List<String> transcript() {
        return Collections_unmodifiable(transcript);
    }

    private static List<String> Collections_unmodifiable(List<String> values) {
        return java.util.Collections.unmodifiableList(new ArrayList<>(values));
    }

    void closeQuietly() {
        if (!closed) {
            closed = true;
            transport.close();
        }
    }

    // ---- frame plumbing -----------------------------------------------------

    private void transmit(byte[] packet) throws FirmwareException {
        if (closed) {
            throw new FirmwareException("session is closed");
        }
        log("TX " + Util.hex(packet));
        try {
            transport.send(packet);
        } catch (IOException dead) {
            throw new FirmwareException("Bluetooth link failed while transmitting: " + dead);
        }
    }

    /** Next decoded frame, waiting at most {@code timeoutMs}. */
    private Gaia.Frame nextFrame(long timeoutMs) throws FirmwareException {
        Gaia.Frame buffered = inbox.poll();
        if (buffered != null) {
            return buffered;
        }
        long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
        while (true) {
            long remaining = (deadline - System.nanoTime()) / 1_000_000L;
            if (remaining <= 0) {
                throw new FirmwareException("no GAIA frame within " + timeoutMs + " ms");
            }
            byte[] chunk;
            try {
                chunk = transport.receive(remaining);
            } catch (IOException dead) {
                throw new FirmwareException("Bluetooth link failed while reading: " + dead);
            }
            if (chunk == null) {
                throw new FirmwareException("no GAIA frame within " + timeoutMs + " ms");
            }
            if (chunk.length == 0) {
                continue;
            }
            log("RX " + Util.hex(chunk));
            for (Gaia.Frame frame : decoder.feed(chunk)) {
                inbox.add(frame);
            }
            buffered = inbox.poll();
            if (buffered != null) {
                return buffered;
            }
        }
    }

    /** Absorb notifications while waiting for the acknowledgement of {@code command}. */
    private Gaia.Frame awaitAck(int command, long timeoutMs) throws FirmwareException {
        while (true) {
            Gaia.Frame frame = nextFrame(timeoutMs);
            if (frame.isAck() && frame.vendor == Gaia.VENDOR_QTIL
                    && frame.command == (command | Gaia.ACK_MASK)) {
                return frame;
            }
            if (!absorb(frame)) {
                throw new FirmwareException("expected acknowledgement of 0x"
                        + Integer.toHexString(command) + ", got " + frame.describe());
            }
        }
    }

    /** True when the frame was a VM-Upgrade notification: queue and acknowledge it. */
    private boolean absorb(Gaia.Frame frame) throws FirmwareException {
        if (frame.vendor != Gaia.VENDOR_QTIL || frame.command != Gaia.EVENT_NOTIFICATION) {
            return false;
        }
        upgradeQueue.add(Gaia.upgradeNotification(frame));
        try {
            transmit(Gaia.qtil(Gaia.EVENT_NOTIFICATION | Gaia.ACK_MASK, new byte[] {0}));
        } catch (FirmwareException linkGone) {
            // The device reboots immediately after COMPLETE_IND: the
            // acknowledgement of the notification itself may legitimately die.
            // A genuinely dead link still surfaces on the next frame or send.
        }
        return true;
    }

    // ---- request primitives ---------------------------------------------------

    /** QTIL command with a zero-status expectation, or one of {@code allowedStatuses}. */
    Gaia.Frame command(int command, byte[] payload, int... allowedStatuses)
            throws FirmwareException {
        transmit(Gaia.qtil(command, payload));
        Gaia.Frame ack = awaitAck(command, ackTimeoutMs);
        int status = ack.status();
        int[] allowed = allowedStatuses.length == 0 ? new int[] {0} : allowedStatuses;
        for (int candidate : allowed) {
            if (status == candidate) {
                return ack;
            }
        }
        throw new FirmwareException("GAIA command 0x" + Integer.toHexString(command)
                + " returned status " + status);
    }

    Gaia.Frame command(int command) throws FirmwareException {
        return command(command, new byte[0]);
    }

    /**
     * Send one Upgrade message on the control channel.  The two host-interlock
     * messages can never leave this engine, mirroring the proven client where
     * replying to the footer failure would destroy the jailbreak state.
     */
    void upgrade(int messageId, byte[] body) throws FirmwareException {
        if (messageId == Upgrade.ABORT_REQ || messageId == Upgrade.ERRORWARN_RES) {
            throw new AssertionError("host interlock: refusing to send "
                    + Upgrade.name(messageId));
        }
        transmit(Gaia.control(messageId, body));
        Gaia.Frame ack = awaitAck(Gaia.UPGRADE_CONTROL, ackTimeoutMs);
        if (ack.status() != 0) {
            throw new FirmwareException(Upgrade.name(messageId) + " rejected with status "
                    + ack.status());
        }
    }

    void upgrade(int messageId) throws FirmwareException {
        upgrade(messageId, new byte[0]);
    }

    /** Transmit one already-encoded DATA packet from {@link Upgrade.Sender}. */
    void sendUpgradePacket(byte[] packet) throws FirmwareException {
        transmit(packet);
        Gaia.Frame ack = awaitAck(Gaia.UPGRADE_CONTROL, ackTimeoutMs);
        if (ack.status() != 0) {
            throw new FirmwareException("DATA rejected with status " + ack.status());
        }
        dataFramesSent++;
        // Firmware bytes only: the GAIA header, the Upgrade header and the
        // last-image flag are framing.  Counting them (as this once did) made a
        // continuation that skipped a single packet look like a full retransfer.
        firmwareBytesSent += Math.max(0, packet.length - Upgrade.DATA_FRAME_OVERHEAD);
    }

    /** Wait for the named Upgrade message, draining interleaved notifications first. */
    Upgrade.Message waitUpgrade(int messageId) throws FirmwareException {
        return waitUpgrades(ackTimeoutMs, messageId);
    }

    /**
     * The next Upgrade notification of any kind.  A device that refuses the
     * handshake answers ERRORWARN_IND instead of the message the host is
     * waiting for, and waiting out the full timeout hides that answer — so the
     * handshake uses this and reacts to what the device actually said.
     */
    Upgrade.Message nextUpgradeMessage(long timeoutMs) throws FirmwareException {
        long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
        while (true) {
            Upgrade.Message queued = upgradeQueue.poll();
            if (queued != null) {
                log("MSG " + Upgrade.name(queued.id));
                if (queued.id == Upgrade.ERRORWARN_IND && queued.body.length >= 2) {
                    upgradeErrorCode = ((queued.body[0] & 0xFF) << 8) | (queued.body[1] & 0xFF);
                }
                return queued;
            }
            long remaining = (deadline - System.nanoTime()) / 1_000_000L;
            if (remaining <= 0) {
                throw new FirmwareException("no Upgrade message within " + timeoutMs + " ms");
            }
            Gaia.Frame frame = nextFrame(remaining);
            if (!absorb(frame)) {
                throw new FirmwareException("expected an Upgrade notification, got "
                        + frame.describe());
            }
        }
    }

    /** The device's last Upgrade error code, or -1 when it has reported none. */
    int upgradeErrorCode() {
        return upgradeErrorCode;
    }

    /**
     * Clear a device-side Upgrade error before a single firmware byte has been
     * sent.  The host interlock forbids ABORT_REQ only while a footer-failed
     * image must stay staged; with nothing staged it is exactly the message
     * that releases a stuck upgrade session.  Best effort by design: the
     * handshake that follows proves whether it worked.
     */
    void clearUpgradeError() throws FirmwareException {
        transmit(Gaia.control(Upgrade.ABORT_REQ, new byte[0]));
        try {
            awaitAck(Gaia.UPGRADE_CONTROL, 2_000L);
        } catch (FirmwareException ignored) {
            // no acknowledgement: the retry decides
        }
    }

    Upgrade.Message waitUpgrades(long timeoutMs, int... messageIds) throws FirmwareException {
        long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
        while (true) {
            for (Upgrade.Message queued : upgradeQueue) {
                for (int wanted : messageIds) {
                    if (queued.id == wanted) {
                        upgradeQueue.remove(queued);
                        log("MSG " + Upgrade.name(wanted));
                        return queued;
                    }
                }
            }
            long remaining = (deadline - System.nanoTime()) / 1_000_000L;
            if (remaining <= 0) {
                throw new FirmwareException("none of the awaited Upgrade messages arrived"
                        + " within " + timeoutMs + " ms");
            }
            Gaia.Frame frame = nextFrame(remaining);
            if (!absorb(frame)) {
                throw new FirmwareException("expected an Upgrade notification, got "
                        + frame.describe());
            }
        }
    }

    // ---- domain helpers --------------------------------------------------------

    void registerUpgradeEvents() throws FirmwareException {
        command(Gaia.REGISTER_NOTIFICATION, new byte[] {Gaia.EVENT_VM_UPGRADE});
    }

    void connectUpgrade() throws FirmwareException {
        command(Gaia.UPGRADE_CONNECT);
    }

    /**
     * FiiO version getter, answered as {@code 00 02 major minor}.  The tool
     * patches several official releases, so the only thing pinned here is the
     * shape of a FiiO answer: which release a device actually runs is reported
     * back and logged, not enforced — the package itself names its release by
     * digest.
     */
    String expectFirmwareVersion() throws FirmwareException {
        Gaia.Frame ack = command(Gaia.FIIO_GETTER, new byte[] {0x02});
        byte[] payload = ack.payload;
        if (payload.length != 4 || payload[0] != 0 || payload[1] != 0x02) {
            throw new FirmwareException("firmware version answered " + Util.hex(payload)
                    + " instead of a FiiO 00 02 major minor answer");
        }
        return (payload[2] & 0xFF) + "." + (payload[3] & 0xFF);
    }

    /** Read PS key 4; a fresh device may answer "absent" (status 5), yielding zeros. */
    int[] readUpgradeContext() throws FirmwareException {
        byte[] key = {(byte) (Upgrade.CONTEXT_PS_KEY >>> 8), (byte) Upgrade.CONTEXT_PS_KEY};
        Gaia.Frame ack = command(Gaia.RETRIEVE_PS_KEY, key, 0, 5);
        upgradeContextAbsent = ack.status() == 5;
        int[] words = upgradeContextAbsent
                ? new int[Upgrade.CONTEXT_WORDS]
                : Upgrade.parseRetrieveAck(ack);
        // Every export carries the live context, so a report of "not idle" can be
        // read without decoding frames by hand.  Status 5 is named, not implied:
        // nineteen zeros from an absent key look exactly like a clean journal.
        log("CTX " + Upgrade.contextHex(words)
                + (upgradeContextAbsent ? " (key 4 absent, status 5)" : "")
                + " (" + Upgrade.describeContextWord(words[0]) + ")");
        return words;
    }

    /** True when the last {@link #readUpgradeContext()} saw status 5, not a stored key. */
    boolean upgradeContextAbsent() {
        return upgradeContextAbsent;
    }

    void storeUpgradeContext(int[] words) throws FirmwareException {
        Gaia.Frame frame = Gaia.decode(Upgrade.storeFrame(Upgrade.CONTEXT_PS_KEY, words));
        command(Gaia.STORE_PS_KEY, frame.payload);
    }

    /** EventSysReboot 0x478F interphase reset: no ack, the device reboots. */
    void sendInterphaseReset() throws FirmwareException {
        transmit(Gaia.qtil(Gaia.SEND_APPLICATION_MESSAGE,
                new byte[] {(byte) (Gaia.EVENT_SYS_REBOOT >>> 8), (byte) Gaia.EVENT_SYS_REBOOT}));
    }

    private void log(String line) {
        transcript.add(line);
    }
}
