package app.btr15.tool;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Stateful simulated BTR15 for JVM scenario tests, driven only through the
 * same GAIA/Upgrade protocol bytes the phone will send over RFCOMM.
 *
 * <p>Device-side truth kept across connections (flash + PS store): running
 * firmware bytes, the trust modulus extracted from the running image's Apps
 * P1 developer-key block, the key-4 upgrade context, the staged image, and a
 * fixed key-1 identity block so tests can prove MAC/section-10 preservation.
 *
 * <p>Footer validation is real RSA-PSS verification against the current trust
 * modulus, so the stock device answers the proven 0x003d footer failure for a
 * developer-signed candidate and a jailbroken device accepts it.  Cold power
 * cycles normalise the staged-id words exactly like the physical device.
 *
 * <p>Fault injection: {@link #crashAt} loses device power at a named
 * persistent-state boundary (state written to flash first, answer lost), and
 * {@link #killDataAfter} drops the link mid-transfer after N image bytes,
 * leaving the partial-transfer context the proven resume path expects.
 */
final class SimBtr15Peer {
    static final int SINK_PREFIX = 0x8001;

    static final int CRASH_FOOTER = 1;
    static final int CRASH_PS_STORE = 2;
    static final int CRASH_AFTER_RESUME = 3;
    static final int CRASH_BEFORE_COMPLETE = 4;
    /** Power lost the instant validation passed, before the host is told. */
    static final int CRASH_AFTER_VALIDATION = 5;

    private int[] ps4 = cleanContext();
    private final int[] ps1 = {0x001C, 0x1CED, 0x0098, 0x40ED};
    private byte[] firmware;
    private BigInteger trustModulus;

    private ByteArrayOutputStream staged;
    private boolean stagedComplete;
    private boolean stagedValid;
    private long stagedId;
    private int received;
    private int skipOffered;
    private boolean awaitingValidation;
    private int validationPolls;
    private boolean linkDown;

    private int crashPoint;
    private int killAfterBytes = -1;
    private int maxSkipObserved;
    private int totalDataPackets;
    /** Bytes the device asks for per {@code DATA_BYTES_REQ}; 240 is the host's chunk. */
    private int requestBytes = Upgrade.DEFAULT_CHUNK;
    /** Where the RSA constant block sits in this device's Apps P1. */
    private final int keyBlockOffset;
    /** The version answer this device gives the FiiO getter. */
    private final byte[] getterAnswer;
    private int silentSyncs;
    private int syncRequests;
    private int connections;
    private int refuseSyncCode = -1;
    private int refuseSyncs;
    private boolean abortClears = true;
    private int aborts;

    SimBtr15Peer(byte[] stockFirmware, BigInteger stockTrust) {
        this.firmware = stockFirmware;
        this.trustModulus = stockTrust;
        this.keyBlockOffset = blockOffsetOf(stockFirmware);
        this.getterAnswer = getterAnswerOf(stockFirmware);
    }

    /**
     * Where this device's RSA constant block lives in Apps P1: the profile of
     * the release it runs.  A flashed image keeps the same layout, so the offset
     * is read once, at construction.
     */
    private static int blockOffsetOf(byte[] image) {
        try {
            FirmwareReleases.Release release = FirmwareReleases.byDigest(image);
            if (release != null) {
                return release.keyBlockP1Offset;
            }
            byte[] p1 = AppPackage.parse(image).partition(FirmwareProfile.P1_NUMBER).payload;
            java.util.List<Integer> hits = FirmwareProfile.findAll(p1, FirmwareProfile.fiioBlock());
            return hits.size() == 1 ? hits.get(0).intValue()
                    : FirmwareProfile.FIIO_BLOCK_P1_OFFSET;
        } catch (Exception unknown) {
            return FirmwareProfile.FIIO_BLOCK_P1_OFFSET;
        }
    }

    /** The version this device answers, taken from the release it runs. */
    private static byte[] getterAnswerOf(byte[] image) {
        byte[] answer = {0, 2, 3, 8};
        FirmwareReleases.Release release = FirmwareReleases.byDigest(image);
        if (release != null && release.label.length() == 4) {
            answer[2] = (byte) (release.label.charAt(1) - '0');
            answer[3] = (byte) (release.label.charAt(3) - '0');
        }
        return answer;
    }

    static int[] cleanContext() {
        try {
            return Upgrade.cleanBaseline(SINK_PREFIX);
        } catch (FirmwareException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    // ---- test-facing device state ---------------------------------------------

    synchronized BigInteger trust() {
        return trustModulus;
    }

    synchronized String firmwareSha256() {
        return Util.sha256Hex(firmware);
    }

    /**
     * Signed-content digest of the running image: stable across rebuilds
     * (random PSS salt lives in the footer), so tests may compare it against
     * a fresh build of the same variant.
     */
    synchronized String firmwareContentSha256() {
        try {
            return Workflows.contentSha256(firmware);
        } catch (FirmwareException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    synchronized int[] key4() {
        return ps4.clone();
    }

    /** Force a key-4 context, e.g. to stand in for a foreign half-done upgrade. */
    synchronized void forceContext(int[] words) {
        ps4 = words.clone();
    }

    synchronized int[] key1() {
        return ps1.clone();
    }

    synchronized int maxSkipObserved() {
        return maxSkipObserved;
    }

    synchronized int totalDataPackets() {
        return totalDataPackets;
    }

    /** Arm a power loss at the next occurrence of the named persistent boundary. */
    synchronized void crashAt(int point) {
        crashPoint = point;
    }

    synchronized void killDataAfter(int bytes) {
        killAfterBytes = bytes;
    }

    /**
     * Ask for {@code bytes} per request instead of a full 240-byte message.
     * The field device paces itself this way and its windows are not multiples
     * of the host's chunk (the proven capture took 1,933,208 bytes in 30
     * requests), so each request that ends off the grid costs a short DATA
     * message of its own — the reason a fixed packet total is only a floor.
     */
    synchronized void requestBytes(int bytes) {
        requestBytes = Math.max(1, bytes);
    }

    /**
     * Serve the next {@code count} SYNC requests the way the field device did
     * on a link it had not really bound yet: acknowledge the GAIA frame (so
     * the host's send succeeds) and never send SYNC_CFM.  Everything else on
     * that link still answers, which is exactly what made the real failure so
     * confusing.
     */
    synchronized void silenceSyncs(int count) {
        silentSyncs = count;
    }

    /** How many SYNC requests the device has seen across all connections. */
    synchronized int syncRequests() {
        return syncRequests;
    }

    /** How many ABORT_REQ messages the host sent. */
    synchronized int aborts() {
        return aborts;
    }

    /**
     * Answer the next {@code count} SYNC requests the way the field device did
     * while an upgrade session was stuck: ERRORWARN_IND with {@code code} and
     * no SYNC_CFM.  ABORT_REQ clears the condition, exactly like the device.
     */
    synchronized void refuseSyncs(int code, int count) {
        refuseSyncCode = code;
        refuseSyncs = count;
        abortClears = true;
    }

    /** A device that stays stuck: nothing the host sends releases the refusal. */
    synchronized void refuseSyncsAlways(int code) {
        refuseSyncCode = code;
        refuseSyncs = Integer.MAX_VALUE;
        abortClears = false;
    }

    /** How many RFCOMM connections the host opened against this device. */
    synchronized int connections() {
        return connections;
    }

    /** User power-cycles the device: PRE_VALIDATE id words normalise to zero. */
    synchronized void coldPowerCycle() {
        linkDown = true;
        stagedComplete = false;
        awaitingValidation = false;
        validationPolls = 0;
        if (ps4[Upgrade.RESUME_WORD] == Upgrade.RESUME_PRE_VALIDATE) {
            ps4[Upgrade.STAGED_ID_LOW_WORD] = 0;
            ps4[Upgrade.STAGED_ID_HIGH_WORD] = 0;
        }
    }

    /** The 60 s IN_PROGRESS timeout fires: the trial bank is discarded. */
    synchronized void rollBackTrial() {
        linkDown = true;
        staged = null;
        stagedComplete = false;
        awaitingValidation = false;
    }

    Transport openConnection() {
        synchronized (this) {
            linkDown = false;
            connections++;
        }
        return new LoopbackTransport(this);
    }

    // ---- protocol engine ---------------------------------------------------------

    /** One host packet in, device frames appended to {@code rx}. */
    synchronized void receive(byte[] chunk, List<byte[]> rx) throws IOException {
        if (linkDown) {
            throw new IOException("RFCOMM link is down (device powered off or rebooting)");
        }
        Gaia.Frame frame;
        try {
            frame = Gaia.decode(chunk);
        } catch (FirmwareException broken) {
            throw new IOException("device cannot parse host frame: " + broken.getMessage());
        }
        List<byte[]> out = new ArrayList<>();
        try {
            process(frame, out);
        } catch (FirmwareException refused) {
            throw new IOException("device refused frame: " + refused.getMessage());
        } catch (IOException powerLossEvent) {
            crashPoint = 0; // the armed boundary fired: power is only lost once
            linkDown = true;
            throw powerLossEvent;
        }
        rx.addAll(out);
    }

    private void process(Gaia.Frame frame, List<byte[]> out) throws FirmwareException,
            IOException {
        if (frame.vendor != Gaia.VENDOR_QTIL) {
            throw new FirmwareException("unsupported GAIA vendor");
        }
        switch (frame.command) {
            case Gaia.REGISTER_NOTIFICATION:
                out.add(Gaia.qtil(Gaia.REGISTER_NOTIFICATION | Gaia.ACK_MASK, new byte[] {0}));
                return;
            case Gaia.EVENT_NOTIFICATION | Gaia.ACK_MASK:
                return;
            case Gaia.UPGRADE_CONNECT:
                out.add(Gaia.qtil(Gaia.UPGRADE_CONNECT | Gaia.ACK_MASK, new byte[] {0}));
                return;
            case Gaia.UPGRADE_DISCONNECT:
                out.add(Gaia.qtil(Gaia.UPGRADE_DISCONNECT | Gaia.ACK_MASK, new byte[] {0}));
                return;
            case Gaia.FIIO_GETTER:
                out.add(Gaia.qtil(Gaia.FIIO_GETTER | Gaia.ACK_MASK, getterAnswer));
                return;
            case Gaia.RETRIEVE_PS_KEY:
                retrieve(frame.payload, out);
                return;
            case Gaia.STORE_PS_KEY:
                store(frame.payload, out);
                return;
            case Gaia.SEND_APPLICATION_MESSAGE:
                interphaseReset();
                return;
            case Gaia.UPGRADE_CONTROL:
                control(Upgrade.Message.decode(frame.payload), out);
                return;
            default:
                throw new FirmwareException("unhandled GAIA command 0x"
                        + Integer.toHexString(frame.command));
        }
    }

    private void retrieve(byte[] payload, List<byte[]> out) throws FirmwareException {
        int key = ((payload[0] & 0xFF) << 8) | (payload[1] & 0xFF);
        byte[] body;
        if (key == Upgrade.CONTEXT_PS_KEY) {
            body = wordsBody(key, ps4);
        } else if (key == 1) {
            body = wordsBody(key, ps1);
        } else {
            body = new byte[] {5};
        }
        out.add(Gaia.qtil(Gaia.RETRIEVE_PS_KEY | Gaia.ACK_MASK, body));
    }

    /** GAIA status byte, then u16be key id, then u16be words. */
    private static byte[] wordsBody(int key, int[] words) {
        byte[] body = new byte[1 + 2 + 2 * words.length];
        body[0] = 0;
        body[1] = (byte) (key >>> 8);
        body[2] = (byte) key;
        for (int i = 0; i < words.length; i++) {
            body[3 + 2 * i] = (byte) (words[i] >>> 8);
            body[4 + 2 * i] = (byte) words[i];
        }
        return body;
    }

    private void store(byte[] payload, List<byte[]> out) throws FirmwareException, IOException {
        int key = ((payload[0] & 0xFF) << 8) | (payload[1] & 0xFF);
        int count = Upgrade.storedWordCount(payload.length);
        if (key != Upgrade.CONTEXT_PS_KEY) {
            throw new FirmwareException("device policy refuses to store key " + key);
        }
        int[] words = new int[Upgrade.CONTEXT_WORDS];
        for (int i = 0; i < count && i < words.length; i++) {
            int at = 2 + 2 * i;
            words[i] = at + 1 < payload.length
                    ? ((payload[at] & 0xFF) << 8) | (payload[at + 1] & 0xFF) : 0;
        }
        ps4 = words;
        ps4[0] = SINK_PREFIX;
        if (crashPoint == CRASH_PS_STORE) {
            // The PS write reached flash; the acknowledgement never made it out.
            throw powerLoss();
        }
        out.add(Gaia.qtil(Gaia.STORE_PS_KEY | Gaia.ACK_MASK, new byte[] {0}));
    }

    /** EventSysReboot interphase reset: drop the staged image, clean the context. */
    private void interphaseReset() throws IOException {
        staged = null;
        stagedComplete = false;
        stagedValid = false;
        stagedId = 0;
        received = 0;
        awaitingValidation = false;
        validationPolls = 0;
        ps4 = cleanContext();
        linkDown = true; // the device reboots; there is no GAIA answer
        throw new IOException("device rebooted after EventSysReboot");
    }

    private void control(Upgrade.Message message, List<byte[]> out)
            throws FirmwareException, IOException {
        byte[] ack = Gaia.qtil(Gaia.UPGRADE_CONTROL | Gaia.ACK_MASK, new byte[] {0});
        switch (message.id) {
            case Upgrade.SYNC_REQ: {
                syncRequests++;
                if (refuseSyncs > 0) {
                    refuseSyncs--;
                    out.add(notification(Upgrade.message(Upgrade.ERRORWARN_IND,
                            new byte[] {(byte) (refuseSyncCode >>> 8),
                                    (byte) refuseSyncCode})));
                    out.add(ack);
                    return;
                }
                int resume = ps4[Upgrade.RESUME_WORD] == Upgrade.RESUME_PRE_VALIDATE ? 1
                        : ps4[Upgrade.RESUME_WORD] == Upgrade.RESUME_VALIDATED ? 2
                        : ps4[Upgrade.RESUME_WORD] == Upgrade.RESUME_POST_REBOOT ? 3 : 0;
                if (silentSyncs > 0) {
                    // Field symptom: the GAIA frame is acknowledged, the
                    // Upgrade answer never comes.
                    silentSyncs--;
                    out.add(ack);
                    return;
                }
                long requested = idFrom(message.body);
                if (resume != 0 && staged != null && requested != stagedId) {
                    // Field behaviour: a trial-resume SYNC echoes the id the host
                    // sent, so announcing the rebuilt id instead of the staged one
                    // is only caught here if the fake device insists — which is
                    // the whole reason this assertion exists.
                    throw new FirmwareException("host announced id "
                            + Long.toHexString(requested) + " but the staged image is "
                            + Long.toHexString(stagedId));
                }
                long id = resume != 0 ? requested : requested;
                // A device holding image bytes directs the continuation offsets,
                // whether it is mid-transfer (resume 0) or staged PRE_VALIDATE.
                skipOffered = (resume == 0 || resume == 1 || resume == 2) && received > 0
                        ? received : 0;
                out.add(notification(Upgrade.message(Upgrade.SYNC_CFM, syncCfm(resume, id))));
                out.add(ack);
                return;
            }
            case Upgrade.START_REQ: {
                if (ps4[Upgrade.RESUME_WORD] == 0 && received == 0) {
                    staged = new ByteArrayOutputStream();
                    stagedComplete = false;
                    stagedValid = false;
                    stagedId = 0;
                }
                byte[] body = new byte[] {0, (byte) (3800 >>> 8), (byte) 3800};
                out.add(notification(Upgrade.message(Upgrade.START_CFM, body)));
                out.add(ack);
                return;
            }
            case Upgrade.START_DATA_REQ: {
                queueDataRequest(out);
                out.add(ack);
                return;
            }
            case Upgrade.DATA: {
                data(message.body, out, ack);
                return;
            }
            case Upgrade.IS_CSR_VALID_DONE_REQ: {
                // After a cold cycle the resume session re-validates the staged
                // image before ImageUpgradeCopy, exactly like a fresh transfer.
                boolean validating = awaitingValidation
                        || ((ps4[Upgrade.RESUME_WORD] == Upgrade.RESUME_PRE_VALIDATE
                                || ps4[Upgrade.RESUME_WORD] == Upgrade.RESUME_VALIDATED)
                                && staged != null);
                if (validating && ++validationPolls >= 3) {
                    awaitingValidation = false;
                    if (crashPoint == CRASH_AFTER_VALIDATION) {
                        // The image is validated and copied in flash; the host
                        // never hears the completion and never acknowledges it:
                        // the field state 2 this suite exists to cover.
                        ps4 = Upgrade.journalContext(SINK_PREFIX, stagedId,
                                Upgrade.RESUME_VALIDATED);
                        throw powerLoss();
                    }
                    out.add(notification(Upgrade.message(Upgrade.TRANSFER_COMPLETE_IND,
                            new byte[0])));
                } else {
                    byte[] backoff = new byte[] {0, 50};
                    out.add(notification(Upgrade.message(Upgrade.IS_CSR_VALID_DONE_CFM, backoff)));
                }
                out.add(ack);
                return;
            }
            case Upgrade.TRANSFER_COMPLETE_RES: {
                applyStaged(out, ack);
                return;
            }
            case Upgrade.IN_PROGRESS_RES: {
                if (staged != null) {
                    out.add(notification(Upgrade.message(Upgrade.COMMIT_REQ, new byte[0])));
                }
                out.add(ack);
                return;
            }
            case Upgrade.COMMIT_CFM: {
                commit(out, ack);
                return;
            }
            case Upgrade.ABORT_REQ: {
                aborts++;
                if (abortClears) {
                    refuseSyncs = 0; // the device releases the stuck session
                }
                staged = null;
                stagedComplete = false;
                received = 0;
                ps4 = cleanContext();
                out.add(ack);
                return;
            }
            default:
                throw new FirmwareException("unhandled Upgrade message " + message.id);
        }
    }

    private void queueDataRequest(List<byte[]> out) throws FirmwareException {
        int offset = skipOffered;
        skipOffered = 0;
        if (offset > maxSkipObserved) {
            maxSkipObserved = offset;
        }
        byte[] body = new byte[8];
        write32(body, 0, requestBytes);
        write32(body, 4, offset);
        out.add(notification(Upgrade.message(Upgrade.DATA_BYTES_REQ, body)));
    }

    private void data(byte[] body, List<byte[]> out, byte[] ack)
            throws FirmwareException, IOException {
        byte last = body[0];
        byte[] slice = Arrays.copyOfRange(body, 1, body.length);
        if (staged == null) {
            staged = new ByteArrayOutputStream();
        }
        staged.write(slice, 0, slice.length);
        received += slice.length;
        totalDataPackets++;
        if (last != 0) {
            finishStaging(out);
            out.add(ack);
            return;
        }
        if (killAfterBytes > 0 && received >= killAfterBytes) {
            persistPartialTransfer();
            killAfterBytes = -1;
            throw powerLoss();
        }
        out.add(ack);
        queueDataRequest(out); // device-driven pump: ask for the next bytes now
    }

    private void finishStaging(List<byte[]> out) throws FirmwareException, IOException {
        stagedComplete = true;
        byte[] image = staged.toByteArray();
        stagedId = upgradeIdOf(image);
        AppPackage parsed = AppPackage.parse(image);
        stagedValid = Pss.verify(trustModulus, parsed.signature, parsed.signedContent());
        if (stagedValid) {
            awaitingValidation = true;
            validationPolls = 0;
            return;
        }
        // Stock trust rejects the developer footer: the exact proven failure,
        // persisted to flash before the notification leaves the device.
        ps4 = Upgrade.journalContext(SINK_PREFIX, stagedId, Upgrade.RESUME_ERROR);
        out.add(notification(Upgrade.message(Upgrade.ERRORWARN_IND,
                new byte[] {(byte) (Upgrade.FOOTER_VALIDATION_FAILED >>> 8),
                        (byte) Upgrade.FOOTER_VALIDATION_FAILED})));
        if (crashPoint == CRASH_FOOTER) {
            throw powerLoss();
        }
    }

    private void persistPartialTransfer() {
        // Proven mid-transfer context: resume START(0), id words zero, one
        // closed partition marker and state UPGRADING — dirty, resumable.
        int[] words = cleanContext();
        words[14] = 1;
        words[15] = 1;
        ps4 = words;
    }

    private void applyStaged(List<byte[]> out, byte[] ack) throws FirmwareException, IOException {
        boolean preValidate = ps4[Upgrade.RESUME_WORD] == Upgrade.RESUME_PRE_VALIDATE;
        // A cold cycle clears the RAM completion flag but the staged flash
        // image survives, so a PRE_VALIDATE resume may still copy the trial.
        boolean copyable = preValidate ? staged != null : stagedComplete && stagedValid;
        if (!copyable) {
            out.add(ack);
            return;
        }
        // ImageUpgradeCopy into the trial bank; the reboot follows the answer.
        ps4 = Upgrade.journalContext(SINK_PREFIX, stagedId, Upgrade.RESUME_POST_REBOOT);
        linkDown = true;
        if (crashPoint == CRASH_AFTER_RESUME) {
            throw powerLoss();
        }
        out.add(ack);
    }

    private void commit(List<byte[]> out, byte[] ack) throws FirmwareException, IOException {
        if (staged == null) {
            throw new FirmwareException("device refuses a commit without a pending trial");
        }
        firmware = staged.toByteArray();
        trustModulus = trustOf(firmware);
        ps4 = cleanContext();
        staged = null;
        stagedComplete = false;
        stagedValid = false;
        received = 0;
        if (crashPoint == CRASH_BEFORE_COMPLETE) {
            throw powerLoss();
        }
        out.add(notification(Upgrade.message(Upgrade.COMPLETE_IND, new byte[0])));
        out.add(ack);
        linkDown = true; // the committed image boots fresh
    }

    // ---- helpers -----------------------------------------------------------------

    private static byte[] notification(Upgrade.Message message) throws FirmwareException {
        byte[] encoded = message.encode();
        byte[] payload = new byte[1 + encoded.length];
        payload[0] = (byte) Gaia.EVENT_VM_UPGRADE;
        System.arraycopy(encoded, 0, payload, 1, encoded.length);
        return Gaia.qtil(Gaia.EVENT_NOTIFICATION, payload);
    }

    private static byte[] syncCfm(int resume, long id) {
        return new byte[] {(byte) resume, (byte) (id >>> 24), (byte) (id >>> 16),
                (byte) (id >>> 8), (byte) id, (byte) Upgrade.UPGRADE_PROTOCOL_VERSION};
    }

    private static long idFrom(byte[] body) {
        if (body.length < 4) {
            return 0;
        }
        return ((body[0] & 0xFFL) << 24) | ((body[1] & 0xFFL) << 16)
                | ((body[2] & 0xFFL) << 8) | (body[3] & 0xFFL);
    }

    private static long upgradeIdOf(byte[] image) {
        int n = image.length;
        return ((image[n - 4] & 0xFFL) << 24) | ((image[n - 3] & 0xFFL) << 16)
                | ((image[n - 2] & 0xFFL) << 8) | (image[n - 1] & 0xFFL);
    }

    /** Trust after commit = the developer-key block embedded in the new Apps P1. */
    private BigInteger trustOf(byte[] image) throws FirmwareException {
        byte[] p1 = AppPackage.parse(image).partition(FirmwareProfile.P1_NUMBER).payload;
        byte[] block = Arrays.copyOfRange(p1, keyBlockOffset, keyBlockOffset + 256);
        return new BigInteger(1, DevKey.swapUint16(block));
    }

    private static void write32(byte[] out, int at, long value) {
        out[at] = (byte) (value >>> 24);
        out[at + 1] = (byte) (value >>> 16);
        out[at + 2] = (byte) (value >>> 8);
        out[at + 3] = (byte) value;
    }

    private IOException powerLoss() {
        linkDown = true;
        return new IOException("device lost power at the injected boundary");
    }
}
