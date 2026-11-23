package app.btr15.tool;

import java.util.Arrays;
import java.util.List;

/**
 * Wire-level regression for the GAIA/Upgrade protocol library against golden
 * vectors emitted by the normative Python codec
 * (tools/generate_btr15_protocol_goldens.py, saved in
 * work/btr15_android_port_assets/protocol_goldens.json) which itself replays
 * the byte assertions proven against the live BTR15.
 */
public final class ProtocolSelfTest {
    private static final String CONNECT = "ff010000000a0640";
    private static final String REGISTER = "ff010001000a400112";
    private static final String INTERPHASE_RESET = "ff010002000a0721478f";
    private static final String SYNC_REQ = "ff010007000a06421300041771c19e";
    private static final String IN_PROGRESS_RES = "ff010004000a06420e000100";
    private static final String COMMIT_CFM = "ff010004000a064210000100";
    private static final String TRANSFER_COMPLETE_RES = "ff010004000a06420c000100";
    private static final String XOR_FRAME = "ff010102000a0640123497";
    private static final String NOTIFICATION = "ff010006000a4003120d0002003d";
    // Golden literals copied verbatim from work/btr15_android_port_assets/protocol_goldens.json.
    private static final String STORE_CLEAN =
            "ff01004c000a07120004000100010000000100000000000000000000000000000000000000000000"
            + "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "00000000";
    private static final String STORE_SINGLE = "ff010010000a071200040001000100000001000000000000";
    private static final String[] DATA_PACKETS = {
        "ff0100f4000a06420400f100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef",
        "ff0100f4000a06420400f100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
        "ff010018000a064204001501e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3",
    };
    // Padding golden: the proven 76-byte store carries these words (generator vector).
    private static final int[] STORE_GOLDEN_WORDS =
            {1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    // Exact live-device footer-failure journal for candidate id 0x78D5E612
    // (btr15_v38_prevalidate_preserving_bootstrap_v4_live.py expected_footer_words).
    private static final int[] ERROR_CONTEXT =
            {0x8001, 1, 1, 2, 0, 0, 1, 1, 1, 2, 0, 0xE612, 0x78D5, 6, 0x000A, 0, 0, 0, 0};
    private static final int[] REPAIRED_CONTEXT =
            {0x8001, 1, 1, 2, 0, 0, 1, 1, 1, 2, 0, 0xE612, 0x78D5, 3, 0x000A, 0, 0, 0, 0};

    private static int checks = 0;

    public static void main(String[] args) throws Exception {
        frameEncodings();
        notificationsAndIds();
        psKeySemantics();
        contextRepair();
        dataPump();
        streamDecoder();
        rejections();
        System.out.println("ProtocolSelfTest: PASS (" + checks + " checks)");
    }

    private static void frameEncodings() throws Exception {
        expectHex(Gaia.qtil(Gaia.UPGRADE_CONNECT), CONNECT, "UPGRADE_CONNECT frame");
        expectHex(Gaia.qtil(Gaia.REGISTER_NOTIFICATION, new byte[] {Gaia.EVENT_VM_UPGRADE}),
                REGISTER, "REGISTER_NOTIFICATION frame");
        expectHex(Gaia.qtil(Gaia.SEND_APPLICATION_MESSAGE,
                        new byte[] {(byte) 0x47, (byte) 0x8F}),
                INTERPHASE_RESET, "interphase EventSysReboot frame");
        expectHex(Gaia.control(Upgrade.SYNC_REQ, Upgrade.big32(0x1771C19EL)),
                SYNC_REQ, "SYNC_REQ frame with upgrade id");
        expectHex(Gaia.control(Upgrade.IN_PROGRESS_RES, new byte[] {0}),
                IN_PROGRESS_RES, "IN_PROGRESS_RES frame");
        expectHex(Gaia.control(Upgrade.COMMIT_CFM, new byte[] {0}),
                COMMIT_CFM, "COMMIT_CFM frame");
        expectHex(Gaia.control(Upgrade.TRANSFER_COMPLETE_RES, new byte[] {0}),
                TRANSFER_COMPLETE_RES, "TRANSFER_COMPLETE_RES frame");
        expectHex(new Gaia.Frame(Gaia.VENDOR_QTIL, 0x0640, new byte[] {0x12, 0x34}, 0x01).encode(),
                XOR_FRAME, "XOR-flagged frame carries the proven checksum");
        Gaia.Frame xor = Gaia.decode(Util.hex(XOR_FRAME));
        expect(xor.flags == Gaia.FLAG_XOR && xor.payload.length == 2, "XOR frame decodes");
    }

    private static void notificationsAndIds() throws Exception {
        Gaia.Frame frame = Gaia.decode(Util.hex(NOTIFICATION));
        Upgrade.Message note = Gaia.upgradeNotification(frame);
        expect(note.id == Upgrade.IN_PROGRESS_IND, "notification carries IN_PROGRESS_IND");
        expect(Arrays.equals(note.body, Util.hex("003d")),
                "notification body carries the 0x003d footer failure");
        expect(Upgrade.FOOTER_VALIDATION_FAILED == 0x003D, "footer failure constant pinned");
        byte[] image = Util.hex("a1b2c3d4");
        expect(Arrays.equals(Upgrade.upgradeIdBytes(image), Util.hex("a1b2c3d4")),
                "upgrade id is the literal tail of the file");
        // Proven 6-byte SYNC_CFM body: resume u8, id 4 bytes BE, protocol u8
        // (btr15_qcc_ota_client.py parse_sync_cfm / MockPostbootWire).
        Upgrade.Message syncCfm = new Upgrade.Message(Upgrade.SYNC_CFM,
                Util.hex("031771c19e05"));
        expect(syncCfm.syncResumeWord() == Upgrade.RESUME_POST_REBOOT
                        && syncCfm.syncUpgradeId() == 0x1771C19EL
                        && syncCfm.syncProtocol() == 5,
                "SYNC_CFM resume word, id and protocol decode in the proven 6-byte layout");
        expect(throwsFirmware(() -> new Upgrade.Message(Upgrade.SYNC_CFM,
                        Util.hex("000300051771c19e")).syncResumeWord()),
                "legacy 8-byte SYNC_CFM guess is refused outright");
        Upgrade.Message startCfm = new Upgrade.Message(Upgrade.START_CFM, Util.hex("000ede"));
        expect(startCfm.startBatteryMillivolts() == 3806, "START_CFM battery decodes");
        expect(throwsFirmware(() -> new Upgrade.Message(Upgrade.START_CFM,
                        Util.hex("010000")).startBatteryMillivolts()),
                "unsuccessful START_CFM is refused");
    }

    private static void psKeySemantics() throws Exception {
        expectHex(Upgrade.storeFrame(Upgrade.CONTEXT_PS_KEY, STORE_GOLDEN_WORDS),
                STORE_CLEAN, "clean 19-word context pads to the 4N handler payload");
        expectHex(Upgrade.storeFrame(Upgrade.CONTEXT_PS_KEY, new int[] {1, 1, 0, 1}),
                STORE_SINGLE, "four-word write pads to sixteen bytes");
        expect(Upgrade.storedWordCount(76) == 19, "76-byte payload stores 19 words");
        expect(Upgrade.storedWordCount(40) == 10, "the double adjustment: 40 bytes store 10 words");
        Gaia.Frame store = Gaia.decode(Util.hex(STORE_CLEAN));
        expect(store.command == Gaia.STORE_PS_KEY && store.payload.length == 0x4C,
                "store frame re-decodes exactly");
    }

    private static void contextRepair() throws Exception {
        expect(Arrays.equals(Upgrade.journalContext(0x8001, 0x78D5E612L, Upgrade.RESUME_ERROR),
                        ERROR_CONTEXT),
                "journal layout reproduces the live footer-failure state word for word");
        int[] repaired = Upgrade.withResumeWord(ERROR_CONTEXT, Upgrade.RESUME_ERROR,
                Upgrade.RESUME_POST_REBOOT);
        expect(Arrays.equals(repaired, REPAIRED_CONTEXT),
                "ERROR to POST_REBOOT repair matches the proven context");
        int[] preValidate = Upgrade.withResumeWord(ERROR_CONTEXT, Upgrade.RESUME_ERROR,
                Upgrade.RESUME_PRE_VALIDATE);
        expect(preValidate[Upgrade.RESUME_WORD] == Upgrade.RESUME_PRE_VALIDATE,
                "ERROR to PRE_VALIDATE jailbreak word matches the corrected sequence");
        boolean moved = false;
        for (int i = 0; i < ERROR_CONTEXT.length; i++) {
            if (i != Upgrade.RESUME_WORD && preValidate[i] != ERROR_CONTEXT[i]) {
                moved = true;
            }
        }
        expect(!moved, "jailbreak rewrites exactly the resume word");
        expect(Upgrade.stagedId(ERROR_CONTEXT) == 0x78D5E612L,
                "staged id decodes from the little-endian halves");
        expect("0001 0001 0002 0000".equals(Upgrade.contextHex(new int[] {1, 1, 2, 0})),
                "journal dump renders every word as four hex digits");
        String dump = Upgrade.contextHex(Upgrade.cleanBaseline(0x8001));
        expect(dump.startsWith("8001 ") && dump.split(" ").length == Upgrade.CONTEXT_WORDS,
                "journal dump covers all 19 words and keeps the sink prefix first");
        expect(dump.indexOf("ff ", 0) < 0 && dump.indexOf("ffff") < 0,
                "journal dump never prints a sign-extended word");
        expect(Upgrade.isCleanContext(Upgrade.cleanBaseline(0x8001)),
                "proven clean baseline (prefix, 1, 1, 2, zeroed journal) accepted");
        expect(Upgrade.isCleanContext(Upgrade.cleanBaseline(0x0001)),
                "both observed sink prefixes validate as clean");
        expect(!Upgrade.isCleanContext(ERROR_CONTEXT), "dirty context not mistaken for clean");
        expect(FlashLogText.failureAdvice(true).contains("Recover unfinished transaction")
                        && !FlashLogText.failureAdvice(false).contains("Recover unfinished transaction"),
                "recovery is only offered when a journal exists to resume");
        expect(FlashLogText.failureAdvice(false).contains("nothing to recover"),
                "a run that never journaled says so instead of pointing at a missing button");
        expect(Upgrade.isCleanContext(new int[] {0x8003, 1, 1, 2,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
                "GATT transport with the config-reset bit is still an idle unit");
        int[] upperBits = Upgrade.cleanBaseline(0x0001);
        upperBits[0] = 0x4001;
        expect(Upgrade.isCleanContext(upperBits),
                "unused bits 8-14 in the transport word do not make a journal busy");
        int[] badTransport = Upgrade.cleanBaseline(0x0001);
        badTransport[0] = 0x0012;
        expect(!Upgrade.isCleanContext(badTransport),
                "a transport value the firmware cannot record is still refused");
        expect("spp".equals(Upgrade.transportName(0x0001))
                        && "gatt".equals(Upgrade.transportName(0x8003))
                        && Upgrade.isConfigReset(0x8003) && !Upgrade.isConfigReset(0x0001),
                "word 0 decodes as gaia_transport_type plus the config-reset bit");
        expect(!Upgrade.isCleanContext(Upgrade.journalContext(0x8001, 0L, 0)),
                "staged header fields with a zeroed journal are not clean");
        expect(throwsFirmware(() -> Upgrade.cleanBaseline(0x1234)),
                "unknown sink prefix is refused");
        expect(throwsFirmware(() -> Upgrade.withResumeWord(ERROR_CONTEXT,
                        Upgrade.RESUME_POST_REBOOT, Upgrade.RESUME_PRE_VALIDATE)),
                "repair from an unexpected resume state is refused");
    }

    private static void dataPump() throws Exception {
        byte[] image = new byte[500];
        for (int i = 0; i < 500; i++) {
            image[i] = (byte) i;
        }
        Upgrade.Sender sender = new Upgrade.Sender(image, Upgrade.DEFAULT_CHUNK);
        byte[][] first = sender.satisfy(240, 0);
        expect(sender.offsetAfter(0) == 240,
                "the transfer offset after one packet is exactly what it delivered");
        byte[][] rest = sender.satisfy(260, 0);
        expect(first.length == 1 && rest.length == 2, "request accounting yields 1 then 2 packets");
        expectHex(first[0], DATA_PACKETS[0], "first DATA packet matches golden");
        expectHex(rest[0], DATA_PACKETS[1], "second DATA packet matches golden");
        expectHex(rest[1], DATA_PACKETS[2], "final DATA packet carries the last-image flag");
        expect(sender.cursor() == 500, "sender cursor lands on the image end");
        expect(sender.offsetAfter(0) == 480 && sender.offsetAfter(1) == 500,
                "one batch reports the device's own offset after every packet");
        expect(first[0].length <= 262 && rest[0].length <= 262,
                "DATA packets stay inside GAIA v1 bounds");
        expect(throwsFirmware(() -> sender.satisfy(16, 1)), "offset past image end is refused");
        expect(throwsFirmware(() -> new Upgrade.Sender(image, 0)), "absurd chunk size is refused");
        boolean refusedPastBatch = false;
        try {
            sender.offsetAfter(2);
        } catch (IllegalArgumentException outOfBatch) {
            refusedPastBatch = true;
        }
        expect(refusedPastBatch,
                "an offset is only offered for a packet of the batch in hand");
    }

    private static void streamDecoder() throws Exception {
        byte[] good = Util.hex(CONNECT);
        byte[] badXor = Util.hex("ff010100000a064100"); // 0x0641 with flag, checksum deliberately wrong
        badXor[badXor.length - 1] ^= 0xFF;
        Gaia.StreamDecoder decoder = new Gaia.StreamDecoder();
        List<Gaia.Frame> first = decoder.feed(concat(new byte[] {0x00}, "garbage".getBytes("US-ASCII"),
                Arrays.copyOf(good, 3)));
        expect(first.isEmpty(), "partial frame after junk is buffered, not guessed");
        List<Gaia.Frame> second = decoder.feed(concat(Arrays.copyOfRange(good, 3, good.length),
                badXor, good, new byte[] {(byte) 0xFF}));
        expect(second.size() == 2, "resynchronised stream yields both good frames, drops the bad XOR");
        expectHex(second.get(0).encode(), CONNECT, "resynced frame one intact");
        expectHex(second.get(1).encode(), CONNECT, "resynced frame two intact");
    }

    private static void rejections() throws Exception {
        expect(throwsFirmware(() -> Gaia.decode(Util.hex("ff010100000a0641ff"))),
                "bad XOR checksum is refused");
        expect(throwsFirmware(() -> Gaia.decode(Util.hex("ff020000000a0640"))),
                "non v1 version byte is refused");
        expect(throwsFirmware(() -> Gaia.decode(Util.hex("ff0100"))),
                "truncated GAIA header is refused");
        expect(throwsFirmware(() -> Upgrade.Message.decode(Util.hex("0d0005ffff"))),
                "Upgrade body length mismatch is refused");
        expect(throwsFirmware(() -> Gaia.upgradeNotification(
                        Gaia.decode(Util.hex(CONNECT)))),
                "control frames are not mistaken for notifications");
        byte[] ack = new Gaia.Frame(Gaia.VENDOR_QTIL, 0x0642 | Gaia.ACK_MASK,
                new byte[] {0}).encode();
        expect(Gaia.expectAck(ack, 0x0642).status() == 0, "matching acknowledgement accepted");
        expect(throwsFirmware(() -> Gaia.expectAck(ack, 0x0640)),
                "acknowledgement for another command is refused");
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int at = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, at, part.length);
            at += part.length;
        }
        return out;
    }

    private interface Action {
        void run() throws Exception;
    }

    private static boolean throwsFirmware(Action action) {
        try {
            action.run();
            return false;
        } catch (FirmwareException expected) {
            return true;
        } catch (Exception other) {
            throw new AssertionError("unexpected failure: " + other, other);
        }
    }

    private static void expectHex(byte[] actual, String goldenHex, String label) {
        expect(Arrays.equals(actual, Util.hex(goldenHex)), label);
    }

    private static void expect(boolean condition, String label) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAIL: " + label);
        }
        System.out.println("ok: " + label);
    }
}
