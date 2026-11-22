package app.btr15.tool;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Offline scenario matrix for the whole updater: full jailbreak, developer
 * update and two-stage stock-restore lifecycles against the simulated peer,
 * then power-loss injection at every persistent-state boundary with recovery
 * through the journal decision tree, proven zero-byte jailbreak resume,
 * device-directed partial-transfer skips, trial rollback, journal hygiene and
 * transcript safety.  Runs entirely in the JVM with real RSA-PSS trust checks.
 */
public final class WorkflowSelfTest {
    private static final String V1_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    private static int checks;
    private static DevKey key;
    private static byte[] official;
    private static byte[] candidate;
    private static byte[] featureUpdate;
    private static byte[] stockPhase1;
    private static final Workflows.Sleeper NO_SLEEP = milliseconds -> { };
    /** The variant label these fixtures journal for a jailbreak staging. */
    private static final String JAILBREAK_LABEL = FirmwareEngine.Variant.DEVELOPER_KEY.name();
    private static final List<Session> openedSessions = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: WorkflowSelfTest <official-v3.8.bin>");
            System.exit(2);
        }
        official = Files.readAllBytes(new File(args[0]).toPath());
        if (!Util.sha256Hex(official).equals(FirmwareProfile.SHA256)) {
            throw new IllegalArgumentException("first argument must be the official v3.8 package");
        }
        key = DevKey.derive(V1_MNEMONIC);
        candidate = FirmwareEngine.build(official, key, FirmwareEngine.Variant.DEVELOPER_KEY).bytes;
        featureUpdate = FirmwareEngine.build(official, key,
                FirmwareEngine.Variant.DEVELOPER_KEY_100HZ2).bytes;
        stockPhase1 = FirmwareEngine.build(official, key,
                FirmwareEngine.Variant.STOCK_PAYLOADS).bytes;

        fullLifecycle();
        jailbreakPowerLossEverywhere();
        updatePowerLossBoundaries();
        silentSyncHandshakeRetry();
        refusedHandshakeIsCleared();
        staleBeginJournalDoesNotBlock();
        partialTransferSkipResume();
        rollbackLeavesSafeGround();
        acceptedKeyFinishesTheUpdate();
        validatedStagingIsFinishedNotReflashed();
        journalHygiene();
        journalDurability();
        restorationKeepsOneRecord();
        transcriptSafety();

        System.out.println("WorkflowSelfTest: PASS (" + checks + " checks)");
    }

    // ---- scenarios ---------------------------------------------------------------

    /**
     * Stock v3.8 → jailbreak (stage, cold cycle, zero-byte resume) → developer
     * update → stock phase 1 (FiiO trust restored by the stock payload) →
     * official package phase 2 → developer-key package rejected again.
     */
    private static void fullLifecycle() throws Exception {
        SimBtr15Peer peer = stockPeer();
        int[] key1Before = peer.key1();
        String dir = freshDir();

        Journal journal = Workflows.jailbreakStage(new File(dir), connector(peer), candidate,
                JAILBREAK_LABEL, NO_SLEEP).journal;
        check(journal.get("phase").equals(Journal.PHASE_KEY4_PRE_VALIDATE),
                "jailbreak stage ends in PRE_VALIDATE");
        check(peer.trust().equals(FirmwareProfile.fiioModulus()),
                "staging alone cannot change device trust");
        check(peer.key4()[13] == Upgrade.RESUME_PRE_VALIDATE, "resume word is PRE_VALIDATE");
        check(Upgrade.stagedId(peer.key4()) == Workflows.imageUpgradeId(candidate),
                "staged id words name the candidate");
        // A device that still carries this transaction's id is accepted: that is
        // both "not cycled yet" (SYNC then reports resume 0 and refuses) and
        // "cycled, but a previous resume registered the id again" — the field
        // case that used to block every retry.  A foreign id is still refused.
        int[] foreign = peer.key4();
        foreign[Upgrade.RESUME_WORD] = Upgrade.RESUME_PRE_VALIDATE;
        foreign[Upgrade.STAGED_ID_LOW_WORD] = 0x5A5A;
        foreign[Upgrade.STAGED_ID_HIGH_WORD] = 0x5A5A;
        peer.forceContext(foreign);
        check(throwsFirmware(() -> Workflows.jailbreakResume(new File(dir), connector(peer),
                        journal, candidate, NO_SLEEP)),
                "resume with a foreign staged id is refused");
        peer.coldPowerCycle();
        check(peer.key4()[11] == 0 && peer.key4()[12] == 0,
                "cold cycle normalises the staged-id words to zero");
        int packetsBeforeResume = peer.totalDataPackets();
        Workflows.jailbreakResume(new File(dir), connector(peer), journal, candidate, NO_SLEEP);
        check(peer.totalDataPackets() == packetsBeforeResume,
                "jailbreak resume retransmitted zero firmware bytes");
        check(peer.trust().equals(key.modulus), "committed candidate now owns device trust");
        check(peer.firmwareSha256().equals(Util.sha256Hex(candidate)),
                "device runs the jailbroken image");
        check(Upgrade.isCleanContext(peer.key4()), "context clean after jailbreak commit");
        check(Journal.findPending(new File(dir)) == null, "jailbreak journal retired on success");

        Workflows.developerUpdate(new File(freshDir()), connector(peer), featureUpdate,
                "100HZ2", NO_SLEEP);
        check(peer.firmwareSha256().equals(Util.sha256Hex(featureUpdate)),
                "developer-key update installed the 100 Hz2 image");

        Workflows.runUpdate(new File(freshDir()), connector(peer), stockPhase1,
                Journal.KIND_STOCK_PHASE1, "STOCK_PAYLOADS", NO_SLEEP);
        check(peer.firmwareSha256().equals(Util.sha256Hex(stockPhase1)),
                "stock phase 1 installed untouched official payloads");
        check(peer.trust().equals(FirmwareProfile.fiioModulus()),
                "stock phase 1 restored FiiO trust from the stock key block");

        Workflows.runUpdate(new File(freshDir()), connector(peer), official,
                Journal.KIND_STOCK_PHASE2, "OFFICIAL", NO_SLEEP);
        check(peer.firmwareSha256().equals(FirmwareProfile.SHA256),
                "stock phase 2 reinstalled the untouched official package");
        check(peer.trust().equals(FirmwareProfile.fiioModulus()),
                "device is fully stock again");
        check(Arrays.equals(peer.key1(), key1Before),
                "key-1 identity (MAC) words survived every transaction");

        String jailbreakDir = freshDir();
        Journal again = Workflows.jailbreakStage(new File(jailbreakDir), connector(peer),
                candidate, JAILBREAK_LABEL, NO_SLEEP).journal;
        check(again.get("phase").equals(Journal.PHASE_KEY4_PRE_VALIDATE),
                "stock device footer-fails the developer package and is recoverable");
        peer.coldPowerCycle();
        Session cleanup = connector(peer).open();
        try {
            cleanup.sendInterphaseReset();
        } catch (FirmwareException rebooting) {
            // expected: EventSysReboot never answers
        } finally {
            cleanup.closeQuietly();
        }
        check(Upgrade.isCleanContext(peer.key4()),
                "interphase reset returns the staged device to a clean context");
        check(peer.trust().equals(FirmwareProfile.fiioModulus())
                        && peer.firmwareSha256().equals(FirmwareProfile.SHA256),
                "developer key stays rejected after stock restoration");
        again.delete();
    }

    /** Power loss at footer failure, PS store, after resume apply, before complete. */
    private static void jailbreakPowerLossEverywhere() throws Exception {
        // 1) Power lost with the footer failure already in flash, answer lost.
        final SimBtr15Peer peer1 = stockPeer();
        peer1.crashAt(SimBtr15Peer.CRASH_FOOTER);
        final String dir1 = freshDir();
        check(throwsFirmware(() -> {
            Workflows.jailbreakStage(new File(dir1), connector(peer1), candidate,
                    JAILBREAK_LABEL, NO_SLEEP);
        }), "footer-boundary power loss surfaces as a link failure");
        check(peer1.key4()[13] == Upgrade.RESUME_ERROR,
                "footer failure survived the power loss in PS store");
        String message = Workflows.recover(new File(dir1), connector(peer1),
                Journal.findPending(new File(dir1)), material(candidate), NO_SLEEP);
        check(message.contains("power-cycle"), "recovery asks for the cold cycle: " + message);
        check(peer1.key4()[13] == Upgrade.RESUME_PRE_VALIDATE,
                "recovery rewrote word 13 across the interruption");
        peer1.coldPowerCycle();
        message = Workflows.recover(new File(dir1), connector(peer1),
                Journal.findPending(new File(dir1)), material(candidate), NO_SLEEP);
        check(message.contains("resume completed"), "recovery finished the jailbreak");
        check(peer1.trust().equals(key.modulus), "device jailbroken after two interruptions");

        // 2) Power lost right after the key-4 PRE_VALIDATE write reached flash.
        final SimBtr15Peer peer2 = stockPeer();
        peer2.crashAt(SimBtr15Peer.CRASH_PS_STORE);
        final String dir2 = freshDir();
        check(throwsFirmware(() -> {
            Workflows.jailbreakStage(new File(dir2), connector(peer2), candidate,
                    JAILBREAK_LABEL, NO_SLEEP);
        }), "store-boundary power loss surfaces as a link failure");
        check(peer2.key4()[13] == Upgrade.RESUME_PRE_VALIDATE,
                "the store itself had already reached the device");
        message = Workflows.recover(new File(dir2), connector(peer2),
                Journal.findPending(new File(dir2)), material(candidate), NO_SLEEP);
        check(message.contains("resume completed"),
                "resume runs with the transaction's own staged id still recorded: " + message);

        // 3) Power lost right after ImageUpgradeCopy staged the trial bank.
        SimBtr15Peer peer3 = stockPeer();
        String dir3 = freshDir();
        Journal journal3 = Workflows.jailbreakStage(new File(dir3), connector(peer3),
                candidate, JAILBREAK_LABEL, NO_SLEEP).journal;
        peer3.coldPowerCycle();
        peer3.crashAt(SimBtr15Peer.CRASH_AFTER_RESUME);
        check(throwsFirmware(() -> Workflows.jailbreakResume(new File(dir3), connector(peer3),
                        journal3, candidate, NO_SLEEP)),
                "resume-apply power loss surfaces as a link failure");
        check(peer3.key4()[13] == Upgrade.RESUME_POST_REBOOT,
                "trial bank is pending POST_REBOOT across the power loss");
        String message3 = Workflows.recover(new File(dir3), connector(peer3), journal3,
                material(candidate), NO_SLEEP);
        check(message3.contains("commit"),
                "recovery finished the interrupted commit: " + message3);
        check(peer3.trust().equals(key.modulus), "trial committed through recovery");
    }

    /** Mid-transfer kill of a developer update re-runs cleanly; commit crash is safe. */
    private static void updatePowerLossBoundaries() throws Exception {
        // Mid-transfer power loss on a device that trusts the key.
        final SimBtr15Peer peerA = jailbrokenPeer();
        peerA.killDataAfter(300_000);
        final String dirA = freshDir();
        check(throwsFirmware(() -> Workflows.developerUpdate(new File(dirA), connector(peerA),
                        featureUpdate, "100HZ2", NO_SLEEP)),
                "mid-transfer kill surfaces as a link failure");
        check(!Upgrade.isCleanContext(peerA.key4()),
                "device kept a dirty mid-transfer journal");
        String message = Workflows.recover(new File(dirA), connector(peerA),
                Journal.findPending(new File(dirA)), material(featureUpdate), NO_SLEEP);
        check(message.contains("resumed from the device"), "message: " + message);
        check(peerA.firmwareSha256().equals(Util.sha256Hex(featureUpdate)),
                "interrupted developer update completed via recovery");

        // Power lost after the commit reached flash but before COMPLETE_IND.
        final SimBtr15Peer peerB = jailbrokenPeer();
        peerB.crashAt(SimBtr15Peer.CRASH_BEFORE_COMPLETE);
        final String dirB = freshDir();
        check(throwsFirmware(() -> Workflows.developerUpdate(new File(dirB), connector(peerB),
                        featureUpdate, "100HZ2", NO_SLEEP)),
                "commit-boundary loss surfaces as a link failure");
        check(Upgrade.isCleanContext(peerB.key4()),
                "device had already committed at the injected boundary");
        message = Workflows.recover(new File(dirB), connector(peerB),
                Journal.findPending(new File(dirB)), material(featureUpdate), NO_SLEEP);
        check(peerB.firmwareSha256().equals(Util.sha256Hex(featureUpdate)),
                "post-commit crash converges to the updated device");
    }

    /**
     * The field failure of 2026-11-20: the device accepted the RFCOMM link,
     * answered the GAIA getters twice, acknowledged the SYNC frame and then
     * sent no SYNC_CFM at all (journal: "no GAIA frame within 5999 ms").  The
     * transaction had staged nothing, so the tool must re-bind the device's
     * single GAIA client on a fresh link and finish — and it must give up
     * after a bounded number of links instead of hanging.
     */
    private static void silentSyncHandshakeRetry() throws Exception {
        byte[] update = FirmwareEngine.build(official, key,
                FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE).bytes;

        SimBtr15Peer peer = new SimBtr15Peer(official, key.modulus); // already trusts our key
        peer.silenceSyncs(1);
        String dir = freshDir();
        Workflows.developerUpdate(new File(dir), connector(peer), update,
                FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE.name(), NO_SLEEP);
        check(peer.syncRequests() >= 2,
                "a SYNC the device silently dropped must be retried, not reported as the"
                        + " end of the transaction");
        check(peer.connections() >= 2,
                "the retry must re-bind on a fresh link, never reuse the silent one");
        check(peer.firmwareContentSha256().equals(Workflows.contentSha256(update)),
                "the update still lands after the device ignored the first handshake");
        check(Journal.findPending(new File(dir)) == null,
                "the retried update retires its journal like any clean run");

        SimBtr15Peer deaf = new SimBtr15Peer(official, key.modulus);
        deaf.silenceSyncs(50); // never answers a handshake
        final String deafDir = freshDir();
        check(throwsFirmware(() -> Workflows.developerUpdate(new File(deafDir), connector(deaf),
                        update, "DEAF", NO_SLEEP)),
                "a device that never answers the handshake must fail, not hang");
        check(deaf.syncRequests() == 3,
                "the handshake is bounded to three fresh links, saw " + deaf.syncRequests());
        check(deaf.firmwareSha256().equals(Util.sha256Hex(official)),
                "a handshake that never completed leaves the device untouched");
    }

    /**
     * The field failure of 2026-11-20 (second act): the device answered SYNC
     * with ERRORWARN_IND 0x0081 and no SYNC_CFM, on every link, until a real
     * ABORT_REQ released the stuck upgrade session.  The transaction must name
     * the refusal instead of reporting silence, and must clear it and finish.
     */
    private static void refusedHandshakeIsCleared() throws Exception {
        byte[] update = FirmwareEngine.build(official, key,
                FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE).bytes;

        SimBtr15Peer peer = new SimBtr15Peer(official, key.modulus);
        peer.refuseSyncs(0x0081, 5); // keeps refusing until the host aborts
        String dir = freshDir();
        Workflows.developerUpdate(new File(dir), connector(peer), update,
                FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE.name(), NO_SLEEP);
        check(peer.aborts() >= 1,
                "a refused handshake must be released with ABORT_REQ, not retried blind");
        check(peer.syncRequests() == 3,
                "one refused SYNC, one accepted SYNC, then the post-reboot commit SYNC —"
                        + " saw " + peer.syncRequests());
        check(peer.firmwareContentSha256().equals(Workflows.contentSha256(update)),
                "the update still lands after the device refused the first handshake");

        // The refusal must be reported as such, never as a timeout.
        SimBtr15Peer deaf = new SimBtr15Peer(official, key.modulus);
        deaf.refuseSyncsAlways(0x0081);
        final SimBtr15Peer stubborn = deaf;
        final String muteDir = freshDir();
        FirmwareException failure = null;
        try {
            Workflows.developerUpdate(new File(muteDir), connector(stubborn), update,
                    "STUBBORN", NO_SLEEP);
        } catch (FirmwareException expected) {
            failure = expected;
        }
        check(failure != null && failure.getMessage().contains("0x81"),
                "a refused handshake names the device's error code, said: "
                        + (failure == null ? "nothing" : failure.getMessage()));
        check(Journal.findPending(new File(muteDir)) != null,
                "a refused handshake keeps its journal for Recovery");
    }

    /**
     * The residue of a failed attempt: a BEGIN journal, nothing staged, and a
     * device whose context is clean.  The next flash must not trip over it
     * ("more than one unfinished transaction"), and a BEGIN journal naming a
     * different device must still be kept.
     */
    private static void staleBeginJournalDoesNotBlock() throws Exception {
        byte[] update = FirmwareEngine.build(official, key,
                FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE).bytes;
        String label = FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE.name();

        SimBtr15Peer peer = new SimBtr15Peer(official, key.modulus);
        String dir = freshDir();
        Journal.create(new File(dir), Journal.KIND_DEVELOPER_UPDATE, "stale-sha",
                "stale-content", 0xABCDEF01L, label, "40:ED:98:1C:1C:ED",
                "content://docs/v38.bin");
        Workflows.developerUpdate(new File(dir), connector(peer), update, label, NO_SLEEP);
        check(Journal.findPending(new File(dir)) == null,
                "a BEGIN journal from an attempt that never reached the device must neither"
                        + " block the next flash nor survive it");
        check(peer.firmwareContentSha256().equals(Workflows.contentSha256(update)),
                "the flash after a dead attempt still lands");

        SimBtr15Peer other = new SimBtr15Peer(official, key.modulus);
        String foreignDir = freshDir();
        Journal foreign = Journal.create(new File(foreignDir), Journal.KIND_DEVELOPER_UPDATE,
                "stale-sha", "stale-content", 0xABCDEF01L, label, "00:02:5B:00:A5:A5",
                "content://docs/v38.bin");
        Workflows.runUpdate(new File(foreignDir), new Workflows.Connector() {
            public Session open() throws FirmwareException {
                Session session = new Session(other.openConnection(), 500L);
                openedSessions.add(session);
                return session;
            }

            public String deviceAddress() {
                return "40:ED:98:1C:1C:ED";
            }
        }, update, Journal.KIND_DEVELOPER_UPDATE, label, NO_SLEEP);
        check(Journal.findPending(new File(foreignDir)).id().equals(foreign.id()),
                "a BEGIN journal stamped with another device must be left for that device");
        foreign.delete();
    }

    /** Proven stock phase-2 semantics: the device directs skips, bytes are saved. */
    private static void partialTransferSkipResume() throws Exception {        SimBtr15Peer peer = jailbrokenPeer();
        Workflows.runUpdate(new File(freshDir()), connector(peer), stockPhase1,
                Journal.KIND_STOCK_PHASE1, "STOCK_PAYLOADS", NO_SLEEP);
        peer.killDataAfter(500_000);
        String dir = freshDir();
        check(throwsFirmware(() -> Workflows.runUpdate(new File(dir), connector(peer), official,
                        Journal.KIND_STOCK_PHASE2, "OFFICIAL", NO_SLEEP)),
                "phase-2 transfer interrupted on schedule");
        Journal pending = Journal.findPending(new File(dir));
        int mark = openedSessions.size();
        String message = Workflows.recover(new File(dir), connector(peer), pending,
                material(official), NO_SLEEP);
        check(message.contains("device's own offsets"), "message: " + message);
        check(peer.maxSkipObserved() >= 500_000,
                "device issued a positive skip offset to the continuation");
        // Sessions opened by recovery: probe first, then the continuation.
        Session continuation = openedSessions.get(mark + 1);
        check(continuation.firmwareBytesSent() < official.length,
                "continuation retransmitted only the missing bytes");
        check(continuation.firmwareBytesSent() > 0,
                "continuation still sent the genuinely missing tail");
        check(peer.firmwareSha256().equals(FirmwareProfile.SHA256),
                "stock phase 2 finished through the partial-resume path");
    }

    /** Nobody confirmed the trial: honest refusal, no blind flashing. */
    private static void rollbackLeavesSafeGround() throws Exception {
        SimBtr15Peer peer = stockPeer();
        String dir = freshDir();
        Journal journal = Workflows.jailbreakStage(new File(dir), connector(peer),
                candidate, JAILBREAK_LABEL, NO_SLEEP).journal;
        peer.coldPowerCycle();
        peer.crashAt(SimBtr15Peer.CRASH_AFTER_RESUME);
        check(throwsFirmware(() -> Workflows.jailbreakResume(new File(dir), connector(peer),
                        journal, candidate, NO_SLEEP)),
                "resume interrupted before the trial could commit");
        peer.rollBackTrial();
        check(throwsFirmware(() -> Workflows.recover(new File(dir), connector(peer), journal,
                        material(candidate), NO_SLEEP)),
                "recovery refuses to chase a trial the device discarded");
        check(peer.trust().equals(FirmwareProfile.fiioModulus()),
                "refusal left the device exactly as stock");
    }

    /**
     * A device that already trusts this key: the candidate passes the footer
     * check, so the staging run must finish the install as the developer update
     * it really is instead of stopping half-way.  The device is polled for its
     * validation — a passive wait hears nothing from an accepted package and
     * times out.
     */
    private static void acceptedKeyFinishesTheUpdate() throws Exception {
        SimBtr15Peer peer = new SimBtr15Peer(official, key.modulus);
        String dir = freshDir();
        Workflows.StageOutcome outcome = Workflows.jailbreakStage(new File(dir), connector(peer),
                candidate, JAILBREAK_LABEL, NO_SLEEP);
        check(!outcome.needsPowerCycle, "an accepted package owes no cold cycle");
        check(Journal.findPending(new File(dir)) == null,
                "the accepted staging retires its own journal");
        check(peer.trust().equals(key.modulus), "trust stays with the developer key");
        check(peer.firmwareSha256().equals(Util.sha256Hex(candidate)),
                "the accepted package is installed, not left in staging");
        check(Upgrade.isCleanContext(peer.key4()), "context is clean after the commit");
        check(peer.key4()[Upgrade.RESUME_WORD] != Upgrade.RESUME_PRE_VALIDATE,
                "no key-4 rewrite happened, because none was needed");

        // A refusal still owes the cycle: the two answers must not be confused.
        SimBtr15Peer stock = stockPeer();
        String stockDir = freshDir();
        Workflows.StageOutcome refused = Workflows.jailbreakStage(new File(stockDir),
                connector(stock), candidate, JAILBREAK_LABEL, NO_SLEEP);
        check(refused.needsPowerCycle, "a footer refusal still owes the cold cycle");
        check(stock.key4()[Upgrade.RESUME_WORD] == Upgrade.RESUME_PRE_VALIDATE,
                "the refusal path still ends in PRE_VALIDATE");
    }

    /**
     * The field state left behind by a host that waited passively for a
     * message a passing footer only sends when polled: the image is staged and
     * validated (resume word 2) but nothing acknowledged it.  Recovery must
     * finish the commit without asking the device to receive the package again.
     */
    private static void validatedStagingIsFinishedNotReflashed() throws Exception {
        SimBtr15Peer peer = new SimBtr15Peer(official, key.modulus);
        String dir = freshDir();
        // Power lost the instant validation passed: the device keeps the
        // validated image staged (word 13 = 2) and nobody ever acknowledged it.
        peer.crashAt(SimBtr15Peer.CRASH_AFTER_VALIDATION);
        check(throwsFirmware(() -> {
            Workflows.jailbreakStage(new File(dir), connector(peer), candidate,
                    JAILBREAK_LABEL, NO_SLEEP);
        }), "the validation-boundary power loss surfaces as a link failure");
        check(peer.key4()[Upgrade.RESUME_WORD] == Upgrade.RESUME_VALIDATED,
                "the device is left holding the validated staging");
        Journal journal = Journal.findPending(new File(dir));
        check(journal != null, "the transaction is still journaled");
        int packetsBefore = peer.totalDataPackets();
        String outcome = Workflows.recover(new File(dir), connector(peer), journal,
                material(candidate), NO_SLEEP);
        check(outcome.contains("finished the commit"), "recovery explains itself: " + outcome);
        check(peer.totalDataPackets() == packetsBefore,
                "the validated staging is finished without retransmitting the package");
        check(peer.firmwareSha256().equals(Util.sha256Hex(candidate)),
                "the staged package is the one that ends up running");
        check(Upgrade.isCleanContext(peer.key4()), "context is clean afterwards");
        check(Journal.findPending(new File(dir)) == null, "the journal is retired");
    }

    private static void journalHygiene() throws Exception {
        String dir = freshDir();
        Journal first = Journal.create(new File(dir), Journal.KIND_DEVELOPER_UPDATE,
                "sha-a", "content-a", 0x11111111L, "X", null, null);
        Journal second = Journal.create(new File(dir), Journal.KIND_JAILBREAK,
                "sha-b", "content-b", 0x22222222L, "Y", null, null);
        check(throwsFirmware(() -> Journal.findPending(new File(dir))),
                "two simultaneous transactions are refused, not guessed");
        first.delete();
        Journal reopened = Journal.findPending(new File(dir));
        check(reopened != null && reopened.id().equals(second.id())
                        && reopened.get("kind").equals(Journal.KIND_JAILBREAK)
                        && reopened.upgradeId() == 0x22222222L
                        && "content-b".equals(reopened.get("staged_content_sha256")),
                "journal survives reopen with fields intact");
        check(reopened.describe().contains("JAILBREAK"), "journal export is readable");
        reopened.delete();
        check(Journal.findPending(new File(dir)) == null, "no phantom journals remain");

        // Field reads are nullable by design (absent vs recorded empty), so a
        // truncated journal must fail as a FirmwareException with a message —
        // never as a bare NullPointerException from a load or a read.
        File broken = new File(dir, "btr15-txn-a-truncated.journal");
        Files.write(broken.toPath(), "version=1\nphase=BEGIN\n".getBytes("UTF-8"));
        check(throwsFirmware(() -> Journal.findPending(new File(dir))),
                "a journal with no kind is rejected, not half-loaded");
        Files.write(broken.toPath(),
                "version=1\nkind=JAILBREAK\nphase=BEGIN\nupgrade_id=zz\n".getBytes("UTF-8"));
        final Journal noId = Journal.findPending(new File(dir));
        check(throwsFirmware(() -> noId.upgradeId()),
                "a non-hexadecimal upgrade id is reported, not thrown as a parser error");
        broken.delete();
        Journal unset = Journal.create(new File(dir), Journal.KIND_DEVELOPER_UPDATE,
                "sha-c", "content-c", 0x33333333L, "Z", null, "content://test/v38.bin");
        check(unset.get("device_address") == null,
                "an unstamped journal answers null, never an empty device");
        check("".equals(unset.getOrEmpty("device_address")),
                "getOrEmpty is the text-safe read of the same field");
        unset.delete();
    }

    /**
     * The record has to outlive a failed replacement, and a record that cannot
     * be read at all must say so instead of looking like an empty phone — the
     * screen only offers Recovery when the difference is visible.
     */
    private static void journalDurability() throws Exception {
        String dir = freshDir();
        File directory = new File(dir);
        File file = new File(dir, "btr15-txn-durable.journal");
        File previous = new File(dir, "btr15-txn-durable.journal.prev");
        Files.write(file.toPath(), "version=1\nkind=DEVELOPER_UPDATE\n".getBytes("UTF-8"));
        Files.write(previous.toPath(), ("version=1\nkind=DEVELOPER_UPDATE\nphase=APPLY_SENT\n"
                + "upgrade_id=44444444\n").getBytes("UTF-8"));
        Journal recovered = Journal.findPending(directory);
        check(recovered != null && recovered.id().equals("durable"),
                "a torn journal is read from the copy set aside beside it");
        check(recovered.get("phase").equals(Journal.PHASE_APPLY_SENT),
                "the copy answers the real phase, not an empty one");

        Files.write(file.toPath(), "garbage\n".getBytes("UTF-8"));
        Files.write(previous.toPath(), "garbage\n".getBytes("UTF-8"));
        FirmwareException both = null;
        try {
            Journal.findPending(directory);
        } catch (FirmwareException expected) {
            both = expected;
        }
        check(both != null, "two unreadable copies are an error, never 'no transaction'");
        check(both.getMessage().contains(".prev"),
                "the message names the copy it also tried: " + both.getMessage());
        check(Journal.deleteAllPending(directory) == 1, "the way out removes the broken record");
        check(!file.exists() && !previous.exists(), "both broken copies are gone");
        check(Journal.findPending(directory) == null, "nothing is left to chase");

        // A finished transaction must not come back through its sidecar: the
        // previous copy only counts while the journal beside it is missing.
        Journal finished = Journal.create(directory, Journal.KIND_DEVELOPER_UPDATE,
                "sha-d", "content-d", 0x55555555L, "X", null, null);
        Files.write(new File(dir, finished.file().getName() + ".prev").toPath(),
                "version=1\nkind=DEVELOPER_UPDATE\nphase=BEGIN\n".getBytes("UTF-8"));
        check(Journal.listPending(directory).size() == 1,
                "a journal and its sidecar are one transaction, not two");
        finished.delete();
        check(Journal.listPending(directory).isEmpty(), "delete takes the sidecar with it");
    }

    /**
     * A stock restoration is one transaction.  Phase 1 used to delete its
     * journal and phase 2 to create its own, so an app close in that gap left a
     * device trusting FiiO again with nothing on disk saying phase 2 was owed —
     * and re-running the menu started at phase 1, which the device no longer
     * trusts.  Both phases therefore share one record, which is only retired
     * once the second one verifies.
     */
    private static void restorationKeepsOneRecord() throws Exception {
        SimBtr15Peer peer = jailbrokenPeer();
        String dir = freshDir();
        try {
            Workflows.restoreStock(new File(dir), connector(peer), images(peer, false), NO_SLEEP);
            check(false, "the dead phase 2 stops the run");
        } catch (FirmwareException expected) {
            check(expected.getMessage().contains("between the phases"),
                    "the interruption is the phase boundary itself");
        }
        check(peer.firmwareSha256().equals(Util.sha256Hex(stockPhase1)),
                "phase 1 landed before the interruption");
        check(peer.trust().equals(FirmwareProfile.fiioModulus()),
                "the device trusts FiiO again with phase 2 still owed");
        Journal pending = Journal.findPending(new File(dir));
        check(pending != null, "the record survives the phase boundary");
        check(pending.get("kind").equals(Journal.KIND_STOCK_RESTORE),
                "the whole restoration is one record, not two transactions");
        check(Journal.PHASE_VERIFIED.equals(pending.getOrEmpty("phase")),
                "the record proves phase 1 finished");
        final String phaseDir = dir;
        String outcome = Workflows.recover(new File(phaseDir), connector(peer),
                pending, restorationMaterial(), NO_SLEEP);
        check(outcome.contains("phase 2"), "recovery continues with phase 2: " + outcome);
        check(peer.firmwareSha256().equals(FirmwareProfile.SHA256),
                "the official package runs again");
        check(Journal.findPending(new File(phaseDir)) == null,
                "the record is retired only once both phases are done");

        // Pressing Restore stock again with the record still pending has to
        // continue it, not open a second transaction.  Phase 2 alone runs: the
        // device trusts FiiO again and would reject the developer-signed phase 1.
        SimBtr15Peer again = jailbrokenPeer();
        String againDir = freshDir();
        try {
            Workflows.restoreStock(new File(againDir), connector(again), images(again, false), NO_SLEEP);
            check(false, "the interrupted restoration stops the first time");
        } catch (FirmwareException expected) {
            check(true, "the restoration is left unfinished");
        }
        check(Journal.listPending(new File(againDir)).size() == 1,
                "exactly one record is on disk before the second press");
        Workflows.restoreStock(new File(againDir), connector(again), workingImages(), NO_SLEEP);
        check(again.firmwareSha256().equals(FirmwareProfile.SHA256),
                "the second press finishes phase 2 and leaves the official package");
        check(Journal.listPending(new File(againDir)).isEmpty(),
                "no second journal was created");

        // And the form where the record is already armed at phase 2, killed
        // inside its own transfer: the resume finishes phase 2 exactly once.
        final SimBtr15Peer killed = jailbrokenPeer();
        final String killedDir = freshDir();
        try {
            Workflows.restoreStock(new File(killedDir), connector(killed), images(killed, true), NO_SLEEP);
            check(false, "the killed phase-2 transfer stops the run");
        } catch (FirmwareException expected) {
            check(true, "the interruption inside phase 2 surfaces");
        }
        Journal armed = Journal.findPending(new File(killedDir));
        check(armed != null && Journal.RESTORATION_PHASE2.equals(armed.restorationPhase()),
                "the record is armed at phase 2 before its first byte");
        String resumed = Workflows.recover(new File(killedDir), connector(killed), armed,
                restorationMaterial(), NO_SLEEP);
        check(resumed.contains("phase 2"), "recovery names the phase it finished: " + resumed);
        check(killed.firmwareSha256().equals(FirmwareProfile.SHA256),
                "the armed phase 2 reinstalls the official package");
        check(Journal.findPending(new File(killedDir)) == null,
                "the record retires after phase 2 verified");
    }

    /**
     * The restoration's two packages.  {@code false} dies at the phase boundary
     * (the app closing between the phases), {@code true} dies inside the phase-2
     * transfer.
     */
    private static Workflows.RestorationImages images(final SimBtr15Peer peer,
                                                      final boolean dieInsidePhaseTwo) {
        return new Workflows.RestorationImages() {
            public byte[] phase1() {
                return stockPhase1;
            }

            public byte[] phase2() throws FirmwareException {
                if (!dieInsidePhaseTwo) {
                    throw new FirmwareException("app closed between the phases");
                }
                // Phase 2 starts, then the link dies 1000 bytes in.
                peer.killDataAfter(1000);
                return official;
            }
        };
    }

    /** Both phases, built the way a healthy run builds them. */
    private static Workflows.RestorationImages workingImages() {
        return new Workflows.RestorationImages() {
            public byte[] phase1() {
                return stockPhase1;
            }

            public byte[] phase2() {
                return official;
            }
        };
    }

    /** Both phases of a restoration, rebuilt from the official package. */
    private static Workflows.RecoveryMaterial restorationMaterial() {
        return new Workflows.RecoveryMaterial() {
            public byte[] imageFor(Journal journal) throws FirmwareException {
                if (Journal.RESTORATION_PHASE2.equals(journal.restorationPhase())) {
                    return official;
                }
                return FirmwareEngine.build(official, key,
                        FirmwareEngine.Variant.STOCK_PAYLOADS).bytes;
            }

            public byte[] official(Journal journal) {
                return official;
            }
        };
    }

    /** Transcripts are the exported logs: hex frames only, never key material. */
    private static void transcriptSafety() {
        StringBuilder all = new StringBuilder();
        for (Session session : openedSessions) {
            for (String line : session.transcript()) {
                all.append(line).append('\n');
            }
        }
        String text = all.toString();
        check(text.contains("TX ff01") && text.contains("RX ff01"),
                "transcripts record the real frames");
        check(!text.contains("abandon") && !text.toLowerCase().contains("mnemonic"),
                "no transcript line leaks the mnemonic");
    }

    // ---- harness ---------------------------------------------------------------

    private static SimBtr15Peer stockPeer() {
        return new SimBtr15Peer(official, FirmwareProfile.fiioModulus());
    }

    private static SimBtr15Peer jailbrokenPeer() {
        return new SimBtr15Peer(candidate, key.modulus);
    }

    private static Workflows.Connector connector(SimBtr15Peer peer) {
        return () -> {
            Session session = new Session(peer.openConnection(), 500L);
            openedSessions.add(session);
            return session;
        };
    }

    private static Workflows.RecoveryMaterial material(byte[] image) {
        return new Workflows.RecoveryMaterial() {
            public byte[] imageFor(Journal journal) {
                return image;
            }

            /** These scenarios stage single packages, so both are the same bytes. */
            public byte[] official(Journal journal) {
                return image;
            }
        };
    }

    private static String freshDir() throws Exception {
        File dir = Files.createTempDirectory("btr15-wf").toFile();
        dir.deleteOnExit();
        return dir.getAbsolutePath();
    }

    private static boolean throwsFirmware(ThrowingAction action) {
        try {
            action.run();
            return false;
        } catch (FirmwareException expected) {
            return true;
        } catch (Exception other) {
            throw new IllegalStateException("unexpected failure kind", other);
        }
    }

    private interface ThrowingAction {
        void run() throws Exception;
    }

    private static void check(boolean condition, String what) {
        if (!condition) {
            throw new AssertionError("FAILED: " + what);
        }
        checks++;
        System.out.println("ok: " + what);
    }
}
