package app.btr15.tool;

import java.io.File;
import java.util.Arrays;

/**
 * The complete device transactions, ported message-for-message from the
 * Python flows proven on the physical BTR15 (btr15_developer_signed_ota.py,
 * btr15_v38_prevalidate_preserving_bootstrap_v4_live.py,
 * btr15_section10_exact_writer_live.py and the stock-restore pair).
 *
 * <ul>
 * <li>Normal developer update: preflight, device-driven transfer, the
 * IS_CSR_VALID_DONE backoff loop, reboot, POST_REBOOT trial commit handshake,
 * clean-context verification.</li>
 * <li>Corrected jailbreak: stage once to the exact 0x003d footer failure with
 * no host reply of any kind, one context read, only word 13 changes
 * ERROR(6) to PRE_VALIDATE(1), stored with the shipped padding and read back,
 * a manual cold power cycle (which zeroes the staged-id words), then a resume
 * session that retransmits zero firmware bytes, rides the normal
 * ImageUpgradeCopy, and finishes with the same trial commit handshake.</li>
 * <li>Two-stage stock restore: phase 1 re-signs untouched official payloads
 * with the developer key (restoring stock behaviour while staying flashable),
 * phase 2 flashes the untouched official FiiO-signed package, which now
 * verifies again; afterwards developer-key packages are rejected — the
 * release-correct end state.</li>
 * </ul>
 *
 * <p>Every boundary is journaled before it is crossed and {@link #recover}
 * implements the decision tree over (journal phase, live key-4 resume word).
 */
final class Workflows {
    /** Opens a fresh Session; callers reconnect around device reboots. */
    interface Connector {
        Session open() throws FirmwareException;

        /**
         * MAC of the device this connector talks to, stamped into every
         * journal it creates so Recovery retargets that exact device.
         * Returns null only when genuinely unknown (JVM tests).
         */
        default String deviceAddress() {
            return null;
        }

        /**
         * Where the user's official v3.8 file lives, stamped into every
         * journal so Recovery can re-open it after an app restart instead of
         * asking the user to find it again.  Null when unknown (JVM tests).
         */
        default String officialUri() {
            return null;
        }

        /**
         * Drop the live link so the next {@link #open()} dials a fresh one,
         * settle delay included.  Used when the device connected and answered
         * nothing: re-binding the single GAIA client is safe and is what the
         * firmware needs.  No-op when there is nothing cached (JVM tests).
         */
        default void recycle() { }

        /**
         * Where coarse transfer progress goes.  It is a log line, not a
         * status value: ten or so lines per transfer, exported with the rest
         * of the process log.  It rides on the connector because the connector
         * is the one part of a transaction the phone wires to the log; the JVM
         * tests that use a bare connector keep the silent default.
         */
        default TransferMeter.Listener progress() {
            return TransferMeter.SILENT;
        }

        /**
         * The phase the transaction has reached, worded for the status line
         * ("HANDSHAKING", "STAGING", "VALIDATING").  Phases are coarse and
         * ordered; the log carries the detail.  No-op for a bare test connector.
         */
        default void status(String status) { }
    }

    /** Injectable so JVM scenario tests run instantly. */
    interface Sleeper {
        void sleep(long milliseconds) throws FirmwareException;
    }

    /** Resolves the exact image bytes a journal refers to (user re-imports if needed). */
    interface RecoveryMaterial {
        byte[] imageFor(Journal journal) throws FirmwareException;

        /**
         * The untouched official package, for the phase-2 tail of a
         * restoration.  It must refuse a file that is not the one the record
         * was built from.
         */
        byte[] official(Journal journal) throws FirmwareException;
    }

    /** The two packages of a stock restoration, built by the caller on demand. */
    interface RestorationImages {
        /** Untouched official payloads, re-signed by the developer key. */
        byte[] phase1() throws FirmwareException;

        /** The untouched official FiiO-signed package. */
        byte[] phase2() throws FirmwareException;
    }

    static final Sleeper DEFAULT_SLEEPER = new Sleeper() {
        public void sleep(long milliseconds) throws FirmwareException {
            try {
                Thread.sleep(milliseconds);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new FirmwareException("interrupted while waiting for the device");
            }
        }
    };

    /** The proven live budget for waiting out a device reboot before commit. */
    private static final int REBOOT_ATTEMPTS = 20;
    private static final long REBOOT_RETRY_MS = 2_500L;

    /**
     * How many fresh links one pre-transfer handshake may use.  The firmware
     * occasionally accepts an RFCOMM connection, acknowledges the cheap GAIA
     * commands and then silently drops every Upgrade message — the observed
     * field failure was "no GAIA frame within 5999 ms" while waiting for
     * SYNC_CFM.  Nothing has been staged when that happens, so re-binding the
     * client on a brand-new link is completely safe.
     */
    private static final int HANDSHAKE_ATTEMPTS = 3;
    private static final long HANDSHAKE_RETRY_MS = 1_000L;

    private Workflows() { }

    // ---- shared building blocks (proven message orders) ----------------------

    static long imageUpgradeId(byte[] image) throws FirmwareException {
        byte[] tail = Upgrade.upgradeIdBytes(image);
        return ((tail[0] & 0xFFL) << 24) | ((tail[1] & 0xFFL) << 16)
                | ((tail[2] & 0xFFL) << 8) | (tail[3] & 0xFFL);
    }

    /**
     * Digest of the signed content (all PARTDATA payloads).  RSA-PSS signs
     * with a fresh random salt, so two builds of the same variant over the
     * same official file differ in the footer bytes and the file digest;
     * the content digest is what a rebuild reproduces bit for bit and is
     * therefore the identity a continuation may match on.  The upgrade id
     * lives inside the signature tail and must be carried from the journal
     * across restarts, never re-derived from rebuilt bytes.
     */
    static String contentSha256(byte[] image) throws FirmwareException {
        return Util.sha256Hex(AppPackage.parse(image).signedContent());
    }

    /** v3.8 answer plus an idle journal: refuse to touch a device mid-transaction. */
    static void preflight(Session s) throws FirmwareException {
        s.expectFirmwareVersion();
        int[] words = s.readUpgradeContext();
        if (!Upgrade.isCleanContext(words)) {
            throw new FirmwareException("device is not idle (resume word " + words[13]
                    + ", staged id " + Long.toHexString(Upgrade.stagedId(words))
                    + "); run Recovery first");
        }
    }

    /** preflight on its own session, for callers that journal only afterwards. */
    private static void preflightOnly(Connector connector) throws FirmwareException {
        connector.status("CHECKING DEVICE");
        Session s = connector.open();
        try {
            preflight(s);
        } finally {
            s.closeQuietly();
        }
    }

    /**
     * An attempt that failed before a single firmware byte moved leaves its
     * BEGIN journal behind, and the next flash would then be refused because
     * two transactions look unfinished.  Retire it only when the device's own
     * context proves it never happened (preflight just proved it clean) and
     * the journal names this device — or names none.  Anything that got
     * further, or belongs to another device, is left for Recovery.
     */
    private static void retireUnstartedJournal(File directory, Connector connector)
            throws FirmwareException {
        Journal pending = Journal.findPending(directory);
        if (pending == null || !Journal.PHASE_BEGIN.equals(pending.getOrEmpty("phase"))) {
            return;
        }
        String mine = connector.deviceAddress();
        String recorded = pending.get("device_address");
        boolean recordedDevice = recorded != null && !recorded.trim().isEmpty();
        if (recordedDevice && mine != null
                && !recorded.trim().equalsIgnoreCase(mine.trim())) {
            return; // another device's unfinished transaction: not ours to retire
        }
        pending.note("retired: the device context was clean, so this attempt never reached it");
        pending.delete();
    }

    /** REGISTER, CONNECT, SYNC (expecting one resume state) and START. */
    private static void syncAndStart(Session s, byte[] image, long upgradeId, int expectResume)
            throws FirmwareException {
        s.registerUpgradeEvents();
        s.connectUpgrade();
        // The id on the wire is the id the device recorded at staging time,
        // which is the journal's — NOT the id of the bytes in hand.  A rebuilt
        // candidate (new random PSS tail, so a new id) must still announce the
        // staged id, or the device answers with the id the host claimed and the
        // resume aborts.  In staging both are the same value.
        s.upgrade(Upgrade.SYNC_REQ, Upgrade.upgradeIdBytes(upgradeId));
        Upgrade.Message syncCfm = awaitSyncCfm(s);
        int resume = syncCfm.syncResumeWord();
        long syncedId = syncCfm.syncUpgradeId();
        syncCfm.syncProtocol();
        if (resume != expectResume) {
            throw new FirmwareException("device reported resume state " + resume
                    + " where " + expectResume + " was required");
        }
        if (syncedId != upgradeId) {
            throw new FirmwareException("device staged image "
                    + String.format(java.util.Locale.ROOT, "%08x", syncedId)
                    + " instead of " + String.format(java.util.Locale.ROOT, "%08x", upgradeId));
        }
        s.upgrade(Upgrade.START_REQ);
        s.waitUpgrade(Upgrade.START_CFM).startBatteryMillivolts();
    }

    /**
     * SYNC_CFM, or the device's own refusal.  The firmware answers a SYNC it
     * will not accept with ERRORWARN_IND (field capture: code 0x0081, 36 ms
     * after the request) and never with SYNC_CFM, so waiting out the timeout
     * reported a meaningless silence.  Anything else the device interleaves is
     * skipped, exactly as before.
     */
    private static Upgrade.Message awaitSyncCfm(Session s) throws FirmwareException {
        while (true) {
            Upgrade.Message message = s.nextUpgradeMessage(Session.DEFAULT_ACK_TIMEOUT_MS);
            if (message.id == Upgrade.SYNC_CFM) {
                return message;
            }
            if (message.id == Upgrade.ERRORWARN_IND) {
                throw new FirmwareException("the device refused the upgrade handshake with"
                        + " ERRORWARN_IND code 0x" + Integer.toHexString(s.upgradeErrorCode()));
            }
        }
    }

    /**
     * {@link #syncAndStart} on a link that the device actually answers, with a
     * bounded number of fresh links when it does not.
     *
     * <p>The firmware sometimes accepts the RFCOMM connection, answers the
     * plain GAIA commands, and then drops every Upgrade message on that link:
     * the field failure was a 5999 ms silence while waiting for SYNC_CFM, on a
     * link whose firmware getter had just answered twice.  Nothing is staged
     * at that point — REGISTER, SYNC and START carry no firmware bytes — so
     * the safe and correct reaction is to drop the client binding, let the
     * device release the old link, and hand the same messages to a new one.
     * Every attempt announces the same id, so the retry cannot cross wires
     * with a staged image.
     */
    private static Session openAndHandshake(Connector connector, byte[] image, long upgradeId,
                                           int expectResume, Sleeper sleeper)
            throws FirmwareException {
        FirmwareException last = null;
        for (int attempt = 1; attempt <= HANDSHAKE_ATTEMPTS; attempt++) {
            connector.status("HANDSHAKING");
            Session s = connector.open();
            try {
                syncAndStart(s, image, upgradeId, expectResume);
                return s;
            } catch (FirmwareException silent) {
                last = silent;
                // A device-side Upgrade error (ERRORWARN at SYNC) keeps every
                // later handshake refused until the host releases it.  Nothing
                // is staged, so the release is safe and happens before the
                // retry rather than after three more failures.
                if (s.upgradeErrorCode() >= 0) {
                    try {
                        s.clearUpgradeError();
                    } catch (FirmwareException cannotClear) {
                        // the fresh link below still gets its chance
                    }
                }
                s.closeQuietly();
                connector.recycle();
                if (attempt < HANDSHAKE_ATTEMPTS) {
                    sleeper.sleep(HANDSHAKE_RETRY_MS);
                }
            }
        }
        throw new FirmwareException("the device answered the connection but not the upgrade"
                + " handshake, on " + HANDSHAKE_ATTEMPTS + " fresh links (last answer: "
                + (last == null || last.getMessage() == null ? "silence" : last.getMessage())
                + "); the device is untouched — run Recovery");
    }

    /**
     * How long the device may take to ask for the first firmware bytes after
     * START.  Field capture (2026-11-20 19:13): SYNC_CFM and START_CFM arrived
     * within 570 ms, then the device went quiet for longer than the 6 s ack
     * timeout and the run reported "no GAIA frame within 5999 ms" — while it
     * was preparing the staging area.  Erasing staging flash is the slowest
     * thing the device does and it is entirely its own business.
     */
    private static final long DEVICE_PREPARE_TIMEOUT_MS = 60_000L;

    /**
     * Coarse progress for one image transfer.  The meter is told what the
     * device holds, not what the host hoped to send, so a continuation that
     * rides the device's own skip offsets still ends at 100%.  The packet total
     * is not handed over as a constant: the meter derives it from the image
     * left, because the device's request boundaries decide how many DATA
     * messages the transfer really costs (see {@link TransferMeter}).  The
     * packet size is the same one the pump chunks with, so the estimate speaks
     * the units the wire uses.
     */
    private static TransferMeter meterFor(Connector connector, byte[] image) {
        return new TransferMeter(connector.progress(), image.length, Upgrade.DEFAULT_CHUNK);
    }

    /** Device-driven pump: honour every DATA_BYTES_REQ, including skip offsets. */
    private static void pumpData(Session s, byte[] image, Connector connector)
            throws FirmwareException {
        TransferMeter meter = meterFor(connector, image);
        Upgrade.Sender sender = new Upgrade.Sender(image, Upgrade.DEFAULT_CHUNK);
        boolean first = true;
        long packetsSent = 0L;
        while (sender.cursor() < image.length) {
            if (first) {
                // Erasing the staging area is the device's own business and the
                // slowest thing it does; the 60 s window below is that patience.
                connector.status("WAITING FOR DEVICE");
            }
            Upgrade.Message request = first
                    ? s.waitUpgrades(DEVICE_PREPARE_TIMEOUT_MS, Upgrade.DATA_BYTES_REQ)
                    : s.waitUpgrades(Session.DEFAULT_VALIDATION_BUDGET_MS,
                            Upgrade.DATA_BYTES_REQ);
            if (first) {
                connector.status("STAGING");
                first = false;
            }
            if (request.body.length != 8) {
                throw new FirmwareException("DATA_BYTES_REQ body is not eight bytes");
            }
            long requested = read32(request.body, 0);
            long startOffset = read32(request.body, 4);
            byte[][] packets = sender.satisfy(requested, startOffset);
            for (int index = 0; index < packets.length; index++) {
                s.sendUpgradePacket(packets[index]);
                // One device request can cover the whole image, so the report
                // is per transmitted packet: the device's own offset after it.
                meter.report(sender.offsetAfter(index), ++packetsSent);
            }
        }
    }

    /**
     * After the last byte: poll IS_CSR_VALID_DONE and tolerate backoff answers,
     * exactly like the proven client, until the device answers with a terminal
     * message.  Polling is what makes this work at all — a device whose footer
     * check passed says nothing until it is asked, which is why the jailbreak
     * branch used to sit out its whole budget in silence on a device that
     * already trusted the key.
     *
     * <p>Returns the terminal {@link Upgrade#TRANSFER_COMPLETE_IND} (with the
     * zero result already sent, so ImageUpgradeCopy may proceed) or the
     * {@link Upgrade#ERRORWARN_IND} — a footer rejection is an answer, not an
     * exception: the jailbreak flow turns it into its checkpoint, a developer
     * update turns it into an error via {@link #requireAccepted}.
     */
    private static Upgrade.Message awaitTerminal(Session s, Sleeper sleeper)
            throws FirmwareException {
        long deadline = System.nanoTime() + Session.DEFAULT_VALIDATION_BUDGET_MS * 1_000_000L;
        while (true) {
            s.upgrade(Upgrade.IS_CSR_VALID_DONE_REQ);
            long remainingMs = Math.max(1L, (deadline - System.nanoTime()) / 1_000_000L);
            Upgrade.Message answer = s.waitUpgrades(remainingMs,
                    Upgrade.IS_CSR_VALID_DONE_CFM, Upgrade.TRANSFER_COMPLETE_IND,
                    Upgrade.ERRORWARN_IND);
            if (answer.id == Upgrade.TRANSFER_COMPLETE_IND) {
                s.upgrade(Upgrade.TRANSFER_COMPLETE_RES, new byte[] {0});
                return answer;
            }
            if (answer.id == Upgrade.ERRORWARN_IND) {
                return answer;
            }
            if (answer.body.length != 2) {
                throw new FirmwareException("IS_CSR_VALID_DONE_CFM backoff is not uint16");
            }
            long backoff = ((answer.body[0] & 0xFFL) << 8) | (answer.body[1] & 0xFFL);
            if (backoff < 1 || backoff > 5_000) {
                throw new FirmwareException("absurd validation backoff " + backoff + " ms");
            }
            sleeper.sleep(backoff);
        }
    }

    /** A developer update needs the terminal answer to be acceptance. */
    private static void requireAccepted(Upgrade.Message terminal) throws FirmwareException {
        if (terminal.id == Upgrade.TRANSFER_COMPLETE_IND) {
            return; // TRANSFER_COMPLETE_IND carries no body; it IS the acceptance
        }
        requireFooterFailure(terminal);
        throw new FirmwareException("device rejected the package signature (0x003d)"
                + " and staged it in the ERROR state; Recovery explains the options");
    }

    private static void requireFooterFailure(Upgrade.Message errorWarn) throws FirmwareException {
        if (errorWarn.body.length != 2
                || (((errorWarn.body[0] & 0xFF) << 8) | (errorWarn.body[1] & 0xFF))
                        != Upgrade.FOOTER_VALIDATION_FAILED) {
            throw new FirmwareException("ERRORWARN_IND carried an unexpected code");
        }
    }

    /**
     * POST_REBOOT trial bank commit: SYNC(3), START, IN_PROGRESS_RES, COMMIT_CFM,
     * COMPLETE_IND — the proven postboot sequence.
     */
    static void commitHandshake(Session s, byte[] image, long upgradeId) throws FirmwareException {
        syncAndStart(s, image, upgradeId, Upgrade.RESUME_POST_REBOOT);
        finishCommit(s);
    }

    /** The messages after the post-reboot SYNC: IN_PROGRESS_RES, COMMIT_CFM, COMPLETE_IND. */
    private static void finishCommit(Session s) throws FirmwareException {
        s.upgrade(Upgrade.IN_PROGRESS_RES, new byte[] {0});
        s.waitUpgrade(Upgrade.COMMIT_REQ);
        s.upgrade(Upgrade.COMMIT_CFM, new byte[] {0});
        Upgrade.Message complete = s.waitUpgrade(Upgrade.COMPLETE_IND);
        if (complete.body.length != 0) {
            throw new FirmwareException("COMPLETE_IND unexpectedly had a body");
        }
    }

    /** Retry across the device reboot; the 60 s device timer is the true bound. */
    private static void commitAfterReboot(Connector connector, byte[] image, long upgradeId,
                                          Sleeper sleeper) throws FirmwareException {
        FirmwareException last = null;
        for (int attempt = 0; attempt < REBOOT_ATTEMPTS; attempt++) {
            Session s = null;
            connector.status("WAITING FOR REBOOT");
            try {
                s = openAndHandshake(connector, image, upgradeId, Upgrade.RESUME_POST_REBOOT,
                        sleeper);
                connector.status("COMMITTING");
                finishCommit(s);
                return;
            } catch (FirmwareException failed) {
                last = failed;
            } finally {
                if (s != null) {
                    s.closeQuietly();
                }
            }
            sleeper.sleep(REBOOT_RETRY_MS);
        }
        throw new FirmwareException("device never returned for its commit handshake: "
                + (last == null ? "unknown" : last.getMessage()));
    }

    /** Proven closing check: v3.8 answer and the (prefix, 1, 1, 2, zero) journal. */
    static void verifyClean(Session s) throws FirmwareException {
        s.expectFirmwareVersion();
        int[] words = s.readUpgradeContext();
        if (!Upgrade.isCleanContext(words)) {
            throw new FirmwareException("device context is still dirty after the transaction"
                    + " (resume word " + words[13] + ")");
        }
    }

    // ---- normal developer-key update (also stock phase 1 and phase 2) ---------

    /**
     * Full signed update against an idle device that already trusts the
     * developer key (phase 2 runs the same engine on the official FiiO-signed
     * package, which passes again after phase 1).
     */
    static void runUpdate(File directory, Connector connector, byte[] image, String kind,
                          String variantLabel, Sleeper sleeper) throws FirmwareException {
        // Probe idleness BEFORE taking a journal: if the device is not idle the
        // run stops without leaving a transaction behind that Recovery would
        // then chase (a phase-BEGIN journal with nothing staged).
        preflightOnly(connector);
        retireUnstartedJournal(directory, connector);
        Journal journal = Journal.create(directory, kind, Util.sha256Hex(image),
                contentSha256(image), imageUpgradeId(image), variantLabel,
                connector.deviceAddress(), connector.officialUri());
        try {
            transferCommitVerify(connector, image, journal, sleeper);
        } finally {
            if (Journal.PHASE_VERIFIED.equals(journal.getOrEmpty("phase"))) {
                journal.delete();
            }
        }
    }

    /**
     * The transfer, the post-reboot trial commit and the closing clean check,
     * on a journal the caller has already created.  The idle preflight is the
     * caller's business.
     */
    private static void transferCommitVerify(Connector connector, byte[] image, Journal journal,
                                             Sleeper sleeper) throws FirmwareException {
        long upgradeId = imageUpgradeId(image);
        try {
            Session s = openAndHandshake(connector, image, upgradeId, 0, sleeper);
            try {
                s.upgrade(Upgrade.START_DATA_REQ);
                pumpData(s, image, connector);
                connector.status("VALIDATING");
                requireAccepted(awaitTerminal(s, sleeper));
                journal.enterPhase(Journal.PHASE_APPLY_SENT);
            } finally {
                s.closeQuietly();
            }
            commitAfterReboot(connector, image, upgradeId, sleeper);
            journal.enterPhase(Journal.PHASE_COMMITTED);
            connector.status("VERIFYING");
            Session verify = connector.open();
            try {
                verifyClean(verify);
            } finally {
                verify.closeQuietly();
            }
            journal.enterPhase(Journal.PHASE_VERIFIED);
        } catch (FirmwareException failed) {
            journal.note("failed: " + failed.getMessage() + " — run Recovery");
            throw failed;
        }
    }

    /**
     * Both stock phases under one record, so Recovery can always tell that a
     * restoration is unfinished and which phase it reached.  Phase 1 restores
     * FiiO's key block; once it verifies, the same record is re-armed at phase
     * 2 and only then is phase 2 flashed.  The record is deleted when phase 2
     * verifies, and only then.
     */
    static void restoreStock(File directory, Connector connector, RestorationImages images,
                             Sleeper sleeper) throws FirmwareException {
        preflightOnly(connector);
        // A restoration that was interrupted keeps its record: continue that one
        // instead of leaving two transactions nothing may guess between.  Phase
        // 1 also runs again only when it never committed — after it did, the
        // device trusts FiiO again and would reject the developer-signed phase 1.
        Journal pending = Journal.findPending(directory);
        if (pending != null) {
            if (!Journal.KIND_STOCK_RESTORE.equals(pending.getOrEmpty("kind"))) {
                throw new FirmwareException("An unfinished "
                        + pending.getOrEmpty("kind").toLowerCase(java.util.Locale.ROOT)
                        + " transaction is already recorded; finish it with Recovery first");
            }
            boolean phaseOneDone = phaseAtLeast(pending.getOrEmpty("phase"),
                    Journal.PHASE_COMMITTED)
                    || Journal.RESTORATION_PHASE2.equals(pending.restorationPhase());
            requireSameContent(phaseOneDone
                    ? contentSha256(images.phase2()) : contentSha256(images.phase1()), pending);
            runRestoration(connector, pending, images, phaseOneDone, sleeper);
            return;
        }
        retireUnstartedJournal(directory, connector);
        byte[] phase1 = images.phase1();
        Journal journal = Journal.create(directory, Journal.KIND_STOCK_RESTORE,
                Util.sha256Hex(phase1), contentSha256(phase1), imageUpgradeId(phase1),
                FirmwareEngine.Variant.STOCK_PAYLOADS.name(), connector.deviceAddress(),
                connector.officialUri());
        journal.setRestorationPhase(Journal.RESTORATION_PHASE1);
        runRestoration(connector, journal, images, false, sleeper);
    }

    /** The picked official file must be the package the record was built from. */
    private static void requireSameContent(String contentSha, Journal journal)
            throws FirmwareException {
        String recorded = journal.get("staged_content_sha256");
        if (recorded != null && !recorded.isEmpty() && !Util.sameHash(contentSha, recorded)) {
            throw new FirmwareException("The selected firmware is not the package this"
                    + " restoration started from; pick that same official file");
        }
    }

    /**
     * Phase 1 (when it is still owed), then phase 2, then retire the record.
     * The record is re-armed for phase 2 before a byte of it moves, so a crash
     * anywhere in here leaves a record that names the phase still to run.
     */
    static void runRestoration(Connector connector, Journal journal, RestorationImages images,
                               boolean phaseOneDone, Sleeper sleeper) throws FirmwareException {
        if (!phaseOneDone) {
            byte[] phase1 = images.phase1();
            transferCommitVerify(connector, phase1, journal, sleeper);
        }
        byte[] phase2 = images.phase2();
        journal.rearm(Util.sha256Hex(phase2), contentSha256(phase2), imageUpgradeId(phase2),
                "OFFICIAL", Journal.PHASE_BEGIN, Journal.RESTORATION_PHASE2);
        transferCommitVerify(connector, phase2, journal, sleeper);
        journal.delete();
    }

    static void developerUpdate(File directory, Connector connector, byte[] image,
                                String variantLabel, Sleeper sleeper) throws FirmwareException {
        runUpdate(directory, connector, image, Journal.KIND_DEVELOPER_UPDATE,
                variantLabel, sleeper);
    }

    // ---- corrected jailbreak ---------------------------------------------------

    /**
     * Stage the candidate onto a stock-trust device and stop at the exact
     * footer failure.  One staging attempt only: the candidate's id is read
     * from the built bytes (never chosen) and the device's own answer must
     * name it back.  No ERRORWARN_RES, no ABORT_REQ — the host interlock in
     * {@link Session} makes those impossible.
     */
    /**
     * How a staging run ended: the device refused the key (footer failure, the
     * jailbreak's own checkpoint, journal kept for the cold-cycle resume) or it
     * already trusted the key and the package is installed as the developer
     * update it really is.
     */
    static final class StageOutcome {
        /** The staging transaction; deleted already when the device accepted it. */
        final Journal journal;
        /** True when the caller must run the cold-cycle checkpoint. */
        final boolean needsPowerCycle;

        StageOutcome(Journal journal, boolean needsPowerCycle) {
            this.journal = journal;
            this.needsPowerCycle = needsPowerCycle;
        }
    }

    /**
     * Stock v3.8 trust check: the candidate must be refused with the exact
     * footer failure.  A device that already trusts the key instead accepts it,
     * and the run continues as the developer update it really is — commit,
     * verify, no cold cycle — because staging a package the device is willing
     * to install and then walking away would be busywork.
     */
    static StageOutcome jailbreakStage(File directory, Connector connector, byte[] candidate,
                                      String variantLabel, Sleeper sleeper)
            throws FirmwareException {
        long upgradeId = imageUpgradeId(candidate);
        preflightOnly(connector);
        retireUnstartedJournal(directory, connector);
        Journal journal = Journal.create(directory, Journal.KIND_JAILBREAK,
                Util.sha256Hex(candidate), contentSha256(candidate), upgradeId,
                variantLabel, connector.deviceAddress(),
                connector.officialUri());
        try {
            Session s = openAndHandshake(connector, candidate, upgradeId, 0, sleeper);
            try {
                s.upgrade(Upgrade.START_DATA_REQ);
                pumpData(s, candidate, connector);
                connector.status("VALIDATING");
                Upgrade.Message terminal = awaitTerminal(s, sleeper);
                if (terminal.id == Upgrade.TRANSFER_COMPLETE_IND) {
                    // The key is already trusted: the device validated the
                    // package and wants it installed.  From here the proven
                    // developer-update tail applies unchanged.
                    journal.note("device already trusted this key and accepted the package;"
                            + " finished as a developer update, no power cycle");
                    journal.enterPhase(Journal.PHASE_APPLY_SENT);
                } else {
                    connector.status("CHECKING FOOTER");
                    requireFooterFailure(terminal);
                    journal.enterPhase(Journal.PHASE_STAGED_FOOTER_FAIL);
                }
            } finally {
                s.closeQuietly();
            }
            if (journal.getOrEmpty("phase").equals(Journal.PHASE_APPLY_SENT)) {
                commitAfterReboot(connector, candidate, upgradeId, sleeper);
                journal.enterPhase(Journal.PHASE_COMMITTED);
                connector.status("VERIFYING");
                Session verify = connector.open();
                try {
                    verifyClean(verify);
                } finally {
                    verify.closeQuietly();
                }
                journal.enterPhase(Journal.PHASE_VERIFIED);
                journal.delete();
                return new StageOutcome(journal, false);
            }
            rewriteKey4ToPreValidate(connector, journal);
        } catch (FirmwareException failed) {
            journal.note("failed: " + failed.getMessage() + " — run Recovery");
            throw failed;
        }
        return new StageOutcome(journal, true);
    }

    /**
     * Device state 2: the staged image validated and the copy ran, but the host
     * never acknowledged the transfer (see {@link Upgrade#RESUME_VALIDATED}).
     * Finish the transaction without making the device receive the package
     * again: poll the copy like every other completion, still serve any late
     * data request, then let the normal trial commit close it.
     */
    static void finishValidated(File directory, Connector connector, Journal journal,
                               byte[] image, Sleeper sleeper) throws FirmwareException {
        long upgradeId = journal.upgradeId();
        connector.status("RESUMING");
        Session s = openAndHandshake(connector, image, upgradeId,
                Upgrade.RESUME_VALIDATED, sleeper);
        try {
            s.upgrade(Upgrade.START_DATA_REQ);
            Upgrade.Sender sender = new Upgrade.Sender(image, Upgrade.DEFAULT_CHUNK);
            while (true) {
                s.upgrade(Upgrade.IS_CSR_VALID_DONE_REQ);
                Upgrade.Message answer = s.waitUpgrades(Session.DEFAULT_ACK_TIMEOUT_MS,
                        Upgrade.IS_CSR_VALID_DONE_CFM, Upgrade.TRANSFER_COMPLETE_IND,
                        Upgrade.ERRORWARN_IND, Upgrade.DATA_BYTES_REQ);
                if (answer.id == Upgrade.TRANSFER_COMPLETE_IND) {
                    s.upgrade(Upgrade.TRANSFER_COMPLETE_RES, new byte[] {0});
                    break;
                }
                if (answer.id == Upgrade.ERRORWARN_IND) {
                    requireFooterFailure(answer);
                    throw new FirmwareException("device rejected the staged package (0x003d)");
                }
                if (answer.id == Upgrade.DATA_BYTES_REQ) {
                    if (answer.body.length != 8) {
                        throw new FirmwareException("DATA_BYTES_REQ body is not eight bytes");
                    }
                    for (byte[] packet : sender.satisfy(read32(answer.body, 0),
                            read32(answer.body, 4))) {
                        s.sendUpgradePacket(packet);
                    }
                    continue;
                }
                if (answer.body.length != 2) {
                    throw new FirmwareException("IS_CSR_VALID_DONE_CFM backoff is not uint16");
                }
                long backoff = ((answer.body[0] & 0xFFL) << 8) | (answer.body[1] & 0xFFL);
                sleeper.sleep(Math.max(1L, Math.min(backoff, 5_000L)));
            }
            journal.enterPhase(Journal.PHASE_APPLY_SENT);
        } finally {
            s.closeQuietly();
        }
        commitAfterReboot(connector, image, upgradeId, sleeper);
        journal.enterPhase(Journal.PHASE_COMMITTED);
        finishVerified(directory, connector, journal);
    }

    /**
     * Exactly one read, exactly one changed word (13: ERROR 6 to
     * PRE_VALIDATE 1), the shipped padding on store, then a read-back proving
     * the write.  A different staged id or resume word aborts untouched.
     */
    static void rewriteKey4ToPreValidate(Connector connector, Journal journal)
            throws FirmwareException {
        long stagedId = journal.upgradeId();
        connector.status("REWRITING CONTEXT");
        Session s = connector.open();
        try {
            int[] words = s.readUpgradeContext();
            if (words[Upgrade.RESUME_WORD] != Upgrade.RESUME_ERROR) {
                throw new FirmwareException("resume word is " + words[Upgrade.RESUME_WORD]
                        + ", not ERROR(6); refusing to rewrite the context");
            }
            if (Upgrade.stagedId(words) != stagedId) {
                throw new FirmwareException("device staged "
                        + Long.toHexString(Upgrade.stagedId(words)) + " but this transaction"
                        + " staged " + Long.toHexString(stagedId));
            }
            int[] repaired = Upgrade.withResumeWord(words, Upgrade.RESUME_ERROR,
                    Upgrade.RESUME_PRE_VALIDATE);
            s.storeUpgradeContext(repaired);
            int[] readBack = s.readUpgradeContext();
            if (!Arrays.equals(readBack, repaired)) {
                throw new FirmwareException("key-4 read-back does not match the repair"
                        + " that was written");
            }
            journal.enterPhase(Journal.PHASE_KEY4_PRE_VALIDATE);
            journal.note("power-cycle the BTR15 off and on, then run the jailbreak resume");
        } finally {
            s.closeQuietly();
        }
    }

    /**
     * A developer-signed package hit the footer check on a device whose
     * firmware does not trust this key (stock): ERROR(6) context, image inert
     * in staging flash.  The honest abort is to write key 4 back to its clean
     * baseline so nothing references the staging any more — never
     * PRE_VALIDATE, which would jailbreak the device through an update the
     * user did not choose as a jailbreak.  Same STORE_PS_KEY write path the
     * staging flow uses, plus a read-back proving the device accepted idle.
     */
    static void discardRejectedStaging(Connector connector, Journal journal)
            throws FirmwareException {
        long stagedId = journal.upgradeId();
        connector.status("DISCARDING PACKAGE");
        Session s = connector.open();
        try {
            int[] words = s.readUpgradeContext();
            if (words[Upgrade.RESUME_WORD] != Upgrade.RESUME_ERROR) {
                throw new FirmwareException("resume word is " + words[Upgrade.RESUME_WORD]
                        + ", not ERROR(6); refusing to discard the staged package");
            }
            if (Upgrade.stagedId(words) != stagedId) {
                throw new FirmwareException("device staged "
                        + Long.toHexString(Upgrade.stagedId(words)) + " but this transaction"
                        + " staged " + Long.toHexString(stagedId)
                        + "; refusing to discard a staging we did not create");
            }
            int[] clean = Upgrade.cleanBaseline(words[0]);
            s.storeUpgradeContext(clean);
            int[] readBack = s.readUpgradeContext();
            if (!Upgrade.isCleanContext(readBack)) {
                throw new FirmwareException("device did not accept the clean context;"
                        + " consult RECOVERY.md before touching the device");
            }
            journal.note("discarded rejected staged package; device left as it was");
            journal.delete();
        } finally {
            s.closeQuietly();
        }
    }

    /**
     * The app restarted mid-transfer and can no longer produce the exact
     * bytes the device is missing (a rebuild carries a different random
     * PSS tail).  Splicing old and new would store a package that fails
     * validation, so the honest abort: clean baseline context (device back
     * to idle, the partial staging inert), journal deleted, and one clear
     * instruction — re-run the update from scratch with one consistent
     * package.
     */
    static void abortMidTransfer(Connector connector, Journal journal)
            throws FirmwareException {
        connector.status("REPAIRING CONTEXT");
        Session s = connector.open();
        try {
            int[] words = s.readUpgradeContext();
            if (Upgrade.isCleanContext(words)) {
                journal.note("device already returned to idle on its own");
                journal.delete();
                return;
            }
            s.storeUpgradeContext(Upgrade.cleanBaseline(words[0]));
            int[] readBack = s.readUpgradeContext();
            if (!Upgrade.isCleanContext(readBack)) {
                throw new FirmwareException("device did not accept the clean context;"
                        + " consult RECOVERY.md before touching the device");
            }
            journal.note("aborted mid-transfer after restart; device returned to idle");
            journal.delete();
        } finally {
            s.closeQuietly();
        }
    }

    /**
     * Resume after the manual cold power cycle: the context must show
     * PRE_VALIDATE with the staged-id words normalised to zero, the device
     * must answer SYNC with resume state 1, and the session may not
     * retransmit a single firmware byte.  The normal copy runs, then the same
     * reboot-plus-commit handshake closes the transaction.
     */
    static void jailbreakResume(File directory, Connector connector, Journal journal,
                                byte[] candidate, Sleeper sleeper) throws FirmwareException {
        connector.status("RESUMING");
        // The wire id is what the device recorded at staging time; a rebuilt
        // candidate carries a fresh random PSS tail, so only the journal
        // knows the true id.  Same bytes match on id, rebuilds match on the
        // deterministic content digest.
        long upgradeId = journal.upgradeId();
        if (imageUpgradeId(candidate) != upgradeId
                && !Util.sameHash(contentSha256(candidate),
                        journal.get("staged_content_sha256"))) {
            throw new FirmwareException("candidate content does not match journal"
                    + " transaction " + journal.id() + "; pick the same official v3.8 file");
        }
        Session s = connector.open();
        try {
            s.expectFirmwareVersion();
            int[] words = s.readUpgradeContext();
            if (words[Upgrade.RESUME_WORD] != Upgrade.RESUME_PRE_VALIDATE) {
                throw new FirmwareException("resume word is " + words[Upgrade.RESUME_WORD]
                        + ", not PRE_VALIDATE(1); Recovery decides what this state means");
            }
            // The staged-id words are zeroed by the cold cycle.  A resume attempt
            // that fails after SYNC registers the id again, so a retry sees them
            // set: accept either zeroed (fresh cycle) or naming THIS transaction,
            // and refuse only a foreign id.  Otherwise one failed resume would
            // block every later attempt with "power it off and on".
            long recorded = Upgrade.stagedId(words);
            if (recorded != 0 && recorded != upgradeId) {
                throw new FirmwareException("device holds staged id "
                        + Long.toHexString(recorded) + ", not this transaction's "
                        + Long.toHexString(upgradeId) + "; Recovery decides what that means");
            }
        } finally {
            s.closeQuietly();
        }
        // The device state is proven above; from here the resume handshake is
        // the same retryable one every other transaction uses.
        Session resume = openAndHandshake(connector, candidate, upgradeId,
                Upgrade.RESUME_PRE_VALIDATE, sleeper);
        try {
            long framesBefore = resume.dataFramesSent();
            connector.status("VALIDATING");
            requireAccepted(awaitTerminal(resume, sleeper));
            if (resume.dataFramesSent() != framesBefore) {
                throw new FirmwareException("resume session retransmitted firmware bytes");
            }
            journal.enterPhase(Journal.PHASE_RESUME_APPLIED);
        } finally {
            resume.closeQuietly();
        }
        commitAfterReboot(connector, candidate, upgradeId, sleeper);
        journal.enterPhase(Journal.PHASE_COMMITTED);
        connector.status("VERIFYING");
        Session verify = connector.open();
        try {
            verifyClean(verify);
        } finally {
            verify.closeQuietly();
        }
        journal.enterPhase(Journal.PHASE_VERIFIED);
        journal.delete();
    }

    // ---- recovery decision tree -------------------------------------------------

    /**
     * Inspect the one unfinished journal plus the live key-4 state and take the
     * single safe step, mirroring the documented RECOVERY tree:
     * resume 3 commits the pending trial, resume 1 continues the jailbreak
     * after the cold cycle, resume 6 rewrites the context, a dirty resume 0
     * re-runs the transfer (the device answers with skip offsets instead of
     * forcing a full reflash), and a clean context means the transaction
     * either already committed or rolled back.  Anything else refuses to act.
     */
    static String recover(File directory, Connector connector, Journal journal,
                          RecoveryMaterial material, Sleeper sleeper) throws FirmwareException {
        connector.status("RECOVERING");
        int[] words;
        Session probe = connector.open();
        try {
            words = probe.readUpgradeContext();
        } finally {
            probe.closeQuietly();
        }
        int resume = words[Upgrade.RESUME_WORD];
        boolean stagedMatches = Upgrade.stagedId(words) == journal.upgradeId();
        if (resume == Upgrade.RESUME_POST_REBOOT && stagedMatches) {
            commitAfterReboot(connector, material.imageFor(journal), journal.upgradeId(),
                    sleeper);
            journal.enterPhase(Journal.PHASE_COMMITTED);
            finishVerified(directory, connector, journal);
            return "Finished interrupted commit; the device completed this transaction";
        }
        if (resume == Upgrade.RESUME_VALIDATED && stagedMatches) {
            finishValidated(directory, connector, journal, material.imageFor(journal), sleeper);
            return "The device held the validated package but never acknowledged it; finished"
                    + " the commit and verified — no power cycle needed";
        }
        if (resume == Upgrade.RESUME_PRE_VALIDATE) {
            // Zeroed staged words mean the cold cycle happened; words naming this
            // very transaction mean a previous resume already registered the id.
            // Only a foreign id means the device has genuinely not cycled.
            long recorded = Upgrade.stagedId(words);
            if (recorded != 0 && recorded != journal.upgradeId()) {
                return "The device staged a different image and has not cold-cycled since;"
                        + " power it off and on, then run Recovery again";
            }
            if (journal.getOrEmpty("kind").equals(Journal.KIND_JAILBREAK)) {
                jailbreakResume(directory, connector, journal,
                        material.imageFor(journal), sleeper);
                return "Jailbreak resume completed after the interruption";
            }
            throw new FirmwareException("PRE_VALIDATE context without a jailbreak journal;"
                    + " consult RECOVERY.md before touching the device");
        }
        if (resume == Upgrade.RESUME_ERROR && stagedMatches) {
            if (!journal.getOrEmpty("kind").equals(Journal.KIND_JAILBREAK)) {
                discardRejectedStaging(connector, journal);
                return "Discarded the rejected staged package; the device keeps running"
                        + " what it ran before (its firmware does not trust this key)";
            }
            rewriteKey4ToPreValidate(connector, journal);
            return "Context repaired to PRE_VALIDATE; power-cycle the device and run Recovery";
        }
        if (resume == 0) {
            boolean stockRestore = Journal.KIND_STOCK_RESTORE.equals(journal.getOrEmpty("kind"));
            if (Upgrade.isCleanContext(words)) {
                if (stockRestore) {
                    // The record names the phase still owed; a finished looking
                    // phase 1 only means phase 2 is next.
                    return continueRestoration(connector, journal, material, sleeper);
                }
                boolean jailbreakKind = journal.getOrEmpty("kind").equals(Journal.KIND_JAILBREAK);
                if (phaseAtLeast(journal.getOrEmpty("phase"), Journal.PHASE_COMMITTED)
                        || (jailbreakKind && phaseAtLeast(journal.getOrEmpty("phase"),
                                Journal.PHASE_STAGED_FOOTER_FAIL))) {
                    finishVerified(directory, connector, journal);
                    return "Device already committed before the interruption; verified clean";
                }
                // Read the fields, then delete: a re-run that crashed after
                // creating its own journal would otherwise leave two unfinished
                // transactions on disk, which nothing may guess between.
                String originalKind = journal.getOrEmpty("kind");
                String originalVariant = journal.get("variant");
                byte[] originalImage = material.imageFor(journal);
                journal.delete();
                if (jailbreakKind) {
                    boolean coldCycle = jailbreakStage(directory, connector, originalImage,
                            originalVariant, sleeper).needsPowerCycle;
                    return coldCycle
                            ? "device rolled back before staging stuck; re-staged and repaired —"
                                    + " power-cycle the device and run Recovery"
                            : "device rolled back before staging stuck; the device accepted the"
                                    + " re-staged package itself and the update completed";
                }
                runUpdate(directory, connector, originalImage, originalKind, originalVariant,
                        sleeper);
                return "Device rolled back cleanly; the full update ran again";
            }
            // Mid-transfer journal (resume 0, dirty): the device keeps what it
            // received and answers with positive skip offsets on re-run, so the
            // continuation only sends what is still missing.  That is only
            // sound with the exact staged bytes — a rebuild differs from the
            // staged copy after the random PSS tail starts, and splicing the
            // two would write a package that fails validation.  After an app
            // restart we can only rebuild, so the safe step is to abort clean
            // and let the user re-run one consistent package from zero.
            byte[] image = material.imageFor(journal);
            if (!Util.sameHash(Util.sha256Hex(image), journal.get("package_sha256"))) {
                abortMidTransfer(connector, journal);
                return "The partial transfer was lost when the app restarted; the device"
                        + " context was cleared safely — run the update again from scratch";
            }
            boolean jailbreakKind = journal.getOrEmpty("kind").equals(Journal.KIND_JAILBREAK);
            long upgradeId = imageUpgradeId(image);
            boolean acceptedNow = false;
            Session s = openAndHandshake(connector, image, upgradeId, 0, sleeper);
            try {
                s.upgrade(Upgrade.START_DATA_REQ);
                long bytesBefore = s.firmwareBytesSent();
                pumpData(s, image, connector);
                if (jailbreakKind) {
                    connector.status("VALIDATING");
                    Upgrade.Message terminal = awaitTerminal(s, sleeper);
                    if (terminal.id == Upgrade.TRANSFER_COMPLETE_IND) {
                        // The device accepted what it was supposed to refuse, so
                        // this is a developer update after all: finish it here
                        // instead of leaving a journal nothing will continue.
                        acceptedNow = true;
                        journal.note("device accepted the package instead of rejecting it;"
                                + " finished as a developer update, no power cycle");
                        journal.enterPhase(Journal.PHASE_APPLY_SENT);
                    } else {
                        connector.status("CHECKING FOOTER");
                        requireFooterFailure(terminal);
                        journal.enterPhase(Journal.PHASE_STAGED_FOOTER_FAIL);
                    }
                } else {
                    connector.status("VALIDATING");
                    requireAccepted(awaitTerminal(s, sleeper));
                    journal.enterPhase(Journal.PHASE_APPLY_SENT);
                    if (s.firmwareBytesSent() - bytesBefore >= image.length) {
                        journal.note("warning: continuation retransmitted every package byte");
                    }
                }
            } finally {
                s.closeQuietly();
            }
            if (acceptedNow) {
                commitAfterReboot(connector, image, upgradeId, sleeper);
                journal.enterPhase(Journal.PHASE_COMMITTED);
                finishVerified(directory, connector, journal);
                return "The device accepted the package this time; the interrupted staging"
                        + " completed as a developer update, without a power cycle";
            }
            if (jailbreakKind) {
                rewriteKey4ToPreValidate(connector, journal);
                return "Interrupted jailbreak staging re-run with the device's own skip"
                        + " offsets and stopped at the footer failure; power-cycle the"
                        + " device and run Recovery again";
            }
            commitAfterReboot(connector, image, imageUpgradeId(image), sleeper);
            journal.enterPhase(Journal.PHASE_COMMITTED);
            if (stockRestore) {
                // Whatever phase this was has just landed and verified; the
                // record stays until the restoration as a whole is done.
                verifyOnly(connector);
                journal.enterPhase(Journal.PHASE_VERIFIED);
                if (Journal.RESTORATION_PHASE2.equals(journal.restorationPhase())) {
                    journal.delete();
                    return "Interrupted restoration phase 2 resumed from the device's own"
                            + " offsets and verified — the device is fully stock again";
                }
                runRestoration(connector, journal, restorationImages(material, journal), true,
                        sleeper);
                return "Interrupted restoration resumed from the device's own offsets;"
                        + " phase 1 finished and phase 2 ran and verified — the device"
                        + " is fully stock again";
            }
            finishVerified(directory, connector, journal);
            return "Interrupted transfer resumed from the device's own offsets and completed";
        }
        throw new FirmwareException("unexpected device state: resume word " + resume
                + " with staged id " + Long.toHexString(Upgrade.stagedId(words))
                + " — device untouched, consult RECOVERY.md");
    }

    /** A clean rollback of a restoration: run whatever phase the record still owes. */
    private static String continueRestoration(Connector connector, Journal journal,
                                              RecoveryMaterial material, Sleeper sleeper)
            throws FirmwareException {
        boolean phaseOneDone = phaseAtLeast(journal.getOrEmpty("phase"), Journal.PHASE_COMMITTED);
        runRestoration(connector, journal, restorationImages(material, journal), phaseOneDone,
                sleeper);
        return phaseOneDone
                ? "The record already had phase 1 committed, so phase 2 ran and verified —"
                        + " the device is fully stock again"
                : "Stock restoration restarted from phase 1 and completed both phases —"
                        + " the device is fully stock again";
    }

    private static RestorationImages restorationImages(final RecoveryMaterial material,
                                                       final Journal journal) {
        return new RestorationImages() {
            public byte[] phase1() throws FirmwareException {
                return material.imageFor(journal);
            }

            public byte[] phase2() throws FirmwareException {
                return material.official(journal);
            }
        };
    }

    private static void verifyOnly(Connector connector) throws FirmwareException {
        connector.status("VERIFYING");
        Session verify = connector.open();
        try {
            verifyClean(verify);
        } finally {
            verify.closeQuietly();
        }
    }

    private static void finishVerified(File directory, Connector connector, Journal journal)
            throws FirmwareException {
        verifyOnly(connector);
        journal.enterPhase(Journal.PHASE_VERIFIED);
        journal.delete();
    }

    /**
     * A device that still holds a half-finished upgrade context while this
     * phone has no journal for it (journal discarded, app data cleared, a
     * different phone ran the attempt).  Nothing can identify the transaction
     * any more, so the only honest action is the documented abort: write the
     * clean baseline context back, prove it with a read-back, and leave the
     * staging flash inert.  The device keeps running what it ran before.
     */
    static String repairOrphanedContext(Connector connector) throws FirmwareException {
        connector.status("REPAIRING CONTEXT");
        Session s = connector.open();
        try {
            int[] words = s.readUpgradeContext();
            if (Upgrade.isCleanContext(words)) {
                return "The device is already idle — nothing to repair";
            }
            s.storeUpgradeContext(Upgrade.cleanBaseline(words[0]));
            int[] readBack = s.readUpgradeContext();
            if (!Upgrade.isCleanContext(readBack)) {
                throw new FirmwareException("device did not accept the clean context;"
                        + " consult RECOVERY.md before touching the device");
            }
            return "The device held an unfinished upgrade with no journal on this phone;"
                    + " its context is clean again (resume word " + words[Upgrade.RESUME_WORD]
                    + " was cleared). Anything that had been staged is inert —"
                    + " run the update or jailbreak again from scratch";
        } finally {
            s.closeQuietly();
        }
    }

    private static boolean phaseAtLeast(String phase, String wanted) {
        return phaseOrder(phase) >= phaseOrder(wanted);
    }

    private static int phaseOrder(String phase) {
        if (phase == null) {
            return 0;
        }
        if (phase.equals(Journal.PHASE_VERIFIED)) {
            return 5;
        }
        if (phase.equals(Journal.PHASE_COMMITTED)) {
            return 4;
        }
        if (phase.equals(Journal.PHASE_RESUME_APPLIED)) {
            return 3;
        }
        if (phase.equals(Journal.PHASE_KEY4_PRE_VALIDATE)) {
            return 2;
        }
        if (phase.equals(Journal.PHASE_APPLY_SENT)
                || phase.equals(Journal.PHASE_STAGED_FOOTER_FAIL)) {
            return 1;
        }
        return 0;
    }

    private static long read32(byte[] body, int at) {
        return ((body[at] & 0xFFL) << 24) | ((body[at + 1] & 0xFFL) << 16)
                | ((body[at + 2] & 0xFFL) << 8) | (body[at + 3] & 0xFFL);
    }
}
