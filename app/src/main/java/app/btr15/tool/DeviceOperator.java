package app.btr15.tool;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Plain-Java coordinator between the UI (or a test) and {@link Workflows}.
 *
 * <p>It owns the three things a phone must never lose across a crash: the
 * transaction journals on disk, the developer key in memory, and the rule
 * that every package is rebuilt from the user's own official v3.8 file and
 * independently re-verified before it may touch the device.  Recovery
 * material is rebuilt from the journal's variant name and confirmed against
 * the journal's SHA-256 — a different package is refused, never guessed.
 *
 * <p>No Android imports on purpose: this class also compiles and runs in the
 * JVM selftests, exactly as the phone executes it.
 */
final class DeviceOperator {
    /**
     * Opens one live session.  The phone hands out a {@link LinkPool}, so all
     * sessions of one wizard step share a single RFCOMM link (the device's
     * GAIA stack serves one client and needs a settle delay after a drop);
     * the JVM selftests hand out fresh simulated sessions instead.
     */
    interface Target {
        Session open() throws FirmwareException;

        /**
         * Drop the live link so the next {@link #open()} dials a fresh one.
         * The phone's {@link LinkPool} implements it; a test target that hands
         * out brand-new simulated connections needs nothing.
         */
        default void recycle() { }
    }

    /** Progress lines for the on-screen flash log. */
    interface Listener {
        void log(String line);

        /**
         * The phase the run has reached, worded for the status line.  Coarse
         * and ordered; the log carries the detail.  Default no-op so a caller
         * that only wants the log needs nothing extra.
         */
        default void status(String status) { }
    }

    private final File journalDir;
    private final DevKey key;
    private final Target target;
    private final Listener listener;
    private final String deviceAddress;
    private final String officialUri;
    /** Transfer progress lands in the same log as everything else. */
    private final TransferMeter.Listener progress;
    /** Prefix for the status line while a two-stage run is under way. */
    private String statusPrefix = "";
    private final List<Session> sessions = new ArrayList<>();

    DeviceOperator(File journalDir, DevKey key, Target target, Listener listener) {
        this(journalDir, key, target, listener, null, null);
    }

    DeviceOperator(File journalDir, DevKey key, Target target, Listener listener,
            String deviceAddress) {
        this(journalDir, key, target, listener, deviceAddress, null);
    }

    /**
     * deviceAddress is the MAC of the device the user selected; it is stamped
     * into every journal this operator creates so Recovery retargets exactly
     * that device — the app never picks a bonded BTR15 on the user's behalf.
     * officialUri likewise records the user's official file so Recovery can
     * re-open it after an app restart.  Neither is key material.
     */
    DeviceOperator(File journalDir, DevKey key, Target target, Listener listener,
            String deviceAddress, String officialUri) {
        this.journalDir = journalDir;
        this.key = key;
        this.target = target;
        this.listener = listener;
        // The transfer's coarse percentage is a log line like any other: it is
        // exported with the log and needs no second reporting channel.
        this.progress = new TransferMeter.Listener() {
            @Override public void onProgress(int percent, long packetsSent, long totalPackets) {
                DeviceOperator.this.listener.log(percent + "% (" + packetsSent + "/"
                        + totalPackets + " packets)");
            }
        };
        // A blank MAC is "unset", never a stamp: journals must only ever
        // carry a real address, so Recovery can trust the field absolutely.
        String trimmed = deviceAddress == null ? "" : deviceAddress.trim();
        this.deviceAddress = trimmed.isEmpty() ? null : trimmed;
        String uri = officialUri == null ? "" : officialUri.trim();
        this.officialUri = uri.isEmpty() ? null : uri;
    }

    // ---- package building (never shipped bytes, always user-imported) --------

    FirmwareEngine.Result prepare(byte[] official, FirmwareEngine.Variant variant)
            throws FirmwareException {
        listener.status(statusPrefix + "SIGNING");
        key.selfCheck(); // the arithmetic must hold before anything is signed
        FirmwareEngine.Result result = FirmwareEngine.build(official, key, variant);
        listener.log("Building package locally: " + result.releaseLabel + " " + variant);
        listener.log("  upgrade id " + result.upgradeIdHex
                + ", sha-256 " + result.outputSha256);
        listener.log("  changes: "
                + (result.patchNames.isEmpty() ? "none" : join(result.patchNames))
                + " (" + result.changedBytes + " bytes changed)");
        if (!result.keptNames.isEmpty()) {
            // Not a change: this package ships these parts exactly as FiiO does.
            listener.log("  inherited from stock: " + join(result.keptNames));
        }
        return result;
    }

    // ---- jailbreak -------------------------------------------------------------

    /**
     * Stage the candidate; afterwards the user must cold power-cycle the BTR15 —
     * unless the device already trusts this key, in which case it accepts the
     * package and the call finishes the install itself.  Returns true when the
     * power-cycle checkpoint is still owed.
     */
    boolean jailbreakStage(byte[] official, FirmwareEngine.Variant variant)
            throws FirmwareException {
        FirmwareEngine.Result candidate = prepare(official, variant);
        listener.log("Staging on the device (one attempt; the footer must fail with 0x003d)…");
        Workflows.StageOutcome outcome = Workflows.jailbreakStage(journalDir, connector(),
                candidate.bytes, variant.name(), sleeper());
        if (!outcome.needsPowerCycle) {
            listener.log("The device already trusted this key: it accepted the package instead of"
                    + " failing the footer check.");
            listener.log("Finished as a developer-key update — no power cycle needed.");
            listener.log("Update complete and verified.");
            return false;
        }
        listener.log("Staged and rewritten to PRE_VALIDATE.");
        listener.log("Power the BTR15 off and on now, then confirm the reconnect.");
        return true;
    }

    /** Resume the staged jailbreak after the cold cycle: zero retransmission. */
    void jailbreakResume(byte[] official) throws FirmwareException {
        Journal journal = pendingJournal();
        if (journal == null) {
            throw new FirmwareException("no staged jailbreak transaction to resume");
        }
        byte[] candidate = rebuildFor(journal, official);
        listener.log("Resuming the staged jailbreak after the cold power cycle…");
        Workflows.jailbreakResume(journalDir, connector(), journal, candidate, sleeper());
        listener.log("Trial committed and verified; device is jailbroken.");
    }

    // ---- developer update --------------------------------------------------------

    void update(byte[] official, FirmwareEngine.Variant variant) throws FirmwareException {
        FirmwareEngine.Result result = prepare(official, variant);
        listener.log("Transferring with the developer key…");
        Workflows.developerUpdate(journalDir, connector(), result.bytes, variant.name(),
                sleeper());
        listener.log("Update complete and verified.");
    }

    // ---- two-stage stock restoration ---------------------------------------------

    void restoreStock(final byte[] official) throws FirmwareException {
        try {
            // The prefix is up before the idle preflight, so not one status line
            // of this run can be mistaken for a plain update.
            statusPrefix = "STOCK 1 OF 2 · ";
            Workflows.restoreStock(journalDir, connector(),
                    new Workflows.RestorationImages() {
                        public byte[] phase1() throws FirmwareException {
                            listener.log("Stock restoration phase 1: untouched official payloads,"
                                    + " re-signed by the developer key…");
                            return prepare(official, FirmwareEngine.Variant.STOCK_PAYLOADS).bytes;
                        }

                        public byte[] phase2() {
                            listener.log("Phase 1 verified: FiiO trust restored by the stock key"
                                    + " block.");
                            listener.log("Stock restoration phase 2: the official FiiO"
                                    + " package, as always…");
                            statusPrefix = "STOCK 2 OF 2 · ";
                            return official;
                        }
                    }, sleeper());
            listener.log("Device is fully stock again.");
        } finally {
            statusPrefix = "";
        }
    }

    // ---- recovery ------------------------------------------------------------------

    boolean hasPendingJournal() throws FirmwareException {
        return Journal.findPending(journalDir) != null;
    }

    Journal pendingJournal() throws FirmwareException {
        return Journal.findPending(journalDir);
    }

    /** One safe recovery step from the journal + live device state. */
    String recover(byte[] official) throws FirmwareException {
        final byte[] officialImage = official;
        Journal journal;
        try {
            journal = pendingJournal();
        } catch (FirmwareException unreadable) {
            // The record exists but cannot be read.  The device's own context is
            // then the only evidence left, and the documented orphan repair is
            // the honest step — the same one taken when there is no record.
            listener.log("The transaction record cannot be read (" + unreadable.getMessage() + ").");
            journal = null;
        }
        if (journal == null) {
            // No usable journal: nothing can identify a transaction, so only the
            // honest abort is left — clean the device's context if it is dirty.
            String outcome = Workflows.repairOrphanedContext(connector());
            listener.log(outcome);
            return outcome;
        }
        listener.log("Recovering transaction " + journal.id() + " (" + journal.getOrEmpty("kind")
                + ", phase " + journal.getOrEmpty("phase") + ")");
        Workflows.RecoveryMaterial material = new Workflows.RecoveryMaterial() {
            public byte[] imageFor(Journal ofJournal) throws FirmwareException {
                return rebuildFor(ofJournal, officialImage);
            }

            /**
             * Phase 2 of a restoration flashes the official package itself.
             * While the record still stands in phase 1, the phase-1 rebuild over
             * these bytes is what proves they are the same official file the
             * transaction was started from.
             */
            public byte[] official(Journal ofJournal) throws FirmwareException {
                if (!Journal.RESTORATION_PHASE2.equals(ofJournal.restorationPhase())) {
                    rebuildFor(ofJournal, officialImage);
                }
                return officialImage;
            }
        };
        String outcome = Workflows.recover(journalDir, connector(), journal, material,
                sleeper());
        return outcome;
    }

    /** Diagnosis line: the live resume word and staged id of the context. */
    String describeContext() throws FirmwareException {
        Session s = target.open();
        try {
            int[] words = s.readUpgradeContext();
            return "Device context: resume word " + words[Upgrade.RESUME_WORD]
                    + ", staged id " + Long.toHexString(Upgrade.stagedId(words));
        } finally {
            s.closeQuietly();
        }
    }

    /**
     * Rebuild the image a journal refers to from the user's own official file,
     * refusing anything that does not hash to the journal's recorded SHA-256.
     */
    byte[] rebuildFor(Journal journal, byte[] official) throws FirmwareException {
        FirmwareEngine.Variant variant = variantFor(journal);
        byte[] image = official;
        if (variant != null) {
            image = FirmwareEngine.build(official, key, variant).bytes;
        }
        // The staged file digest covers a random RSA-PSS signature and can
        // never match a rebuild; the journal's staged content digest (the
        // payload region that gets signed) is the identity a rebuild
        // reproduces bit for bit.  Journals without the content field fall
        // back to the exact-file comparison.
        String expectedContent = journal.get("staged_content_sha256");
        if (expectedContent != null && expectedContent.length() > 0) {
            String contentSha = Util.sha256Hex(AppPackage.parse(image).signedContent());
            if (!Util.sameHash(contentSha, expectedContent)) {
                throw new FirmwareException("the selected firmware file is not the package"
                        + " this transaction used (content sha " + contentSha
                        + ", journal expects " + expectedContent
                        + "); pick the same official v3.8 file");
            }
        } else if (!Util.sameHash(Util.sha256Hex(image), journal.get("package_sha256"))) {
            throw new FirmwareException("the selected firmware file is not the package this"
                    + " transaction used (sha " + Util.sha256Hex(image) + ", journal expects "
                    + journal.get("package_sha256") + "); pick the same official v3.8 file");
        }
        return image;
    }

    /** null means "the untouched official package" (stock restoration phase 2). */
    static FirmwareEngine.Variant variantFor(Journal journal) throws FirmwareException {
        String kind = journal.getOrEmpty("kind");
        if (Journal.KIND_STOCK_RESTORE.equals(kind)) {
            // One record covers both phases; which package it names is the
            // phase it stands at, not the kind.
            return Journal.RESTORATION_PHASE2.equals(journal.restorationPhase())
                    ? null : FirmwareEngine.Variant.STOCK_PAYLOADS;
        }
        if (Journal.KIND_STOCK_PHASE1.equals(kind)) {
            return FirmwareEngine.Variant.STOCK_PAYLOADS;
        }
        if (Journal.KIND_STOCK_PHASE2.equals(kind)) {
            return null;
        }
        if (Journal.KIND_JAILBREAK.equals(kind) || Journal.KIND_DEVELOPER_UPDATE.equals(kind)) {
            // The variant name is the record of what was staged.  Journals from
            // before automute became selectable store a free-form jailbreak
            // label, so an unparseable value falls back to that era's meaning
            // (developer key with automute) instead of refusing a continuation
            // that is otherwise provable by its content digest.
            String variant = journal.get("variant");
            if (variant != null && !variant.isEmpty()) {
                try {
                    return FirmwareEngine.Variant.valueOf(variant);
                } catch (IllegalArgumentException unknown) {
                    if (Journal.KIND_DEVELOPER_UPDATE.equals(kind)) {
                        throw new FirmwareException("journal variant " + variant
                                + " is not a package this app version can rebuild");
                    }
                    return FirmwareEngine.Variant.DEVELOPER_KEY;
                }
            }
            if (Journal.KIND_JAILBREAK.equals(kind)) {
                return FirmwareEngine.Variant.DEVELOPER_KEY;
            }
            throw new FirmwareException("journal records no variant to rebuild");
        }
        throw new FirmwareException("unknown journal kind " + kind);
    }

    // ---- plumbing -----------------------------------------------------------------

    /**
     * Flash-wizard probe: the FiiO GAIA getter over the shared link.  Returns
     * the version the device reports, so the screen can say which release is
     * running instead of assuming one.  Closing the session keeps the pooled
     * link warm for the workflow that follows, so the device never sees a
     * disconnect/reconnect pair.
     */
    String probeConnection() throws FirmwareException {
        Session session = target.open();
        try {
            return session.expectFirmwareVersion();
        } finally {
            session.closeQuietly();
        }
    }

    Workflows.Connector connector() {
        return new Workflows.Connector() {
            public Session open() throws FirmwareException {
                Session session = target.open();
                sessions.add(session);
                return session;
            }

            public String deviceAddress() {
                return deviceAddress;
            }

            public String officialUri() {
                return officialUri;
            }

            public void recycle() {
                target.recycle();
            }

            public TransferMeter.Listener progress() {
                return progress;
            }

            public void status(String status) {
                listener.status(statusPrefix + status);
            }
        };
    }

    /**
     * The official file the pending journal was started from, or null when the
     * journal predates source stamping (or was created by tests).
     */
    String pendingOfficialUri() throws FirmwareException {
        Journal pending = Journal.findPending(journalDir);
        return pending == null ? null : pending.get("official_uri");
    }

    /**
     * The device MAC recorded by the pending journal, or null when the
     * journal predates device stamping (or was created by tests).  Recovery
     * retargets this MAC and never picks a bonded device on its own.
     */
    String pendingDeviceAddress() throws FirmwareException {
        Journal pending = Journal.findPending(journalDir);
        return pending == null ? null : pending.get("device_address");
    }

    /** Exported transcripts: hex frames only — never key material. */
    String transcriptExport() {
        StringBuilder out = new StringBuilder();
        for (Session session : sessions) {
            for (String line : session.transcript()) {
                out.append(line).append('\n');
            }
        }
        return out.toString();
    }

    private static Workflows.Sleeper sleeper() {
        return new Workflows.Sleeper() {
            public void sleep(long milliseconds) throws FirmwareException {
                try {
                    Thread.sleep(milliseconds);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new FirmwareException("transaction interrupted by the user");
                }
            }
        };
    }

    private static String join(List<String> values) {
        StringBuilder out = new StringBuilder();
        for (String value : values) {
            if (out.length() > 0) {
                out.append(", ");
            }
            out.append(value);
        }
        return out.toString();
    }
}
