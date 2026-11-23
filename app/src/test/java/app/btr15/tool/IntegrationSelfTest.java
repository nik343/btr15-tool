package app.btr15.tool;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Proves the exact code path MainActivity executes — DeviceOperator's public
 * entry points — against the simulated BTR15 over the loopback transport:
 * the full jailbreak lifecycle (stage → cold cycle → zero-byte resume), a
 * developer update, the two-stage stock restore, a rejected update cleaned up
 * by recovery (discard staging, never jailbreak-by-accident), a crash at the
 * footer boundary recovered through the operator's own material rebuild,
 * refusal of a mismatched official file, and the log's transfer counter for both install methods.
 *
 * Usage: java app.btr15.tool.IntegrationSelfTest <official v3.8 path>
 */
public final class IntegrationSelfTest {
    private static final String V1_MNEMONIC = "abandon abandon abandon abandon abandon"
            + " abandon abandon abandon abandon abandon abandon about";

    private static int checks;

    public static void main(String[] args) throws Exception {
        require(args.length >= 3, "expected the official v3.8, v3.5 and v4.4 firmware paths");
        official = Files.readAllBytes(new File(args[0]).toPath());
        require(Util.sameHash(FirmwareProfile.SHA256, Util.sha256Hex(official)),
                "argument is not the official v3.8 package");
        key = DevKey.derive(V1_MNEMONIC);

        fullLifecycle();
        recoverAfterFooterCrash();
        refuseWrongFile();
        linkPoolContract();
        journalDeviceHygiene();
        noJournalOnBusyDevice();
        silentHandshakeReachesThePool();
        bothMethodsReportTransferProgress();
        shortRequestsCannotOvershootTheCounter();
        meterThrottlesTheLog();
        packetTotalFollowsTheRealTransfer();
        statusLineFollowsThePhases();
        acceptedJailbreakFinishesAsAnUpdate();
        otherReleasesUseTheSamePipeline(
                Files.readAllBytes(new File(args[1]).toPath()),
                Files.readAllBytes(new File(args[2]).toPath()));

        System.out.println("IntegrationSelfTest: PASS (" + checks + " checks)");
    }

    private static byte[] official;
    private static DevKey key;

    // ---- shared-link contract (LinkPool) ----------------------------------------
    // The BTR15 serves one GAIA client and answers with silence when re-dialled
    // too quickly (field audit HCI).  The phone therefore pools one link per
    // wizard step; these checks pin that behaviour mechanically.

    private static final class FakeLink implements Transport {
        boolean dead;
        boolean answersGaia = true; // the wrong SPP record never answers GAIA

        public void send(byte[] packet) { }

        public byte[] receive(long timeoutMs) {
            return null;
        }

        public void close() {
            dead = true;
        }

        public boolean isDead() {
            return dead;
        }
    }

    private static void gaiaVerify(Transport transport) throws IOException {
        if (!((FakeLink) transport).answersGaia) {
            throw new IOException("this SPP record did not answer GAIA");
        }
    }

    private static long elapsedMs(long sinceNanos) {
        return (System.nanoTime() - sinceNanos) / 1_000_000L;
    }

    private static void linkPoolContract() throws Exception {
        final FakeLink[] current = new FakeLink[1];
        final int[] connects = new int[1];
        LinkPool pool = new LinkPool(new LinkPool.Lift() {
            public Transport connect() {
                connects[0]++;
                current[0] = new FakeLink();
                return current[0];
            }

            public void verify(Transport transport) throws IOException {
                gaiaVerify(transport);
            }
        });
        // A pool is always created straight after the previous step released
        // its link, so even the very first dial owes the device the settle.
        long firstDial = System.nanoTime();
        Session first = pool.open();
        require(elapsedMs(firstDial) >= LinkPool.SETTLE_MS - 200,
                "the first dial of a step must settle too — it follows a release");
        Session second = pool.open();
        require(first != null && second != null, "pool must hand out sessions");
        require(connects[0] == 1, "sessions must share one link, not re-dial");
        first.closeQuietly();
        require(!current[0].dead, "closing a session must not drop the shared link");
        require(pool.open() != null && connects[0] == 1,
                "a session opened after another closed must reuse the link");

        current[0].dead = true; // the device reboots mid-step
        long began = System.nanoTime();
        pool.open();
        require(connects[0] == 2, "a dead link must be replaced by exactly one redial");
        require(elapsedMs(began) >= LinkPool.SETTLE_MS - 200,
                "redial must wait for the device to release the old link");

        FakeLink secondLink = current[0];
        pool.release();
        require(secondLink.dead, "release must politely close the physical link");
        began = System.nanoTime();
        pool.open();
        require(connects[0] == 3, "the step after a release must dial a fresh link");
        require(elapsedMs(began) >= LinkPool.SETTLE_MS - 200,
                "even after a polite release the device needs its settle delay");

        // The BTR15 advertises several SPP records under the same UUID and
        // SDP rotates between them (phone HCI: scn=2 silent, scn=1 live).
        // A link dialed onto a record that never answers GAIA must be
        // dropped and re-dialled — a step must never run on a dead record.
        final List<FakeLink> dialed = new ArrayList<>();
        LinkPool rotating = new LinkPool(new LinkPool.Lift() {
            public Transport connect() {
                FakeLink link = new FakeLink();
                link.answersGaia = !dialed.isEmpty(); // first record is dead
                dialed.add(link);
                return link;
            }

            public void verify(Transport transport) throws IOException {
                gaiaVerify(transport);
            }
        });
        require(rotating.open() != null,
                "the pool must re-dial until a link actually answers GAIA");
        require(dialed.size() == 2, "a silent SPP record must be discarded and dialled again once");
        require(dialed.get(0).dead, "the discarded record's socket must be closed");
        require(!dialed.get(1).dead, "the answering record must stay open for the step");

        // The settle must happen AFTER every other client is closed.  The field
        // run that failed closed the probe 209 ms before the new link came up:
        // the firmware then answered the cheap getters and dropped every
        // Upgrade message on the new link.
        final long[] releasedAt = new long[1];
        final long[] connectedAt = new long[1];
        final int[] releases = new int[1];
        LinkPool ordered = new LinkPool(new LinkPool.Lift() {
            public void releaseOthers() {
                releases[0]++;
                releasedAt[0] = System.nanoTime();
            }

            public Transport connect() {
                connectedAt[0] = System.nanoTime();
                return new FakeLink();
            }

            public void verify(Transport transport) throws IOException {
                gaiaVerify(transport);
            }
        });
        require(ordered.open() != null, "the pool must hand out a session");
        require(releases[0] == 1,
                "every dial must first let go of the other GAIA clients, saw " + releases[0]);
        require(elapsedMs(releasedAt[0]) >= LinkPool.SETTLE_MS - 200,
                "the settle must run after the release, not before it");

        // recycle(): a handshake the device ignored re-binds on a brand-new link.
        final FakeLink[] currentTwo = new FakeLink[1];
        final int[] connectsTwo = new int[1];
        LinkPool recyclable = new LinkPool(new LinkPool.Lift() {
            public Transport connect() {
                connectsTwo[0]++;
                currentTwo[0] = new FakeLink();
                return currentTwo[0];
            }

            public void verify(Transport transport) throws IOException {
                gaiaVerify(transport);
            }
        });
        recyclable.open();
        recyclable.recycle();
        require(currentTwo[0].dead, "recycle must close the link the device stopped answering");
        recyclable.open();
        require(connectsTwo[0] == 2, "the session after a recycle must be dialled fresh");
    }

    /**
     * A blank MAC is "unset": journals may only ever carry a real device, and
     * the transaction's own source (device + official file) must survive an
     * app restart inside the journal — the wizard's memory does not.
     */
    private static void journalDeviceHygiene() throws Exception {
        SimBtr15Peer peer = new SimBtr15Peer(official, FirmwareProfile.fiioModulus());
        File blankDir = tempDir();
        DeviceOperator blank = new DeviceOperator(blankDir, key, connectorFor(peer),
                new RecordingListener(), "   ");
        blank.jailbreakStage(official, FirmwareEngine.Variant.DEVELOPER_KEY);
        require(Journal.findPending(blankDir).get("device_address") == null,
                "a blank MAC must never be stamped into a journal");
        require(blank.pendingDeviceAddress() == null,
                "a blank stamp reads back as unset, never as an empty device");

        File dir = tempDir();
        SimBtr15Peer secondPeer = new SimBtr15Peer(official, FirmwareProfile.fiioModulus());
        DeviceOperator op = new DeviceOperator(dir, key, connectorFor(secondPeer),
                new RecordingListener(), " 40:ED:98:1C:1C:ED ", "content://docs/v38.bin");
        op.jailbreakStage(official, FirmwareEngine.Variant.DEVELOPER_KEY);
        require("40:ED:98:1C:1C:ED".equals(op.pendingDeviceAddress()),
                "a padded MAC is trimmed before it is stamped");
        require("content://docs/v38.bin".equals(op.pendingOfficialUri()),
                "the official file is journaled, so Recovery re-opens it after a restart");
    }

    /**
     * No junk journals and no dead ends: a run against a busy device leaves no
     * transaction behind, and a dirty device without a journal can still be
     * brought back to idle.
     */
    private static void noJournalOnBusyDevice() throws Exception {
        SimBtr15Peer busyPeer = new SimBtr15Peer(official, FirmwareProfile.fiioModulus());
        File busyDir = tempDir();
        int[] dirty = new int[Upgrade.CONTEXT_WORDS];
        dirty[0] = 0x0001; // transport spp, no config-reset flag
        dirty[Upgrade.RESUME_WORD] = Upgrade.RESUME_ERROR;
        dirty[Upgrade.STAGED_ID_LOW_WORD] = 0x1234;
        busyPeer.forceContext(dirty);
        RecordingListener repairLog = new RecordingListener();
        DeviceOperator busy = new DeviceOperator(busyDir, key, connectorFor(busyPeer),
                repairLog, "40:ED:98:1C:1C:ED");
        try {
            busy.jailbreakStage(official, FirmwareEngine.Variant.DEVELOPER_KEY);
            require(false, "staging on a busy device must refuse");
        } catch (FirmwareException expected) {
            require(expected.getMessage().indexOf("not idle") >= 0,
                    "the refusal names the device state, not a stray journal");
        }
        require(!busy.hasPendingJournal(),
                "a refused preflight must not leave a journal to chase");

        String repaired = busy.recover(official);
        require(Upgrade.isCleanContext(busyPeer.key4()),
                "recovery with no journal must clear an orphaned context");
        require(repaired.indexOf("clean") >= 0, "the repair explains itself");
        require(repairLog.statuses.contains("REPAIRING CONTEXT"),
                "the status line says the context is being repaired: " + repairLog.statuses);
        require(!busy.hasPendingJournal(), "the repair leaves no journal");
        // Device is idle again, so a normal staging run now works.
        busy.jailbreakStage(official, FirmwareEngine.Variant.DEVELOPER_KEY);
        require(busy.hasPendingJournal(), "staging proceeds once the device is idle");
    }

    // ---- the MainActivity happy path, end to end -------------------------------

    private static void fullLifecycle() throws Exception {
        SimBtr15Peer peer = new SimBtr15Peer(official, FirmwareProfile.fiioModulus());
        int[] key1Before = peer.key1();
        RecordingListener log = new RecordingListener();
        DeviceOperator op = new DeviceOperator(tempDir(), key, connectorFor(peer), log,
                "40:ED:98:1C:1C:ED");

        require(!op.hasPendingJournal(), "fresh journal dir must be clean");

        // Jailbreak: stage; the UI's power-cycle step happens outside the app.
        op.jailbreakStage(official, FirmwareEngine.Variant.DEVELOPER_KEY);
        require(op.hasPendingJournal(), "staging must leave a journal");
        require("40:ED:98:1C:1C:ED".equals(op.pendingDeviceAddress()),
                "the journal must record the transaction device — Recovery never guesses");
        require(peer.key4()[Upgrade.RESUME_WORD] == Upgrade.RESUME_PRE_VALIDATE,
                "staging must leave PRE_VALIDATE");
        int stagedPackets = peer.totalDataPackets();
        peer.coldPowerCycle();

        op.jailbreakResume(official);
        require(!op.hasPendingJournal(), "resume must delete the journal");
        require(peer.totalDataPackets() == stagedPackets,
                "resume must retransmit zero firmware bytes");
        require(op.transcriptExport().length() > 0, "transcript export must be populated");
        byte[] candidate = FirmwareEngine.build(official, key,
                FirmwareEngine.Variant.DEVELOPER_KEY).bytes;
        require(peer.firmwareContentSha256().equals(Workflows.contentSha256(candidate)),
                "device must run the staged candidate after jailbreak");
        require(peer.trust().equals(key.modulus), "jailbreak must move trust to the dev key");
        require(java.util.Arrays.equals(peer.key1(), key1Before),
                "PS key 1 identity (MAC) must survive the jailbreak");

        // Developer update on the now-jailbroken device.
        op.update(official, FirmwareEngine.Variant.DEVELOPER_KEY_100HZ2);
        byte[] v8 = FirmwareEngine.build(official, key,
                FirmwareEngine.Variant.DEVELOPER_KEY_100HZ2).bytes;
        require(peer.firmwareContentSha256().equals(Workflows.contentSha256(v8)),
                "device must run the 100 Hz2 update");
        require(!op.hasPendingJournal(), "update must delete its journal");
        require(java.util.Arrays.equals(peer.key1(), key1Before),
                "PS key 1 identity (MAC) must survive the update");

        // Automute is opt-in end to end: the no-automute variant transports,
        // commits and leaves the device on exactly the bytes a later rebuild of
        // the same variant produces (so Recovery would match too).
        op.update(official, FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE);
        byte[] plain = FirmwareEngine.build(official, key,
                FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE).bytes;
        require(peer.firmwareContentSha256().equals(Workflows.contentSha256(plain)),
                "device must run the no-automute package");
        require(!op.hasPendingJournal(), "no-automute update must delete its journal");

        // Two-stage stock restore through the operator.  Every status line of
        // the two phases says which phase it belongs to, so a long restore can
        // never be mistaken for one endless run.
        int beforeStock = log.statuses.size();
        op.restoreStock(official);
        int afterStock = log.statuses.size();
        boolean announcedOne = false;
        boolean announcedTwo = false;
        for (String status : log.statuses.subList(beforeStock, afterStock)) {
            require(status.startsWith("STOCK "), "stock statuses carry their phase: " + status);
            announcedOne |= status.startsWith("STOCK 1 OF 2 · ");
            announcedTwo |= status.startsWith("STOCK 2 OF 2 · ");
        }
        require(announcedOne && announcedTwo, "both stock phases are announced");
        require(peer.firmwareSha256().equals(FirmwareProfile.SHA256),
                "stock restore must leave the official package running");
        require(peer.trust().equals(FirmwareProfile.fiioModulus()),
                "stock restore must return trust to FiiO");
        require(!op.hasPendingJournal(), "stock restore must leave no journal");

        // A developer update on the now-stock device must fail and self-clean:
        // recovery discards the staging and must NOT rewrite it to PRE_VALIDATE.
        final DeviceOperator lateOp = op;
        expectFails(new ThrowingRunnable() {
            public void run() throws Exception {
                lateOp.update(official, FirmwareEngine.Variant.DEVELOPER_KEY);
            }
        }, "developer package must footer-fail on a stock-trust device");
        require(op.hasPendingJournal(), "the failed update must leave a journal");
        require(peer.key4()[Upgrade.RESUME_WORD] == Upgrade.RESUME_ERROR,
                "footer failure must leave ERROR(6) context");
        String outcome = op.recover(official);
        require(outcome.toLowerCase(Locale.US).contains("discarded"),
                "recovery must discard the rejected staging: " + outcome);
        require(log.statuses.contains("DISCARDING PACKAGE"),
                "the status line says the staging is being discarded: " + log.statuses);
        require(!op.hasPendingJournal(), "discard must clear the journal");
        require(Upgrade.isCleanContext(peer.key4()), "discard must return the device to idle");
        require(peer.trust().equals(FirmwareProfile.fiioModulus())
                        && peer.firmwareSha256().equals(FirmwareProfile.SHA256),
                "discard must leave the stock device untouched (no jailbreak-by-accident)");
        require(log.lines.size() > 0, "operator must have emitted progress lines");
    }

    // ---- crash in staging, then recover through the operator ---------------------

    private static void recoverAfterFooterCrash() throws Exception {
        SimBtr15Peer peer = new SimBtr15Peer(official, FirmwareProfile.fiioModulus());
        peer.crashAt(SimBtr15Peer.CRASH_FOOTER);
        RecordingListener log = new RecordingListener();
        final DeviceOperator op = new DeviceOperator(tempDir(), key, connectorFor(peer), log);

        expectFails(new ThrowingRunnable() {
            public void run() throws Exception {
                op.jailbreakStage(official, FirmwareEngine.Variant.DEVELOPER_KEY);
            }
        }, "footer-boundary power loss must surface as a link failure");
        require(op.hasPendingJournal(), "crash must leave the journal");

        // Power comes back; recovery walks the same tree the UI's button does.
        String outcome = op.recover(official);
        require(outcome.toLowerCase(Locale.US).contains("power"),
                "recovery must ask for the cold cycle: " + outcome);
        require(peer.key4()[Upgrade.RESUME_WORD] == Upgrade.RESUME_PRE_VALIDATE,
                "recovery must rewrite ERROR to PRE_VALIDATE for the jailbreak journal");
        int guard = 0;
        while (op.hasPendingJournal() && guard++ < 4) {
            peer.coldPowerCycle();
            op.recover(official);
        }
        require(!op.hasPendingJournal(), "recovery must converge to a clean state");
        requireCapitalizedLines(log.lines, "Recovery");
        byte[] candidate = FirmwareEngine.build(official, key,
                FirmwareEngine.Variant.DEVELOPER_KEY).bytes;
        require(peer.firmwareContentSha256().equals(Workflows.contentSha256(candidate)),
                "recovered jailbreak must end on the candidate firmware");
    }

    // ---- material safety: the wrong official file must be refused ----------------

    private static void refuseWrongFile() throws Exception {
        SimBtr15Peer peer = new SimBtr15Peer(official, FirmwareProfile.fiioModulus());
        final DeviceOperator op = new DeviceOperator(tempDir(), key, connectorFor(peer),
                new RecordingListener());
        op.jailbreakStage(official, FirmwareEngine.Variant.DEVELOPER_KEY);
        peer.coldPowerCycle();
        final byte[] tampered = official.clone();
        tampered[1_000_000] ^= 0x01; // a different file posing as official
        expectFails(new ThrowingRunnable() {
            public void run() throws Exception {
                op.jailbreakResume(tampered);
            }
        }, "a mismatched official file must be refused against the journal hash");
        require(op.hasPendingJournal(), "refusal must leave the journal intact");
        op.jailbreakResume(official);
        require(!op.hasPendingJournal(), "the right file must still complete the job");
    }

    // ---- helpers -------------------------------------------------------------------

    private static DeviceOperator.Target connectorFor(final SimBtr15Peer peer) {
        return new DeviceOperator.Target() {
            public Session open() {
                return new Session(peer.openConnection(), 500L);
            }
        };
    }

    /**
     * The whole phone path for the field failure: DeviceOperator → Workflows →
     * Connector.recycle → Target.recycle.  A device that acknowledges the SYNC
     * frame and never answers it must make the operator drop the link and
     * re-bind, and the update must still land.
     */
    private static void silentHandshakeReachesThePool() throws Exception {
        final SimBtr15Peer peer = new SimBtr15Peer(official, key.modulus);
        peer.silenceSyncs(1);
        final int[] recycles = new int[1];
        DeviceOperator.Target target = new DeviceOperator.Target() {
            public Session open() {
                return new Session(peer.openConnection(), 500L);
            }

            public void recycle() {
                recycles[0]++;
            }
        };
        File dir = tempDir();
        RecordingListener log = new RecordingListener();
        DeviceOperator op = new DeviceOperator(dir, key, target, log,
                "40:ED:98:1C:1C:ED", "content://docs/v38.bin");
        op.update(official, FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE);
        require(recycles[0] >= 1,
                "a silently dropped handshake must recycle the link through the operator, saw "
                        + recycles[0]);
        require(peer.syncRequests() >= 2, "the handshake must be sent again");
        require(!op.hasPendingJournal(), "the retried update must retire its journal");
        require(peer.trust().equals(key.modulus),
                "the device still trusts the developer key after the retry");
    }

    // ---- the log's transfer percentage -------------------------------------------

    /**
     * Both install methods hand the same device-driven pump the same meter, so
     * both must log the package percentage as a counter line.  The simulated
     * transfer finishes inside one 500 ms interval, which is exactly the case
     * the interval rule exists for: the start and the terminal 100% survive,
     * the middle is throttled away.
     */
    private static void bothMethodsReportTransferProgress() throws Exception {
        RecordingListener devLog = new RecordingListener();
        SimBtr15Peer devPeer = new SimBtr15Peer(official, key.modulus);
        DeviceOperator devOp = new DeviceOperator(tempDir(), key, connectorFor(devPeer), devLog,
                "40:ED:98:1C:1C:ED");
        devOp.update(official, FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE);
        List<ProgressLine> devProgress = progressLines(devLog);
        require(devProgress.size() >= 2, "a developer update must log progress: " + devProgress);
        require(devProgress.get(0).percent == 0, "the log starts at 0%: " + devProgress);
        require(lastPercent(devProgress) == 100,
                "the log ends on the whole package: " + devProgress);
        require(monotonic(devProgress), "the percentage never goes backwards: " + devProgress);
        ProgressLine devLast = devProgress.get(devProgress.size() - 1);
        require(devLast.sent == devLast.total && devLast.total == packetCount(official.length),
                "the counter runs 1..packet-count and ends on the whole package: " + devLast);

        RecordingListener jailbreakLog = new RecordingListener();
        SimBtr15Peer stockPeer = new SimBtr15Peer(official, FirmwareProfile.fiioModulus());
        DeviceOperator jailbreakOp = new DeviceOperator(tempDir(), key, connectorFor(stockPeer),
                jailbreakLog, "40:ED:98:1C:1C:ED");
        jailbreakOp.jailbreakStage(official, FirmwareEngine.Variant.DEVELOPER_KEY);
        List<ProgressLine> jailbreakProgress = progressLines(jailbreakLog);
        require(lastPercent(jailbreakProgress) == 100,
                "jailbreak staging must log the full package too: " + jailbreakProgress);
        require(monotonic(jailbreakProgress),
                "jailbreak staging never logs backwards: " + jailbreakProgress);

        // The lines are log lines like any other: nothing may be smuggled into
        // them that the log does not already carry, and they must be exported.
        require(jailbreakLog.lines.contains(jailbreakProgress.get(0).line),
                "the progress line is a normal log line");

        // One house style for the screen: every line opens a sentence.
        requireCapitalizedLines(devLog.lines, "a developer update");
        requireCapitalizedLines(jailbreakLog.lines, "jailbreak staging");
    }

    /**
     * A device that asks for less than a full message per request — the field
     * device's own pacing — costs one DATA message per request instead of one
     * per 240 bytes.  The counter must stay truthful through that: the
     * numerator is exactly the messages that went on the wire (the peer counts
     * them too), and the denominator ends on it instead of on the ideal grid
     * the old code printed, which is what produced {@code 8086/8061}.
     */
    private static void shortRequestsCannotOvershootTheCounter() throws Exception {
        SimBtr15Peer peer = new SimBtr15Peer(official, key.modulus);
        peer.requestBytes(100); // the device's window is not a multiple of the chunk
        RecordingListener log = new RecordingListener();
        DeviceOperator op = new DeviceOperator(tempDir(), key, connectorFor(peer), log,
                "40:ED:98:1C:1C:ED");
        op.update(official, FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE);

        List<ProgressLine> lines = progressLines(log);
        require(!lines.isEmpty(), "short requests still report progress");
        ProgressLine last = lines.get(lines.size() - 1);
        require(last.percent == 100, "the log ends on the whole package: " + last);
        require(last.sent == last.total,
                "the finished counter is the messages it took: " + last);
        require(last.sent == peer.totalDataPackets(),
                "the numerator is the DATA messages the device received, not an estimate: "
                        + last.sent + " logged, " + peer.totalDataPackets() + " on the wire");
        require(last.sent > packetCount(official.length),
                "short windows cost more messages than the ideal grid: " + last.sent
                        + " vs " + packetCount(official.length));
        for (ProgressLine line : lines) {
            require(line.sent <= line.total,
                    "no progress line may claim more messages than its own total: " + line);
        }
        require(monotonic(lines), "short requests never log a backwards percentage: " + lines);

        // Both numbers are real, so nothing in the display or the export may
        // strip the total: the line reads the same on screen as in the log.
        require(FlashLogText.displayLine(last.line).equals(last.line),
                "the on-screen log shows the counter exactly as it is built: " + last.line);
        require(FlashLogText.forExport(last.line).equals(last.line),
                "the exported log keeps both numbers: " + last.line);
    }

    /**
     * The meter's policy on an injected clock: one line per ten-percent band,
     * never two inside the interval, and 100% always delivered.
     */
    private static void meterThrottlesTheLog() throws Exception {
        RecordingProgress sink = new RecordingProgress();
        final long[] now = {0L};
        TransferMeter meter = new TransferMeter(sink, 2_000_000L, 100_000L,
                TransferMeter.MIN_INTERVAL_MS, new TransferMeter.Clock() {
                    public long millis() {
                        return now[0];
                    }
                });
        for (int step = 0; step <= 20; step++) { // 5% every second, like a real link
            meter.report(100_000L * step, step);
            now[0] += 1_000L;
        }
        require(sink.percentages.size() == 11,
                "one report per ten-percent band: " + sink.percentages);
        require(sink.first() == 0 && sink.last() == 100,
                "the band stream covers start to finish: " + sink.percentages);
        require(sink.lastPacketsSent() == 20 && sink.totalPackets() == 20,
                "the counter reaches the packet total");

        // A burst inside one interval says nothing; the band is reported on the
        // next call that is far enough away.
        final RecordingProgress burst = new RecordingProgress();
        final long[] burstNow = {0L};
        TransferMeter burstMeter = new TransferMeter(burst, 1_000L, 10L,
                TransferMeter.MIN_INTERVAL_MS, new TransferMeter.Clock() {
                    public long millis() {
                        return burstNow[0];
                    }
                });
        burstMeter.report(0L, 0L);
        burstNow[0] += 100L;
        burstMeter.report(500L, 5L);
        require(burst.percentages.size() == 1, "a report inside 500 ms is dropped: "
                + burst.percentages);
        burstNow[0] += 600L;
        burstMeter.report(510L, 6L);
        require(burst.percentages.size() == 2 && burst.last() == 51,
                "the next call after the interval reports the current value: "
                        + burst.percentages);

        // Reaching the end of the package is never throttled away.
        final RecordingProgress finished = new RecordingProgress();
        final long[] finishNow = {0L};
        TransferMeter finishMeter = new TransferMeter(finished, 1_000L, 10L,
                TransferMeter.MIN_INTERVAL_MS, new TransferMeter.Clock() {
                    public long millis() {
                        return finishNow[0];
                    }
                });
        finishMeter.report(999L, 9L);
        finishMeter.report(1_000L, 10L);
        require(finished.last() == 100, "100% always gets through: " + finished.percentages);

        // An empty package cannot be "nearly done".
        require(TransferMeter.percentOf(0L, 0L) == 100,
                "an empty package is complete, not 0%");
        require(TransferMeter.percentOf(1L, 2L) == 50, "half of a package reads as 50%");
        require(TransferMeter.percentOf(1L, 3L) == 33, "a third never rounds up to 100%");
    }

    /**
     * The denominator is the transfer's real packet count, not the ideal grid.
     * It starts on the grid, grows by one for every short message the device's
     * own request boundary forces, and is exactly the messages sent once the
     * package is complete — which is the fact a finished transfer needs, since
     * the device is what decides how the image is sliced.
     */
    private static void packetTotalFollowsTheRealTransfer() throws Exception {
        long bytes = 1_932_460L;
        long grid = packetCount((int) bytes);
        require(TransferMeter.totalPacketsFor(0L, 0L, bytes, Upgrade.DEFAULT_CHUNK) == grid,
                "an untouched image is estimated on the full-message grid: " + grid);
        require(TransferMeter.totalPacketsFor(bytes, 7L, bytes, Upgrade.DEFAULT_CHUNK) == 7L,
                "a complete package is exactly the messages it took");
        require(TransferMeter.totalPacketsFor(bytes / 2L, grid / 2L + 5L, bytes,
                Upgrade.DEFAULT_CHUNK) == grid / 2L + 5L
                        + packetCount((int) (bytes - bytes / 2L)),
                "the short messages already sent are carried into the total");

        // The field case: the device held the whole package after 8086 DATA
        // messages, and the ideal grid said 8061.  The line must read 8086/8086.
        require(TransferMeter.totalPacketsFor(bytes, 8086L, bytes, Upgrade.DEFAULT_CHUNK) == 8086L,
                "a finished transfer never reports the device as over its own total");
        long[] probes = {0L, 1L, 7L, grid / 2L, grid - 1L, grid, 8086L};
        for (long sent : probes) {
            long percentBytes = Math.min(bytes, sent * Upgrade.DEFAULT_CHUNK);
            long total = TransferMeter.totalPacketsFor(percentBytes, sent, bytes,
                    Upgrade.DEFAULT_CHUNK);
            require(total >= sent, "the total never falls below the messages sent: "
                    + sent + "/" + total);
            require(total >= grid, "the total never drops below the ideal grid: " + sent
                    + "/" + total);
        }
    }

    /** Lines like {@code 40% (3221/8053 packets)}. */
    private static final class ProgressLine {
        final int percent;
        final long sent;
        final long total;
        final String line;

        ProgressLine(int percent, long sent, long total, String line) {
            this.percent = percent;
            this.sent = sent;
            this.total = total;
            this.line = line;
        }

        @Override public String toString() {
            return line;
        }
    }

    private static final java.util.regex.Pattern PROGRESS_LINE =
            java.util.regex.Pattern.compile("^(\\d{1,3})% \\((\\d+)/(\\d+) packets\\)$");

    private static List<ProgressLine> progressLines(RecordingListener log) {
        List<ProgressLine> found = new ArrayList<ProgressLine>();
        for (String line : log.lines) {
            java.util.regex.Matcher match = PROGRESS_LINE.matcher(line);
            if (match.matches()) {
                found.add(new ProgressLine(Integer.parseInt(match.group(1)),
                        Long.parseLong(match.group(2)), Long.parseLong(match.group(3)), line));
            }
        }
        return found;
    }

    private static int lastPercent(List<ProgressLine> lines) {
        require(!lines.isEmpty(), "expected at least one progress line");
        return lines.get(lines.size() - 1).percent;
    }

    private static boolean monotonic(List<ProgressLine> lines) {
        int previous = -1;
        for (ProgressLine line : lines) {
            if (line.percent <= previous) {
                return false;
            }
            previous = line.percent;
        }
        return true;
    }

    private static long packetCount(int imageBytes) {
        return (imageBytes + (long) Upgrade.DEFAULT_CHUNK - 1L) / Upgrade.DEFAULT_CHUNK;
    }

    // ---- the status line ---------------------------------------------------------

    /**
     * The status line walks the phases the run actually crosses, in order, one
     * word each: the log carries the detail, the status carries the place.
     */
    private static void statusLineFollowsThePhases() throws Exception {
        RecordingListener devLog = new RecordingListener();
        SimBtr15Peer devPeer = new SimBtr15Peer(official, key.modulus);
        DeviceOperator devOp = new DeviceOperator(tempDir(), key, connectorFor(devPeer), devLog,
                "40:ED:98:1C:1C:ED");
        devOp.update(official, FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE);
        requireSubsequence(devLog.statuses, "SIGNING", "CHECKING DEVICE", "HANDSHAKING",
                "WAITING FOR DEVICE", "STAGING", "VALIDATING", "WAITING FOR REBOOT",
                "COMMITTING", "VERIFYING");
        require(devLog.statuses.contains("CHECKING FOOTER") == false,
                "a developer update never claims to check a jailbreak footer");

        RecordingListener jailbreakLog = new RecordingListener();
        SimBtr15Peer stockPeer = new SimBtr15Peer(official, FirmwareProfile.fiioModulus());
        DeviceOperator jailbreakOp = new DeviceOperator(tempDir(), key, connectorFor(stockPeer),
                jailbreakLog, "40:ED:98:1C:1C:ED");
        jailbreakOp.jailbreakStage(official, FirmwareEngine.Variant.DEVELOPER_KEY);
        requireSubsequence(jailbreakLog.statuses, "SIGNING", "CHECKING DEVICE", "HANDSHAKING",
                "WAITING FOR DEVICE", "STAGING", "VALIDATING", "CHECKING FOOTER",
                "REWRITING CONTEXT");

        RecordingListener resumeLog = new RecordingListener();
        SimBtr15Peer resumePeer = new SimBtr15Peer(official, FirmwareProfile.fiioModulus());
        DeviceOperator resumeOp = new DeviceOperator(tempDir(), key, connectorFor(resumePeer),
                resumeLog, "40:ED:98:1C:1C:ED");
        resumeOp.jailbreakStage(official, FirmwareEngine.Variant.DEVELOPER_KEY);
        resumePeer.coldPowerCycle();
        resumeOp.jailbreakResume(official);
        requireSubsequence(resumeLog.statuses, "RESUMING", "HANDSHAKING", "VALIDATING",
                "WAITING FOR REBOOT", "COMMITTING", "VERIFYING");
    }

    private static void requireSubsequence(List<String> actual, String... wanted) {
        int at = 0;
        for (String status : actual) {
            if (at < wanted.length && status.equals(wanted[at])) {
                at++;
            }
        }
        require(at == wanted.length, "status phases missing or out of order: " + actual
                + " (stopped after " + (at == 0 ? "nothing" : wanted[at - 1]) + ")");
    }

    // ---- jailbreak selected on a device that already trusts the key -------------

    /**
     * The phone path for "jailbreak chosen, but the device already trusts this
     * key": the run must switch to the developer update by itself, commit and
     * verify, and owe no power-cycle checkpoint.
     */
    private static void acceptedJailbreakFinishesAsAnUpdate() throws Exception {
        SimBtr15Peer peer = new SimBtr15Peer(official, key.modulus);
        RecordingListener log = new RecordingListener();
        DeviceOperator op = new DeviceOperator(tempDir(), key, connectorFor(peer), log,
                "40:ED:98:1C:1C:ED");
        boolean coldCycle = op.jailbreakStage(official, FirmwareEngine.Variant.DEVELOPER_KEY);
        require(!coldCycle, "an accepted package must not ask for a power cycle");
        require(!op.hasPendingJournal(), "the accepted run retires its journal");
        require(peer.trust().equals(key.modulus), "the device keeps the developer trust");
        byte[] candidate = FirmwareEngine.build(official, key,
                FirmwareEngine.Variant.DEVELOPER_KEY).bytes;
        require(peer.firmwareContentSha256().equals(Workflows.contentSha256(candidate)),
                "the device runs the package it accepted");
        require(Upgrade.isCleanContext(peer.key4()), "context is clean after the commit");
        require(log.lines.toString().contains("no power cycle needed"),
                "the log says the cycle was skipped: " + log.lines);
        requireSubsequence(log.statuses, "STAGING", "VALIDATING", "WAITING FOR REBOOT",
                "COMMITTING", "VERIFYING");
    }

    /**
     * The whole pipeline on releases other than v3.8: the same builder, pump,
     * footer check, journal and commit must work when the device runs v3.5 or
     * v4.4 — including the jailbreak's own 0x003d checkpoint and cold cycle.
     */
    private static void otherReleasesUseTheSamePipeline(byte[] v35, byte[] v44) throws Exception {
        SimBtr15Peer peer = new SimBtr15Peer(v35, key.modulus);
        RecordingListener log = new RecordingListener();
        DeviceOperator op = new DeviceOperator(tempDir(), key, connectorFor(peer), log,
                "40:ED:98:1C:1C:ED");
        op.update(v35, FirmwareEngine.Variant.DEVELOPER_KEY);
        byte[] candidate = FirmwareEngine.build(v35, key,
                FirmwareEngine.Variant.DEVELOPER_KEY).bytes;
        require(peer.firmwareContentSha256().equals(Workflows.contentSha256(candidate)),
                "a v3.5 device ends up running the v3.5 package it was given");
        require(Upgrade.isCleanContext(peer.key4()), "v3.5 context is clean after the commit");
        require(log.lines.toString().contains("Building package locally: v3.5"),
                "the log names the release it built from: " + log.lines);

        SimBtr15Peer stock = new SimBtr15Peer(v44, FirmwareProfile.fiioModulus());
        DeviceOperator jailbreak = new DeviceOperator(tempDir(), key, connectorFor(stock),
                new RecordingListener(), "40:ED:98:1C:1C:ED");
        require(jailbreak.jailbreakStage(v44, FirmwareEngine.Variant.DEVELOPER_KEY),
                "a stock v4.4 device fails the footer and owes the power cycle");
        require(stock.key4()[Upgrade.RESUME_WORD] == Upgrade.RESUME_PRE_VALIDATE,
                "the v4.4 journal was rewritten to PRE_VALIDATE");
        stock.coldPowerCycle();
        jailbreak.jailbreakResume(v44);
        require(!jailbreak.hasPendingJournal(), "the v4.4 jailbreak retired its journal");
        require(stock.trust().equals(key.modulus), "the v4.4 device now trusts the developer key");
        require(stock.firmwareContentSha256().equals(Workflows.contentSha256(candidate(v44))),
                "the v4.4 device runs the v4.4 package it was given");
    }

    private static byte[] candidate(byte[] releaseBytes) throws FirmwareException {
        return FirmwareEngine.build(releaseBytes, key, FirmwareEngine.Variant.DEVELOPER_KEY).bytes;
    }

    private static File tempDir() throws Exception {
        File dir = Files.createTempDirectory("btr15-integration").toFile();
        dir.deleteOnExit();
        return dir;
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private static void expectFails(ThrowingRunnable body, String message) {
        try {
            body.run();
            throw new AssertionError(message);
        } catch (AssertionError wrong) {
            throw wrong;
        } catch (Exception expected) {
            checks++; // refusal or link failure is the pass condition
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        checks++;
    }

    /**
     * The flash screen's one convention: every line opens a sentence — a capital
     * letter, a digit for the percent counter, or two leading spaces for the
     * package detail lines.  Lowercase openers are what made the recovery lines
     * read like text from a different writer.
     */
    private static void requireCapitalizedLines(List<String> lines, String context) {
        for (String line : lines) {
            if (line.isEmpty() || line.startsWith("  ")) {
                continue;
            }
            char first = line.charAt(0);
            require(Character.isUpperCase(first) || Character.isDigit(first),
                    context + " logged a line that does not start a sentence: " + line);
        }
    }

    private static final class RecordingListener implements DeviceOperator.Listener {
        final List<String> lines = new ArrayList<String>();
        final List<String> statuses = new ArrayList<String>();

        @Override public void log(String line) {
            lines.add(line);
        }

        @Override public void status(String status) {
            statuses.add(status);
        }
    }

    /** The meter's sink: exactly the values the log line is built from. */
    private static final class RecordingProgress implements TransferMeter.Listener {
        final List<Integer> percentages = new ArrayList<Integer>();
        final List<Long> packetsSent = new ArrayList<Long>();
        long totalPackets;

        @Override public void onProgress(int percent, long sent, long total) {
            percentages.add(Integer.valueOf(percent));
            packetsSent.add(Long.valueOf(sent));
            totalPackets = total;
        }

        int first() {
            return percentages.get(0).intValue();
        }

        int last() {
            return percentages.get(percentages.size() - 1).intValue();
        }

        long lastPacketsSent() {
            return packetsSent.get(packetsSent.size() - 1).longValue();
        }

        long totalPackets() {
            return totalPackets;
        }
    }
}
