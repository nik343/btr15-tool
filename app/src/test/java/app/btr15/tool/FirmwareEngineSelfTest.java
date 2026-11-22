package app.btr15.tool;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

/**
 * Full regression for the offline firmware engine against the live-flashed
 * proven artifacts (official v3.8, the automute+devkey candidate, V7, V8, and
 * the stock phase-one package).
 *
 * <p>The proven files were signed with the historical prototype key, so
 * whole-file digests cannot repeat under a mnemonic-derived key.  The
 * key-independent facts therefore anchor the test: every byte outside the
 * 514-byte QCC constant block window and the 256-byte footer must match the
 * proven artifact exactly, partition 1 and all other partitions must match
 * outright, and both signature invariants plus every retired-patch assertion
 * must hold.
 *
 * <p>Usage: java app.btr15.tool.FirmwareEngineSelfTest &lt;official.bin&gt;
 * &lt;candidate.bin&gt; &lt;v7.bin&gt; &lt;v8.bin&gt; &lt;phase1.bin&gt; &lt;v2.2.bin&gt;
 * &lt;v3.5.bin&gt; &lt;v4.4.bin&gt;
 */
public final class FirmwareEngineSelfTest {
    private static final String V1_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    private static final int KEY_WINDOW = FirmwareProfile.FIIO_BLOCK_P1_OFFSET;
    private static final int KEY_WINDOW_END = KEY_WINDOW + FirmwareProfile.QCC_BLOCK_SIZE;
    /** Some partition other than Apps P1 that no variant may modify (the 572 KB code slice). */
    private static final int OUTER_PARTITION = 5;

    private static int checks = 0;
    private static DevKey key;

    public static void main(String[] args) throws Exception {
        if (args.length < 8) {
            throw new IllegalArgumentException("usage: FirmwareEngineSelfTest official candidate"
                    + " v7 v8 phase1 v22 v35 v44");
        }
        key = DevKey.derive(V1_MNEMONIC);
        byte[] official = read(args[0]);
        byte[] candidate = read(args[1]);
        byte[] v7 = read(args[2]);
        byte[] v8 = read(args[3]);

        officialBaseAccepts(official);
        refuseBadBase(official);
        variantAgainstProven(official, candidate, FirmwareEngine.Variant.DEVELOPER_KEY,
                FirmwareProfile.P1_SIZE, "candidate");
        variantAgainstProven(official, v7, FirmwareEngine.Variant.DEVELOPER_KEY_100HZ,
                FirmwareProfile.P1_SIZE + HundredHertzPins.V7_EXTENSION.length, "v7");
        variantAgainstProven(official, v8, FirmwareEngine.Variant.DEVELOPER_KEY_100HZ2,
                FirmwareProfile.P1_SIZE + HundredHertzPins.V7_EXTENSION.length
                        + HundredHertzPins.V8_EXTENSION.length, "v8");
        stockPhaseOne(official);
        stockPhaseOneAgainstProven(official, read(args[4]));
        automuteIsOptional(official);
        tamperFails(official);
        everyRegisteredReleaseBuilds(read(args[5]), read(args[6]), read(args[7]));
        unlistedPackagesAreCheckedNotGuessed(read(args[0]), read(args[5]), read(args[6]),
                read(args[7]));
        changeRowsMatchTheRelease();
        System.out.println("FirmwareEngineSelfTest: PASS (" + checks + " checks)");
    }

    /**
     * A package that is not in the table is still worked on: the key block is
     * located by searching for FiiO's own bytes, and the two patches are
     * decided by running their real passes.  The probe must agree with every
     * pinned release, and agree with what a build then actually does.
     */
    private static void unlistedPackagesAreCheckedNotGuessed(byte[] v38, byte[] v22, byte[] v35,
            byte[] v44) throws Exception {
        // The mechanical probe agrees with the pinned truth on all four releases.
        expect(probeAutomute(v22) == false, "v2.2: probe finds no automute timers");
        expect(probeAutomute(v35) && probeAutomute(v38) && probeAutomute(v44),
                "v3.5, v3.8 and v4.4: probe finds both automute timers");
        expect(probeHundredHertz(v38), "v3.8: probe accepts the 100 Hz chain");
        expect(!probeHundredHertz(v22) && !probeHundredHertz(v35) && !probeHundredHertz(v44),
                "v2.2, v3.5 and v4.4: probe refuses the 100 Hz chain");

        // An unlisted but FiiO-signed package: one header byte differs, which the
        // signature does not cover, so the digest is unknown while the image is
        // still genuinely FiiO's.
        byte[] unlisted = v38.clone();
        long headerSize = u32be(unlisted, 8);
        unlisted[12 + (int) headerSize - 1] ^= 0x01;
        expect(FirmwareReleases.byDigest(unlisted) == null, "the altered header is unlisted");
        FirmwareReleases.Release described = FirmwareReleases.describe(unlisted);
        expect(!described.official && described.label.equals("unrecognized"),
                "an unlisted package describes itself");
        expect(described.keyBlockP1Offset == 0x966BC, "its FiiO key block is located afield");
        expect(described.p1Size == FirmwareProfile.P1_SIZE, "its Apps P1 is identified");
        expect(described.automute && described.hundredHertz,
                "its capabilities are probed, not assumed");

        // And the engine builds from it, proving the description is enough.
        FirmwareEngine.Result built = FirmwareEngine.build(unlisted, key,
                FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE);
        expect(Pss.verify(key.modulus, built.parsed.signature, built.parsed.signedContent()),
                "an unlisted package builds and verifies");

        // A package whose key material is not FiiO's (our own build) is refused:
        // the block cannot be located, so nothing may be promised about it.
        byte[] devSigned = FirmwareEngine.build(v38, key,
                FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE).bytes;
        expect(throwsFirmware(() -> FirmwareReleases.describe(devSigned)),
                "a package whose key block is not FiiO's is refused");

        // A row for an unlisted package names the mechanical reason.
        ChangeOptions.Row unlistedAutomute = ChangeOptions.automute(described, false, true);
        expect(unlistedAutomute.enabled && unlistedAutomute.label.equals("Automute fix"),
                "an unlisted package that has the timers keeps the plain automute name");
    }

    private static boolean probeAutomute(byte[] release) throws Exception {
        AppPackage pkg = AppPackage.parse(release);
        return FirmwareEngine.probePatches(pkg.partition(FirmwareProfile.P1_NUMBER).payload,
                pkg.partition(FirmwareProfile.PARTITION1_P1).payload).automute;
    }

    private static boolean probeHundredHertz(byte[] release) throws Exception {
        AppPackage pkg = AppPackage.parse(release);
        return FirmwareEngine.probePatches(pkg.partition(FirmwareProfile.P1_NUMBER).payload,
                pkg.partition(FirmwareProfile.PARTITION1_P1).payload).hundredHertz;
    }

    /**
     * The profile table is the whole multi-release story: every registered
     * release must build, verify, and get the developer key block written where
     * its own FiiO block sat — and the two optional changes must be available
     * exactly where the release's code carries them.
     */
    private static void everyRegisteredReleaseBuilds(byte[] v22, byte[] v35, byte[] v44)
            throws Exception {
        expect(FirmwareReleases.identify(v22).label.equals("v2.2"), "v2.2 is a registered release");
        expect(FirmwareReleases.identify(v35).label.equals("v3.5"), "v3.5 is a registered release");
        expect(FirmwareReleases.identify(v44).label.equals("v4.4"), "v4.4 is a registered release");
        expect(throwsFirmware(() -> FirmwareReleases.identify(new byte[4096])),
                "an unknown file is not a release");
        byte[] tampered = v44.clone();
        tampered[1000] ^= 0x01;
        expect(throwsFirmware(() -> FirmwareReleases.identify(tampered)),
                "a tampered release is refused");
        expect(FirmwareReleases.labels().equals("v2.2, v3.5, v3.8 or v4.4"),
                "the release list reads: " + FirmwareReleases.labels());
        expect(FirmwareReleases.jailbreakScope().equals(
                        "Supported firmware: v2.2, v3.5, v3.8 or v4.4"),
                "the Method step's scope reads: " + FirmwareReleases.jailbreakScope());

        for (byte[] releaseBytes : new byte[][] {v22, v35, v44}) {
            FirmwareReleases.Release profile = FirmwareReleases.identify(releaseBytes);
            FirmwareEngine.Result result = FirmwareEngine.build(releaseBytes, key,
                    FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE);
            AppPackage built = result.parsed;
            String label = profile.label;
            expect(result.releaseLabel.equals(label), label + ": the build names its release");
            expect(Pss.verify(key.modulus, built.signature, built.signedContent()),
                    label + ": package verifies under the developer key");
            expect(!Pss.verify(FirmwareProfile.fiioModulus(), built.signature,
                            built.signedContent()),
                    label + ": package no longer verifies under FiiO's key");
            byte[] p1 = built.partition(profile.p1Number).payload;
            expect(FirmwareProfile.matches(p1, profile.keyBlockP1Offset, key.qccBlock),
                    label + ": developer block sits where FiiO's key was");
            expect(FirmwareProfile.findAll(p1, FirmwareProfile.fiioBlock()).isEmpty(),
                    label + ": no FiiO block is left in Apps P1");
            expect(p1.length == profile.p1Size, label + ": Apps P1 length unchanged");
            expect(built.upgradeId() != profile.upgradeId, label + ": upgrade id differs from"
                    + " the official one");
        }

        // v2.2's P1 has no automute timer pair: the engine refuses it outright.
        expect(throwsFirmware(() -> FirmwareEngine.build(v22, key,
                        FirmwareEngine.Variant.DEVELOPER_KEY)),
                "v2.2 refuses the automute fix");
        for (byte[] releaseBytes : new byte[][] {v35, v44}) {
            FirmwareReleases.Release profile = FirmwareReleases.identify(releaseBytes);
            FirmwareEngine.Result patched = FirmwareEngine.build(releaseBytes, key,
                    FirmwareEngine.Variant.DEVELOPER_KEY);
            expect(patched.patchNames.contains("left_dac_automute_timer")
                            && patched.patchNames.contains("right_dac_automute_timer"),
                    profile.label + ": both automute timer sites patched");
        }
        expect(throwsFirmware(() -> FirmwareEngine.build(v35, key,
                        FirmwareEngine.Variant.DEVELOPER_KEY_100HZ)),
                "v3.5 refuses the 100 Hz demo");
        expect(throwsFirmware(() -> FirmwareEngine.build(v44, key,
                        FirmwareEngine.Variant.DEVELOPER_KEY_100HZ2)),
                "v4.4 refuses the 100 Hz demo");
    }

    /** The two grey-out reasons and their exact words, pinned. */
    private static void changeRowsMatchTheRelease() {
        ChangeOptions.Row automute38 = ChangeOptions.automute(FirmwareReleases.V38, false, true);
        expect(automute38.enabled && automute38.checked
                        && automute38.label.equals("Automute fix"),
                "v3.8 automute row keeps its name and can be ticked");
        ChangeOptions.Row hundred38 = ChangeOptions.hundredHertz(FirmwareReleases.V38, false, true);
        expect(hundred38.enabled && hundred38.checked && hundred38.label.equals("100 Hz demo"),
                "v3.8 100 Hz row keeps its name and can be ticked");

        ChangeOptions.Row automute22 = ChangeOptions.automute(FirmwareReleases.V22, false, true);
        expect(!automute22.enabled && !automute22.checked
                        && automute22.label.equals("Automute fix (v3.5 and newer only)"),
                "v2.2 automute row: " + automute22.label);

        for (FirmwareReleases.Release release : new FirmwareReleases.Release[] {
                FirmwareReleases.V22, FirmwareReleases.V35, FirmwareReleases.V44}) {
            ChangeOptions.Row row = ChangeOptions.hundredHertz(release, false, true);
            expect(!row.enabled && !row.checked
                            && row.label.equals("100 Hz demo (only written for v3.8 at the"
                                    + " moment)"),
                    release.label + " 100 Hz row: " + row.label);
        }
        ChangeOptions.Row automute35 = ChangeOptions.automute(FirmwareReleases.V35, false, false);
        expect(automute35.enabled && automute35.label.equals("Automute fix"),
                "v3.5 can take the automute fix");

        // Stock restore greys both and leaves their names alone.
        ChangeOptions.Row automuteStock = ChangeOptions.automute(FirmwareReleases.V22, true, true);
        expect(!automuteStock.enabled && !automuteStock.checked
                        && automuteStock.label.equals("Automute fix"),
                "stock restore greys the automute row without renaming it");
        ChangeOptions.Row hundredStock = ChangeOptions.hundredHertz(FirmwareReleases.V44, true, true);
        expect(!hundredStock.enabled && !hundredStock.checked
                        && hundredStock.label.equals("100 Hz demo"),
                "stock restore greys the 100 Hz row without renaming it");

        // An unrecognized package says so instead of claiming a release rule.
        ChangeOptions.Row unknown = ChangeOptions.automute(null, false, true);
        expect(!unknown.enabled && unknown.label.equals("Automute fix (supported firmware only)"),
                "an unknown package names its own reason: " + unknown.label);
    }

    private static void officialBaseAccepts(byte[] official) throws Exception {
        AppPackage pkg = FirmwareProfile.requireOfficialV38(official);
        expect(Pss.verify(FirmwareProfile.fiioModulus(), pkg.signature, pkg.signedContent()),
                "official v3.8 verifies under the FiiO release key");
        expect(pkg.upgradeId() == FirmwareProfile.UPGRADE_ID, "official upgrade id pinned");
        byte[] p1 = pkg.partition(FirmwareProfile.P1_NUMBER).payload;
        expect(FirmwareProfile.matches(p1, KEY_WINDOW, FirmwareProfile.fiioBlock())
                        && Util.sha256Hex(FirmwareProfile.fiioBlock())
                                .equalsIgnoreCase(FirmwareProfile.FIIO_BLOCK_SHA256),
                "FiiO block reconstruction matches the pinned digest");
    }

    private static void refuseBadBase(byte[] official) {
        byte[] wrongLength = Arrays.copyOf(official, official.length - 1);
        expect(throwsFirmware(() -> FirmwareProfile.requireOfficialV38(wrongLength)),
                "truncated base is refused");
        byte[] tampered = official.clone();
        tampered[official.length - 4096] ^= 0x01;
        expect(throwsFirmware(() -> FirmwareProfile.requireOfficialV38(tampered)),
                "tampered base is refused");
        byte[] foreign = new byte[4096];
        expect(throwsFirmware(() -> FirmwareProfile.requireOfficialV38(foreign)),
                "non-container base is refused");
    }

    private static void variantAgainstProven(byte[] official, byte[] proven,
                                             FirmwareEngine.Variant variant, int p1Size,                                             String label) throws Exception {
        FirmwareEngine.Result result = FirmwareEngine.build(official, key, variant);
        AppPackage built = result.parsed;
        AppPackage reference = AppPackage.parse(proven);
        expect(result.bytes.length == proven.length, label + ": package length matches proven");
        expect(built.partition(FirmwareProfile.P1_NUMBER).payload.length == p1Size,
                label + ": Apps P1 length matches the pinned chain");
        expect(built.upgradeId() != FirmwareProfile.UPGRADE_ID, label + ": id differs from official");
        expect(Pss.verify(key.modulus, built.signature, built.signedContent()),
                label + ": verifies under the mnemonic-derived developer key");
        expect(!Pss.verify(FirmwareProfile.fiioModulus(), built.signature, built.signedContent()),
                label + ": rejected under the FiiO release key");

        // Key-independent equivalence: every byte outside the key-block window
        // inside P1 and outside the footer must equal the proven artifact.
        byte[] builtP1 = built.partition(FirmwareProfile.P1_NUMBER).payload;
        byte[] provenP1 = reference.partition(FirmwareProfile.P1_NUMBER).payload;
        expect(builtP1.length == provenP1.length, label + ": P1 length equals proven");
        int differences = 0;
        for (int i = 0; i < builtP1.length; i++) {
            boolean keyWindow = i >= KEY_WINDOW && i < KEY_WINDOW_END;
            if (builtP1[i] != provenP1[i] && !keyWindow) {
                differences++;
            }
        }
        expect(differences == 0, label
                + ": P1 is byte-identical to the proven image outside the key block");
        for (AppPackage.Partition partition : built.partitions) {
            if (partition.number == FirmwareProfile.P1_NUMBER) {
                continue;
            }
            byte[] mine = partition.payload;
            byte[] theirs = reference.partition(partition.number).payload;
            expect(Arrays.equals(mine, theirs),
                    label + ": partition " + partition.number + " identical to proven");
        }
        expect(FirmwareProfile.matches(builtP1, KEY_WINDOW, key.qccBlock),
                label + ": developer QCC block embedded at the pinned offset");
        expect(FirmwareProfile.findAll(builtP1, FirmwareProfile.fiioBlock()).isEmpty(),
                label + ": FiiO block fully replaced");
        FirmwareProfile.requireRetiredIdentityOverridesAbsent(builtP1);
        FirmwareProfile.requireAutoCommitStock(builtP1);
        checks += 2;
        System.out.println("ok: " + label + ": retired overrides absent, autocommit stock");
    }

    private static void stockPhaseOne(byte[] official) throws Exception {
        FirmwareEngine.Result result =
                FirmwareEngine.build(official, key, FirmwareEngine.Variant.STOCK_PAYLOADS);
        AppPackage built = result.parsed;
        expect(result.bytes.length == official.length, "phase1 length matches official");
        byte[] mine = result.bytes.clone();
        byte[] stock = official.clone();
        // Everything except the footer signature region must be identical.
        System.arraycopy(stock, stock.length - AppPackage.SIGNATURE_SIZE, mine,
                mine.length - AppPackage.SIGNATURE_SIZE, AppPackage.SIGNATURE_SIZE);
        expect(Arrays.equals(mine, stock),
                "phase1 is byte-identical to official outside the footer signature");
        expect(Pss.verify(key.modulus, built.signature, built.signedContent()),
                "phase1 verifies under the developer key");
        expect(!Pss.verify(FirmwareProfile.fiioModulus(), built.signature, built.signedContent()),
                "phase1 rejected under the FiiO release key");
        expect(built.upgradeId() != FirmwareProfile.UPGRADE_ID, "phase1 upgrade id differs");
        expect(result.patchNames.isEmpty(),
                "stock phase 1 changes no payload at all, saw " + result.patchNames);
        expect(result.keptNames.contains("stock_payloads"),
                "stock phase 1 reports untouched stock payloads as inherited");
    }

    private static void stockPhaseOneAgainstProven(byte[] official, byte[] proven)
            throws Exception {
        FirmwareEngine.Result result =
                FirmwareEngine.build(official, key, FirmwareEngine.Variant.STOCK_PAYLOADS);
        AppPackage built = result.parsed;
        AppPackage reference = AppPackage.parse(proven);
        for (AppPackage.Partition partition : built.partitions) {
            expect(Arrays.equals(partition.payload, reference.partition(partition.number).payload),
                    "phase1 partition " + partition.number + " matches proven payload");
        }
        expect(Pss.verify(key.modulus, built.signature, built.signedContent()),
                "phase1 re-signs the exact proven signed content");
    }

    /**
     * Automute is opt-in: without it both timer sites must still hold FiiO's
     * stock instruction, the package must verify, and a package built for the
     * other answer must be refused so the two can never be confused.
     */
    private static void automuteIsOptional(byte[] official) throws Exception {
        byte[] officialP1 = FirmwareProfile.requireOfficialV38(official)
                .partition(FirmwareProfile.P1_NUMBER).payload;

        FirmwareEngine.Result plain = FirmwareEngine.build(official, key,
                FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE);
        expect(!plain.patchNames.contains("left_dac_automute_timer")
                        && !plain.patchNames.contains("right_dac_automute_timer"),
                "no-automute build must not claim to have patched the timers");
        expect(plain.keptNames.contains("stock_automute_timers"),
                "no-automute build reports the stock timers as inherited, not as a change");
        expect(plain.patchNames.size() == 1 && plain.patchNames.contains("upgrade_release_key"),
                "with no changes selected the only edit is the developer key block, saw "
                        + plain.patchNames);
        byte[] plainP1 = plain.parsed.partition(FirmwareProfile.P1_NUMBER).payload;
        boolean allStock = true;
        for (String contextHex : FirmwareProfile.AUTOMUTE_CONTEXTS) {
            byte[] context = Util.hex(contextHex);
            java.util.List<Integer> hits = FirmwareProfile.findAll(plainP1, context);
            allStock &= hits.size() == 1 && FirmwareProfile.matches(plainP1, hits.get(0),
                    FirmwareProfile.AUTOMUTE_BEFORE)
                    && Arrays.equals(
                            Arrays.copyOfRange(plainP1, hits.get(0), hits.get(0) + 2),
                            Arrays.copyOfRange(officialP1, hits.get(0), hits.get(0) + 2));
        }
        expect(allStock, "both automute sites stay byte-identical to stock");

        FirmwareEngine.Result patched = FirmwareEngine.build(official, key,
                FirmwareEngine.Variant.DEVELOPER_KEY);
        byte[] patchedP1 = patched.parsed.partition(FirmwareProfile.P1_NUMBER).payload;
        boolean bothPatched = true;
        for (String contextHex : FirmwareProfile.AUTOMUTE_CONTEXTS) {
            byte[] patchedContext = new byte[Util.hex(contextHex).length];
            byte[] context = Util.hex(contextHex);
            patchedContext[0] = FirmwareProfile.AUTOMUTE_AFTER[0];
            patchedContext[1] = FirmwareProfile.AUTOMUTE_AFTER[1];
            System.arraycopy(context, 2, patchedContext, 2, context.length - 2);
            bothPatched &= FirmwareProfile.findAll(patchedP1, patchedContext).size() == 1;
        }
        expect(bothPatched, "the automute build patches both sites");

        expect(throwsFirmware(() -> FirmwareEngine.verify(plain.bytes, official, key,
                        FirmwareEngine.Variant.DEVELOPER_KEY)),
                "a no-automute package is refused when automute was expected");
        expect(throwsFirmware(() -> FirmwareEngine.verify(patched.bytes, official, key,
                        FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE)),
                "an automute package is refused when stock timers were expected");

        expect(FirmwareEngine.Variant.forChoices(false, false)
                        == FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE
                        && FirmwareEngine.Variant.forChoices(true, false)
                                == FirmwareEngine.Variant.DEVELOPER_KEY
                        && FirmwareEngine.Variant.forChoices(false, true)
                                == FirmwareEngine.Variant.DEVELOPER_KEY_NO_AUTOMUTE_100HZ2
                        && FirmwareEngine.Variant.forChoices(true, true)
                                == FirmwareEngine.Variant.DEVELOPER_KEY_100HZ2,
                "every change combination maps to its own journalable variant");
    }

    private static void tamperFails(byte[] official) throws Exception {
        FirmwareEngine.Result result =
                FirmwareEngine.build(official, key, FirmwareEngine.Variant.DEVELOPER_KEY);
        byte[] p1 = result.bytes;
        int p1Start = payloadStart(p1, FirmwareProfile.P1_NUMBER);
        int p5Start = payloadStart(p1, OUTER_PARTITION);

        byte[] tamperedP1 = result.bytes.clone();
        tamperedP1[p1Start + 0x2000] ^= 0x40; // untouched interior byte of Apps P1
        expect(throwsFirmware(() -> FirmwareEngine.verify(tamperedP1, official, key,
                        FirmwareEngine.Variant.DEVELOPER_KEY)),
                "tampered Apps P1 fails verification");

        byte[] tamperedKey = result.bytes.clone();
        tamperedKey[p1Start + KEY_WINDOW + 100] ^= 0x01; // inside the embedded key block
        expect(throwsFirmware(() -> FirmwareEngine.verify(tamperedKey, official, key,
                        FirmwareEngine.Variant.DEVELOPER_KEY)),
                "tampered embedded developer key block fails verification");

        byte[] tamperedOuter = result.bytes.clone();
        tamperedOuter[p5Start + 4096] ^= 0x01; // a byte in an untouched partition
        expect(throwsFirmware(() -> FirmwareEngine.verify(tamperedOuter, official, key,
                        FirmwareEngine.Variant.DEVELOPER_KEY)),
                "changed outer partition fails verification");

        byte[] swapped = result.bytes.clone();
        for (int i = 0; i < 128; i++) { // reverse the halves of the footer signature
            int front = swapped.length - AppPackage.SIGNATURE_SIZE + i;
            int back = swapped.length - 1 - i;
            byte a = swapped[front];
            swapped[front] = swapped[back];
            swapped[back] = a;
        }
        expect(throwsFirmware(() -> FirmwareEngine.verify(swapped, official, key,
                        FirmwareEngine.Variant.DEVELOPER_KEY)),
                "scrambled footer signature fails verification");

        byte[] truncated = Arrays.copyOf(result.bytes, result.bytes.length - 1);
        expect(throwsFirmware(() -> FirmwareEngine.verify(truncated, official, key,
                        FirmwareEngine.Variant.DEVELOPER_KEY)),
                "truncated package fails verification");
    }

    /** File offset where the payload of one partition number begins. */
    private static int payloadStart(byte[] blob, int number) throws FirmwareException {
        long cursor = 12 + u32be(blob, 8);
        while (cursor + 8 < blob.length) {
            byte[] magic = Arrays.copyOfRange(blob, (int) cursor, (int) cursor + 8);
            if (!java.util.Arrays.equals(magic, Util.hex("5041525444415441"))) {
                break; // APPUPFTR or anything else ends the PARTDATA run
            }
            long recordSize = u32be(blob, (int) cursor + 8);
            int found = ((blob[(int) cursor + 14] & 0xFF) << 8) | (blob[(int) cursor + 15] & 0xFF);
            if (found == number) {
                return (int) cursor + 16;
            }
            cursor += 12 + recordSize; // magic(8) + size(4) + type(2) + number(2) + payload(rs-4)
        }
        throw new FirmwareException("partition " + number + " not found while walking");
    }

    private static long u32be(byte[] value, int offset) {
        return ((long) (value[offset] & 0xFF) << 24)
                | ((long) (value[offset + 1] & 0xFF) << 16)
                | ((long) (value[offset + 2] & 0xFF) << 8)
                | (long) (value[offset + 3] & 0xFF);
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

    private static byte[] read(String path) throws java.io.IOException {
        Path file = Paths.get(path);
        if (!Files.isRegularFile(file)) {
            throw new IllegalArgumentException("missing test artifact: " + path);
        }
        return Files.readAllBytes(file);
    }

    private static void expect(boolean condition, String label) {
        checks++;
        if (!condition) {
            throw new AssertionError("FAIL: " + label);
        }
        System.out.println("ok: " + label);
    }
}
