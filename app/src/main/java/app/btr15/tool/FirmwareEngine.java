package app.btr15.tool;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Offline BTR15 firmware engine: parse, verify, patch and RSA-PSS-sign APPUPFTR
 * update packages entirely on-device, with an independent re-verification of
 * every artifact before it may be flashed.
 *
 * <p>Every build starts from one of the pinned official releases
 * ({@link FirmwareReleases#identify}), applies only the pinned transformations
 * for the requested variant, re-signs the concatenated PARTDATA payloads with
 * the developer key, then re-parses the emitted bytes from scratch and proves
 * the manifest delta, both signature invariants (developer-valid,
 * FiiO-invalid), and that the retired auto-commit and identity-override patches
 * stay absent. Nothing is trusted from the build pass: {@link #verify}
 * re-derives everything from the output bytes.
 */
final class FirmwareEngine {

    /**
     * Patch variants the tool can produce.  Every developer variant carries the
     * developer upgrade key; the automute fix and the 100 Hz edits are separate,
     * individually selectable changes on top of it, so the variant name is the
     * complete record of what a package contains (Recovery rebuilds from it).
     *
     * <p>The automute-carrying constants keep the historical names, so journals
     * written before automute became selectable still resolve and rebuild to
     * the bytes they staged.</p>
     */
    enum Variant {
        /** Automute plus the developer upgrade key: the historical jailbreak base. */
        DEVELOPER_KEY(false, 0, true),
        /** Automute, developer key, and the 100 Hz menu (V7 chain). */
        DEVELOPER_KEY_100HZ(false, 1, true),
        /** Automute, developer key, and 100 Hz + 100 Hz2 deadline menu (V8 chain). */
        DEVELOPER_KEY_100HZ2(false, 2, true),
        /** Developer key only: Apps P1 keeps FiiO's stock automute timers. */
        DEVELOPER_KEY_NO_AUTOMUTE(false, 0, false),
        /** Developer key and the 100 Hz menu, stock automute timers. */
        DEVELOPER_KEY_NO_AUTOMUTE_100HZ(false, 1, false),
        /** Developer key and the 100 Hz / 100 Hz2 deadline menu, stock automute timers. */
        DEVELOPER_KEY_NO_AUTOMUTE_100HZ2(false, 2, false),
        /** Untouched official payloads re-signed by the developer key (stock phase 1). */
        STOCK_PAYLOADS(true, 0, false);

        final boolean stockPayloads;
        final int hundredHertzStage;
        final boolean automute;

        Variant(boolean stockPayloads, int hundredHertzStage, boolean automute) {
            this.stockPayloads = stockPayloads;
            this.hundredHertzStage = hundredHertzStage;
            this.automute = automute;
        }

        /** The developer variant for a selection of the two opt-in changes. */
        static Variant forChoices(boolean automute, boolean hundredHertz) {
            if (hundredHertz) {
                return automute ? DEVELOPER_KEY_100HZ2 : DEVELOPER_KEY_NO_AUTOMUTE_100HZ2;
            }
            return automute ? DEVELOPER_KEY : DEVELOPER_KEY_NO_AUTOMUTE;
        }
    }

    /** A completed, independently re-verified package plus its audit summary. */
    static final class Result {
        final byte[] bytes;
        final AppPackage parsed;
        /** The official release this package was built from, e.g. {@code v3.5}. */
        final String releaseLabel;
        final long upgradeId;
        final String upgradeIdHex;
        final String outputSha256;
        final String p1Sha256;
        final int changedBytes;
        /** Everything this package actively edits, in the order it was applied. */
        final List<String> patchNames;
        /**
         * What the build deliberately left exactly as FiiO ships it.  These
         * are not edits: "automute not selected" means the stock timers are
         * inherited untouched, so reporting it as a patch would claim a change
         * that never happened.
         */
        final List<String> keptNames;

        Result(byte[] bytes, AppPackage parsed, String releaseLabel, long upgradeId,
               String upgradeIdHex, String outputSha256, String p1Sha256, int changedBytes,
               List<String> patchNames, List<String> keptNames) {
            this.bytes = bytes;
            this.parsed = parsed;
            this.releaseLabel = releaseLabel;
            this.upgradeId = upgradeId;
            this.upgradeIdHex = upgradeIdHex;
            this.outputSha256 = outputSha256;
            this.p1Sha256 = p1Sha256;
            this.changedBytes = changedBytes;
            this.patchNames = patchNames;
            this.keptNames = keptNames;
        }
    }

    private FirmwareEngine() { }

    /**
     * Build and fully verify one variant. {@code official} must be the exact
     * audited v3.8 release bytes; {@code key} signs the output and its public
     * half is embedded into Apps P1 (except for {@link Variant#STOCK_PAYLOADS}).
     * Refuses to emit anything that does not pass {@link #verify}.
     */
    static Result build(byte[] official, DevKey key, Variant variant) throws FirmwareException {
        FirmwareReleases.Release release = FirmwareReleases.describe(official);
        requireCapable(release, variant);
        AppPackage base = AppPackage.parse(official);
        List<String> patchNames = new ArrayList<>();
        List<String> keptNames = new ArrayList<>();

        byte[] p1 = base.partition(release.p1Number).payload;
        byte[] partition1 = base.partition(FirmwareProfile.PARTITION1_P1).payload;
        if (!variant.stockPayloads) {
            if (variant.automute) {
                p1 = applyAutomute(p1, patchNames);
            } else {
                keptNames.add("stock_automute_timers");
            }
            p1 = applyDeveloperKey(p1, key, patchNames, release.keyBlockP1Offset);
            if (variant.hundredHertzStage >= 1) {
                p1 = applyHundredHertzStage(p1, HundredHertzPins.V7_SITES,
                        HundredHertzPins.V7_EXTENSION, HundredHertzPins.V7_EXTENSION_P1_OFFSET,
                        HundredHertzPins.V7_EXTENSION_SHA256, patchNames, "100hz_menu_v7");
                partition1 = applySizeWordEdit(partition1, HundredHertzPins.PARTITION1_P1_SIZE_V7,
                        "v7 P1 size word");
            }
            if (variant.hundredHertzStage >= 2) {
                p1 = applyHundredHertzStage(p1, HundredHertzPins.V8_SITES,
                        HundredHertzPins.V8_EXTENSION, HundredHertzPins.V8_EXTENSION_P1_OFFSET,
                        HundredHertzPins.V8_EXTENSION_SHA256, patchNames, "100hz2_deadline_v8");
                partition1 = applySizeWordEdit(partition1, HundredHertzPins.PARTITION1_P1_SIZE_V8,
                        "v8 P1 size word");
            }
        } else {
            keptNames.add("stock_payloads");
        }

        List<AppPackage.Partition> newPartitions = new ArrayList<>();
        for (AppPackage.Partition partition : base.partitions) {
            if (partition.number == release.p1Number) {
                newPartitions.add(new AppPackage.Partition(partition.type, partition.number, p1));
            } else if (partition.number == FirmwareProfile.PARTITION1_P1) {
                newPartitions.add(new AppPackage.Partition(partition.type, partition.number,
                        partition1));
            } else {
                newPartitions.add(partition);
            }
        }

        AppPackage provisional = AppPackage.parse(
                AppPackage.assemble(base.header, newPartitions, new byte[AppPackage.SIGNATURE_SIZE]));
        byte[] signature = key.signPss(provisional.signedContent());
        byte[] output = AppPackage.assemble(base.header, newPartitions, signature);

        AppPackage parsed = verify(output, official, key, variant);
        long upgradeId = parsed.upgradeId();
        if (upgradeId == base.upgradeId()) {
            throw new FirmwareException("output upgrade id collides with the official package");
        }
        return new Result(output, parsed, release.label, upgradeId, String.format("%08x", upgradeId),
                Util.sha256Hex(output),
                Util.sha256Hex(parsed.partition(release.p1Number).payload),
                countChanged(official, output), patchNames, keptNames);
    }

    /**
     * Refuse a variant the release's own code cannot take: the automute timer
     * pair only exists from v3.5 on, and the 100 Hz menu was written against
     * v3.8's exact Apps P1.  The screen greys these out; this is the mechanical
     * gate behind the grey.
     */
    private static void requireCapable(FirmwareReleases.Release release, Variant variant)
            throws FirmwareException {
        if (variant.stockPayloads) {
            return;
        }
        if (variant.automute && !release.automute) {
            throw new FirmwareException("the automute fix has no timer pair in " + release.label
                    + "; it is written for v3.5 and newer");
        }
        if (variant.hundredHertzStage >= 1 && !release.hundredHertz) {
            throw new FirmwareException("the 100 Hz demo is written for v3.8 only");
        }
    }

    /** Which of the two optional patches a package's own code accepts. */
    static final class PatchSupport {
        final boolean automute;
        final boolean hundredHertz;

        PatchSupport(boolean automute, boolean hundredHertz) {
            this.automute = automute;
            this.hundredHertz = hundredHertz;
        }
    }

    /**
     * Decide the two capabilities by <em>running the real patch passes</em> on
     * the image and seeing whether they hold — not by looking anything up.  This
     * is the same code the build runs, so a package the probe accepts cannot
     * fail later for a layout reason: the automute anchors must each match
     * exactly once and begin with the live instruction, and the 100 Hz chain
     * must find its sites, its extension offset at the end of Apps P1, and the
     * partition-1 size word it rewrites (payload offset 80).
     *
     * <p>Nothing is modified: the passes work on copies.
     */
    static PatchSupport probePatches(byte[] p1, byte[] partition1) {
        boolean automute = true;
        try {
            applyAutomute(p1.clone(), new ArrayList<String>());
        } catch (FirmwareException cannot) {
            automute = false;
        }
        boolean hundredHertz = true;
        try {
            byte[] stage1 = applyHundredHertzStage(p1.clone(), HundredHertzPins.V7_SITES,
                    HundredHertzPins.V7_EXTENSION, HundredHertzPins.V7_EXTENSION_P1_OFFSET,
                    HundredHertzPins.V7_EXTENSION_SHA256, new ArrayList<String>(), "100hz_menu_v7");
            byte[] stage2 = applyHundredHertzStage(stage1, HundredHertzPins.V8_SITES,
                    HundredHertzPins.V8_EXTENSION, stage1.length,
                    HundredHertzPins.V8_EXTENSION_SHA256, new ArrayList<String>(),
                    "100hz2_deadline_v8");
            applySizeWordEdit(partition1.clone(), HundredHertzPins.PARTITION1_P1_SIZE_V8,
                    "v8 P1 size word");
            if (stage2.length != HundredHertzPins.V7_EXTENSION_P1_OFFSET
                    + HundredHertzPins.V7_EXTENSION.length + HundredHertzPins.V8_EXTENSION.length) {
                hundredHertz = false;
            }
        } catch (FirmwareException cannot) {
            hundredHertz = false;
        }
        return new PatchSupport(automute, hundredHertz);
    }

    /**
     * Independent re-verification of a finished package against the official
     * base: valid container, developer-valid and FiiO-invalid signature, every
     * partition that the variant must not touch byte-identical to stock, the
     * pinned P1 length and 100 Hz tails, the rewritten Apps size word in
     * partition 1, the developer block where FiiO's key sat, and the absence of
     * every retired patch.
     */
    static AppPackage verify(byte[] candidate, byte[] official, DevKey key, Variant variant)
            throws FirmwareException {
        FirmwareReleases.Release release = FirmwareReleases.describe(official);
        requireCapable(release, variant);
        AppPackage base = AppPackage.parse(official);
        AppPackage pkg = AppPackage.parse(candidate);
        byte[] content = pkg.signedContent();

        if (!Pss.verify(key.modulus, pkg.signature, content)) {
            throw new FirmwareException("package does not verify under the developer key");
        }
        if (Pss.verify(FirmwareProfile.fiioModulus(), pkg.signature, content)) {
            throw new FirmwareException("package must not verify under the FiiO release key");
        }
        if (!Arrays.equals(pkg.header, base.header)) {
            throw new FirmwareException("package header changed");
        }
        if (pkg.partitions.size() != base.partitions.size()) {
            throw new FirmwareException("partition count differs from the official base");
        }

        boolean hz = variant.hundredHertzStage >= 1;
        for (int index = 0; index < base.partitions.size(); index++) {
            AppPackage.Partition mine = pkg.partitions.get(index);
            AppPackage.Partition stock = base.partitions.get(index);
            if (mine.type != stock.type || mine.number != stock.number) {
                throw new FirmwareException("partition identity changed at index " + index);
            }
            if (mine.number == release.p1Number && !variant.stockPayloads) {
                continue; // deep-checked below
            }
            if (mine.number == FirmwareProfile.PARTITION1_P1 && hz) {
                continue; // deep-checked below
            }
            if (!Arrays.equals(mine.payload, stock.payload)) {
                throw new FirmwareException("partition " + mine.number
                        + " changed but the variant does not modify it");
            }
        }

        AppPackage.Partition p1 = pkg.partition(release.p1Number);
        if (variant.stockPayloads) {
            if (!Arrays.equals(p1.payload, base.partition(release.p1Number).payload)) {
                throw new FirmwareException("stock payload variant altered Apps P1");
            }
            return pkg;
        }

        FirmwareProfile.requireRetiredIdentityOverridesAbsent(p1.payload);
        if (release.official) {
            // A pinned release is known to ship FiiO's 60-second rollback gate;
            // an unlisted package's timing layout is its own business.
            FirmwareProfile.requireAutoCommitStock(p1.payload);
        }
        if (!FirmwareProfile.matches(p1.payload, release.keyBlockP1Offset, key.qccBlock)
                || !FirmwareProfile.findAll(p1.payload, FirmwareProfile.fiioBlock()).isEmpty()) {
            throw new FirmwareException("developer RSA block is not the single block at its"
                    + " offset");
        }
        if (variant.automute) {
            if (!containsPatchedAutomute(p1.payload)) {
                throw new FirmwareException("automute was requested but the patches are not"
                        + " both present exactly once");
            }
        } else if (release.automute && !containsStockAutomute(p1.payload)) {
            throw new FirmwareException("automute was not requested but the stock timers are"
                    + " not both still in place");
        }
        if (!hz) {
            if (p1.payload.length != release.p1Size) {
                throw new FirmwareException("developer package changed the Apps P1 length");
            }
            return pkg;
        }

        int v7End = release.p1Size + HundredHertzPins.V7_EXTENSION.length;
        int expectedP1 = variant.hundredHertzStage >= 2
                ? v7End + HundredHertzPins.V8_EXTENSION.length : v7End;
        if (p1.payload.length != expectedP1) {
            throw new FirmwareException("Apps P1 length does not match the 100 Hz variant");
        }
        requireTail(p1.payload, release.p1Size, HundredHertzPins.V7_EXTENSION);
        if (variant.hundredHertzStage >= 2) {
            requireTail(p1.payload, v7End, HundredHertzPins.V8_EXTENSION);
        }
        verifySizeWord(pkg.partition(FirmwareProfile.PARTITION1_P1).payload,
                base.partition(FirmwareProfile.PARTITION1_P1).payload,
                variant.hundredHertzStage >= 2
                        ? HundredHertzPins.PARTITION1_P1_SIZE_V8
                        : HundredHertzPins.PARTITION1_P1_SIZE_V7);
        return pkg;
    }

    // ---- patch primitives ---------------------------------------------------

    private static byte[] applyAutomute(byte[] p1, List<String> names) throws FirmwareException {
        byte[] out = p1.clone();
        for (int site = 0; site < FirmwareProfile.AUTOMUTE_CONTEXTS.length; site++) {
            byte[] context = Util.hex(FirmwareProfile.AUTOMUTE_CONTEXTS[site]);
            List<Integer> hits = FirmwareProfile.findAll(out, context);
            if (hits.size() != 1) {
                throw new FirmwareException("automute anchor " + site + " matched "
                        + hits.size() + " times, expected exactly one");
            }
            int at = hits.get(0);
            if (!FirmwareProfile.matches(out, at, FirmwareProfile.AUTOMUTE_BEFORE)) {
                throw new FirmwareException("automute anchor did not begin with the live instruction");
            }
            System.arraycopy(FirmwareProfile.AUTOMUTE_AFTER, 0, out, at, 2);
            names.add(site == 0 ? "left_dac_automute_timer" : "right_dac_automute_timer");
        }
        return out;
    }

    private static byte[] applyDeveloperKey(byte[] p1, DevKey key, List<String> names, int at)
            throws FirmwareException {
        byte[] fiio = FirmwareProfile.fiioBlock();
        List<Integer> hits = FirmwareProfile.findAll(p1, fiio);
        if (hits.size() != 1 || hits.get(0) != at) {
            throw new FirmwareException("FiiO RSA block is not the single pinned block");
        }
        byte[] out = p1.clone();
        System.arraycopy(key.qccBlock, 0, out, at, FirmwareProfile.QCC_BLOCK_SIZE);
        names.add("upgrade_release_key");
        return out;
    }

    /**
     * Apply one pinned 100 Hz stage. Every site is validated against the
     * stage's pre-edit snapshot (later sites deliberately see the bytes the
     * earlier sites will have rewritten in the previous stage, not in this
     * one), then all sites are applied, then the extension is appended at its
     * pinned offset. Any mismatch aborts without touching the caller's bytes.
     */
    private static byte[] applyHundredHertzStage(byte[] p1, HundredHertzPins.Site[] sites,
                                                 byte[] extension, int extensionP1Offset,
                                                 String extensionSha, List<String> names,
                                                 String label) throws FirmwareException {
        if (p1.length != extensionP1Offset) {
            throw new FirmwareException(label + ": P1 length " + p1.length
                    + " does not match the pinned extension offset " + extensionP1Offset);
        }
        if (!Util.sha256Hex(extension).equalsIgnoreCase(extensionSha)) {
            throw new FirmwareException(label + ": extension body digest changed");
        }
        byte[] snapshot = p1.clone();
        int keyWindowStart = FirmwareProfile.FIIO_BLOCK_P1_OFFSET;
        int keyWindowEnd = keyWindowStart + FirmwareProfile.QCC_BLOCK_SIZE;
        for (HundredHertzPins.Site site : sites) {
            int end = site.offset + site.before.length;
            if (site.offset < keyWindowEnd && end > keyWindowStart) {
                throw new FirmwareException(label + ": site 0x"
                        + Integer.toHexString(site.offset) + " overlaps the key block window");
            }
            if (end > snapshot.length) {
                throw new FirmwareException(label + ": site 0x"
                        + Integer.toHexString(site.offset) + " runs past the end of P1");
            }
            if (!FirmwareProfile.matches(snapshot, site.offset - site.contextBefore.length,
                    site.contextBefore)) {
                throw new FirmwareException(label + ": context before 0x"
                        + Integer.toHexString(site.offset) + " changed");
            }
            if (!FirmwareProfile.matches(snapshot, site.offset, site.before)) {
                throw new FirmwareException(label + ": bytes at 0x"
                        + Integer.toHexString(site.offset) + " changed");
            }
        }
        byte[] out = Arrays.copyOf(snapshot, snapshot.length + extension.length);
        System.arraycopy(extension, 0, out, extensionP1Offset, extension.length);
        for (HundredHertzPins.Site site : sites) {
            System.arraycopy(site.after, 0, out, site.offset, site.after.length);
        }
        names.add(label);
        return out;
    }

    /** Rewrite the Apps P1 length word inside partition 1 (u16 LE at offset 80). */
    private static byte[] applySizeWordEdit(byte[] partition1, byte[] after, String label)
            throws FirmwareException {
        byte[] out = partition1.clone();
        int at = HundredHertzPins.PARTITION1_P1_SIZE_WORD_OFFSET;
        if (!FirmwareProfile.matches(out, at, HundredHertzPins.PARTITION1_P1_SIZE_CANDIDATE)
                && !FirmwareProfile.matches(out, at, HundredHertzPins.PARTITION1_P1_SIZE_V7)) {
            throw new FirmwareException(label + ": size word is neither the candidate nor V7 value");
        }
        if (FirmwareProfile.matches(out, at, after)) {
            throw new FirmwareException(label + ": size word already rewritten");
        }
        System.arraycopy(after, 0, out, at, after.length);
        return out;
    }

    // ---- verification primitives -------------------------------------------

    private static boolean containsPatchedAutomute(byte[] p1) {
        for (String contextHex : FirmwareProfile.AUTOMUTE_CONTEXTS) {
            byte[] context = Util.hex(contextHex);
            byte[] patched = new byte[context.length];
            patched[0] = FirmwareProfile.AUTOMUTE_AFTER[0];
            patched[1] = FirmwareProfile.AUTOMUTE_AFTER[1];
            System.arraycopy(context, 2, patched, 2, context.length - 2);
            if (FirmwareProfile.findAll(p1, patched).size() != 1
                    || !FirmwareProfile.findAll(p1, context).isEmpty()) {
                return false;
            }
        }
        return true;
    }

    /**
     * True when both automute sites still hold FiiO's stock timer instruction —
     * the exact bytes the patch would replace, each present exactly once and
     * none of them already patched.
     */
    private static boolean containsStockAutomute(byte[] p1) {
        for (String contextHex : FirmwareProfile.AUTOMUTE_CONTEXTS) {
            byte[] context = Util.hex(contextHex);
            java.util.List<Integer> hits = FirmwareProfile.findAll(p1, context);
            if (hits.size() != 1) {
                return false;
            }
            if (!FirmwareProfile.matches(p1, hits.get(0), FirmwareProfile.AUTOMUTE_BEFORE)) {
                return false;
            }
        }
        return true;
    }

    private static void requireTail(byte[] p1, int offset, byte[] expected) throws FirmwareException {
        if (offset + expected.length > p1.length
                || !Arrays.equals(Arrays.copyOfRange(p1, offset, offset + expected.length), expected)) {
            throw new FirmwareException("appended 100 Hz extension differs from the pinned body");
        }
    }

    private static void verifySizeWord(byte[] partition1, byte[] officialPartition1, byte[] expected)
            throws FirmwareException {
        if (!FirmwareProfile.matches(partition1,
                HundredHertzPins.PARTITION1_P1_SIZE_WORD_OFFSET, expected)) {
            throw new FirmwareException("partition 1 Apps size word was not rewritten");
        }
        for (int i = 0; i < partition1.length; i++) {
            boolean isWord = i >= HundredHertzPins.PARTITION1_P1_SIZE_WORD_OFFSET
                    && i < HundredHertzPins.PARTITION1_P1_SIZE_WORD_OFFSET + expected.length;
            if (!isWord && partition1[i] != officialPartition1[i]) {
                throw new FirmwareException("partition 1 changed outside the Apps size word");
            }
        }
    }

    // ---- helpers -----------------------------------------------------------

    private static int countChanged(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        int changed = Math.abs(a.length - b.length);
        for (int i = 0; i < n; i++) {
            if (a[i] != b[i]) {
                changed++;
            }
        }
        return changed;
    }
}
