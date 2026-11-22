package app.btr15.tool;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The official BTR15 Bluetooth releases this tool can patch, one profile each.
 *
 * <p>Every profile pins only what a build and its re-verification need: the
 * package's own size and digest (the identity a user can hand us), its upgrade
 * id, the Apps P1 size and digest, the manifest's partition sizes, where FiiO's
 * 514-byte RSA constant block sits inside that P1, and which of the two optional
 * patches the release's code can take.  The container, the signing scheme, the
 * upgrade state machine and the journal vectors are identical in all of them —
 * only these numbers move.
 *
 * <p>The block's offset is pinned <em>and</em> proven by searching for the
 * block's own bytes, so a future release that relocates it can never be patched
 * in the wrong place: the search must find exactly one block, and it must be the
 * one the profile names.
 */
final class FirmwareReleases {

    /** One official release, as the engine needs it. */
    static final class Release {
        /** How the screen names it, e.g. {@code v3.8}. */
        final String label;
        final int size;
        final String sha256;
        final long upgradeId;
        /** Official payload manifest: {type, number, size} in record order. */
        final int[][] manifest;
        final int p1Number;
        final int p1Size;
        final String p1Sha256;
        /** Where FiiO's own constant block sits, inside Apps P1. */
        final int keyBlockP1Offset;
        /** The automute timer pair exists in this P1 (v3.5 and newer). */
        final boolean automute;
        /** The 100 Hz menu has been written against this exact P1 (v3.8 only). */
        final boolean hundredHertz;
        /** The full audited v3.8 profile applies, not just the generic checks. */
        final boolean audited;
        /** True for the pinned table; false for a package described from its own bytes. */
        final boolean official;

        Release(String label, int size, String sha256, long upgradeId, int[][] manifest,
                int p1Number, int p1Size, String p1Sha256, int keyBlockP1Offset, boolean automute,
                boolean hundredHertz, boolean audited, boolean official) {
            this.label = label;
            this.size = size;
            this.sha256 = sha256;
            this.upgradeId = upgradeId;
            this.manifest = manifest;
            this.p1Number = p1Number;
            this.p1Size = p1Size;
            this.p1Sha256 = p1Sha256;
            this.keyBlockP1Offset = keyBlockP1Offset;
            this.automute = automute;
            this.hundredHertz = hundredHertz;
            this.audited = audited;
            this.official = official;
        }

        @Override public String toString() {
            return label;
        }
    }

    private static final int[][] MANIFEST_V22 = {
        {0, 0, 16}, {0, 1, 272}, {0, 4, 10_872}, {0, 5, 572_112},
        {0, 6, 69_968}, {0, 7, 551_772}, {0, 9, 634_380},
    };
    private static final int[][] MANIFEST_V35 = {
        {0, 0, 16}, {0, 1, 272}, {0, 4, 10_872}, {0, 5, 572_112},
        {0, 6, 69_968}, {0, 7, 642_960}, {0, 9, 635_812},
    };
    private static final int[][] MANIFEST_V38 = {
        {0, 0, 16}, {0, 1, 272}, {0, 4, 10_872}, {0, 5, 572_112},
        {0, 6, 69_968}, {0, 7, 642_960}, {0, 9, 635_832},
    };
    private static final int[][] MANIFEST_V44 = {
        {0, 0, 16}, {0, 1, 272}, {0, 4, 10_872}, {0, 5, 572_112},
        {0, 6, 69_968}, {0, 7, 642_960}, {0, 9, 631_068},
    };

    static final Release V22 = new Release("v2.2", 1_839_820,
            "23cd28fe60d6613cbf6e099a0181234283a92880b36fd1f500ae2405dc9f1993",
            0x1c95a78bL, MANIFEST_V22, 9, 634_380,
            "38c8a668f875c3318a6090ee258348ba71dee766cbdec1f4c7aa73b9e2ebf587",
            0x9611C, false, false, false, true);

    static final Release V35 = new Release("v3.5", 1_932_440,
            "ead376aba18e344680df8dbebfd13014a16114f8aab684b2b57a78e7022d74b6",
            0x4aeb3355L, MANIFEST_V35, 9, 635_812,
            "d92af415c25fbf2108cc7cd5131723938909583675e605ad37ad1ce7e54ec859",
            0x966A8, true, false, false, true);

    static final Release V38 = new Release("v3.8", FirmwareProfile.SIZE,
            FirmwareProfile.SHA256, FirmwareProfile.UPGRADE_ID, MANIFEST_V38,
            FirmwareProfile.P1_NUMBER, FirmwareProfile.P1_SIZE, FirmwareProfile.P1_SHA256,
            FirmwareProfile.FIIO_BLOCK_P1_OFFSET, true, true, true, true);

    static final Release V44 = new Release("v4.4", 1_927_696,
            "940e15176fbaa8c037afa6e78d9bc1d294bcb101947e4a695f38652ba90da1a8",
            0x358c1f0dL, MANIFEST_V44, 9, 631_068,
            "df4b10f0ab0d2badf5c810aeb25ac0d75c4be28326554a21e20906ed8a8dad6f",
            0x95420, true, false, false, true);

    /** Newest first: the order the firmware screen lists them in. */
    static final List<Release> ALL = java.util.Collections.unmodifiableList(
            Arrays.asList(V44, V38, V35, V22));

    private FirmwareReleases() { }

    /** The profile whose digest this file claims to be, or null when unknown. */
    static Release byDigest(byte[] blob) {
        return blob == null ? null : byDigestHex(Util.sha256Hex(blob), blob.length);
    }

    /** The profile a picked file belongs to, from the digest the picker already has. */
    static Release byDigestHex(String sha256, long size) {
        if (sha256 == null) {
            return null;
        }
        String lower = sha256.toLowerCase(java.util.Locale.ROOT);
        for (Release release : ALL) {
            if (release.size == size && release.sha256.equals(lower)) {
                return release;
            }
        }
        return null;
    }

    /** "v2.2, v3.5, v3.8 or v4.4", for messages that must name the scope. */
    static String labels() {
        List<String> names = new ArrayList<>();
        for (Release release : ALL) {
            names.add(release.label);
        }
        java.util.Collections.reverse(names);
        StringBuilder text = new StringBuilder();
        for (int index = 0; index < names.size(); index++) {
            if (index > 0) {
                text.append(index == names.size() - 1 ? " or " : ", ");
            }
            text.append(names.get(index));
        }
        return text.toString();
    }

    /**
     * The Method step's one-line scope under "Jailbreak / first install".
     *
     * <p>It names what the jailbreak was written and tested against, and nothing
     * more: the step still offers the jailbreak for any firmware, because
     * susceptibility is the user's call and the firmware step is where a package
     * that cannot be patched is refused.
     */
    static String jailbreakScope() {
        return "Supported firmware: " + labels();
    }

    /**
     * Prove the bytes are one of the pinned official releases and return its
     * profile.  Generic checks run for every release; v3.8 additionally keeps
     * its full audited profile (per-partition digests and the identity gates).
     */
    static Release identify(byte[] blob) throws FirmwareException {
        Release release = byDigest(blob);
        if (release == null) {
            throw new FirmwareException("This package has no pinned release profile ("
                    + labels() + "); it has to be described from its own bytes");
        }
        AppPackage pkg = AppPackage.parse(blob);
        if (pkg.partitions.size() != release.manifest.length) {
            throw new FirmwareException(release.label + ": partition count changed");
        }
        for (int index = 0; index < release.manifest.length; index++) {
            AppPackage.Partition partition = pkg.partitions.get(index);
            int[] expected = release.manifest[index];
            if (partition.type != expected[0] || partition.number != expected[1]
                    || partition.payload.length != expected[2]) {
                throw new FirmwareException(release.label + ": manifest entry " + index
                        + " changed");
            }
        }
        if (pkg.upgradeId() != release.upgradeId) {
            throw new FirmwareException(release.label + ": official upgrade id changed");
        }
        if (!Pss.verify(FirmwareProfile.fiioModulus(), pkg.signature, pkg.signedContent())) {
            throw new FirmwareException(release.label + ": base package does not verify under"
                    + " the FiiO release key");
        }
        byte[] p1 = pkg.partition(release.p1Number).payload;
        if (p1.length != release.p1Size
                || !Util.sha256Hex(p1).equalsIgnoreCase(release.p1Sha256)) {
            throw new FirmwareException(release.label + ": Apps P1 does not match the audited"
                    + " image");
        }
        byte[] stock = FirmwareProfile.fiioBlock();
        List<Integer> blocks = FirmwareProfile.findAll(p1, stock);
        if (blocks.size() != 1 || blocks.get(0) != release.keyBlockP1Offset) {
            throw new FirmwareException(release.label + ": FiiO RSA block is not the single block"
                    + " at 0x" + Integer.toHexString(release.keyBlockP1Offset));
        }
        FirmwareProfile.requireRetiredIdentityOverridesAbsent(p1);
        FirmwareProfile.requireAutoCommitStock(p1);
        if (release.audited) {
            FirmwareProfile.requireOfficialV38(blob);
        }
        return release;
    }

    /**
     * The engine's description of any package the user picked: the pinned
     * profile when the digest is one of the four, otherwise the facts read out
     * of the file itself.  This is what makes the tool versatile without
     * guessing — an unlisted package is accepted only when FiiO's own signature
     * verifies and its 514-byte key block can be found in exactly one place,
     * which is precisely what has to be true for the block to be replaced
     * safely.
     */
    static Release describe(byte[] blob) throws FirmwareException {
        Release pinned = byDigest(blob);
        return pinned != null ? identify(blob) : discover(blob);
    }

    /** Read the engine's facts out of a package that is not in the pinned table. */
    private static Release discover(byte[] blob) throws FirmwareException {
        AppPackage pkg = AppPackage.parse(blob);
        if (!Pss.verify(FirmwareProfile.fiioModulus(), pkg.signature, pkg.signedContent())) {
            throw new FirmwareException("This package is not signed with FiiO's release key");
        }
        byte[] stock = FirmwareProfile.fiioBlock();
        AppPackage.Partition carrying = null;
        int at = 0;
        for (AppPackage.Partition partition : pkg.partitions) {
            List<Integer> hits = FirmwareProfile.findAll(partition.payload, stock);
            if (hits.isEmpty()) {
                continue;
            }
            if (hits.size() > 1 || carrying != null) {
                throw new FirmwareException("FiiO's 514-byte key block is not in exactly one"
                        + " place in this package");
            }
            carrying = partition;
            at = hits.get(0).intValue();
        }
        if (carrying == null) {
            throw new FirmwareException("FiiO's 514-byte key block could not be found in this"
                    + " package, so it cannot be replaced safely");
        }
        if (carrying.type != 0) {
            throw new FirmwareException("FiiO's key block is not inside a firmware payload");
        }
        int[][] manifest = new int[pkg.partitions.size()][3];
        for (int index = 0; index < manifest.length; index++) {
            AppPackage.Partition partition = pkg.partitions.get(index);
            manifest[index][0] = partition.type;
            manifest[index][1] = partition.number;
            manifest[index][2] = partition.payload.length;
        }
        byte[] partition1;
        try {
            partition1 = pkg.partition(FirmwareProfile.PARTITION1_P1).payload;
        } catch (FirmwareException absent) {
            partition1 = new byte[0]; // no size-word carrier: the 100 Hz probe fails on its own
        }
        FirmwareEngine.PatchSupport patches = FirmwareEngine.probePatches(carrying.payload,
                partition1);
        FirmwareProfile.requireRetiredIdentityOverridesAbsent(carrying.payload);
        return new Release("unrecognized", blob.length, Util.sha256Hex(blob), pkg.upgradeId(),
                manifest, carrying.number, carrying.payload.length, carrying.sha256Hex(), at,
                patches.automute, patches.hundredHertz, false, false);
    }
}
