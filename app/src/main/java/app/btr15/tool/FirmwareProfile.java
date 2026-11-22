package app.btr15.tool;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Pinned facts about the official FiiO BTR15 v3.8 firmware, the only base
 * this tool may patch.
 *
 * <p>The digests are the audited values of the released package: the whole
 * file, the manifest, every partition payload, and the 514-byte Qualcomm
 * RSA/Montgomery constant block that lives inside Apps P1.  A base package
 * must reproduce them, carry a signature that verifies under the FiiO release
 * key, and show no trace of the two retired Bluetooth-identity experiments or
 * of the retired auto-commit patch, or every build is refused.
 */
final class FirmwareProfile {
    static final int SIZE = 1_932_460;
    static final String SHA256 =
            "26b21c1779bd9229b7256a055b1d1e55834a0ee48e500b6e0c952206911fdb39";
    static final int P1_NUMBER = 9;
    static final int P1_SIZE = 635_832;
    static final String P1_SHA256 =
            "94a11359efb932897c1406d02199ce9b42a62f9ee0c53ff7e40f5acdb51db113";
    static final String SIGNED_CONTENT_SHA256 =
            "35202961cd1fb56abd1b1a4890e1533796ebddf6587a995aebeba0a8628c960c";
    static final long UPGRADE_ID = 0x1771c19eL;
    static final int PARTITION1_P1 = 1;

    /** 514-byte RSA/Montgomery constant block location and FiiO identities. */
    static final int QCC_BLOCK_SIZE = 514;
    static final int FIIO_BLOCK_P1_OFFSET = 0x966BC;
    static final String FIIO_BLOCK_SHA256 =
            "18fdf35d72fb776bbec471924f570b331db6822af6b665c1f09696d11be12cdf";
    static final String FIIO_MODULUS_HEX =
            "b4d9af43f43b603ee78c32bea167560b841628a633be8ac3f9ce4a14f6eb2f71"
          + "f3b9d21438b010670226ff953dfadf68b78b86eccce30e16870adaa012a8f51c"
          + "d99c2fe3742d880bf81580e20082972fdc895130775b0a4598f6d9331fb80d39"
          + "c6a5dfefa4a9df0a2a36d1e78dafc44f0ac2113cd072d8da713f14b6a73808b4"
          + "60d160fa5a7430f201bdff24fcf099db2014058ca60c469906cbb5a1aafc92"
          + "b4f57315477ac78a2f4bc39ba31b7eb379ec64996d3971df70dbe265577476a"
          + "1d550088656bcc4e5610a22c05ff1ff2e44d2ffb9e046a071b3d01150340ca4"
          + "e69e9602b2fff47472cc277c0f44e5c745278304fb9771262519cac24673957c"
          + "040b";

    /** Official payload manifest: {type, number, size} in record order. */
    static final int[][] MANIFEST = {
        {0, 0, 16}, {0, 1, 272}, {0, 4, 10_872}, {0, 5, 572_112},
        {0, 6, 69_968}, {0, 7, 642_960}, {0, 9, P1_SIZE},
    };
    static final String[] MANIFEST_PAYLOAD_SHA256 = {
        "7086698371ad11cf55cc9a16e1603b3849aa767285b2ae0c7f1a5dc057c4d3aa",
        "9090d2c29adbd4b7561aa679dd59e99fd807185549f9df7651262df56d770e12",
        "6099b860d021ace3c19fb8dbe1121b1ce8655de7e9bbd73b5e054bc7e060cd45",
        "ce6c46255accbb514ea8b606fbe4182a4ecd712ffccdef1432424783c1d22424",
        "fcc6a69601700ec606a33e48c399e4e562644869b556280110c191b2420b9e39",
        "b00d08968b55443d42b12e945fe0fe39028d2d54b9377ccada534155a385641e",
        P1_SHA256,
    };

    /** ES9219 automute timer: register 4 timer value 3 -> 0, exactly two sites. */
    static final String[] AUTOMUTE_CONTEXTS = {
        "c4200321b29211f035eb066e0321b292", // left  dac
        "c4200321729211f025ea066e03217292", // right dac
    };
    static final byte[] AUTOMUTE_BEFORE = Util.hex("c420");
    static final byte[] AUTOMUTE_AFTER = Util.hex("0400");

    /**
     * Retired auto-commit patch (never apply, never ship): a jailbreak or OTA
     * candidate must keep the stock 60-second rollback gate so commit stays a
     * deliberate, host-driven step.
     */
    static final byte[] AUTOCOMMIT_STOCK_CONTEXT = Util.hex("fbff3be4300418601004166201f025e8");
    static final byte[] AUTOCOMMIT_PATCHED_CONTEXT = Util.hex("fbff3be4300416001004166201f025e8");

    /** Retired Bluetooth-identity overrides that must never appear. */
    static final int CL_INIT_HOOK_P1_OFFSET = 0x061CE;
    static final byte[] CL_INIT_STOCK = Util.hex("10f333e5");
    static final int IDENTITY_INIT_P1_OFFSET = 0x2850E;
    static final byte[] IDENTITY_STOCK_PREFIX = Util.hex(
            "f41c87f0405b01092071022286f237e316003a280322bff22be5422044083300"
          + "97f237ef2ff800c20e62f186f99cb18639ab31e68ac6");
    static final byte[] IDENTITY_REPLACEMENT = Util.hex(
            "f11c86f0405b01f001f6ed78318f01f0984031ab21f0ed40f19c322883f220ef"
          + "f148d84c");
    static final byte[] IDENTITY_POSTINIT_BODY = Util.hex(
            "f11c86f0405b01f001f6ed78318f01f0984031ab21f0ed40f19c4220f148d84c"
          + "f11c160082f0505b83f234ee3200fef124eaf148d84c");

    private FirmwareProfile() { }

    static BigInteger fiioModulus() {
        return new BigInteger(1, Util.hex(FIIO_MODULUS_HEX));
    }

    /**
     * Rebuild the exact 514-byte constant block for the FiiO release key:
     * byte-swapped big-endian modulus, m_dash little-endian, then the
     * byte-swapped 2^4096 mod n Montgomery R-squared.
     */
    static byte[] fiioBlock() {
        BigInteger modulus = fiioModulus();
        byte[] block = new byte[QCC_BLOCK_SIZE];
        byte[] modulusBigEndian = DevKey.toFixed(modulus, 256);
        System.arraycopy(DevKey.swapUint16(modulusBigEndian), 0, block, 0, 256);
        int low16 = ((modulusBigEndian[254] & 0xFF) << 8) | (modulusBigEndian[255] & 0xFF);
        int mDash = BigInteger.valueOf(low16).modInverse(BigInteger.valueOf(1L << 16))
                .negate().mod(BigInteger.valueOf(1L << 16)).intValue();
        block[256] = (byte) mDash;
        block[257] = (byte) (mDash >>> 8);
        BigInteger rSquared = BigInteger.valueOf(2).modPow(BigInteger.valueOf(4096), modulus);
        System.arraycopy(DevKey.swapUint16(DevKey.toFixed(rSquared, 256)), 0, block, 258, 256);
        return block;
    }

    /** Verify a candidate base is exactly the audited official v3.8 package. */
    static AppPackage requireOfficialV38(byte[] blob) throws FirmwareException {
        if (blob.length != SIZE || !Util.sha256Hex(blob).equalsIgnoreCase(SHA256)) {
            throw new FirmwareException(
                    "base firmware is not the official BTR15 v3.8 release package");
        }
        AppPackage pkg = AppPackage.parse(blob);
        if (pkg.partitions.size() != MANIFEST.length) {
            throw new FirmwareException("official manifest partition count changed");
        }
        for (int index = 0; index < MANIFEST.length; index++) {
            AppPackage.Partition partition = pkg.partitions.get(index);
            if (partition.type != MANIFEST[index][0]
                    || partition.number != MANIFEST[index][1]
                    || partition.payload.length != MANIFEST[index][2]
                    || !partition.sha256Hex().equalsIgnoreCase(MANIFEST_PAYLOAD_SHA256[index])) {
                throw new FirmwareException("official manifest entry " + index + " changed");
            }
        }
        byte[] signed = pkg.signedContent();
        if (!Util.sha256Hex(signed).equalsIgnoreCase(SIGNED_CONTENT_SHA256)) {
            throw new FirmwareException("official signed content digest changed");
        }
        if (pkg.upgradeId() != UPGRADE_ID) {
            throw new FirmwareException("official upgrade id changed");
        }
        if (!Pss.verify(fiioModulus(), pkg.signature, signed)) {
            throw new FirmwareException(
                    "base package does not verify under the FiiO release key");
        }
        byte[] p1 = pkg.partition(P1_NUMBER).payload;
        if (p1.length != P1_SIZE || !Util.sha256Hex(p1).equalsIgnoreCase(P1_SHA256)) {
            throw new FirmwareException("official Apps P1 does not match the audited image");
        }
        byte[] block = Arrays.copyOfRange(p1, FIIO_BLOCK_P1_OFFSET,
                FIIO_BLOCK_P1_OFFSET + QCC_BLOCK_SIZE);
        if (!Util.sha256Hex(block).equalsIgnoreCase(FIIO_BLOCK_SHA256)
                || !Arrays.equals(block, fiioBlock())) {
            throw new FirmwareException("FiiO RSA constant block moved or changed");
        }
        requireStockIdentityGates(p1);
        requireRetiredIdentityOverridesAbsent(p1);
        requireAutoCommitStock(p1);
        return pkg;
    }

    /** The untouched image must still carry both stock identity code sites. */
    static void requireStockIdentityGates(byte[] p1) throws FirmwareException {
        if (p1.length == P1_SIZE && !Arrays.equals(Arrays.copyOfRange(
                p1, CL_INIT_HOOK_P1_OFFSET, CL_INIT_HOOK_P1_OFFSET + 4), CL_INIT_STOCK)) {
            throw new FirmwareException("v3.8 CL_INIT identity-hook site is not stock");
        }
        if (p1.length == P1_SIZE && !Arrays.equals(Arrays.copyOfRange(
                p1, IDENTITY_INIT_P1_OFFSET,
                IDENTITY_INIT_P1_OFFSET + IDENTITY_STOCK_PREFIX.length), IDENTITY_STOCK_PREFIX)) {
            throw new FirmwareException("v3.8 identity-function prefix is not stock");
        }
    }

    /** Fail closed if either rejected v3.8 runtime identity patch appears. */
    static void requireRetiredIdentityOverridesAbsent(byte[] p1) throws FirmwareException {
        if (!findAll(p1, IDENTITY_REPLACEMENT).isEmpty()) {
            throw new FirmwareException("retired early Bluetooth identity override is present");
        }
        if (!findAll(p1, IDENTITY_POSTINIT_BODY).isEmpty()) {
            throw new FirmwareException("retired post-Connection-init identity body is present");
        }
        if (p1.length == P1_SIZE && !Arrays.equals(Arrays.copyOfRange(
                p1, CL_INIT_HOOK_P1_OFFSET, CL_INIT_HOOK_P1_OFFSET + 4), CL_INIT_STOCK)) {
            throw new FirmwareException("v3.8 CL_INIT identity-hook site is not stock");
        }
        if (p1.length == P1_SIZE && !Arrays.equals(Arrays.copyOfRange(
                p1, IDENTITY_INIT_P1_OFFSET,
                IDENTITY_INIT_P1_OFFSET + IDENTITY_STOCK_PREFIX.length), IDENTITY_STOCK_PREFIX)) {
            throw new FirmwareException("v3.8 identity-function prefix is not stock");
        }
    }

    /** The 60-second rollback gate must remain exactly as FiiO shipped it. */
    static void requireAutoCommitStock(byte[] p1) throws FirmwareException {
        if (!findAll(p1, AUTOCOMMIT_PATCHED_CONTEXT).isEmpty()) {
            throw new FirmwareException("retired auto-commit patch must never be shipped");
        }
        if (findAll(p1, AUTOCOMMIT_STOCK_CONTEXT).isEmpty()) {
            throw new FirmwareException("Apps auto-commit gate context is missing from P1");
        }
    }

    static java.util.List<Integer> findAll(byte[] blob, byte[] needle) {
        java.util.List<Integer> hits = new java.util.ArrayList<>();
        for (int start = 0; start + needle.length <= blob.length; start++) {
            if (matches(blob, start, needle)) {
                hits.add(start);
            }
        }
        return hits;
    }

    static boolean matches(byte[] blob, int offset, byte[] needle) {
        if (offset < 0 || offset + needle.length > blob.length) {
            return false;
        }
        for (int i = 0; i < needle.length; i++) {
            if (blob[offset + i] != needle[i]) {
                return false;
            }
        }
        return true;
    }
}
