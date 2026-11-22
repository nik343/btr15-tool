package app.btr15.tool;

/**
 * Pinned 100 Hz / 100 Hz2 Apps P1 edit chain for the offline firmware engine.
 *
 * <p>Generated from work/btr15_android_port_assets/pinned_edit_plan.json (see
 * tools/extract_btr15_100hz_pinned_diff.py, whose reconstruction was verified
 * byte-exact against the live-flashed V7 and V8 packages).  Stage order is
 * fixed: candidate -> V7 sites -> V7 extension -> V8 sites -> V8 extension.
 * The V8 stage rewrites parts of the V7 stage, so the chain must run whole.
 *
 * <p>Every in-place site carries its P1 offset, the eight bytes that must
 * precede it, and the exact before/after bytes; any mismatch aborts the
 * build.  The appended extension bodies are carried as base64 below and are
 * checked against their pinned SHA-256 digests before use.  The Apps P1 size
 * word inside partition 1 (payload offset 80, uint16 little-endian) is
 * rewritten last so the image header agrees with the new P1 length.
 */
final class HundredHertzPins {

    static final class Site {
        final int offset;
        final byte[] contextBefore;
        final byte[] before;
        final byte[] after;

        private Site(int offset, byte[] contextBefore, byte[] before, byte[] after) {
            this.offset = offset;
            this.contextBefore = contextBefore;
            this.before = before;
            this.after = after;
        }
    }

    static final Site[] V7_SITES = {
        site(32766, "3bea902405600200", "1bf035e7", "9bf42beb"),
        site(33070, "2be1902405605208", "1af025ee", "9bf43be1"),
        site(44974, "0200f4ff23e07282", "01", "41"),
        site(45000, "046612f039e2036e", "12f021e4", "83f437ee"),
        site(45006, "036e12f021e47282", "01", "41"),
        site(50186, "2bed08f002f13d93", "01", "41"),
        site(50196, "8a4cca4c52540ff0", "11", "13"),
        site(50199, "4c52540ff011f021", "f2e2b8", "f1eea8"),
        site(50418, "c81c08f003f13d93", "01", "41"),
        site(54260, "f11c08f002f13d93", "01", "41"),
        site(54306, "f11c08f002f13d93", "01", "41"),
        site(54352, "f11c08f002f13d93", "01", "41"),
        site(580776, "e7ee00005beb0000", "13ec00", "3fb809"),
    };
    static final int V7_EXTENSION_P1_OFFSET = 635832;
    static final String V7_EXTENSION_SHA256 = "fda769d7f40962d8462ba0f05a0142d5eb45c03d80469c16a8dc5d50e274974b";

    static final Site[] V8_SITES = {
        site(32766, "3bea902405600200", "9b", "9d"),
        site(32768, "9024056002009bf4", "2beb", "33e7"),
        site(33070, "2be1902405605208", "9b", "9c"),
        site(33072, "9024056052089bf4", "3be1", "23ee"),
        site(44974, "0200f4ff23e07282", "41", "81"),
        site(45000, "046612f039e2036e", "83", "85"),
        site(45002, "12f039e2036e83f4", "37ee", "3be5"),
        site(45006, "036e83f437ee7282", "41", "81"),
        site(50186, "2bed08f002f13d93", "41", "81"),
        site(50200, "52540ff013f021f1", "eea8", "31b8"),
        site(50418, "c81c08f003f13d93", "41", "81"),
        site(54260, "f11c08f002f13d93", "41", "81"),
        site(54306, "f11c08f002f13d93", "41", "81"),
        site(54352, "f11c08f002f13d93", "41", "81"),
        site(580776, "e7ee00005beb0000", "3fb8", "57ba"),
    };
    static final int V8_EXTENSION_P1_OFFSET = 637124;
    static final String V8_EXTENSION_SHA256 = "18c66e9e008bd6d06e71635699679e5aeb819bd9fc05d10c4dca622b55f0410c";

    /** Apps P1 length word: uint16 little-endian at payload offset 80. */
    static final int PARTITION1_P1_SIZE_WORD_OFFSET = 80;
    static final byte[] PARTITION1_P1_SIZE_CANDIDATE = Util.hex("b8b3");
    static final byte[] PARTITION1_P1_SIZE_V7 = Util.hex("c4b8");
    static final byte[] PARTITION1_P1_SIZE_V8 = Util.hex("0abc");

    static final byte[] V7_EXTENSION = Util.unbase64(
            "HcQAACPEAAApxAAAL8QAADXEAAA7xAAAQcQAAEfEAABNxAAAU8QAAFnEAABfxAAAN7gJAPYcAfBU8xDPUSCJxhDwYCQCaAEAL/JS"
            + "1pLGQt4v8VHWSd4BMOHwaIvg8GmLQjDi8GqL4fBriwLwf0Di8GyLgjDi8G2L4PBui8Ii4vBvi+HwcIuBIOHwcYsDIoJWAfA94kLY"
            + "klhS3krYklha3mDeYdjJQGnecN6BFHneathx2IoAgN5R2FAEBmJB2AnBAPGT3oPeWdhQBAhiSdgJwQDxk96B2MkSgd4DCQEARHEO"
            + "TC/xU9abxpxYEAUGYhvBAPOT3gDze8gJI4nGedgB8trYid4BCQcADG4HAJDwACQFbJDwRyQCaofYkPADJARqAPt3yBpukPBTJBdo"
            + "kPBaJBRmL/lY1gYAr/YBwC/xUtaEIUMI804QBAVgMQAA8ZLevxJ2IDAm8WWJ2BfwCeoJdZDwYCTTZXHYSSBx3nnYAfBgRHnecdjI"
            + "JJtlA/AgQYIUj/sz7WHYSSBh3ggli2WDIAJXrU7+8KzzEM/2SNhMGCcDaAIAWm4QBBliGAQDYgI4VG5YJARiAvDwQE9umCQEYgLw"
            + "8EFKbtgkBGIC8LBBRW6YJu5pAvD/Q0BuUCQDYJAkFmJYJANsmCYEaALw/EA1bpgkA2BYJgRiAvADQy5umSQD8ZLeA/AD8lLYJ27Q"
            + "JAZiWCXhYZgl32Hwb1gk3G2YJtpnmCQDYsIgGG7YJANiwiMUbhglA2ICIxBuWCUDYgI7DG6YJblh2CW3YQHwwEMC8ABDGCYA8QLA"
            + "2EwYJQNsAgBFbhAEEWJYJARiAvBCQD5umCQEYgLwf0A5bgLwQEDYJAHwAsAzblAkA2CQJBRiGAQDYoI7K25YJARiAvBRQCZumCQE"
            + "YgLwSUAhbtgk82MC8EVAHG7QJApiGATdYQEiAvB/QBglAfECwBFuGAQEYgLwYUAMblgk4mGYJOVhAfBDQALwRUDYJAHxAsDYTPIc"
            + "FwAeAAPwQEAEAAIA7v476gMwBAACAO7+MeozADoAjvsp7gQwIwACAO7+P+kE8EBAIwACAO7+M+nySNhM8RxQNAhokD8GZhgFBGjh"
            + "IVgEA2gCABZuJfPfO4EhjUzCTJFBaQSJxkgl9WcbBZ7GCwB/TwD2k96ZEAIACAQh8ELO8UjYTPEcECcGaCDwQiQDZhgnA2gCABVu"
            + "JPP0O8EijEzCTNFCYQSOxrAm9WcDTwT2UdYA8ZPemRACAAgEIfBCzvFI2EzxHBYAYU4RAFAnAmgBADAEB2AIBANiASMIbkkkBm5J"
            + "IInGSCcCaAEACgCI+y3vfPsr4PFI2EzIHAIAcPsp4I77I+UqTkFOUCcEaEEjikzKTEEhikzKTI77Le7ISNhM9BwGAAXyUdYB89jY"
            + "Gff/HwcAj/cBwC/xUdaKxksIok8QBAVgOQAA8ZLethJ/IDgm8WUyAPRI2EzyHQYABwAzADoA308BEcrrfyA4J/llgjIzAI77MegD"
            + "IwIRjvsr5nYgMCftZfJJ2EwI8ALxPZPYTBBO/v8f/qvoiPsz6hAvBmIiABhO/v9//sXp/v9v/sPnyByH+zvkI/AtUPX+N+MCK4j7"
            + "I+lCIBtOAgD9/z3ryEjYTPEcEAQFYBbmYPBgJARoBgBCIAZuciAg8GAkAmgCAAZOMgD9/zPq8UjYTPIcFgCCIOz+KecXAD7sh/sj"
            + "4oUiI/AtUDwA8/436vJI2Ew=");
    static final byte[] V8_EXTENSION = Util.unbase64(
            "HcQAACPEAAApxAAAL8QAADXEAAA7xAAAQcQAAEfEAABNxAAAU8QAAFnEAABfxAAAN7gJAE+6CQAYJwNoAgCJbhAEGWIYBANiAjiD"
            + "blgkBGIC8PBAfm6YJARiAvDwQXlu2CQEYgLwsEF0bpgm7mkC8P9Db25QJANgkCQWYlgkA2yYJgRoAvD8QGRumCQDYFgmBGIC8AND"
            + "XW6ZJAPxkt4D8APyUthWbtAkBmJYJeFhmCXfYfBvECUkYlgk2m2YJthnmCQDYsIgRW7YJANiwiNBbhglA2ICIz1uWCUDYgI7OW6Y"
            + "Jbdh2CW1YQHwwEMC8ABDGCYA8QLALW4C8ABDKm4YBARiAvD8QSVuWCQEYgLw/kEgbpgkA2LCIRxu2CTUYRgl+2FYJQRiAvD/QBNu"
            + "mCXvYdglBGIC8IBDDG4YJt5hWCbcYQHw/kMC8P5BmCYA8QLA2EzxHRAEA2BWiARu6/455RYA6/4z5ZIFxBCDItpOBBED8GBA1k4x"
            + "1gXxU8YyALpOQtb8/yft8UnYTG1O/v8f/pPkh/s76RAvEGIiABHmAvAQ8gItBWAHT/7/f/6j5SIA0U/+/3/+meX+/2/+l+PIHAIA"
            + "bvsl6Yz7P+3+/zHrek7+/zvskCcEaIEjikzKTEEhikzKTI37I+fISNhM8RwQJwZoIPBOJANmGCcDaAIAFW4k8/Q7wSKMTMJM0UJh"
            + "BI7GsCb1ZxJPBPZR1gDxk96ZEAIACAQh8ELO8UjYTPEcFgD+/zvpEQCQJwJoAQAwBAdgCAQDYkEjCG5JJAZuSSCJxognAmgBAAoA"
            + "h/sj43r7IeTxSNhMyByF+ynuI/AtUPP+Je0CK4f7MeLq/j3sgyI6TgIA/P8n5chI2Ez0HAYABfJR1gHz2NgZ9/8fBwCP9wHAL/FR"
            + "1orGSwiiTxAEBWA5AADxkt62En8gOCbxZTIA9EjYTPIdBgAHADMAOgDfTwERyut/IDgn+WUCKjMAjPsp7AMjAhGM+yPqdiAwJ+1l"
            + "8knYTPMcFwAeAAIi6v4z7hAJUfACSYHwAO6H8AGOhfsj6SPwLVA1AEQI8v434fNI2ExyHAUABgAM8CBACkyXUzZU9hMtVPAEA2T2"
            + "BC3IElQmjCoAckjYTA==");

    private static Site site(int offset, String context, String before, String after) {
        return new Site(offset, Util.hex(context), Util.hex(before), Util.hex(after));
    }

    private HundredHertzPins() { }
}
