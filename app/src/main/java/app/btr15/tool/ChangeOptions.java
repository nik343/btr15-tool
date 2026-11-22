package app.btr15.tool;

/**
 * Which of the two optional changes the selected firmware can take, and what
 * its row says while it cannot.
 *
 * <p>There are three different reasons for a grey row and they must never be
 * confused: "Restore stock firmware" greys both without renaming them (the
 * choice is simply unavailable, not unsupported), v2.2 has no automute timer
 * pair to patch, and the 100 Hz menu has only been written against v3.8's Apps
 * P1.  Keeping the decision here — no Android types — lets the JVM suites pin
 * the exact words the screen shows.
 */
final class ChangeOptions {
    static final String AUTOMUTE = "Automute fix";
    /** v2.2's P1 carries no automute sites; every later pinned release does. */
    static final String AUTOMUTE_NEWER_ONLY = "Automute fix (v3.5 and newer only)";
    /** An unlisted package whose P1 has no automute timer pair to patch. */
    static final String AUTOMUTE_NO_TIMERS = "Automute fix (no automute timers in this firmware)";
    static final String AUTOMUTE_SUPPORTED_ONLY = "Automute fix (supported firmware only)";
    static final String HUNDRED_HZ = "100 Hz demo";
    static final String HUNDRED_HZ_V38_ONLY =
            "100 Hz demo (only written for v3.8 at the moment)";
    static final String HUNDRED_HZ_SUPPORTED_ONLY = "100 Hz demo (supported firmware only)";

    /** One change row: its words, whether it can be tapped, and its real state. */
    static final class Row {
        final String label;
        final boolean enabled;
        final boolean checked;

        Row(String label, boolean enabled, boolean checked) {
            this.label = label;
            this.enabled = enabled;
            this.checked = checked;
        }
    }

    private ChangeOptions() { }

    /**
     * The automute row for the selected firmware.
     *
     * @param release      the engine's description of the package: a pinned
     *                     profile, or the facts discovered in an unlisted file
     *                     (never null once the file was accepted)
     * @param restoreStock the stock-restore choice owns both rows right now
     * @param selected     what the user last chose
     */
    static Row automute(FirmwareReleases.Release release, boolean restoreStock, boolean selected) {
        if (restoreStock) {
            return new Row(AUTOMUTE, false, false);
        }
        if (release == null) {
            return new Row(AUTOMUTE_SUPPORTED_ONLY, false, false);
        }
        if (!release.automute) {
            return new Row(release.official ? AUTOMUTE_NEWER_ONLY : AUTOMUTE_NO_TIMERS,
                    false, false);
        }
        return new Row(AUTOMUTE, true, selected);
    }

    /** The 100 Hz row for the selected firmware, under the same three reasons. */
    static Row hundredHertz(FirmwareReleases.Release release, boolean restoreStock,
            boolean selected) {
        if (restoreStock) {
            return new Row(HUNDRED_HZ, false, false);
        }
        if (release == null) {
            return new Row(HUNDRED_HZ_SUPPORTED_ONLY, false, false);
        }
        if (!release.hundredHertz) {
            // Same reason for a pinned release and for an unlisted package: the
            // menu's sites, its extension offset at the end of Apps P1 and the
            // partition-1 size word only line up in that layout.
            return new Row(HUNDRED_HZ_V38_ONLY, false, false);
        }
        return new Row(HUNDRED_HZ, true, selected);
    }
}
