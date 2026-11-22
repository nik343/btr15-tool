package app.btr15.tool;

/** Formats the Flash screen and its diagnostic export. */
final class FlashLogText {
    static final String RESTART_REQUIRED = "RESTART REQUIRED";
    static final String UPDATE_REJECTED = "UPDATE REJECTED";

    private static final String PARTIAL_TRANSFER_LOST =
            "The partial transfer was lost when the app restarted; the device"
                    + " context was cleared safely — run the update again from scratch";
    private static final String PACKAGE_REJECTED =
            "Discarded the rejected staged package; the device keeps running"
                    + " what it ran before (its firmware does not trust this key)";

    private FlashLogText() { }

    static String forDisplay(CharSequence log) {
        return format(log, false);
    }

    static String forExport(CharSequence log) {
        return format(log, true);
    }

    static String displayLine(String line) {
        if (line.startsWith("Building package locally: ")) {
            return "Building package…";
        }
        if (line.startsWith("SHA-256: ") || line.startsWith("  upgrade id ")
                || line.startsWith("  changes: ") || line.startsWith("  inherited from stock: ")
                || line.equals("Update complete and verified.")) {
            return null;
        }
        return recoveryOutcome(line);
    }

    static String recoveryFinishedStatus(String outcome) {
        switch (outcome) {
            case PARTIAL_TRANSFER_LOST:
                return RESTART_REQUIRED;
            case PACKAGE_REJECTED:
                return UPDATE_REJECTED;
            default:
                return "COMPLETE";
        }
    }

    private static String recoveryOutcome(String line) {
        switch (line) {
            case "Device already committed before the interruption; verified clean":
                return "The BTR15 had already installed the update."
                        + " Recovery verified that no update is pending.";
            case "Interrupted transfer resumed from the device's own offsets and completed":
                return "Recovery resumed the transfer where it stopped"
                        + " and verified the installation.";
            case "Device rolled back cleanly; the full update ran again":
                return "The BTR15 returned to its previous firmware."
                        + " Recovery ran the update again and verified the installation.";
            case PARTIAL_TRANSFER_LOST:
                return "The app restarted before the transfer finished."
                        + " Recovery cleared the partial update."
                        + " Tap Finish, then select the firmware to start the update again.";
            case PACKAGE_REJECTED:
                return "The BTR15 rejected the package because it does not trust this signing key."
                        + " Recovery discarded the package. The previous firmware is still installed.";
            default:
                return line;
        }
    }

    /**
     * The export is the raw log: the transfer counter keeps the numbers it was
     * built from.  Those are the DATA messages actually sent and the count the
     * transfer will really end on — the meter derives that total from the image
     * still to go, so the pair is always consistent and finishes at N/N.
     */
    private static String format(CharSequence log, boolean export) {
        StringBuilder result = new StringBuilder(log.length());
        String text = log.toString();
        int start = 0;
        while (start < text.length()) {
            int end = text.indexOf('\n', start);
            boolean terminated = end >= 0;
            String line = text.substring(start, terminated ? end : text.length());
            String formatted = export ? line : displayLine(line);
            if (formatted != null) {
                result.append(formatted);
                if (terminated) {
                    result.append('\n');
                }
            }
            start = terminated ? end + 1 : text.length();
        }
        return result.toString();
    }
}
