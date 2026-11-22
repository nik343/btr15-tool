package app.btr15.tool;

/**
 * Coarse transfer progress for the process log, measured in what the device
 * actually holds: the pump reports the image offset it has just transmitted
 * and the number of DATA messages that took, and this turns that into a log
 * line such as {@code 40% (3221/8053 packets)}.
 *
 * <p>Deliberately coarse.  A 1.9 MB package is ~8000 DATA messages and the
 * transfer runs for minutes, so a line per packet would flood the log: the
 * meter reports at most once per ten-percent band and never twice inside
 * {@link #MIN_INTERVAL_MS}, which caps a whole transfer at eleven lines.  The
 * one report that always gets through is 100% — the package being fully on
 * the device is the fact the next phase depends on.
 *
 * <p>The packet total is derived, never assumed.  A package does not travel on
 * a fixed packet grid: the device grants the bytes it wants next, and the
 * proven capture took 1,933,208 bytes in 30 requests — 8,080 DATA messages
 * where dividing by 240 predicts 8,056 — because every request that ends off
 * the grid costs one short message of its own.  A fixed denominator is only a
 * floor the real count overtakes, which is how a finished transfer came to be
 * logged as {@code 100% (8086/8061 packets)}.  The total reported here is the
 * count that will really happen: the messages already sent plus the messages
 * the rest of the image still needs at the current packet size.  It creeps up
 * by one whenever a short message occurs, and it lands exactly on the messages
 * sent once the device holds the whole package — so the pair can never read
 * past its own total.
 *
 * <p>No Android imports on purpose: the JVM selftests execute this class
 * exactly as the phone does, with an injected clock so the policy is provable
 * without waiting.
 */
final class TransferMeter {
    /**
     * Where the coarse updates go: one line in the process log, e.g.
     * {@code 40% (3221/8053 packets)}.  Called on the transfer thread, never
     * on the UI thread, so an implementation must hop to the UI itself.
     */
    interface Listener {
        /**
         * @param percent     whole percent of the package now on the device, 0..100
         * @param packetsSent DATA messages this transfer has transmitted so far
         * @param totalPackets DATA messages this transfer will take — the ones
         *        already sent plus what the rest of the image still needs, so it
         *        is exact once the package is complete and never below
         *        {@code packetsSent}
         */
        void onProgress(int percent, long packetsSent, long totalPackets);
    }

    /** Monotonic milliseconds; injectable so tests never have to wait. */
    interface Clock {
        long millis();
    }

    /** No-op listener: the JVM selftests and any caller without a log to write to. */
    static final Listener SILENT = new Listener() {
        @Override public void onProgress(int percent, long packetsSent, long totalPackets) { }
    };

    /** Report when the percentage enters a new ten-percent band... */
    static final int BAND_PERCENT = 10;
    /** ...and never closer together than this, so a fast link cannot flood the log. */
    static final long MIN_INTERVAL_MS = 500L;

    private static final Clock SYSTEM_CLOCK = new Clock() {
        @Override public long millis() {
            return System.nanoTime() / 1_000_000L;
        }
    };

    private final Listener listener;
    private final long totalBytes;
    /** Bytes in one DATA message at full length; the unit of the packet estimate. */
    private final long bytesPerPacket;
    private final long minIntervalMs;
    private final Clock clock;
    private int lastBand = -1;
    /** Wall time of the last report, or -1 while nothing has been reported yet. */
    private long lastReportAt = -1L;

    TransferMeter(Listener listener, long totalBytes, long bytesPerPacket) {
        this(listener, totalBytes, bytesPerPacket, MIN_INTERVAL_MS, SYSTEM_CLOCK);
    }

    TransferMeter(Listener listener, long totalBytes, long bytesPerPacket, long minIntervalMs,
            Clock clock) {
        this.listener = listener == null ? SILENT : listener;
        this.totalBytes = totalBytes;
        this.bytesPerPacket = Math.max(1L, bytesPerPacket);
        this.minIntervalMs = Math.max(0L, minIntervalMs);
        this.clock = clock == null ? SYSTEM_CLOCK : clock;
    }

    /**
     * Bytes on the device as a whole percent.  Everything below the package
     * size rounds down, so 100 means the device holds all of it — never "nearly
     * all of it".
     */
    static int percentOf(long bytesOnDevice, long totalBytes) {
        if (totalBytes <= 0L) {
            return 100;
        }
        if (bytesOnDevice <= 0L) {
            return 0;
        }
        if (bytesOnDevice >= totalBytes) {
            return 100;
        }
        return (int) Math.min(99L, (bytesOnDevice * 100L) / totalBytes);
    }

    /**
     * The packet count this transfer will end on, given where the device is
     * now: everything already sent, plus one message for each packet's worth of
     * image that is still to go.  The rest of the image is assumed to travel in
     * full-length messages, which is what the device asks for whenever its
     * request window happens to cover a whole number of them; every short tail
     * the device's own request boundary forces shows up here as one extra
     * message the moment it is sent.  When nothing is left this is exactly
     * {@code packetsSent}.
     */
    static long totalPacketsFor(long bytesOnDevice, long packetsSent, long totalBytes,
            long bytesPerPacket) {
        long remaining = Math.max(0L, totalBytes - Math.max(0L, bytesOnDevice));
        long unit = Math.max(1L, bytesPerPacket);
        return Math.max(0L, packetsSent) + (remaining + unit - 1L) / unit;
    }

    /**
     * Say how much of the package the device holds now, and how many DATA
     * messages carried it.  Cheap enough to call for every packet: the usual
     * answer is "no new information".
     */
    void report(long bytesOnDevice, long packetsSent) {
        int percent = percentOf(bytesOnDevice, totalBytes);
        int band = percent / BAND_PERCENT;
        if (band <= lastBand) {
            return; // still inside the band that was already reported
        }
        long now = clock.millis();
        boolean complete = percent >= 100;
        if (!complete && lastReportAt >= 0L && now - lastReportAt < minIntervalMs) {
            return; // too soon; the band is still there to report on the next call
        }
        lastBand = band;
        lastReportAt = now;
        listener.onProgress(percent, packetsSent,
                totalPacketsFor(bytesOnDevice, packetsSent, totalBytes, bytesPerPacket));
    }
}
