package app.btr15.tool;

import java.io.IOException;

/**
 * One live link, many sessions.
 *
 * The BTR15's GAIA stack serves exactly one client and takes a moment to
 * release an RFCOMM link after the phone drops it — the retained HCI from
 * the field audit shows a re-dial made immediately after a disconnect
 * connects at RFCOMM level yet is never read by the firmware (the first
 * frame then answers with silence, exactly like the historical 0x0720
 * capture).  The proven PC client ran whole upgrades on a single connection
 * for that reason; this pool reproduces that: sessions borrow the one live
 * transport, {@code Session.close()} no longer tears the socket down, and a
 * fresh link is dialled only after the previous one died (device reboot,
 * power cycle) or was explicitly released — always with a settle delay so
 * the firmware can drop the old link first, with retries in case the
 * channel still reports itself busy.  The settle applies to the first dial
 * too: a pool is always created right after the previous step released.
 *
 * <p>The settle must run AFTER every other client is closed, not before: a
 * field run closed the probe socket 209 ms before the new RFCOMM link came
 * up and the firmware answered the cheap GAIA getters on the new link while
 * silently dropping every Upgrade message on it — the upgrade manager was
 * still bound to the socket that had just gone.  {@link Lift#releaseOthers()}
 * therefore runs first, then the settle, then the connect.
 */
final class LinkPool implements DeviceOperator.Target, Workflows.Connector {
    /**
     * Dials one fresh physical link (a connected BluetoothSocket on the
     * phone) and proves it is the GAIA one.  The BTR15 advertises several
     * SPP records under the same UUID and Android's SDP rotates between them;
     * a socket on the wrong record either is torn down by the device within
     * milliseconds or never answers a frame (the historical "no GAIA frame
     * within N ms").  verify() asks the firmware-version getter once — when
     * it does not answer, LinkPool drops that socket and dials again, and SDP
     * resolves a different record.
     */
    interface Lift {
        /**
         * Let go of every other socket that could be holding the device's
         * single GAIA client slot (the wizard's own probe connection).  Called
         * once per dial attempt, BEFORE the settle delay, so the firmware has
         * the whole settle to notice the drop.
         */
        default void releaseOthers() { }

        Transport connect() throws IOException;

        /**
         * Probes a freshly connected link with one cheap GAIA command.
         * Must throw IOException when the link is not a working GAIA link;
         * must leave the link open when it answers.
         */
        void verify(Transport transport) throws IOException;
    }

    /** Time the device plausibly needs to release a dropped RFCOMM client. */
    static final long SETTLE_MS = 1_500L;
    static final int CONNECT_ATTEMPTS = 3;

    private final Lift lift;
    private Transport link;

    LinkPool(Lift lift) {
        this.lift = lift;
    }

    @Override
    public synchronized Session open() throws FirmwareException {
        if (link != null && link.isDead()) {
            retire();
        }
        if (link == null) {
            link = dial();
        }
        return new Session(new Borrowed(link), Session.DEFAULT_ACK_TIMEOUT_MS);
    }

    /** Politely give the device its GAIA client slot back (end of a wizard step). */
    synchronized void release() {
        if (link != null) {
            Transport dying = link;
            link = null;
            dying.close();
        }
    }

    /**
     * Drop the live link and dial a fresh one after the usual settle.  The
     * workflows ask for this when the device accepted a connection but never
     * answered a handshake message: nothing has been staged at that point, so
     * a brand-new client binding is always safe and is what the firmware
     * needs to answer again.
     */
    public synchronized void recycle() {
        retire();
    }

    /** Forget the current link (it died); the next open() re-dials after settling. */
    private void retire() {
        if (link != null) {
            Transport dying = link;
            link = null;
            dying.close();
        }
    }

    private Transport dial() throws FirmwareException {
        IOException last = null;
        for (int attempt = 1; attempt <= CONNECT_ATTEMPTS; attempt++) {
            // Always settle, and always after letting go of every other
            // client: a fresh pool starts right after the previous step
            // released its link (or after a device reboot), so even the first
            // dial follows a drop the firmware still has to notice.
            lift.releaseOthers();
            settle("letting the BTR15 release the previous link");
            Transport fresh = null;
            try {
                fresh = lift.connect();
                lift.verify(fresh); // the wrong SPP record never answers GAIA
                return fresh;
            } catch (IOException | RuntimeException probeFailure) {
                last = probeFailure instanceof IOException
                        ? (IOException) probeFailure
                        : new IOException("link probe failed", probeFailure);
                if (fresh != null) {
                    fresh.close(); // drop the bad record so SDP rotates
                }
            }
        }
        throw new FirmwareException("cannot reach the BTR15: "
                + (last == null || last.getMessage() == null
                        ? "the RFCOMM link was refused" : last.getMessage()));
    }

    private static void settle(String why) throws FirmwareException {
        try {
            Thread.sleep(SETTLE_MS);
        } catch (InterruptedException paused) {
            Thread.currentThread().interrupt();
            throw new FirmwareException("interrupted while " + why);
        }
    }

    /** Session-visible handle onto the shared link; close() must not kill it. */
    private static final class Borrowed implements Transport {
        private final Transport real;

        Borrowed(Transport real) {
            this.real = real;
        }

        @Override public void send(byte[] packet) throws IOException {
            real.send(packet);
        }

        @Override public byte[] receive(long timeoutMs) throws IOException {
            return real.receive(timeoutMs);
        }

        @Override public boolean isDead() {
            return real.isDead();
        }

        @Override public void close() {
            // The shared link outlives the session that borrowed it.
        }
    }
}
