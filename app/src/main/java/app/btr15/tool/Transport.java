package app.btr15.tool;

/**
 * Byte-oriented link to the BTR15.  The Android build binds this to a connected
 * BluetoothSocket RFCOMM stream (SPP UUID 00001101-0000-1000-8000-00805F9B34FB);
 * the JVM tests bind it to the simulated peer behind a loopback queue.  The
 * protocol engine treats every IOException as "the link died right now" and
 * relies on the transaction journal, never on this object, for recovery.
 */
interface Transport {
    /** Transmit exactly these bytes; throw if the link is not writable. */
    void send(byte[] packet) throws java.io.IOException;

    /**
     * Return any received bytes (any chunk length), or {@code null} when the
     * timeout elapsed with nothing readable.  A closed link throws IOException.
     */
    byte[] receive(long timeoutMs) throws java.io.IOException;

    /** Close the link.  Never throws. */
    void close();

    /** True once the link is dead or closed (device reboot, host close). */
    boolean isDead();
}
