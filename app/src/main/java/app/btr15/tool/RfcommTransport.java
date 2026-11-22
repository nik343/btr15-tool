package app.btr15.tool;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothSocket;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Real SPP transport: one RFCOMM connection to the BTR15, whole GAIA packets
 * out, stream chunks in.  A daemon reader thread moves bytes into a queue so
 * {@link #receive(long)} can honour the caller's timeout; every device
 * reboot (commit, interphase reset, power cycle) closes the RFCOMM stream,
 * which surfaces here as an IOException exactly where {@link Session} expects
 * link-death to trigger journal-aware retry logic.
 */
final class RfcommTransport implements Transport {
    static final UUID SPP_UUID = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB");

    /** Marker queued when the link dies; never a legal GAIA chunk. */
    private static final byte[] LINK_CLOSED = new byte[0];

    private final BluetoothSocket socket;
    private final OutputStream out;
    private final LinkedBlockingQueue<byte[]> rx = new LinkedBlockingQueue<>();
    private volatile IOException dead;

    RfcommTransport(BluetoothAdapter adapter, String address) throws IOException {
        adapter.cancelDiscovery(); // discovery makes RFCOMM connects slow and flaky
        BluetoothDevice device = adapter.getRemoteDevice(address);
        BluetoothSocket connecting;
        try {
            connecting = device.createInsecureRfcommSocketToServiceRecord(SPP_UUID);
        } catch (IOException unusable) {
            throw new IOException("cannot create the RFCOMM socket: " + unusable);
        }
        try {
            connecting.connect();
        } catch (IOException refused) {
            closeQuietly(connecting);
            android.util.Log.w("Btr15Link", "RFCOMM connect refused for " + address, refused);
            throw new IOException("the BTR15 refused the connection: " + refused);
        }
        android.util.Log.i("Btr15Link", "RFCOMM link up to " + address);
        socket = connecting;
        out = socket.getOutputStream();
        Thread reader = new Thread(new Runnable() {
            public void run() {
                pump();
            }
        }, "btr15-rfcomm-read");
        reader.setDaemon(true);
        reader.start();
    }

    private void pump() {
        InputStream in;
        try {
            in = socket.getInputStream();
        } catch (IOException broken) {
            fail(broken);
            return;
        }
        byte[] buffer = new byte[4096];
        try {
            while (true) {
                int count = in.read(buffer);
                if (count < 0) {
                    fail(new IOException("RFCOMM stream ended (the device rebooted?)"));
                    return;
                }
                if (count > 0) {
                    byte[] chunk = Arrays.copyOf(buffer, count);
                    logWire("RX", chunk);
                    rx.add(chunk);
                }
            }
        } catch (IOException closed) {
            fail(closed); // socket.close() during close(), or the device vanished
        }
    }

    private void fail(IOException cause) {
        if (dead == null) {
            dead = cause;
            android.util.Log.i("Btr15Link", "RFCOMM link died", cause);
        }
        rx.add(LINK_CLOSED); // wake every waiting receive
    }

    @Override
    public void send(byte[] packet) throws IOException {
        IOException link = dead;
        if (link != null) {
            throw link;
        }
        out.write(packet); // one complete GAIA v1 packet (<=262 bytes) per write
        out.flush();
        logWire("TX", packet);
    }

    /**
     * The handshake is a handful of tiny frames; a transfer is thousands of
     * DATA packets.  Logging every short frame puts the whole GAIA exchange in
     * logcat (readable over adb, no export needed) without flooding it.
     */
    private static void logWire(String direction, byte[] bytes) {
        if (bytes.length <= 64) {
            android.util.Log.i("Btr15Wire", direction + " " + Util.hex(bytes));
        }
    }

    @Override
    public byte[] receive(long timeoutMs) throws IOException {
        byte[] chunk;
        try {
            chunk = rx.poll(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while waiting for the BTR15", interrupted);
        }
        if (chunk == null) {
            return null; // caller loops until its own deadline
        }
        if (chunk.length == 0) {
            IOException link = dead;
            throw link != null ? link : new IOException("RFCOMM link closed");
        }
        return chunk;
    }

    @Override
    public void close() {
        IOException previous = dead;
        dead = previous != null ? previous : new IOException("RFCOMM transport closed");
        closeQuietly(socket); // unblocks the reader thread
        rx.add(LINK_CLOSED);
    }

    @Override
    public boolean isDead() {
        return dead != null;
    }

    private static void closeQuietly(BluetoothSocket value) {
        try {
            value.close();
        } catch (IOException ignored) {
            // best-effort cleanup
        }
    }
}
