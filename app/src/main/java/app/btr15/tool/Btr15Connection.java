package app.btr15.tool;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.content.Context;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/** Public-API RFCOMM/SPP connection and read-only BTR15 identity probe. */
final class Btr15Connection {
    private static final String TAG = "BTR15Tool";
    private static final UUID SPP_UUID =
            UUID.fromString("00001101-0000-1000-8000-00805F9B34FB");
    private static final byte[] VERSION_REQUEST = new byte[] {
            (byte) 0xFF, 0x01, 0x00, 0x01, 0x00, 0x0A, 0x04, 0x00, 0x02
    };

    static final class Device {
        final String name;
        final String address;

        Device(String name, String address) {
            this.name = name == null || name.trim().length() == 0 ? "Unknown device" : name;
            this.address = address;
        }

        boolean isNamedBtr15() {
            return name.toUpperCase(Locale.US).contains("BTR15");
        }
    }

    static final class Probe {
        final Device device;
        final String firmwareVersion;

        Probe(Device device, String firmwareVersion) {
            this.device = device;
            this.firmwareVersion = firmwareVersion;
        }
    }

    private android.bluetooth.BluetoothSocket socket;
    private Probe probe;
    private int attemptNumber;

    static BluetoothAdapter adapter(Context context) {
        BluetoothManager manager =
                (BluetoothManager) context.getSystemService(Context.BLUETOOTH_SERVICE);
        return manager == null ? null : manager.getAdapter();
    }

    static List<Device> bondedDevices(Context context) {
        BluetoothAdapter adapter = adapter(context);
        if (adapter == null) {
            return Collections.emptyList();
        }
        Set<BluetoothDevice> bonded = adapter.getBondedDevices();
        List<Device> result = new ArrayList<>();
        for (BluetoothDevice device : bonded) {
            if (device.getBondState() == BluetoothDevice.BOND_BONDED) {
                result.add(new Device(device.getName(), device.getAddress()));
            }
        }
        Collections.sort(result, new Comparator<Device>() {
            @Override public int compare(Device left, Device right) {
                if (left.isNamedBtr15() != right.isNamedBtr15()) {
                    return left.isNamedBtr15() ? -1 : 1;
                }
                int names = left.name.compareToIgnoreCase(right.name);
                return names != 0 ? names : left.address.compareToIgnoreCase(right.address);
            }
        });
        return result;
    }

    Probe connectAndProbe(Context context, Device selected) throws Exception {
        return connectAndProbe(context, selected, beginProbe());
    }

    synchronized int beginProbe() {
        close();
        return attemptNumber;
    }

    synchronized boolean isCurrentAttempt(int attempt) {
        return attemptNumber == attempt;
    }

    Probe connectAndProbe(Context context, Device selected, int attempt) throws Exception {
        if (!isCurrentAttempt(attempt)) {
            throw new IllegalStateException("Connection was cancelled");
        }
        BluetoothAdapter adapter = adapter(context);
        if (adapter == null || !adapter.isEnabled()) {
            throw new IllegalStateException("Bluetooth is off");
        }
        // Android can keep discovery active after the user leaves Settings;
        // RFCOMM connections are unreliable and unnecessarily slow while it
        // is running.  This is a public, local adapter operation and sends no
        // packet to the BTR15.
        adapter.cancelDiscovery();
        BluetoothDevice remote = adapter.getRemoteDevice(selected.address);
        android.bluetooth.BluetoothSocket candidate =
                remote.createInsecureRfcommSocketToServiceRecord(SPP_UUID);
        try {
            synchronized (this) {
                if (attempt != attemptNumber) {
                    throw new IllegalStateException("Connection was cancelled");
                }
                socket = candidate;
            }
            candidate.connect();
            String version = probeFirmwareVersion(candidate);
            Probe connected = new Probe(
                    new Device(remote.getName(), remote.getAddress()), version);
            synchronized (this) {
                if (socket != candidate) {
                    throw new IllegalStateException("Connection was cancelled");
                }
                probe = connected;
            }
            return connected;
        } catch (Exception error) {
            if (isCurrentAttempt(attempt)) {
                Log.e(TAG, "BTR15 RFCOMM probe failed", error);
            }
            closeQuietly(candidate);
            synchronized (this) {
                if (socket == candidate) {
                    socket = null;
                    probe = null;
                }
            }
            throw error;
        }
    }

    /** Reads only the idle device-screen socket. Returns true on remote link loss. */
    boolean awaitDisconnect(Probe expected) {
        android.bluetooth.BluetoothSocket monitored;
        synchronized (this) {
            if (probe != expected || socket == null) {
                return false;
            }
            monitored = socket;
        }
        try {
            InputStream input = monitored.getInputStream();
            byte[] ignored = new byte[256];
            while (input.read(ignored) >= 0) {
                // The version probe has already finished. Discard unsolicited data.
            }
        } catch (IOException | SecurityException disconnected) {
            // Android reports a closed remote socket through read failure or EOF.
        }
        synchronized (this) {
            if (socket != monitored) {
                return false;
            }
            closeSocket();
            return true;
        }
    }

    Probe verify() throws Exception {
        android.bluetooth.BluetoothSocket currentSocket;
        Probe currentProbe;
        synchronized (this) {
            currentSocket = socket;
            currentProbe = probe;
            if (currentSocket == null || !currentSocket.isConnected() || currentProbe == null) {
                throw new IllegalStateException("BTR15 is not connected");
            }
        }
        String version = probeFirmwareVersion(currentSocket);
        Probe verified = new Probe(currentProbe.device, version);
        synchronized (this) {
            if (socket != currentSocket) {
                throw new IllegalStateException("BTR15 disconnected during verification");
            }
            probe = verified;
        }
        return verified;
    }

    synchronized boolean isConnectedTo(String address) {
        return socket != null && socket.isConnected() && probe != null
                && probe.device.address.equalsIgnoreCase(address);
    }

    synchronized Probe currentProbe() {
        return probe;
    }

    synchronized void close() {
        attemptNumber++;
        closeSocket();
    }

    private void closeSocket() {
        closeQuietly(socket);
        socket = null;
        probe = null;
    }

    private static String probeFirmwareVersion(android.bluetooth.BluetoothSocket socket)
            throws Exception {
        OutputStream output = socket.getOutputStream();
        output.write(VERSION_REQUEST);
        output.flush();

        InputStream input = socket.getInputStream();
        ByteArrayOutputStream received = new ByteArrayOutputStream();
        long deadline = System.currentTimeMillis() + 5000L;
        while (System.currentTimeMillis() < deadline) {
            while (input.available() > 0) {
                byte[] part = new byte[Math.min(512, input.available())];
                int count = input.read(part);
                if (count < 0) {
                    throw new IllegalStateException("BTR15 closed the connection");
                }
                received.write(part, 0, count);
                String version = findVersionResponse(received.toByteArray());
                if (version != null) {
                    return version;
                }
                if (received.size() > 4096) {
                    throw new IllegalStateException("Unexpected response from Bluetooth device");
                }
            }
            Thread.sleep(20L);
        }
        throw new IllegalStateException("The selected device did not answer as a BTR15");
    }

    private static String findVersionResponse(byte[] data) {
        int offset = 0;
        while (offset + 4 <= data.length) {
            if ((data[offset] & 0xFF) != 0xFF || (data[offset + 1] & 0xFF) != 0x01) {
                offset++;
                continue;
            }
            int flags = data[offset + 2] & 0xFF;
            int payloadLength = data[offset + 3] & 0xFF;
            int frameLength = 8 + payloadLength + ((flags & 0x01) == 0 ? 0 : 1);
            if (offset + frameLength > data.length) {
                return null;
            }
            if ((flags & 0x01) != 0) {
                int xor = 0;
                for (int i = 0; i < frameLength; i++) {
                    xor ^= data[offset + i] & 0xFF;
                }
                if (xor != 0) {
                    offset++;
                    continue;
                }
            }
            int vendor = ((data[offset + 4] & 0xFF) << 8) | (data[offset + 5] & 0xFF);
            int command = ((data[offset + 6] & 0xFF) << 8) | (data[offset + 7] & 0xFF);
            if (vendor == 0x000A && command == 0x8400 && payloadLength == 4
                    && data[offset + 8] == 0 && data[offset + 9] == 2) {
                return (data[offset + 10] & 0xFF) + "." + (data[offset + 11] & 0xFF);
            }
            offset += frameLength;
        }
        return null;
    }

    private static void closeQuietly(android.bluetooth.BluetoothSocket value) {
        if (value != null) {
            try {
                value.close();
            } catch (Exception ignored) {
                // Best-effort cleanup.
            }
        }
    }
}
