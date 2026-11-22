package app.btr15.tool;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/** In-JVM RFCOMM stand-in: host frames reach the peer, device frames queue back. */
final class LoopbackTransport implements Transport {
    private final SimBtr15Peer peer;
    private final Deque<byte[]> rx = new ArrayDeque<>();
    private boolean open = true;

    LoopbackTransport(SimBtr15Peer peer) {
        this.peer = peer;
    }

    public void send(byte[] packet) throws IOException {
        if (!open) {
            throw new IOException("transport closed by the host");
        }
        List<byte[]> replies = new ArrayList<>();
        peer.receive(packet, replies);
        rx.addAll(replies);
    }

    public byte[] receive(long timeoutMs) throws IOException {
        if (!open) {
            throw new IOException("transport closed by the host");
        }
        return rx.poll();
    }

    public void close() {
        open = false;
        rx.clear();
    }

    public boolean isDead() {
        return !open;
    }
}
