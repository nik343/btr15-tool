package app.btr15.tool;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Buffers a picked file under a hard size cap.
 *
 * <p>Everything after the read (structure check, digest, release describe) needs
 * the bytes anyway, but the file list offers anything: a video or an app package
 * can be hundreds of megabytes.  The cap stops such a pick while it is still
 * streaming, so the refusal is a message instead of an out-of-memory death.  No
 * BTR15 package comes near the limit — every supported release is about 1.9 MB —
 * so it only ever costs room for a future one.
 */
final class FirmwareRead {
    static final long MAX_BYTES = 8L * 1024L * 1024L;
    private static final String LIMIT_TEXT = "8 MB";

    private FirmwareRead() { }

    static byte[] all(InputStream input) throws IOException, FirmwareException {
        if (input == null) {
            throw new IOException("The selected file could not be opened");
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[16384];
        int count;
        while ((count = input.read(chunk)) > 0) {
            if (buffer.size() + count > MAX_BYTES) {
                throw new FirmwareException("The selected file is larger than " + LIMIT_TEXT
                        + "; it is not a firmware package");
            }
            buffer.write(chunk, 0, count);
        }
        return buffer.toByteArray();
    }
}
