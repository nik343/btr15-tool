package app.btr15.tool;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Persistent, crash-atomic transaction journal for one device transaction.
 *
 * <p>Every state boundary of the jailbreak, developer update and two-stage
 * stock-restore workflows is written before the operation is attempted, using
 * write-temp-then-rename, so an interrupted run always finds either the old or
 * the new journal — never a torn one.  Where the platform will not replace the
 * old file in place, the old record is moved aside instead of deleted and read
 * as the fallback, so a failed swap can never leave the app with no record at
 * all.  {@link Workflows#recover} reads the
 * journal together with the live key-4 context and follows the documented
 * recovery decision tree.  Journals never contain the developer key, its
 * mnemonic, or package bytes: only digests, upgrade ids, phases and steps.
 */
final class Journal {
    static final String KIND_JAILBREAK = "JAILBREAK";
    static final String KIND_DEVELOPER_UPDATE = "DEVELOPER_UPDATE";
    static final String KIND_STOCK_PHASE1 = "STOCK_RESTORE_PHASE1";
    static final String KIND_STOCK_PHASE2 = "STOCK_RESTORE_PHASE2";
    /**
     * One stock restoration: both phases share a single record, because the
     * phase-1 journal used to be deleted before phase 2 created its own — an
     * app close in that gap left the device trusting FiiO again with nothing on
     * disk saying the second phase was still owed.
     */
    static final String KIND_STOCK_RESTORE = "STOCK_RESTORE";
    static final String RESTORATION_PHASE1 = "PHASE1";
    static final String RESTORATION_PHASE2 = "PHASE2";

    static final String PHASE_BEGIN = "BEGIN";
    static final String PHASE_APPLY_SENT = "APPLY_SENT";
    static final String PHASE_STAGED_FOOTER_FAIL = "STAGED_FOOTER_FAIL";
    static final String PHASE_KEY4_PRE_VALIDATE = "KEY4_PRE_VALIDATE";
    static final String PHASE_RESUME_APPLIED = "RESUME_APPLIED";
    static final String PHASE_COMMITTED = "COMMITTED";
    static final String PHASE_VERIFIED = "VERIFIED";

    private static final String PREFIX = "btr15-txn-";
    private static final String SUFFIX = ".journal";
    /** The last readable copy, kept until the write it belongs to has landed. */
    private static final String PREVIOUS = ".prev";
    private static final String TEMP = ".tmp";

    private final File file;
    private final File directory;
    private final String id;
    private final Map<String, String> fields = new LinkedHashMap<>();
    private final List<String> steps = new ArrayList<>();

    private Journal(File directory, String id) {
        this.directory = directory;
        this.id = id;
        this.file = new File(directory, PREFIX + id + SUFFIX);
    }

    /**
     * package_sha256 identifies the exact staged file (random RSA-PSS salt
     * makes every build unique, so it only matches the bytes that were
     * actually staged).  staged_content_sha256 identifies the deterministic
     * signed content — the payloads plus key block — which a rebuild from the
     * same official file reproduces bit for bit; recovery uses it to accept a
     * rebuilt continuation after an app restart.  device_address records the
     * MAC the transaction was started on, so Recovery targets that exact
     * device and never has to guess between several bonded BTR15s.
     * official_uri records where the user's official v3.8 file lives, so a
     * Recovery after an app restart re-opens it instead of demanding that the
     * user find it again (the picker holds a persistable read grant).
     */
    static Journal create(File directory, String kind, String packageSha256,
                          String stagedContentSha256, long upgradeId, String variant,
                          String deviceAddress, String officialUri)
            throws FirmwareException {
        require(directory.isDirectory(), "journal directory does not exist: " + directory);
        String id = Long.toString(System.currentTimeMillis(), 36)
                + "-" + Long.toHexString(upgradeId);
        Journal journal = new Journal(directory, id);
        journal.fields.put("version", "1");
        journal.fields.put("id", id);
        journal.fields.put("kind", kind);
        journal.fields.put("package_sha256", packageSha256);
        journal.fields.put("staged_content_sha256", stagedContentSha256);
        journal.fields.put("upgrade_id", String.format(Locale.ROOT, "%08x", upgradeId));
        journal.fields.put("variant", variant);
        if (deviceAddress != null) {
            journal.fields.put("device_address", deviceAddress);
        }
        if (officialUri != null) {
            journal.fields.put("official_uri", officialUri);
        }
        journal.fields.put("phase", PHASE_BEGIN);
        journal.step(PHASE_BEGIN);
        journal.persist();
        return journal;
    }

    static Journal open(File directory, String id) throws FirmwareException {
        Journal journal = new Journal(directory, id);
        require(journal.file.isFile() || journal.previousFile().isFile(),
                "journal does not exist: " + journal.file);
        journal.load();
        return journal;
    }

    /** The single unfinished transaction, or null.  Two at once is refused. */
    static Journal findPending(File directory) throws FirmwareException {
        Journal found = null;
        for (File candidate : pendingFiles(directory)) {
            if (found != null) {
                throw new FirmwareException("more than one unfinished transaction in "
                        + directory + "; resolve manually (see RECOVERY decision tree)");
            }
            found = open(directory, nameOf(candidate));
        }
        return found;
    }

    static List<String> listPending(File directory) {
        List<String> ids = new ArrayList<>();
        for (File candidate : pendingFiles(directory)) {
            ids.add(nameOf(candidate));
        }
        return ids;
    }

    /**
     * Remove every pending record, readable or not: the way out of a journal
     * that cannot be read, where {@link #findPending} cannot even answer.
     */
    static int deleteAllPending(File directory) {
        int removed = 0;
        for (String id : listPending(directory)) {
            File plain = new File(directory, PREFIX + id + SUFFIX);
            if (plain.delete()) {
                removed++;
            }
            removeQuietly(new File(directory, PREFIX + id + SUFFIX + PREVIOUS));
            removeQuietly(new File(directory, PREFIX + id + SUFFIX + TEMP));
        }
        return removed;
    }

    private static File[] pendingFiles(File directory) {
        File[] files = directory.listFiles();
        if (files == null) {
            return new File[0];
        }
        // Keyed by transaction id so the sorted order is still creation order,
        // and so a journal and the previous copy beside it count as one
        // unfinished transaction instead of looking like two.
        Map<String, File> byId = new TreeMap<>();
        for (File candidate : files) {
            if (!candidate.isFile()) {
                continue;
            }
            String name = candidate.getName();
            boolean plain = name.startsWith(PREFIX) && name.endsWith(SUFFIX);
            boolean previous = name.startsWith(PREFIX) && name.endsWith(SUFFIX + PREVIOUS);
            if (!plain && !previous) {
                continue;
            }
            String id = nameOf(candidate);
            File known = byId.get(id);
            if (known == null || (plain && known.getName().endsWith(SUFFIX + PREVIOUS))) {
                byId.put(id, candidate);
            }
        }
        return byId.values().toArray(new File[0]);
    }

    private static String nameOf(File file) {
        String name = file.getName();
        if (name.endsWith(SUFFIX + PREVIOUS)) {
            return name.substring(PREFIX.length(),
                    name.length() - SUFFIX.length() - PREVIOUS.length());
        }
        return name.substring(PREFIX.length(), name.length() - SUFFIX.length());
    }

    String id() {
        return id;
    }

    File file() {
        return file;
    }

    /**
     * The raw field value, or null when absent — callers must be able to
     * tell "the journal never recorded this" from a recorded empty string.
     */
    String get(String key) {
        return fields.get(key);
    }

    /** The field value, or empty when absent — for plain text and label use. */
    String getOrEmpty(String key) {
        String value = fields.get(key);
        return value == null ? "" : value;
    }

    long upgradeId() throws FirmwareException {
        String id = get("upgrade_id");
        require(id != null && !id.isEmpty(),
                "journal records no upgrade id: " + file.getName());
        try {
            return Long.parseLong(id, 16);
        } catch (NumberFormatException malformed) {
            throw new FirmwareException("journal upgrade id " + id + " is not hexadecimal");
        }
    }

    /** Record a phase (persisted before the operation begins) and append a step. */
    void enterPhase(String phase) throws FirmwareException {
        fields.put("phase", phase);
        step(phase);
        persist();
    }

    /** Which stock phase the record stands at ({@code PHASE1} before anything ran). */
    String restorationPhase() {
        return getOrEmpty("restoration_phase");
    }

    void setRestorationPhase(String phase) throws FirmwareException {
        fields.put("restoration_phase", phase);
        step("restoration " + phase);
        persist();
    }

    /**
     * Point the record at the next package and start a fresh phase, in one
     * atomic write.  Stock phase 2 is a different package under a different
     * signature than phase 1, so the identity fields have to move with it.
     */
    void rearm(String packageSha256, String stagedContentSha256, long upgradeId,
               String variant, String phase, String restorationPhase) throws FirmwareException {
        fields.put("package_sha256", packageSha256);
        fields.put("staged_content_sha256", stagedContentSha256);
        fields.put("upgrade_id", String.format(Locale.ROOT, "%08x", upgradeId));
        fields.put("variant", variant);
        fields.put("phase", phase);
        fields.put("restoration_phase", restorationPhase);
        step(phase + " (" + restorationPhase + ")");
        persist();
    }

    void note(String text) throws FirmwareException {
        step(text);
        persist();
    }

    void step(String text) {
        String stamp = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.ROOT)
                .format(new Date());
        steps.add(stamp + "  " + text);
    }

    /** Human-readable journal for exported logs and the recovery screen. */
    String describe() {
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, String> entry : new TreeMap<>(fields).entrySet()) {
            out.append(entry.getKey()).append(" = ").append(entry.getValue()).append('\n');
        }
        out.append("steps:\n");
        for (String line : steps) {
            out.append("  ").append(line).append('\n');
        }
        return out.toString();
    }

    void delete() throws FirmwareException {
        require(file.delete() || !file.exists(), "journal could not be removed: " + file);
        // The previous copy and any abandoned temp belong to this record: a
        // leftover .prev would otherwise bring a finished transaction back.
        removeQuietly(previousFile());
        removeQuietly(new File(directory, file.getName() + TEMP));
    }

    private File previousFile() {
        return new File(directory, file.getName() + PREVIOUS);
    }

    /**
     * Replace the journal with the current fields.  The new text is written and
     * flushed to disk first; only then is it swapped in.  The normal path is a
     * single rename over the old file, but where the platform refuses to
     * replace in place the old record is set aside — never deleted — so a
     * failed swap still leaves the last readable copy for Recovery.
     */
    private void persist() throws FirmwareException {
        File temp = new File(directory, file.getName() + TEMP);
        writeTo(temp);
        if (temp.renameTo(file)) {
            removeQuietly(previousFile());
            return;
        }
        File previous = previousFile();
        removeQuietly(previous);
        if (file.isFile() && !file.renameTo(previous)) {
            throw new FirmwareException("journal could not be set aside for replacement: " + file);
        }
        if (temp.renameTo(file)) {
            removeQuietly(previous);
            return;
        }
        if (previous.isFile()) {
            previous.renameTo(file);
        }
        throw new FirmwareException("journal could not be replaced: " + file);
    }

    private void writeTo(File target) throws FirmwareException {
        FileOutputStream stream = null;
        Writer writer = null;
        try {
            stream = new FileOutputStream(target);
            writer = new OutputStreamWriter(stream, "UTF-8");
            for (Map.Entry<String, String> entry : fields.entrySet()) {
                writer.write(entry.getKey() + "=" + entry.getValue() + "\n");
            }
            for (String line : steps) {
                writer.write("# " + line + "\n");
            }
            writer.flush();
            // The record is the only thing that survives a power loss, so do
            // not report it written until the bytes are actually on the medium.
            stream.getFD().sync();
        } catch (IOException broken) {
            throw new FirmwareException("journal write failed: " + broken);
        } finally {
            closeQuietly(writer);
            closeQuietly(stream);
        }
    }

    private void load() throws FirmwareException {
        try {
            readFrom(file);
        } catch (FirmwareException primary) {
            File previous = previousFile();
            if (!previous.isFile()) {
                throw primary;
            }
            try {
                readFrom(previous);
            } catch (FirmwareException fallback) {
                throw new FirmwareException(primary.getMessage()
                        + "; the copy set aside beside it is unreadable too: "
                        + fallback.getMessage());
            }
        }
    }

    private void readFrom(File source) throws FirmwareException {
        Reader reader = null;
        try {
            reader = new InputStreamReader(new FileInputStream(source), "UTF-8");
            StringBuilder text = new StringBuilder();
            char[] chunk = new char[4096];
            int read;
            while ((read = reader.read(chunk)) > 0) {
                text.append(chunk, 0, read);
            }
            fields.clear();
            steps.clear();
            for (String line : text.toString().split("\n")) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                if (line.startsWith("# ")) {
                    steps.add(line.substring(2));
                } else {
                    int at = line.indexOf('=');
                    if (at > 0) {
                        fields.put(line.substring(0, at), line.substring(at + 1));
                    }
                }
            }
            require("1".equals(get("version")) && !getOrEmpty("kind").isEmpty()
                            && !getOrEmpty("phase").isEmpty(),
                    "journal is not a recognised v1 transaction record: " + source.getName());
        } catch (IOException broken) {
            throw new FirmwareException("journal read failed: " + broken);
        } finally {
            closeQuietly(reader);
        }
    }

    private static void removeQuietly(File file) {
        if (file != null && file.exists()) {
            file.delete();
        }
    }

    private static void closeQuietly(java.io.Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException ignored) {
                // best effort
            }
        }
    }

    private static void require(boolean condition, String message) throws FirmwareException {
        if (!condition) {
            throw new FirmwareException(message);
        }
    }
}
