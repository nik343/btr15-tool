package app.btr15.tool;

import android.Manifest;
import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Insets;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.provider.Settings;
import android.text.Editable;
import android.text.InputType;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Small, procedure-based, offline UI proof for the planned BTR15 utility. */
public final class MainActivity extends Activity {
    private static final int PICK_FIRMWARE = 41;
    private static final int CREATE_LOG = 42;
    private static final int REQUEST_BLUETOOTH = 43;
    private static final int ENABLE_BLUETOOTH = 44;

    private static final int STEP_FIRMWARE = 0;
    private static final int STEP_KEY = 1;
    private static final int STEP_METHOD = 2;
    private static final int STEP_CHANGES = 3;
    private static final int STEP_DEVICE = 4;
    private static final int STEP_REVIEW = 5;
    private static final int STEP_COUNT = 6;

    private static final int POWER_CYCLE_WAITING_FOR_OFF = 1;
    private static final int POWER_CYCLE_WAITING_FOR_ON = 2;
    private static final int POWER_CYCLE_RECONNECTING = 3;
    private static final int POWER_CYCLE_RECONNECT_FAILED = 4;
    private static final int POWER_CYCLE_WAITING_FOR_DARK = 5;
    private static final int POWER_CYCLE_CONNECTED_HOLD = 6;
    private static final long POWER_CYCLE_DARK_HOLD_MILLIS = 7000L;
    private static final long POWER_CYCLE_CONNECTED_HOLD_MILLIS = 1400L;

    private static final int WHITE = Color.rgb(255, 255, 255);
    private static final int BLACK = Color.rgb(17, 17, 17);
    private static final int MID = Color.rgb(92, 92, 92);
    /** Box text that is already filled in but not yet edited by the user. */
    private static final int PREFILL = Color.rgb(122, 122, 122);
    private static final int DISABLED_TEXT = Color.rgb(153, 153, 153);
    private static final int LINE = Color.rgb(207, 207, 207);
    private static final int DISABLED = Color.rgb(232, 232, 232);
    private static final int ATTENTION = Color.rgb(161, 48, 48);
    private static final int NOTE_TEXT_SP = 15;

    private static final Map<String, String> KNOWN_FIRMWARE = new HashMap<>();

    static {
        KNOWN_FIRMWARE.put(
                "23CD28FE60D6613CBF6E099A0181234283A92880B36FD1F500AE2405DC9F1993", "v2.2");
        KNOWN_FIRMWARE.put(
                "EAD376ABA18E344680DF8DBEBFD13014A16114F8AAB684B2B57A78E7022D74B6", "v3.5");
        KNOWN_FIRMWARE.put(
                "26B21C1779BD9229B7256A055B1D1E55834A0EE48E500B6E0C952206911FDB39", "v3.8");
        KNOWN_FIRMWARE.put(
                "940E15176FBAA8C037AFA6E78D9BC1D294BCB101947E4A695F38652BA90DA1A8", "v4.4");
    }

    private LinearLayout stage;
    private ScrollView stageScroll;
    private TextView stepNumber;
    private LinearLayout flashHeader;
    private LinearLayout firmwareCredits;
    private Button backButton;
    private Button nextButton;

    private int step;
    private Uri firmwareUri;
    private String firmwareName;
    private String firmwareHash;
    private String firmwareVersion;
    /** The pinned official release the picked file is, or null when unrecognized. */
    private FirmwareReleases.Release firmwareRelease;
    /** Why a read package still cannot be flashed, when its key block is not usable. */
    private String firmwareBlockedReason;
    private long firmwareBytes;
    private boolean readingFirmware;
    private boolean firmwareReadFailed;
    private String firmwareValidationError;

    private boolean useExistingMnemonic;
    private String existingMnemonic = "";
    /** The identity already in the Keystore store, shown as the box hint. */
    private String savedExistingMnemonic;
    private String generatedMnemonic = "";
    private String identityError;
    private boolean useJailbreak = true;
    private boolean automute;
    private boolean demo100Hz;
    private boolean restoreStock;

    private final Btr15Connection btr15 = new Btr15Connection();
    /** Shared RFCOMM link of the current wizard step (the device serves one client). */
    private volatile LinkPool activeLinkPool;
    private List<Btr15Connection.Device> bondedDevices = Collections.emptyList();
    private String selectedDeviceAddress;    private boolean connectingDevice;
    /** Set when a pending transaction needs an input from the wizard. */
    private boolean returnToFirmwareForRecovery;
    private String connectionError;
    private String connectionErrorDetail;
    private final StringBuilder diagnosticLog = new StringBuilder();

    /** Set when a recorded transaction exists but its journal cannot be read. */
    private String journalLookupError;

    private boolean flashScreen;
    private boolean flashStarted;
    private boolean flashRunning;
    private boolean recoveryNeedsIdentity;
    private boolean powerCycleRequired;
    private boolean powerCycleScreen;
    private int powerCycleState;
    private String powerCycleError;
    private boolean powerCycleReceiverRegistered;
    private boolean powerCycleReconnectInProgress;
    private boolean powerCycleReconnectPending;
    private boolean powerCycleLayoutPassPending;
    private boolean powerCycleLayoutMeasured;
    private volatile int flashRunToken;
    private String flashStatus = "READY";
    private volatile String lastTranscript = "";
    private final StringBuilder flashLog = new StringBuilder();
    private TextView flashStatusView;
    private TextView flashLogView;

    private final BroadcastReceiver powerCycleReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            handlePowerCycleBluetoothEvent(intent);
        }
    };

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        if (getIntent() != null && getIntent().getBooleanExtra(EXTRA_SELFTEST, false)) {
            runSelfTestMode();
            return;
        }
        getWindow().setStatusBarColor(WHITE);
        getWindow().setNavigationBarColor(WHITE);
        int systemUi = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
        if (Build.VERSION.SDK_INT >= 26) {
            systemUi |= View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
        }
        getWindow().getDecorView().setSystemUiVisibility(systemUi);
        loadSigningIdentityDefault();
        View root = buildScreen();
        setContentView(root);
        applySystemBarInsets(root);
        renderStep();
    }

    /**
     * Target SDK 35 is drawn edge to edge on Android 15 and later, so the fixed
     * paddings would slide the header under the status bar and the footer
     * buttons under the navigation bar.  Take the real system-bar insets as
     * outer padding on the root instead of guessing them at a fixed dp value,
     * and leave older releases on their own window fitting.
     */
    private void applySystemBarInsets(View root) {
        if (Build.VERSION.SDK_INT < 30) {
            return;
        }
        getWindow().setDecorFitsSystemWindows(false);
        root.setFitsSystemWindows(false);
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            Insets bars = insets.getInsets(WindowInsets.Type.systemBars()
                    | WindowInsets.Type.displayCutout());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return insets;
        });
    }

    /**
     * adb-visible proof mode: `am start -n app.btr15.tool/.MainActivity
     * --ez run_selftest true` runs the frozen vector suites (BIP-39, BDKD-v1
     * key derivation, GAIA wire frames) plus the CrossProof digests on this
     * device and writes the results to logcat, proving the phone's runtime
     * matches the build PC bit for bit.  No UI, no permissions, no radios.
     */
    private static final String EXTRA_SELFTEST = "run_selftest";

    private void runSelfTestMode() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                boolean ok = true;
                try {
                    System.out.println("XPROOF BEGIN device=" + android.os.Build.MODEL
                            + " sdk=" + android.os.Build.VERSION.SDK_INT);
                    Bip39SelfTest.main(new String[0]);
                    DevKeySelfTest.main(new String[0]);
                    ProtocolSelfTest.main(new String[0]);
                    System.out.print(CrossProof.run());
                } catch (Throwable failure) {
                    ok = false;
                    android.util.Log.e("Btr15Proof", "XPROOF FAILED", failure);
                }
                android.util.Log.i("Btr15Proof", ok ? "XPROOF DONE PASS" : "XPROOF DONE FAIL");
                finish();
            }
        }, "btr15-selftest").start();
    }

    @Override
    protected void onDestroy() {
        flashRunToken++;
        unregisterPowerCycleReceiver();
        releaseLink();
        btr15.close();
        super.onDestroy();
    }

    private View buildScreen() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(WHITE);

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.VERTICAL);
        header.setPadding(dp(22), dp(18), dp(22), dp(14));
        LinearLayout top = new LinearLayout(this);
        top.setGravity(Gravity.CENTER_VERTICAL);
        String appName = "BTR15 Tool";
        String versionSuffix = "";
        try {
            String version = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
            if (version != null && !version.isEmpty()) {
                versionSuffix = " " + version;
            }
        } catch (PackageManager.NameNotFoundException ignored) {
            // The header can still display the app name.
        }
        SpannableString brandTitle = new SpannableString(appName + versionSuffix);
        brandTitle.setSpan(new StyleSpan(Typeface.BOLD), 0, appName.length(),
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        TextView brand = text("", 16, BLACK, false);
        brand.setText(brandTitle);
        top.addView(brand, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        stepNumber = label("1 of 6");
        top.addView(stepNumber);
        header.addView(top);
        header.addView(rule(BLACK, 2), fullWidth(dp(2), dp(13)));
        root.addView(header);

        flashHeader = new LinearLayout(this);
        flashHeader.setOrientation(LinearLayout.VERTICAL);
        flashHeader.setPadding(dp(22), dp(20), dp(22), 0);
        flashHeader.addView(headingView("Flash"));
        flashStatusView = label(flashStatus);
        flashStatusView.setPadding(0, 0, 0, dp(14));
        flashHeader.addView(flashStatusView);
        flashHeader.addView(rule(BLACK, 1));
        flashHeader.setVisibility(View.GONE);
        root.addView(flashHeader);

        stageScroll = new ScrollView(this);
        stageScroll.setFillViewport(true);
        stage = new LinearLayout(this);
        stage.setOrientation(LinearLayout.VERTICAL);
        stage.setPadding(dp(22), dp(20), dp(22), dp(28));
        stageScroll.addView(stage);
        root.addView(stageScroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        LinearLayout footer = new LinearLayout(this);
        footer.setOrientation(LinearLayout.VERTICAL);
        firmwareCredits = new LinearLayout(this);
        firmwareCredits.setOrientation(LinearLayout.VERTICAL);
        firmwareCredits.setPadding(dp(22), dp(8), dp(22), dp(18));
        firmwareCredits.addView(text("Built by nik343 with help from AI",
                NOTE_TEXT_SP, BLACK, false), marginTop(0));
        firmwareCredits.addView(text(
                "Flashing with this unofficial tool may erase device data or leave your BTR15 unusable",
                NOTE_TEXT_SP, ATTENTION, true), marginTop(dp(6)));
        footer.addView(firmwareCredits, marginTop(0));
        footer.addView(rule(LINE, 1));
        LinearLayout actions = new LinearLayout(this);
        actions.setPadding(dp(22), dp(13), dp(22), dp(18));

        backButton = outlineButton("Back");
        backButton.setOnClickListener(v -> {
            if (flashScreen) {
                if (powerCycleScreen) {
                    exportLog();
                } else if (!flashRunning && isFlashFinished()) {
                    exportLog();
                } else if (!flashRunning) {
                    flashScreen = false;
                    renderStep();
                }
            } else if (step > 0) {
                if (step == STEP_DEVICE) {
                    invalidateDeviceConnection();
                }
                returnToFirmwareForRecovery = false;
                step--;
                renderStep();
            }
        });
        actions.addView(backButton, new LinearLayout.LayoutParams(0, dp(48), 1f));
        View gap = new View(this);
        actions.addView(gap, new LinearLayout.LayoutParams(dp(10), 1));

        nextButton = solidButton("Continue");
        nextButton.setOnClickListener(v -> handlePrimaryAction());
        actions.addView(nextButton, new LinearLayout.LayoutParams(0, dp(48), 2f));
        footer.addView(actions);
        root.addView(footer);
        return root;
    }

    private void handlePrimaryAction() {
        if (flashScreen) {
            if (powerCycleScreen) {
                if (!hasBluetoothPermission()) {
                    requestBluetoothPermission();
                } else if (!powerCycleReconnectInProgress) {
                    attemptPowerCycleReconnect(false);
                }
                return;
            }
            if (!flashRunning && isFlashFinished()) {
                resetToStart();
                return;
            }
            if (!flashRunning && recoveryNeedsIdentity) {
                flashScreen = false;
                recoveryNeedsIdentity = false;
                returnToFirmwareForRecovery = true;
                useExistingMnemonic = true;
                useJailbreak = false;
                restoreStock = false;
                existingMnemonic = "";
                savedExistingMnemonic = null;
                identityError = null;
                step = STEP_KEY;
                renderStep();
                return;
            }
            if (!flashRunning && pendingJournalExists()) {
                startRecoveryFlow();
                return;
            }
            exportLog();
            return;
        }
        if (step == STEP_KEY && !saveSelectedIdentity()) {
            return;
        }
        if (step == STEP_DEVICE && !isSelectedDeviceConnected()) {
            connectSelectedDevice();
            return;
        }
        if ((step == STEP_KEY || step == STEP_DEVICE) && returnToFirmwareForRecovery) {
            returnToFirmwareForRecovery = false;
            step = STEP_FIRMWARE;
            renderStep();
            return;
        }
        if (step < STEP_REVIEW) {
            step++;
            renderStep();
            return;
        }
        if (!isSelectedDeviceConnected()) {
            step = STEP_DEVICE;
            renderStep();
            return;
        }
        flashScreen = true;
        flashStarted = false;
        powerCycleRequired = false;
        powerCycleScreen = false;
        powerCycleLayoutPassPending = false;
        powerCycleLayoutMeasured = false;
        powerCycleState = 0;
        powerCycleError = null;
        powerCycleReconnectPending = false;
        flashRunToken++;
        flashLog.setLength(0);
        renderStep();
    }

    private void renderStep() {
        boolean showFlashLog = flashScreen && !powerCycleScreen;
        int logScrollY = flashLogView != null && stageScroll.canScrollVertically(1)
                ? stageScroll.getScrollY() : -1;
        flashLogView = null;
        flashHeader.setVisibility(showFlashLog ? View.VISIBLE : View.GONE);
        firmwareCredits.setVisibility(!flashScreen && step == STEP_FIRMWARE
                ? View.VISIBLE : View.GONE);
        stage.setPadding(dp(22), showFlashLog ? 0 : dp(20), dp(22), showFlashLog ? 0 : dp(28));
        stageScroll.setVerticalScrollBarEnabled(true);
        stage.removeAllViews();
        stageScroll.scrollTo(0, 0);
        if (flashScreen) {
            renderFlash(logScrollY);
            return;
        }

        setFooterWeights(1f, 2f);
        stepNumber.setText((step + 1) + " of " + STEP_COUNT);
        backButton.setText("Back");
        backButton.setVisibility(step == STEP_FIRMWARE ? View.GONE : View.VISIBLE);
        nextButton.setText(step == STEP_REVIEW ? "Flash" : "Continue");
        switch (step) {
            case STEP_FIRMWARE:
                renderFirmware();
                break;
            case STEP_KEY:
                renderKey();
                break;
            case STEP_METHOD:
                renderMethod();
                break;
            case STEP_CHANGES:
                renderChanges();
                break;
            case STEP_DEVICE:
                renderDevice();
                break;
            default:
                renderReview();
                break;
        }
    }

    private void renderFirmware() {
        heading("Select firmware");
        Button choose = outlineButton(firmwareUri == null ? "Choose file" : "Choose another file");
        choose.setOnClickListener(v -> openFirmwarePicker());
        stage.addView(choose, fullWidth(dp(48), dp(8)));

        Journal pending = pendingJournal();
        if (pending != null) {
            warning("An unfinished transaction was found on this phone: " + pendingSummary()
                    + ". It is recommended to finish it with Recovery before starting anything new.");
            Button recover = outlineButton("Recover unfinished transaction");
            recover.setOnClickListener(v -> startRecoveryFlow());
            stage.addView(recover, fullWidth(dp(48), dp(8)));
            Button discard = new HoldToDiscardButton(this, DISABLED, dp(1),
                    this::discardPendingJournal);
            styleButton(discard, "Discard unfinished transaction");
            discard.setTextColor(BLACK);
            discard.setBackground(rect(WHITE, BLACK, 1));
            discard.setStateListAnimator(null);
            discard.setContentDescription("Discard unfinished transaction. Hold for three seconds.");
            stage.addView(discard, fullWidth(dp(48), dp(8)));
            if (pendingDeviceUnstamped()) {
                Button pick = outlineButton("Select the device for this transaction");
                pick.setOnClickListener(v -> {
                    returnToFirmwareForRecovery = true;
                    step = STEP_DEVICE;
                    renderStep();
                });
                stage.addView(pick, fullWidth(dp(48), dp(8)));
            }
        } else if (journalLookupError != null) {
            // A record exists but cannot be read: Recovery still runs (it reads
            // the device and rewrites the record), and Discard is the way out.
            warning("An unfinished transaction is recorded on this phone but its journal cannot be"
                    + " read: " + journalLookupError + ".");
            muted("Recovery reads the BTR15's own context and repairs it; Discard drops the broken"
                    + " record and clears the device.");
            Button recover = outlineButton("Recover unfinished transaction");
            recover.setOnClickListener(v -> startRecoveryFlow());
            stage.addView(recover, fullWidth(dp(48), dp(8)));
            Button discard = new HoldToDiscardButton(this, DISABLED, dp(1),
                    this::discardPendingJournal);
            styleButton(discard, "Discard unreadable record");
            discard.setTextColor(BLACK);
            discard.setBackground(rect(WHITE, BLACK, 1));
            discard.setStateListAnimator(null);
            discard.setContentDescription("Discard unreadable record. Hold for three seconds.");
            stage.addView(discard, fullWidth(dp(48), dp(8)));
            Button pick = outlineButton("Select the device for this transaction");
            pick.setOnClickListener(v -> {
                returnToFirmwareForRecovery = true;
                step = STEP_DEVICE;
                renderStep();
            });
            stage.addView(pick, fullWidth(dp(48), dp(8)));
        }
        if (firmwareUri == null) {
            muted("No file selected");
            setNextEnabled(false);
            return;
        }
        if (readingFirmware) {
            muted("Reading file…");
            setNextEnabled(false);
            return;
        }
        property("Version", firmwareVersion == null ? "Unknown" : firmwareVersion);
        property("File", firmwareName);
        property("Size", formatBytes(firmwareBytes));
        property("SHA-256", firmwareHash == null ? "Unavailable" : firmwareHash);
        if (firmwareBlockedReason != null && !firmwareReadFailed) {
            // FiiO's key block cannot be found and replaced safely: Continuing
            // would build a package this app could not promise anything about.
            warning(firmwareBlockedReason);
        } else if (firmwareRelease != null && !firmwareRelease.official && !firmwareReadFailed) {
            warning("This firmware is not in the supported list.");
        }
        if (firmwareReadFailed) {
            warning(firmwareValidationError == null
                    ? "The file could not be read." : firmwareValidationError);
        }
        // An unlisted package is allowed to continue once its key block is
        // identified; only an unusable one is refused here.
        setNextEnabled(!firmwareReadFailed && firmwareRelease != null);
    }

    private void renderKey() {
        heading("Signing identity");
        LinearLayout choices = new LinearLayout(this);
        choices.setOrientation(LinearLayout.VERTICAL);
        if (!returnToFirmwareForRecovery) {
            choices.addView(choiceRow("New 12-word mnemonic", !useExistingMnemonic, v -> {
                useExistingMnemonic = false;
                // A new identity defaults to the first-install option.
                useJailbreak = true;
                restoreStock = false;
                renderStep();
            }));
        }
        choices.addView(choiceRow("Existing 12-word mnemonic", useExistingMnemonic, v -> {
            useExistingMnemonic = true;
            // A mnemonic the user already holds is a key this device may
            // already trust, so the Method step opens on the developer-key
            // update it can run without a power cycle.
            useJailbreak = false;
            restoreStock = false;
            renderStep();
        }));
        stage.addView(choices);

        if (useExistingMnemonic) {
            // The identity the phone already holds is shown as the HINT, so it
            // looks filled in but leaves the box empty: typing or pasting a
            // mnemonic replaces it outright instead of having to delete first.
            if (savedExistingMnemonic == null) {
                try {
                    String saved = MnemonicStore.loadExisting(this);
                    if (saved != null && Bip39.isValid(saved)) {
                        savedExistingMnemonic = saved;
                    }
                } catch (Exception unavailable) {
                    identityError = "Signing identity could not be loaded. Restore your mnemonic.";
                }
            }
            sectionLabel("Mnemonic");
            EditText input = mnemonicInput();
            input.setText(existingMnemonic);
            input.setHint(savedExistingMnemonic == null ? "12 words" : savedExistingMnemonic);
            input.setHintTextColor(savedExistingMnemonic == null ? MID : PREFILL);
            stage.addView(input, fullWidth(dp(96), dp(8)));
            TextView validity = text("", 12, MID, false);
            stage.addView(validity, marginTop(dp(7)));
            input.addTextChangedListener(new TextWatcher() {
                @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) { }
                @Override public void onTextChanged(CharSequence s, int start, int before, int countValue) {
                    existingMnemonic = s.toString();
                    updateMnemonicValidity(validity);
                }
                @Override public void afterTextChanged(Editable s) { }
            });
            updateMnemonicValidity(validity);
        } else {
            if (generatedMnemonic.length() == 0) {
                try {
                    generatedMnemonic = MnemonicStore.loadOrCreate(this);
                    identityError = null;
                } catch (Exception error) {
                    identityError = "Signing identity could not be loaded. Restore your mnemonic.";
                }
            }
            if (identityError != null) {
                warning(identityError);
                setNextEnabled(false);
                return;
            }
            sectionLabel("Mnemonic");
            TextView mnemonic = new TextView(this);
            styleMnemonicBox(mnemonic);
            mnemonic.setText(generatedMnemonic);
            mnemonic.setTextIsSelectable(true);
            mnemonic.setMinHeight(dp(96));
            stage.addView(mnemonic, marginTop(dp(8)));

            String backupText = "BACK UP THIS MNEMONIC. Keep it somewhere safe; it is recommended to"
                    + " use the key for subsequent updates. Losing it while running firmware that is"
                    + " no longer vulnerable to the exploit used for the jailbreak risks leaving the"
                    + " device permanently stuck on that firmware. See Jailbreak.md for more"
                    + " information";
            SpannableString backupMessage = new SpannableString(backupText);
            int emphasisEnd = "BACK UP THIS MNEMONIC".length();
            backupMessage.setSpan(new ForegroundColorSpan(ATTENTION), 0, emphasisEnd,
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            backupMessage.setSpan(new StyleSpan(Typeface.BOLD), 0, emphasisEnd,
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            TextView backup = text("", 14, BLACK, false);
            backup.setText(backupMessage);
            backup.setLineSpacing(dp(3), 1f);
            backup.setPadding(0, dp(16), 0, dp(8));
            stage.addView(backup);
            setNextEnabled(true);
        }
    }

    private EditText mnemonicInput() {
        EditText box = new EditText(this);
        box.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        box.setMinLines(3);
        box.setMaxLines(4);
        styleMnemonicBox(box);
        return box;
    }

    private void styleMnemonicBox(TextView box) {
        box.setTextColor(BLACK);
        box.setTextSize(16);
        box.setLineSpacing(dp(3), 1f);
        box.setIncludeFontPadding(true);
        box.setGravity(Gravity.TOP | Gravity.START);
        box.setPadding(dp(12), dp(11), dp(12), dp(11));
        box.setBackground(rect(WHITE, BLACK, 1));
    }

    private void updateMnemonicValidity(TextView view) {
        String effective = effectiveExistingMnemonic();
        int count = wordCount(effective);
        boolean valid = Bip39.isValid(effective);
        if (count == 12 && !valid) {
            view.setText("Invalid mnemonic");
            view.setTextColor(ATTENTION);
        } else {
            view.setText(count + " / 12");
            view.setTextColor(MID);
        }
        setNextEnabled(valid);
    }

    /**
     * What the box actually signs with: the typed text, or the identity the
     * phone already holds while the box is still untouched.
     */
    private String effectiveExistingMnemonic() {
        String typed = existingMnemonic == null ? "" : existingMnemonic.trim();
        if (typed.length() > 0) {
            return typed;
        }
        return savedExistingMnemonic == null ? "" : savedExistingMnemonic;
    }

    private boolean saveSelectedIdentity() {
        String mnemonic = useExistingMnemonic
                ? Bip39.normalize(effectiveExistingMnemonic()) : generatedMnemonic;
        if (!Bip39.isValid(mnemonic)) {
            return false;
        }
        try {
            MnemonicStore.save(this, mnemonic);
            generatedMnemonic = mnemonic;
            savedExistingMnemonic = mnemonic;
            identityError = null;
            return true;
        } catch (Exception error) {
            identityError = "Signing identity could not be saved.";
            Toast.makeText(this, identityError, Toast.LENGTH_LONG).show();
            return false;
        }
    }

    private void loadSigningIdentityDefault() {
        savedExistingMnemonic = null;
        try {
            savedExistingMnemonic = MnemonicStore.loadConfirmed(this);
        } catch (Exception unavailable) {
            // The signing screen still allows restoring a backed-up mnemonic.
        }
        useExistingMnemonic = savedExistingMnemonic != null;
        useJailbreak = !useExistingMnemonic;
    }

    private void rememberSigningIdentity(String mnemonic, boolean confirmed) {
        try {
            MnemonicStore.setDeveloperUpdateConfirmed(this, mnemonic, confirmed);
        } catch (Exception unavailable) {
            appendFlashLog("Could not save the signing identity preference.");
        }
    }

    private void renderMethod() {
        heading("Install method");
        LinearLayout choices = new LinearLayout(this);
        choices.setOrientation(LinearLayout.VERTICAL);
        choices.addView(choiceRow("Jailbreak / first install",
                FirmwareReleases.jailbreakScope(), useJailbreak, true, v -> {
            useJailbreak = true;
            restoreStock = false;
            renderStep();
        }));
        choices.addView(choiceRow("Developer-key update", !useJailbreak, v -> {
            useJailbreak = false;
            renderStep();
        }));
        stage.addView(choices);
        setNextEnabled(true);
    }

    private void renderChanges() {
        heading("Select changes");
        boolean stockRestoreAvailable = canRestoreStock();
        if (!stockRestoreAvailable) {
            restoreStock = false;
        }
        // One source of truth for both rows: its words, whether it can be tapped
        // and whether it is really on.  A change the release cannot take is never
        // left checked, and stock restore greys both without renaming them.
        ChangeOptions.Row automuteRow = ChangeOptions.automute(firmwareRelease, restoreStock,
                automute);
        ChangeOptions.Row hundredHertzRow = ChangeOptions.hundredHertz(firmwareRelease, restoreStock,
                demo100Hz);
        automute = automuteRow.checked;
        demo100Hz = hundredHertzRow.checked;

        stage.addView(choiceRow(automuteRow.label, automuteRow.checked, automuteRow.enabled, v -> {
            automute = !automute;
            renderStep();
        }));
        stage.addView(choiceRow(hundredHertzRow.label, hundredHertzRow.checked,
                hundredHertzRow.enabled, v -> {
                    demo100Hz = !demo100Hz;
                    renderStep();
                }));
        stage.addView(choiceRow("Restore stock firmware", restoreStock,
                stockRestoreAvailable, v -> {
                    restoreStock = !restoreStock;
                    if (restoreStock) {
                        automute = false;
                        demo100Hz = false;
                    }
                    renderStep();
                }));

        if (!stockRestoreAvailable && !useJailbreak) {
            muted("Select a recognized stock firmware to enable this.");
        }
        setNextEnabled(true);
    }

    private void renderDevice() {
        heading("Connect BTR15");
        BluetoothAdapter adapter = Btr15Connection.adapter(this);
        if (adapter == null) {
            warning("Bluetooth is not available on this phone.");
            setNextEnabled(false);
            return;
        }
        if (!hasBluetoothPermission()) {
            Button permission = outlineButton("Allow Bluetooth access");
            permission.setOnClickListener(v -> requestBluetoothPermission());
            stage.addView(permission, fullWidth(dp(48), dp(8)));
            setNextEnabled(false);
            return;
        }
        if (!adapter.isEnabled()) {
            Button enable = outlineButton("Turn on Bluetooth");
            enable.setOnClickListener(v -> startActivityForResult(
                    new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE), ENABLE_BLUETOOTH));
            stage.addView(enable, fullWidth(dp(48), dp(8)));
            setNextEnabled(false);
            return;
        }

        try {
            bondedDevices = Btr15Connection.bondedDevices(this);
        } catch (SecurityException error) {
            requestBluetoothPermission();
            setNextEnabled(false);
            return;
        }

        List<Btr15Connection.Device> named = new ArrayList<>();
        for (Btr15Connection.Device device : bondedDevices) {
            if (device.isNamedBtr15()) {
                named.add(device);
            }
        }
        List<Btr15Connection.Device> shown = named.isEmpty() ? bondedDevices : named;
        if (selectedDeviceAddress == null && named.size() == 1) {
            selectedDeviceAddress = named.get(0).address;
        }

        if (shown.isEmpty()) {
            muted("Pair the BTR15 in Android's Bluetooth settings.");
            Button settings = outlineButton("Open Bluetooth settings");
            settings.setOnClickListener(v -> startActivity(
                    new Intent(Settings.ACTION_BLUETOOTH_SETTINGS)));
            stage.addView(settings, fullWidth(dp(48), dp(8)));
            nextButton.setText("Connect");
            setNextEnabled(false);
            return;
        }
        if (named.isEmpty()) {
            muted("Choose the paired BTR15.");
        }
        for (Btr15Connection.Device device : shown) {
            stage.addView(deviceRow(device));
        }

        Btr15Connection.Probe probe = btr15.currentProbe();
        boolean connected = probe != null && isSelectedDeviceConnected();
        if (connectingDevice) {
            muted("Connecting…");
        } else if (connectionError != null) {
            warning(connectionError);
            Button export = outlineButton("Export log");
            export.setOnClickListener(v -> exportLog());
            stage.addView(export, fullWidth(dp(48), dp(8)));
        } else if (connected) {
            property("Status", "Connected");
            property("Installed firmware", "v" + probe.firmwareVersion);
        }

        nextButton.setText(connected ? "Continue" : "Connect");
        setNextEnabled(!connectingDevice && (connected || selectedDevice() != null));
    }

    private LinearLayout deviceRow(Btr15Connection.Device device) {
        boolean selected = device.address.equalsIgnoreCase(selectedDeviceAddress);
        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setMinimumHeight(dp(62));
        row.setPadding(0, dp(8), 0, dp(8));
        row.setClickable(true);
        row.setFocusable(true);
        row.setOnClickListener(v -> {
            if (!device.address.equalsIgnoreCase(selectedDeviceAddress)) {
                invalidateDeviceConnection();
            }
            selectedDeviceAddress = device.address;
            connectionError = null;
            renderStep();
        });

        View mark = new View(this);
        mark.setBackground(rect(selected ? BLACK : WHITE, BLACK, 1));
        row.addView(mark, new LinearLayout.LayoutParams(dp(18), dp(18)));

        LinearLayout copy = new LinearLayout(this);
        copy.setOrientation(LinearLayout.VERTICAL);
        copy.setPadding(dp(12), 0, 0, 0);
        copy.addView(text(device.name, 16, BLACK, false));
        TextView address = text(device.address, 12, MID, false);
        address.setPadding(0, dp(4), 0, 0);
        copy.addView(address);
        row.addView(copy, new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        return row;
    }

    private void connectSelectedDevice() {
        Btr15Connection.Device selected = selectedDevice();
        if (selected == null || connectingDevice) {
            return;
        }
        int attempt = btr15.beginProbe();
        connectingDevice = true;
        connectionError = null;
        connectionErrorDetail = null;
        appendDiagnostic("Connecting to " + selected.name + " (" + selected.address + ")");
        renderStep();
        new Thread(() -> {
            Btr15Connection.Probe connected;
            try {
                connected = btr15.connectAndProbe(getApplicationContext(), selected, attempt);
            } catch (Exception error) {
                runOnUiThread(() -> {
                    if (!isDeviceConnectionCurrent(attempt)) {
                        return;
                    }
                    connectingDevice = false;
                    connectionError = "Could not connect. Make sure the BTR15 is on and paired.";
                    connectionErrorDetail = error.getClass().getSimpleName()
                            + (error.getMessage() == null ? "" : ": " + error.getMessage());
                    appendDiagnostic("Connection failed: " + connectionErrorDetail);
                    renderStep();
                });
                return;
            }
            runOnUiThread(() -> {
                if (isDeviceConnectionCurrent(attempt)) {
                    connectingDevice = false;
                    renderStep();
                }
            });
            if (btr15.awaitDisconnect(connected)) {
                runOnUiThread(() -> {
                    if (!isDeviceConnectionCurrent(attempt)) {
                        return;
                    }
                    connectionError = "Connection lost. Reconnect to the BTR15.";
                    appendDiagnostic("BTR15 connection lost.");
                    renderStep();
                });
            }
        }, "btr15-connect").start();
    }

    private void invalidateDeviceConnection() {
        btr15.close();
        connectingDevice = false;
        connectionError = null;
        connectionErrorDetail = null;
    }

    private boolean isDeviceConnectionCurrent(int attempt) {
        return !flashScreen && (step == STEP_DEVICE || step == STEP_REVIEW)
                && btr15.isCurrentAttempt(attempt);
    }

    private Btr15Connection.Device selectedDevice() {
        if (selectedDeviceAddress == null) {
            return null;
        }
        for (Btr15Connection.Device device : bondedDevices) {
            if (device.address.equalsIgnoreCase(selectedDeviceAddress)) {
                return device;
            }
        }
        return null;
    }

    private boolean isSelectedDeviceConnected() {
        return selectedDeviceAddress != null && btr15.isConnectedTo(selectedDeviceAddress);
    }

    private boolean hasBluetoothPermission() {
        if (Build.VERSION.SDK_INT < 31) {
            return true;
        }
        return checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                        == PackageManager.PERMISSION_GRANTED
                && checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN)
                        == PackageManager.PERMISSION_GRANTED;
    }

    private void requestBluetoothPermission() {
        if (Build.VERSION.SDK_INT >= 31) {
            requestPermissions(new String[] {
                            Manifest.permission.BLUETOOTH_CONNECT,
                            Manifest.permission.BLUETOOTH_SCAN
                    },
                    REQUEST_BLUETOOTH);
        }
    }

    private void renderReview() {
        heading("Confirm");
        property("Version", firmwareVersion == null ? "Unknown" : firmwareVersion);
        property("File", firmwareName == null ? "None" : firmwareName);
        Btr15Connection.Probe probe = btr15.currentProbe();
        property("Device", probe == null ? "Not connected" : probe.device.name);
        property("Address", probe == null ? "—" : probe.device.address);
        property("Installed firmware", probe == null ? "—" : "v" + probe.firmwareVersion);
        property("Identity", useExistingMnemonic ? "Existing mnemonic" : "New mnemonic");
        property("Method", useJailbreak ? "Jailbreak / first install" : "Developer-key update");
        property("Changes", selectedChangesSummary());
        setNextEnabled(isSelectedDeviceConnected());
    }

    private boolean canRestoreStock() {
        return !useJailbreak && firmwareVersion != null;
    }

    private String selectedChangesSummary() {
        if (restoreStock) {
            return "Restore stock firmware";
        }
        boolean takeAutomute = ChangeOptions.automute(firmwareRelease, false, automute).checked;
        boolean takeHundredHertz = ChangeOptions.hundredHertz(firmwareRelease, false, demo100Hz)
                .checked;
        if (takeAutomute && takeHundredHertz) {
            return "Automute fix, 100 Hz demo";
        }
        if (takeAutomute) {
            return "Automute fix";
        }
        if (takeHundredHertz) {
            return "100 Hz demo";
        }
        return "None";
    }

    private void renderFlash(int logScrollY) {
        if (powerCycleScreen) {
            renderPowerCycle();
            return;
        }

        stepNumber.setText("FLASH");

        boolean startNow = !flashStarted;
        if (startNow) {
            flashStarted = true;
            flashRunning = true;
            flashStatus = "PREPARING";
        }
        boolean finished = !flashRunning && isFlashFinished();
        boolean offerIdentity = !flashRunning && recoveryNeedsIdentity;
        // Stopped with a live journal: the primary action becomes one-tap
        // Recovery right here — the user never has to hunt for the button.
        boolean offerRecovery = !flashRunning && !finished && !offerIdentity
                && pendingJournalExists();
        setFooterWeights(1f, finished ? 1f : 2f);
        backButton.setText(finished ? "Export log" : "Back");
        backButton.setVisibility(flashRunning ? View.GONE : View.VISIBLE);
        nextButton.setText(finished ? "Finish"
                : offerIdentity ? "Re-enter mnemonic"
                : offerRecovery ? "Recover unfinished transaction" : "Export log");
        setNextEnabled(flashLog.length() > 0);

        flashStatusView.setText(flashStatus);
        flashLogView = text(FlashLogText.forDisplay(flashLog), 13, BLACK, false);
        flashLogView.setTypeface(Typeface.MONOSPACE);
        flashLogView.setTextIsSelectable(true);
        flashLogView.setLineSpacing(dp(2), 1f);
        flashLogView.setPadding(0, dp(16), 0, dp(24));
        stage.addView(flashLogView);
        positionFlashLog(logScrollY);

        if (startNow) {
            int token = ++flashRunToken;
            new Thread(() -> runFlashPreparation(token), "flash-preview").start();
        }
    }

    private void renderPowerCycle() {
        float logicalWidth = getResources().getDisplayMetrics().widthPixels
                / getResources().getDisplayMetrics().density;
        setFooterWeights(logicalWidth < 330f ? 1.25f : 1f,
                logicalWidth < 330f ? 1.75f : 2f);
        stepNumber.setText("FLASH");
        heading("Power cycle required");

        if (stageScroll != null && stageScroll.getHeight() > 0) {
            powerCycleLayoutMeasured = true;
        } else if (!powerCycleLayoutMeasured && !powerCycleLayoutPassPending) {
            powerCycleLayoutPassPending = true;
            stage.post(() -> {
                powerCycleLayoutPassPending = false;
                if (powerCycleScreen && stage != null) {
                    renderStep();
                }
            });
        }

        if (stageScroll != null) {
            stageScroll.setVerticalScrollBarEnabled(true);
        }

        registerPowerCycleReceiver();

        // The device drawing stays vector-native while the Bluetooth state
        // machine selects the matching display/arrow variant.
        addPowerCycleIllustration();

        TextView action = text(powerCycleInstruction(), 16, BLACK, false);
        action.setGravity(Gravity.START);
        action.setTextAlignment(View.TEXT_ALIGNMENT_VIEW_START);
        action.setPadding(0, 0, 0, dp(18));
        stage.addView(action);

        boolean needsDeviceChoice = powerCycleState == POWER_CYCLE_RECONNECT_FAILED
                || selectedDevice() == null;
        if (needsDeviceChoice) {
            warning(powerCycleState == POWER_CYCLE_RECONNECT_FAILED
                    ? "Could not reconnect. Select the BTR15 and try again."
                    : "Select the paired BTR15 to continue.");
            renderPowerCycleDevices();
        }

        renderPowerCycleActions();
    }

    private void renderPowerCycleActions() {
        backButton.setText("Export log");
        backButton.setVisibility(View.VISIBLE);
        if (!hasBluetoothPermission()) {
            nextButton.setText("Allow Bluetooth access");
            setNextEnabled(true);
        } else if (powerCycleReconnectInProgress
                || powerCycleState == POWER_CYCLE_CONNECTED_HOLD) {
            nextButton.setText("Connecting…");
            setNextEnabled(false);
        } else if (powerCycleState == POWER_CYCLE_WAITING_FOR_OFF
                || powerCycleState == POWER_CYCLE_WAITING_FOR_DARK) {
            nextButton.setText("Waiting…");
            setNextEnabled(false);
        } else {
            nextButton.setText("Reconnect");
            setNextEnabled(selectedDevice() != null);
        }
    }

    private void addPowerCycleIllustration() {
        Btr15VectorIllustration illustration = new Btr15VectorIllustration(
                this, powerCycleIllustrationVariant());
        int availableWidth = stage != null && stage.getWidth() > 0
                ? stage.getWidth() - stage.getPaddingLeft() - stage.getPaddingRight()
                : getResources().getDisplayMetrics().widthPixels - dp(44);
        availableWidth = Math.max(1, availableWidth);
        int illustrationHeight = Btr15VectorIllustration.recommendedHeight(this,
                availableWidth);
        if (stageScroll != null && stageScroll.getHeight() > 0) {
            int contentWidth = Math.max(1, availableWidth);
            TextView instructionMeasure = text(powerCycleInstruction(), 16, BLACK, false);
            instructionMeasure.setGravity(Gravity.START);
            instructionMeasure.setTextAlignment(View.TEXT_ALIGNMENT_VIEW_START);
            instructionMeasure.setPadding(0, 0, 0, dp(18));
            instructionMeasure.measure(
                    View.MeasureSpec.makeMeasureSpec(contentWidth, View.MeasureSpec.EXACTLY),
                    View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED));

            int fixedHeight = stage.getPaddingTop() + stage.getPaddingBottom();
            for (int index = 0; index < stage.getChildCount(); index++) {
                View child = stage.getChildAt(index);
                child.measure(
                        View.MeasureSpec.makeMeasureSpec(contentWidth, View.MeasureSpec.EXACTLY),
                        View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED));
                fixedHeight += child.getMeasuredHeight();
            }
            int margins = dp(4);
            int availableHeight = stageScroll.getHeight() - fixedHeight
                    - instructionMeasure.getMeasuredHeight() - margins;
            if (availableHeight > 0) {
                illustrationHeight = Math.min(illustrationHeight, availableHeight);
            }
        }
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                illustrationHeight);
        params.topMargin = dp(2);
        params.bottomMargin = dp(2);
        stage.addView(illustration, params);
    }

    private int powerCycleIllustrationVariant() {
        if (powerCycleState == POWER_CYCLE_WAITING_FOR_OFF) {
            return Btr15VectorIllustration.DISPLAY_ON_ARROW;
        }
        if (powerCycleState == POWER_CYCLE_WAITING_FOR_DARK) {
            return Btr15VectorIllustration.DISPLAY_OFF;
        }
        return Btr15VectorIllustration.DISPLAY_OFF_ARROW;
    }

    private String powerCycleInstruction() {
        if (powerCycleState == POWER_CYCLE_WAITING_FOR_OFF) {
            return "Turn the BTR15 completely off.";
        }
        if (powerCycleState == POWER_CYCLE_WAITING_FOR_DARK) {
            return "Wait until its display is dark.";
        }
        return "Turn it back on in Bluetooth mode and leave it on.";
    }

    private void instruction(String number, String value) {
        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setMinimumHeight(dp(52));
        row.setPadding(0, dp(8), 0, dp(8));

        TextView index = text(number, 16, BLACK, true);
        row.addView(index, new LinearLayout.LayoutParams(dp(18),
                ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView instruction = text(value, 16, BLACK, false);
        instruction.setLineSpacing(dp(2), 1f);
        instruction.setPadding(dp(12), 0, 0, 0);
        row.addView(instruction, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        stage.addView(row);
    }

    private void renderPowerCycleDevices() {
        try {
            bondedDevices = Btr15Connection.bondedDevices(this);
        } catch (Exception error) {
            return;
        }
        List<Btr15Connection.Device> named = new ArrayList<>();
        for (Btr15Connection.Device device : bondedDevices) {
            if (device.isNamedBtr15()) {
                named.add(device);
            }
        }
        List<Btr15Connection.Device> shown = named.isEmpty() ? bondedDevices : named;
        for (Btr15Connection.Device device : shown) {
            stage.addView(powerCycleDeviceRow(device));
        }
    }

    private LinearLayout powerCycleDeviceRow(Btr15Connection.Device device) {
        boolean selected = device.address.equalsIgnoreCase(selectedDeviceAddress);
        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setMinimumHeight(dp(62));
        row.setPadding(0, dp(8), 0, dp(8));
        row.setClickable(true);
        row.setFocusable(true);
        row.setOnClickListener(v -> {
            btr15.close();
            selectedDeviceAddress = device.address;
            powerCycleError = null;
            powerCycleReconnectPending = false;
            powerCycleState = POWER_CYCLE_WAITING_FOR_ON;
            renderStep();
        });

        View mark = new View(this);
        mark.setBackground(rect(selected ? BLACK : WHITE, BLACK, 1));
        row.addView(mark, new LinearLayout.LayoutParams(dp(18), dp(18)));

        LinearLayout copy = new LinearLayout(this);
        copy.setOrientation(LinearLayout.VERTICAL);
        copy.setPadding(dp(12), 0, 0, 0);
        copy.addView(text(device.name, 16, BLACK, false));
        TextView address = text(device.address, 12, MID, false);
        address.setPadding(0, dp(4), 0, 0);
        copy.addView(address);
        row.addView(copy, new LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        return row;
    }

    private void registerPowerCycleReceiver() {
        if (powerCycleReceiverRegistered || !hasBluetoothPermission()) {
            return;
        }
        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothDevice.ACTION_ACL_DISCONNECTED);
        filter.addAction(BluetoothDevice.ACTION_ACL_CONNECTED);
        try {
            if (Build.VERSION.SDK_INT >= 33) {
                // Bluetooth broadcasts originate from a privileged system app,
                // so Android requires an exported dynamic receiver for them.
                registerReceiver(powerCycleReceiver, filter, Context.RECEIVER_EXPORTED);
            } else {
                registerReceiver(powerCycleReceiver, filter);
            }
            powerCycleReceiverRegistered = true;
        } catch (Exception error) {
            powerCycleError = usefulMessage(error);
            powerCycleState = POWER_CYCLE_RECONNECT_FAILED;
        }
    }

    private void unregisterPowerCycleReceiver() {
        if (!powerCycleReceiverRegistered) {
            return;
        }
        try {
            unregisterReceiver(powerCycleReceiver);
        } catch (Exception ignored) {
            // It may already have been removed with the Activity.
        }
        powerCycleReceiverRegistered = false;
    }

    private void handlePowerCycleBluetoothEvent(Intent intent) {
        if (!powerCycleRequired || selectedDeviceAddress == null || intent == null) {
            return;
        }
        BluetoothDevice device;
        try {
            if (Build.VERSION.SDK_INT >= 33) {
                device = intent.getParcelableExtra(
                        BluetoothDevice.EXTRA_DEVICE, BluetoothDevice.class);
            } else {
                device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
            }
            if (device == null
                    || !selectedDeviceAddress.equalsIgnoreCase(device.getAddress())) {
                return;
            }
        } catch (SecurityException error) {
            return;
        }

        String action = intent.getAction();
        if (BluetoothDevice.ACTION_ACL_DISCONNECTED.equals(action)) {
            btr15.close();
            powerCycleReconnectPending = false;
            powerCycleState = POWER_CYCLE_WAITING_FOR_DARK;
            powerCycleError = null;
            flashLog.append("BTR15 disconnected.\n");
            if (powerCycleScreen) {
                renderStep();
            }
            scheduleDisplayDarkTransition(flashRunToken);
        } else if (BluetoothDevice.ACTION_ACL_CONNECTED.equals(action)
                && powerCycleState != POWER_CYCLE_WAITING_FOR_OFF
                && !powerCycleReconnectInProgress) {
            flashLog.append("Bluetooth link restored.\n");
            if (powerCycleState == POWER_CYCLE_WAITING_FOR_DARK) {
                powerCycleReconnectPending = true;
            } else if (powerCycleState == POWER_CYCLE_WAITING_FOR_ON) {
                attemptPowerCycleReconnect(true);
            }
        }
    }

    private void scheduleDisplayDarkTransition(int token) {
        new Thread(() -> {
            try {
                Thread.sleep(POWER_CYCLE_DARK_HOLD_MILLIS);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                return;
            }
            runOnUiThread(() -> {
                if (token != flashRunToken || !powerCycleRequired
                        || powerCycleState != POWER_CYCLE_WAITING_FOR_DARK) {
                    return;
                }
                powerCycleState = POWER_CYCLE_WAITING_FOR_ON;
                renderStep();
                if (powerCycleReconnectPending) {
                    powerCycleReconnectPending = false;
                    attemptPowerCycleReconnect(true);
                }
            });
        }, "power-cycle-dark-hold").start();
    }

    private void attemptPowerCycleReconnect(boolean automatic) {
        if (!powerCycleRequired || powerCycleReconnectInProgress) {
            return;
        }
        Btr15Connection.Device selected = selectedDevice();
        if (selected == null) {
            powerCycleState = POWER_CYCLE_RECONNECT_FAILED;
            powerCycleError = "No paired BTR15 is selected";
            renderStep();
            return;
        }

        int token = flashRunToken;
        powerCycleReconnectInProgress = true;
        powerCycleState = POWER_CYCLE_RECONNECTING;
        powerCycleError = null;
        flashLog.append(automatic
                ? "Reconnecting after Bluetooth link event.\n"
                : "Reconnecting to selected BTR15.\n");
        renderStep();

        new Thread(() -> {
            try {
                if (automatic) {
                    Thread.sleep(800L);
                }
                Btr15Connection.Probe connected =
                        btr15.connectAndProbe(getApplicationContext(), selected);
                runOnUiThread(() -> finishPowerCycleReconnect(token, selected, connected));
            } catch (Exception error) {
                runOnUiThread(() -> failPowerCycleReconnect(token, selected, error));
            }
        }, "power-cycle-reconnect").start();
    }

    private void finishPowerCycleReconnect(int token, Btr15Connection.Device selected,
            Btr15Connection.Probe connected) {
        if (token != flashRunToken || !powerCycleRequired
                || !selected.address.equalsIgnoreCase(selectedDeviceAddress)) {
            btr15.close();
            return;
        }
        powerCycleReconnectInProgress = false;
        powerCycleReconnectPending = false;
        powerCycleState = POWER_CYCLE_CONNECTED_HOLD;
        powerCycleError = null;
        flashStatus = "CONNECTED";
        flashLog.append("Connection restored.\n")
                .append("Installed firmware: v").append(connected.firmwareVersion).append('\n');
        renderStep();
        new Thread(() -> {
            try {
                Thread.sleep(POWER_CYCLE_CONNECTED_HOLD_MILLIS);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                return;
            }
            runOnUiThread(() -> finishPowerCycleConnectedHold(token, selected));
        }, "power-cycle-connected-hold").start();
    }

    private void finishPowerCycleConnectedHold(int token, Btr15Connection.Device selected) {
        if (token != flashRunToken || !powerCycleRequired
                || powerCycleState != POWER_CYCLE_CONNECTED_HOLD
                || !selected.address.equalsIgnoreCase(selectedDeviceAddress)) {
            return;
        }
        powerCycleRequired = false;
        powerCycleScreen = false;
        powerCycleState = 0;
        unregisterPowerCycleReceiver();
        flashLog.append("Waiting for device to become ready…\n");
        renderStep();
        new Thread(() -> runPostPowerCyclePreview(token), "flash-preview-resume").start();
    }

    private void failPowerCycleReconnect(int token, Btr15Connection.Device selected,
            Exception error) {
        if (token != flashRunToken || !powerCycleRequired
                || !selected.address.equalsIgnoreCase(selectedDeviceAddress)) {
            return;
        }
        powerCycleReconnectInProgress = false;
        powerCycleReconnectPending = false;
        powerCycleState = POWER_CYCLE_RECONNECT_FAILED;
        powerCycleError = usefulMessage(error);
        flashLog.append("Reconnect failed: ").append(powerCycleError).append('\n');
        renderStep();
    }

    private void runPostPowerCyclePreview(int token) {
        try {
            Thread.sleep(5000L); // let the rebooted BTR15 bring its SPP service up
            if (token != flashRunToken || !flashScreen) {
                return;
            }
            runOnUiThread(() -> {
                if (token == flashRunToken && flashScreen) {
                    flashStatus = "RESUMING";
                    if (flashStatusView != null) {
                        flashStatusView.setText(flashStatus);
                    }
                }
            });
            byte[] official = readOfficialForTransaction(true);
            // Same never-guess rule as Recovery: the journal knows which
            // device this transaction staged on, and the resume must return to
            // exactly that one, whatever the wizard field says by now.
            retargetToJournalDevice();
            btr15.close(); // resume sessions dial their own RFCOMM connections
            DeviceOperator operator = newDeviceOperator(deriveSelectedKey());
            try {
                operator.jailbreakResume(official);
                appendFlashLog("Update complete. Enjoy!");
                finishFlashPreparation(token, "COMPLETE");
            } finally {
                lastTranscript = operator.transcriptExport();
            }
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
        } catch (Exception error) {
            appendFlashLog("");
            appendErrorLog(error);
            appendFlashLog("The staged jailbreak stays journaled; press \"Recover unfinished"
                    + " transaction\" below — the Firmware step's Recovery does the same.");
            finishFlashPreparation(token, "STOPPED");
        }
    }

    private void runFlashPreparation(int token) {
        DeviceOperator operator = null;
        try {
            postStatus("READING PACKAGE");
            appendFlashLog("Reading the selected package…");
            byte[] official = readFirmwareBytes(firmwareUri);
            if (firmwareHash == null || !Util.sameHash(firmwareHash, Util.sha256Hex(official))) {
                throw new IllegalStateException("The selected firmware changed after review");
            }
            // The picked bytes must be one of the pinned official releases: every
            // patch offset, the key block and the journal rebuild all key off the
            // profile this identifies.
            FirmwareReleases.Release release = FirmwareReleases.describe(official);
            appendFlashLog("Firmware: " + release.label
                    + (release.official ? " official" : " package")
                    + " (" + formatBytes(official.length) + ")");
            appendFlashLog("SHA-256: " + firmwareHash);
            if (token != flashRunToken || !flashScreen) {
                return;
            }

            appendFlashLog("Deriving the signing identity…");
            postStatus("SIGNING");
            String mnemonic = requireSelectedMnemonic();
            DevKey key = DevKey.derive(mnemonic);
            appendFlashLog("Signing identity ready");

            appendFlashLog("Checking BTR15 connection…");
            if (selectedDeviceAddress == null) {
                throw new IllegalStateException("No BTR15 selected — go back to the device step");
            }
            // The probe runs on the same pooled link the workflow will use:
            // the BTR15 must never see a disconnect/reconnect pair here.
            operator = newDeviceOperator(key);
            postStatus("CHECKING DEVICE");
            String installedFirmware = operator.probeConnection();
            String deviceName = null;
            try {
                deviceName = Btr15Connection.adapter(this)
                        .getRemoteDevice(selectedDeviceAddress).getName();
            } catch (Exception unknown) {
                // the name is cosmetic; the GAIA getter proved the device itself
            }
            appendFlashLog("Device: " + (deviceName == null ? "FIIO BTR15" : deviceName));
            appendFlashLog("Address: " + selectedDeviceAddress);
            appendFlashLog("Installed firmware: v" + installedFirmware
                    + " (GAIA getter verified)");
            appendFlashLog("Method: " + (useJailbreak ? "Jailbreak / first install"
                    : restoreStock ? "Restore stock firmware" : "Developer-key update"));
            appendFlashLog("Changes: " + selectedChangesSummary());
            appendFlashLog("");
            if (token != flashRunToken || !flashScreen) {
                return;
            }

            if (restoreStock) {
                operator.restoreStock(official);
                rememberSigningIdentity(mnemonic, false);
                appendFlashLog("Update complete. Enjoy!");
                finishFlashPreparation(token, "COMPLETE");
            } else if (useJailbreak) {
                boolean coldCycleNeeded = operator.jailbreakStage(official, selectedVariant());
                if (token != flashRunToken || !flashScreen) {
                    return;
                }
                if (coldCycleNeeded) {
                    enterPowerCycleCheckpoint(token);
                } else {
                    // The device already trusted this key, so the staging run
                    // committed and verified the package itself: nothing is owed.
                    rememberSigningIdentity(mnemonic, true);
                    appendFlashLog("Update complete. Enjoy!");
                    finishFlashPreparation(token, "COMPLETE");
                }
            } else {
                operator.update(official, selectedVariant());
                rememberSigningIdentity(mnemonic, true);
                appendFlashLog("Update complete. Enjoy!");
                finishFlashPreparation(token, "COMPLETE");
            }
        } catch (Exception error) {
            appendFlashLog("");
            appendErrorLog(error);
            appendFlashLog("If the device was mid-transaction the journal kept the state:"
                    + " press \"Recover unfinished transaction\" below, or use the Firmware"
                    + " step's Recovery button.");
            finishFlashPreparation(token, "STOPPED");
        } finally {
            // One capture point, so a failure is exportable too: the hex
            // transcript is the only record of which message the device ignored.
            if (operator != null) {
                lastTranscript = operator.transcriptExport();
            }
            releaseLink();
        }
    }

    /** One safe recovery step from the journal plus the live device state. */
    private void startRecoveryFlow() {
        flashScreen = true;
        flashStarted = true;
        flashRunning = true;
        recoveryNeedsIdentity = false;
        powerCycleScreen = false;
        flashStatus = "RECOVERING";
        flashLog.setLength(0);
        renderStep();
        final int token = ++flashRunToken;
        new Thread(() -> runRecovery(token), "btr15-recovery").start();
    }

    /**
     * Recovery must work with the file the transaction was started from, even
     * after an app restart cleared the wizard.  The journal kept its URI (the
     * picker holds a persistable read grant), so re-open it there and adopt
     * the freshly computed digest; the authoritative identity check happens
     * later against the journal's signed-content digest.
     */
    private byte[] readOfficialForTransaction(boolean mayAdoptFromJournal)
            throws IOException, FirmwareException {
        if (firmwareUri == null && mayAdoptFromJournal) {
            String stored = null;
            try {
                Journal pending = Journal.findPending(journalDirectory());
                stored = pending == null ? null : pending.get("official_uri");
            } catch (FirmwareException unreadable) {
                stored = null;
            }
            if (stored != null && !stored.trim().isEmpty()) {
                firmwareUri = Uri.parse(stored.trim());
                firmwareName = displayName(firmwareUri);
                firmwareHash = null;
                appendFlashLog("Re-opened the firmware this transaction used: "
                        + (firmwareName == null ? firmwareUri : firmwareName));
            }
        }
        if (firmwareUri == null) {
            throw new IOException("Recovery needs the official v3.8 file: choose it here"
                    + " (\"Choose file\") and press Recovery again");
        }
        final byte[] bytes = readFirmwareBytes(firmwareUri);
        String actual = Util.sha256Hex(bytes);
        if (firmwareHash == null) {
            firmwareHash = actual; // adopted: nothing to compare against yet
        } else if (!Util.sameHash(firmwareHash, actual)) {
            throw new IOException("Recovery needs the same official v3.8 file"
                    + " that was selected during review");
        }
        return bytes;
    }

    private void runRecovery(int token) {
        try {
            byte[] official = readOfficialForTransaction(true);
            // Never guess the device.  The journal that Recovery continues
            // names the exact MAC the transaction started on; older journals
            // fall back to the address chosen on the Device step.  With no
            // trustworthy answer the run stops — several BTR15s may be
            // bonded, and touching the wrong one is not an option.
            String wanted = resolveTransactionDevice(true);
            appendFlashLog("Recovery device: " + wanted
                    + " — the device this transaction was started on");
            DevKey key = deriveSelectedKey();
            DeviceOperator operator = newDeviceOperator(key);
            appendFlashLog("Recovery: reading the device's upgrade context…");
            try {
                appendFlashLog(operator.describeContext());
            } catch (FirmwareException unreadable) {
                appendFlashLog("Device context unreadable: " + unreadable.getMessage());
            }
            try {
                String outcome = operator.recover(official);
                // The outcome IS the instruction — say it once and stop.  Every
                // non-idle branch of the tree ends with what to do next.
                appendFlashLog(outcome);
                boolean idleNow = !operator.hasPendingJournal();
                if (idleNow && outcome.indexOf("power") < 0
                        && outcome.indexOf("Power") < 0) {
                    finishFlashPreparation(token, FlashLogText.recoveryFinishedStatus(outcome));
                } else {
                    finishFlashPreparation(token, "STOPPED");
                }
            } finally {
                lastTranscript = operator.transcriptExport();
            }
        } catch (MissingSigningIdentityException unavailable) {
            appendFlashLog("The signing identity is unavailable."
                    + " Tap Re-enter mnemonic and enter the phrase used for this update.");
            finishFlashPreparation(token, "STOPPED", true);
        } catch (Exception error) {
            appendErrorLog(error);
            finishFlashPreparation(token, "STOPPED");
        } finally {
            releaseLink();
        }
    }

    // ---- real-transaction plumbing ------------------------------------------

    private byte[] readFirmwareBytes(Uri uri) throws IOException, FirmwareException {
        if (uri == null) {
            throw new IOException("No firmware file selected");
        }
        try (InputStream input = getContentResolver().openInputStream(uri)) {
            if (input == null) {
                throw new IOException("The selected firmware file could not be opened");
            }
            return FirmwareRead.all(input);
        }
    }

    private DevKey deriveSelectedKey() {
        return DevKey.derive(requireSelectedMnemonic());
    }

    private String requireSelectedMnemonic() {
        String mnemonic = useExistingMnemonic
                ? Bip39.normalize(effectiveExistingMnemonic()) : generatedMnemonic;
        if (!Bip39.isValid(mnemonic)) {
            // An app restart clears the wizard's in-memory identity; Recovery
            // must sign with the stored identity the transaction used.  Only
            // load what exists — never create a fresh key silently, that
            // would sign with a key the device has never seen.
            try {
                mnemonic = MnemonicStore.loadExisting(this);
            } catch (Exception unavailable) {
                mnemonic = null;
            }
            if (Bip39.isValid(mnemonic)) {
                existingMnemonic = mnemonic;
                useExistingMnemonic = true;
            }
        }
        if (!Bip39.isValid(mnemonic)) {
            throw new MissingSigningIdentityException();
        }
        return mnemonic;
    }

    private static final class MissingSigningIdentityException extends IllegalStateException {
        MissingSigningIdentityException() {
            super("The signing identity is unavailable — go back to the Identity step"
                    + " and re-enter your mnemonic");
        }
    }

    /**
     * The variant name is the complete record of the selected changes: the
     * developer key is always present, automute and the 100 Hz menu are the two
     * opt-in extras.  Recovery rebuilds from this name, so it must never lose
     * a selection.
     */
    private FirmwareEngine.Variant selectedVariant() {
        // The package may only carry changes this release can actually take.
        boolean takeAutomute = ChangeOptions.automute(firmwareRelease, restoreStock, automute).checked;
        boolean takeHundredHertz = ChangeOptions.hundredHertz(firmwareRelease, restoreStock,
                demo100Hz).checked;
        return FirmwareEngine.Variant.forChoices(takeAutomute, takeHundredHertz);
    }

    private File journalDirectory() {
        File directory = new File(getFilesDir(), "journals");
        if (!directory.isDirectory() && !directory.mkdirs()) {
            throw new IllegalStateException("The transaction journal directory is unavailable");
        }
        return directory;
    }

    private DeviceOperator newDeviceOperator(DevKey key) {
        return new DeviceOperator(journalDirectory(), key, rfcommTarget(),
                new DeviceOperator.Listener() {
                    @Override public void log(String line) {
                        appendFlashLog(line);
                    }

                    @Override public void status(String status) {
                        postStatus(status);
                    }
                }, selectedDeviceAddress, firmwareUri == null ? null : firmwareUri.toString());
    }

    /**
     * The status line, written by the workflow as it crosses each phase.  The
     * run happens on its own thread, so the phase always hops to the UI; a
     * late line from a run that has moved on is dropped.
     */
    private void postStatus(final String status) {
        runOnUiThread(() -> {
            if (!flashScreen || powerCycleScreen || !flashRunning) {
                return;
            }
            flashStatus = status;
            if (flashStatusView != null) {
                flashStatusView.setText(flashStatus);
            }
        });
    }

    /**
     * All sessions of one wizard step share a single RFCOMM link through a
     * pool; a fresh pool (and so a fresh socket after a settle delay) starts
     * with every step.  The link is released when the step ends.
     */
    private DeviceOperator.Target rfcommTarget() {
        final String address = selectedDeviceAddress;
        LinkPool pool = new LinkPool(new LinkPool.Lift() {
            /**
             * The device's GAIA stack serves exactly ONE client, so the Device
             * step's own probe socket must be gone before the pooled link
             * dials.  This runs before the pool's settle delay (not after it):
             * closing the probe 209 ms before the new socket connected let the
             * firmware answer the cheap getters on the new link while dropping
             * every Upgrade message on it, because its upgrade manager still
             * belonged to the socket that had just gone.
             */
            @Override public void releaseOthers() {
                btr15.close();
            }

            @Override public Transport connect() throws IOException {
                if (address == null) {
                    throw new IOException("no BTR15 selected");
                }
                BluetoothAdapter adapter = Btr15Connection.adapter(MainActivity.this);
                if (adapter == null || !adapter.isEnabled()) {
                    throw new IOException("Bluetooth is off on the phone");
                }
                return new RfcommTransport(adapter, address);
            }

            @Override public void verify(Transport transport) throws IOException {
                // One firmware-version getter proves this socket is the GAIA
                // SPP record and not one of the other services the BTR15
                // advertises under the same UUID (those never answer a frame
                // or are torn down immediately).  Link re-dials on failure.
                Session probe = new Session(transport, LINK_VERIFY_TIMEOUT_MS);
                try {
                    probe.expectFirmwareVersion();
                } catch (Exception silent) {
                    throw new IOException(
                            "this SPP record did not answer GAIA — trying the next one",
                            silent);
                }
                // Answered: the pool owns the link now; it stays open.
            }
        });
        activeLinkPool = pool;
        return pool;
    }

    /**
     * Resolve the exact bonded device this transaction belongs to, without
     * ever guessing: the journal's stamped MAC wins, an unstamped journal
     * falls back to the Device-step choice, and with neither answer the caller
     * is told to pick one.  A blank MAC is always "unset".
     */
    private String resolveTransactionDevice(boolean mayUseFieldChoice)
            throws FirmwareException {
        String wanted = null;
        Journal pending = Journal.findPending(journalDirectory());
        if (pending != null) {
            wanted = pending.get("device_address");
        }
        if (wanted != null && wanted.trim().isEmpty()) {
            wanted = null; // legacy or blank stamp — not a trustworthy answer
        }
        if (wanted == null && mayUseFieldChoice && selectedDeviceAddress != null
                && !selectedDeviceAddress.trim().isEmpty()) {
            wanted = selectedDeviceAddress.trim();
        }
        if (wanted == null) {
            throw new FirmwareException("The transaction does not name a device — go back to"
                    + " the Device step, pick your BTR15, then run this again");
        }
        Btr15Connection.Device found = null;
        for (Btr15Connection.Device candidate : Btr15Connection.bondedDevices(this)) {
            if (candidate.address.equalsIgnoreCase(wanted)) {
                found = candidate;
                break;
            }
        }
        if (found == null) {
            throw new FirmwareException("The transaction device " + wanted
                    + " is not bonded to this phone any more");
        }
        selectedDeviceAddress = found.address;
        return found.address;
    }

    /**
     * Point the wizard at the device the pending transaction staged on.
     * Silent when there is no journal: the resume is already on its device.
     */
    private void retargetToJournalDevice() throws FirmwareException {
        Journal pending = Journal.findPending(journalDirectory());
        if (pending == null || pending.get("device_address") == null) {
            return;
        }
        String address = resolveTransactionDevice(false);
        appendFlashLog("Resuming on " + address + " — the device this transaction staged on");
    }

    /** A dead SPP record must not stall a dial for long before rotating. */
    private static final long LINK_VERIFY_TIMEOUT_MS = 2_500L;

    /** Give the BTR15 its GAIA client slot back when the wizard step is over. */
    private void releaseLink() {
        LinkPool pool = activeLinkPool;
        activeLinkPool = null;
        if (pool != null) {
            pool.release();
        }
    }

    /**
     * File I/O is tiny (a handful of journal files) but never on the main
     * thread's path.  A record that exists but cannot be read is not the same
     * as no record: the reason is kept so the screen can say so and Recovery
     * stays reachable instead of quietly disappearing.
     */
    private Journal pendingJournal() {
        journalLookupError = null;
        try {
            return Journal.findPending(journalDirectory());
        } catch (FirmwareException unreadable) {
            journalLookupError = unreadable.getMessage();
            return null;
        }
    }

    private boolean pendingJournalExists() {
        return pendingJournal() != null;
    }

    /**
     * Drop the pending journal without touching the device — for a transaction
     * that never got anywhere (or one the user wants to abandon).  The device's
     * own key-4 context is untouched: a later run rewrites it from scratch, and
     * Recovery is the right tool when the device is half-way.
     */
    private void discardPendingJournal() {
        try {
            Journal pending = Journal.findPending(journalDirectory());
            if (pending != null) {
                String summary = pendingSummary();
                pending.delete();
                Toast.makeText(this, "Discarded: " + summary, Toast.LENGTH_LONG).show();
            } else if (journalLookupError != null) {
                int removed = Journal.deleteAllPending(journalDirectory());
                Toast.makeText(this, "Discarded " + removed + " unreadable record(s): "
                        + journalLookupError, Toast.LENGTH_LONG).show();
            } else {
                Toast.makeText(this, "No unfinished transaction", Toast.LENGTH_SHORT).show();
            }
        } catch (Exception error) {
            Toast.makeText(this, "Could not discard the transaction: " + usefulMessage(error),
                    Toast.LENGTH_LONG).show();
        }
        renderStep();
    }

    /** One readable line about the pending transaction, for the Firmware step. */
    private String pendingSummary() {
        try {
            Journal pending = Journal.findPending(journalDirectory());
            if (pending == null) {
                return "none";
            }
            String device = pending.get("device_address");
            String kind = pending.getOrEmpty("kind");
            String label = humanKind(kind);
            if (!pending.restorationPhase().isEmpty()) {
                label = label + ", " + pending.restorationPhase().toLowerCase(Locale.ROOT);
            }
            return label + ", phase " + pending.getOrEmpty("phase") + ", device "
                    + (device == null || device.trim().isEmpty()
                            ? "not recorded" : device.trim());
        } catch (Exception unreadable) {
            return "unreadable journal — export the log";
        }
    }

    /** True when the pending transaction predates device stamping (or cannot be read). */
    private boolean pendingDeviceUnstamped() {
        try {
            Journal pending = Journal.findPending(journalDirectory());
            if (pending == null) {
                return journalLookupError != null;
            }
            String device = pending.get("device_address");
            return device == null || device.trim().isEmpty();
        } catch (Exception unreadable) {
            return true;
        }
    }

    private static String humanKind(String kind) {
        if (Journal.KIND_JAILBREAK.equals(kind)) {
            return "jailbreak";
        }
        if (Journal.KIND_DEVELOPER_UPDATE.equals(kind)) {
            return "developer-key update";
        }
        if (Journal.KIND_STOCK_RESTORE.equals(kind)) {
            return "stock restore";
        }
        if (Journal.KIND_STOCK_PHASE1.equals(kind)) {
            return "stock restore, phase 1";
        }
        if (Journal.KIND_STOCK_PHASE2.equals(kind)) {
            return "stock restore, phase 2";
        }
        return kind.isEmpty() ? "unknown transaction" : kind;
    }

    private void enterPowerCycleCheckpoint(int token) {
        runOnUiThread(() -> {
            if (token != flashRunToken || !flashScreen) {
                return;
            }
            powerCycleRequired = true;
            powerCycleScreen = true;
            powerCycleLayoutPassPending = false;
            powerCycleLayoutMeasured = false;
            powerCycleState = POWER_CYCLE_WAITING_FOR_OFF;
            powerCycleError = null;
            powerCycleReconnectInProgress = false;
            powerCycleReconnectPending = false;
            flashStatus = "WAITING FOR POWER CYCLE";
            registerPowerCycleReceiver();
            renderStep();
        });
    }

    private void appendFlashLog(String line) {
        runOnUiThread(() -> {
            flashLog.append(line).append('\n');
            if (flashLogView != null && FlashLogText.displayLine(line) != null) {
                boolean followLatest = !stageScroll.canScrollVertically(1);
                flashLogView.setText(FlashLogText.forDisplay(flashLog));
                if (followLatest) {
                    positionFlashLog(-1);
                }
            }
        });
    }

    private void positionFlashLog(int scrollY) {
        TextView log = flashLogView;
        stageScroll.getViewTreeObserver().addOnPreDrawListener(
                new ViewTreeObserver.OnPreDrawListener() {
                    @Override public boolean onPreDraw() {
                        stageScroll.getViewTreeObserver().removeOnPreDrawListener(this);
                        if (flashLogView == log) {
                            int position = scrollY < 0 ? stage.getHeight() : scrollY;
                            stageScroll.scrollTo(0, position);
                        }
                        return true;
                    }
                });
    }

    private void finishFlashPreparation(int token, String status) {
        finishFlashPreparation(token, status, false);
    }

    private void finishFlashPreparation(int token, String status, boolean needsIdentity) {
        runOnUiThread(() -> {
            if (token != flashRunToken || !flashScreen) {
                return;
            }
            flashRunning = false;
            recoveryNeedsIdentity = needsIdentity;
            flashStatus = status;
            renderStep();
        });
    }

    private boolean isFlashFinished() {
        return "COMPLETE".equals(flashStatus)
                || FlashLogText.RESTART_REQUIRED.equals(flashStatus)
                || FlashLogText.UPDATE_REJECTED.equals(flashStatus);
    }

    private void setFooterWeights(float first, float second) {
        if (backButton != null) {
            LinearLayout.LayoutParams firstParams =
                    (LinearLayout.LayoutParams) backButton.getLayoutParams();
            if (firstParams != null) {
                firstParams.weight = first;
                backButton.setLayoutParams(firstParams);
            }
        }
        if (nextButton != null) {
            LinearLayout.LayoutParams secondParams =
                    (LinearLayout.LayoutParams) nextButton.getLayoutParams();
            if (secondParams != null) {
                secondParams.weight = second;
                nextButton.setLayoutParams(secondParams);
            }
        }
    }

    private void resetToStart() {
        flashRunToken++;
        unregisterPowerCycleReceiver();
        btr15.close();

        flashScreen = false;
        flashStarted = false;
        flashRunning = false;
        recoveryNeedsIdentity = false;
        returnToFirmwareForRecovery = false;
        powerCycleRequired = false;
        powerCycleScreen = false;
        powerCycleLayoutPassPending = false;
        powerCycleLayoutMeasured = false;
        powerCycleState = 0;
        powerCycleError = null;
        powerCycleReconnectInProgress = false;
        powerCycleReconnectPending = false;
        flashStatus = "READY";
        flashLog.setLength(0);
        flashLogView = null;

        step = STEP_FIRMWARE;
        firmwareUri = null;
        firmwareName = null;
        firmwareHash = null;
        firmwareVersion = null;
        firmwareRelease = null;
        firmwareBlockedReason = null;
        firmwareBytes = 0;
        readingFirmware = false;
        firmwareReadFailed = false;
        firmwareValidationError = null;

        existingMnemonic = "";
        identityError = null;
        loadSigningIdentityDefault();
        automute = false;
        demo100Hz = false;
        restoreStock = false;

        bondedDevices = Collections.emptyList();
        selectedDeviceAddress = null;
        connectingDevice = false;
        connectionError = null;
        connectionErrorDetail = null;
        diagnosticLog.setLength(0);
        renderStep();
    }

    private String usefulMessage(Exception error) {
        String message = error.getMessage();
        return message == null || message.trim().length() == 0
                ? error.getClass().getSimpleName() : message;
    }

    /** One ERROR line, plus the exact cure when the link itself was refused. */
    private void appendErrorLog(Exception error) {
        String message = usefulMessage(error);
        appendFlashLog("ERROR: " + message);
        if (message.indexOf("cannot reach the BTR15") < 0) {
            return;
        }
        appendFlashLog("Every dial was dropped the instant it connected — the BTR15 does this"
                + " while it still holds the interrupted upgrade session. Power the BTR15 off,"
                + " wait five seconds, then power it back on; the upgrade context lives in the"
                + " device's non-volatile memory and in the journal. Then press \"Recover"
                + " unfinished transaction\" — Recovery reads the device's context and"
                + " continues from the exact step that stopped.");
    }

    private void exportLog() {
        if (flashLog.length() == 0 && diagnosticLog.length() == 0) {
            return;
        }
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/plain");
        String stamp = new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date());
        intent.putExtra(Intent.EXTRA_TITLE, "btr15-" + stamp + ".txt");
        startActivityForResult(intent, CREATE_LOG);
    }

    private String exportedLog() {
        StringBuilder result = new StringBuilder();
        result.append("BTR15 Tool\n");
        result.append("Android ").append(Build.VERSION.RELEASE)
                .append(" (API ").append(Build.VERSION.SDK_INT).append(")\n");
        if (firmwareName != null) {
            result.append("Firmware file: ").append(firmwareName).append('\n');
            result.append("Firmware SHA-256: ").append(firmwareHash).append('\n');
        }
        if (diagnosticLog.length() > 0) {
            result.append("\nConnection log\n").append(diagnosticLog);
        }
        if (flashLog.length() > 0) {
            result.append("\nProcess log\n").append(FlashLogText.forExport(flashLog));
        }
        if (lastTranscript.length() > 0) {
            result.append("\nProtocol transcript (hex frames only)\n").append(lastTranscript);
        }
        return result.toString();
    }

    private void appendDiagnostic(String line) {
        diagnosticLog.append(line).append('\n');
    }

    private void openFirmwarePicker() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/octet-stream");
        startActivityForResult(intent, PICK_FIRMWARE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == ENABLE_BLUETOOTH) {
            if (!flashScreen && step == STEP_DEVICE) {
                renderStep();
            }
            return;
        }
        if (requestCode == CREATE_LOG) {
            if (resultCode == RESULT_OK && data != null && data.getData() != null) {
                try (OutputStream output = getContentResolver().openOutputStream(data.getData(), "w")) {
                    if (output == null) {
                        throw new IllegalStateException("File could not be opened");
                    }
                    output.write(exportedLog().getBytes(StandardCharsets.UTF_8));
                    Toast.makeText(this, "Log exported", Toast.LENGTH_SHORT).show();
                } catch (Exception error) {
                    Toast.makeText(this, "Log could not be exported", Toast.LENGTH_LONG).show();
                }
            }
            return;
        }
        if (requestCode != PICK_FIRMWARE || resultCode != RESULT_OK || data == null) {
            return;
        }
        Uri uri = data.getData();
        if (uri == null) {
            return;
        }
        try {
            int flags = data.getFlags() & Intent.FLAG_GRANT_READ_URI_PERMISSION;
            getContentResolver().takePersistableUriPermission(uri, flags);
        } catch (SecurityException ignored) {
            // The selected file remains usable for the current workflow.
        }
        firmwareUri = uri;
        firmwareName = displayName(uri);
        firmwareHash = null;
        firmwareVersion = null;
        firmwareRelease = null;
        firmwareBlockedReason = null;
        firmwareBytes = 0;
        firmwareReadFailed = false;
        firmwareValidationError = null;
        if (firmwareName == null
                || !firmwareName.toLowerCase(Locale.US).endsWith(".bin")) {
            firmwareReadFailed = true;
            firmwareValidationError = "Select a .bin firmware image.";
            readingFirmware = false;
            renderStep();
            return;
        }
        readingFirmware = true;
        renderStep();
        new Thread(() -> inspectFirmware(uri), "firmware-inspection").start();
    }

    private void inspectFirmware(Uri uri) {
        FirmwareInspection result = null;
        String validationError = null;
        try (InputStream input = getContentResolver().openInputStream(uri)) {
            result = inspectFirmwareStream(input);
        } catch (FirmwareInspector.InvalidFirmwareException error) {
            validationError = error.getMessage();
        } catch (Exception ignored) {
            // Render a user-facing read warning without exposing implementation details.
        }
        final FirmwareInspection inspected = result;
        final String inspectedError = validationError;
        runOnUiThread(() -> {
            readingFirmware = false;
            firmwareReadFailed = inspected == null;
            firmwareValidationError = inspectedError;
            firmwareBytes = inspected == null ? 0 : inspected.bytes;
            firmwareHash = inspected == null ? null : inspected.hash;
            firmwareVersion = inspected == null ? null : KNOWN_FIRMWARE.get(inspected.hash);
            firmwareRelease = inspected == null ? null : inspected.release;
            firmwareBlockedReason = inspected == null ? null : inspected.blockedReason;
            renderStep();
        });
    }

    private FirmwareInspection inspectFirmwareFile(Uri uri) throws Exception {
        if (uri == null) {
            throw new IllegalStateException("No firmware selected");
        }
        try (InputStream input = getContentResolver().openInputStream(uri)) {
            return inspectFirmwareStream(input);
        }
    }

    /**
     * Reading a package decides two things at once: what it is, and whether its
     * FiiO key block can be found and replaced at all.  A recognized release is
     * validated against its pinned profile; any other package is described from
     * its own bytes (FiiO signature + exactly one key block), and when even that
     * fails the reason travels to the screen so Continue can be refused.
     */
    private FirmwareInspection inspectFirmwareStream(InputStream input) throws Exception {
        byte[] data = readAll(input);
        FirmwareInspector.Result meta = FirmwareInspector.inspect(new ByteArrayInputStream(data));
        FirmwareReleases.Release release = null;
        String blockedReason = null;
        try {
            release = FirmwareReleases.describe(data);
        } catch (FirmwareException unusable) {
            blockedReason = unusable.getMessage();
        }
        return new FirmwareInspection(meta.hash, meta.bytes, release, blockedReason);
    }

    private byte[] readAll(InputStream input) throws Exception {
        return FirmwareRead.all(input);
    }

    private static final class FirmwareInspection {
        final String hash;
        final long bytes;
        final FirmwareReleases.Release release;
        final String blockedReason;

        FirmwareInspection(String hash, long bytes, FirmwareReleases.Release release,
                String blockedReason) {
            this.hash = hash;
            this.bytes = bytes;
            this.release = release;
            this.blockedReason = blockedReason;
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions,
            int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQUEST_BLUETOOTH) {
            if ((!flashScreen && step == STEP_DEVICE) || powerCycleScreen) {
                renderStep();
            }
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (stage != null && !flashScreen && step == STEP_DEVICE && !connectingDevice) {
            renderStep();
        } else if (stage != null && powerCycleScreen) {
            registerPowerCycleReceiver();
            renderStep();
        }
    }

    private String displayName(Uri uri) {
        try (Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int column = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (column >= 0) {
                    return cursor.getString(column);
                }
            }
        } catch (Exception ignored) {
            // Use the URI segment below.
        }
        String segment = uri.getLastPathSegment();
        return segment == null ? "Selected file" : segment;
    }

    private LinearLayout choiceRow(String value, boolean selected, View.OnClickListener listener) {
        return choiceRow(value, null, selected, true, listener);
    }

    private LinearLayout choiceRow(String value, boolean selected, boolean enabled,
            View.OnClickListener listener) {
        return choiceRow(value, null, selected, enabled, listener);
    }

    /** A row whose option needs a second, quieter line saying what it covers. */
    private LinearLayout choiceRow(String value, String note, boolean selected, boolean enabled,
            View.OnClickListener listener) {
        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setMinimumHeight(dp(52));
        row.setPadding(0, dp(8), 0, dp(8));
        row.setEnabled(enabled);
        row.setClickable(enabled);
        row.setFocusable(enabled);
        if (enabled) {
            row.setOnClickListener(listener);
        }
        View mark = new View(this);
        int markColor = selected && enabled ? BLACK : WHITE;
        int strokeColor = enabled ? BLACK : DISABLED_TEXT;
        mark.setBackground(rect(markColor, strokeColor, 1));
        row.addView(mark, new LinearLayout.LayoutParams(dp(18), dp(18)));
        TextView label = text(value, 16, enabled ? BLACK : DISABLED_TEXT, false);
        if (note == null) {
            label.setPadding(dp(12), 0, 0, 0);
            row.addView(label, new LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
            return row;
        }
        LinearLayout copy = new LinearLayout(this);
        copy.setOrientation(LinearLayout.VERTICAL);
        copy.setPadding(dp(12), 0, 0, 0);
        copy.addView(label);
        TextView subtext = text(note, 12, enabled ? MID : DISABLED_TEXT, false);
        subtext.setPadding(0, dp(4), 0, 0);
        copy.addView(subtext);
        row.addView(copy, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        return row;
    }

    private void heading(String value) {
        stage.addView(headingView(value));
    }

    private TextView headingView(String value) {
        TextView title = text(value, 25, BLACK, true);
        title.setPadding(0, 0, 0, dp(18));
        return title;
    }

    private void sectionLabel(String value) {
        TextView title = label(value);
        title.setPadding(0, dp(20), 0, dp(7));
        stage.addView(title);
    }

    private void property(String key, String value) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(0, dp(12), 0, dp(12));
        row.addView(label(key));
        TextView content = text(value == null ? "" : value, 16, BLACK, false);
        content.setTextIsSelectable(true);
        content.setPadding(0, dp(6), 0, 0);
        row.addView(content);
        stage.addView(row);
    }

    private void warning(String value) {
        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(16), 0, dp(8));
        View bar = new View(this);
        bar.setBackgroundColor(BLACK);
        row.addView(bar, new LinearLayout.LayoutParams(dp(4), dp(34)));
        TextView view = text(value, 14, BLACK, true);
        view.setPadding(dp(12), 0, 0, 0);
        row.addView(view, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        stage.addView(row);
    }

    private void muted(String value) {
        TextView view = text(value, NOTE_TEXT_SP, MID, false);
        view.setPadding(0, dp(12), 0, dp(12));
        stage.addView(view);
    }

    private TextView label(String value) {
        TextView view = text(value.toUpperCase(Locale.US), 11, MID, true);
        view.setLetterSpacing(0.12f);
        return view;
    }

    private TextView text(String value, int size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setTypeface(Typeface.create("sans-serif", bold ? Typeface.BOLD : Typeface.NORMAL));
        view.setIncludeFontPadding(false);
        return view;
    }

    private Button outlineButton(String value) {
        Button button = baseButton(value);
        button.setTextColor(BLACK);
        button.setBackground(rect(WHITE, BLACK, 1));
        return button;
    }

    private Button solidButton(String value) {
        Button button = baseButton(value);
        button.setTextColor(WHITE);
        button.setBackground(rect(BLACK, BLACK, 1));
        return button;
    }

    private Button baseButton(String value) {
        Button button = new Button(this);
        styleButton(button, value);
        return button;
    }

    private void styleButton(Button button, String value) {
        button.setText(value);
        button.setTextSize(13);
        button.setTypeface(Typeface.create("sans-serif", Typeface.BOLD));
        button.setAllCaps(false);
        button.setMinHeight(0);
        button.setMinWidth(0);
        button.setPadding(dp(12), 0, dp(12), 0);
    }

    private void setNextEnabled(boolean enabled) {
        nextButton.setEnabled(enabled);
        nextButton.setTextColor(enabled ? WHITE : MID);
        nextButton.setBackground(rect(enabled ? BLACK : DISABLED,
                enabled ? BLACK : DISABLED, 1));
    }

    private View rule(int color, int height) {
        View line = new View(this);
        line.setBackgroundColor(color);
        line.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(height)));
        return line;
    }

    private GradientDrawable rect(int fill, int stroke, int width) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setShape(GradientDrawable.RECTANGLE);
        drawable.setColor(fill);
        drawable.setCornerRadius(0);
        if (width > 0) {
            drawable.setStroke(dp(width), stroke);
        }
        return drawable;
    }

    private LinearLayout.LayoutParams fullWidth(int height, int topMargin) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, height);
        params.topMargin = topMargin;
        return params;
    }

    private LinearLayout.LayoutParams marginTop(int topMargin) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.topMargin = topMargin;
        return params;
    }

    private int wordCount(String words) {
        String trimmed = words == null ? "" : words.trim();
        return trimmed.length() == 0 ? 0 : trimmed.split("\\s+").length;
    }

    private String formatBytes(long bytes) {
        return String.format(Locale.US, "%.2f MB", bytes / 1048576.0);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
