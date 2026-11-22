package app.btr15.tool;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Encrypts the signing mnemonic at rest with a non-exportable Android Keystore key. */
final class MnemonicStore {
    private static final String PREFERENCES = "signing_identity_v1";
    private static final String CIPHERTEXT = "mnemonic_ciphertext";
    private static final String IV = "mnemonic_iv";
    private static final String DEVELOPER_UPDATE_CONFIRMED = "developer_update_confirmed";
    private static final String KEY_ALIAS = "btr15_signing_identity_v1";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private MnemonicStore() { }

    static synchronized String loadOrCreate(Context context) throws Exception {
        String stored = loadExisting(context);
        if (stored != null) {
            return stored;
        }
        String mnemonic = Bip39.generate();
        save(context, mnemonic);
        return mnemonic;
    }

    /** The stored mnemonic, or null when none exists; never creates one. */
    static synchronized String loadExisting(Context context) throws Exception {
        SharedPreferences preferences = preferences(context);
        String ciphertext = preferences.getString(CIPHERTEXT, null);
        String iv = preferences.getString(IV, null);
        if (ciphertext == null && iv == null) {
            return null;
        }
        if (ciphertext == null || iv == null) {
            throw new IllegalStateException("Signing identity storage is incomplete");
        }

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(),
                new GCMParameterSpec(128, Base64.decode(iv, Base64.NO_WRAP)));
        String mnemonic = new String(
                cipher.doFinal(Base64.decode(ciphertext, Base64.NO_WRAP)),
                StandardCharsets.UTF_8);
        if (!Bip39.isValid(mnemonic)) {
            throw new IllegalStateException("Stored signing identity is invalid");
        }
        return Bip39.normalize(mnemonic);
    }

    static synchronized String loadConfirmed(Context context) throws Exception {
        if (!preferences(context).getBoolean(DEVELOPER_UPDATE_CONFIRMED, false)) {
            return null;
        }
        return loadExisting(context);
    }

    static synchronized void setDeveloperUpdateConfirmed(
            Context context, String mnemonic, boolean confirmed) throws Exception {
        SharedPreferences preferences = preferences(context);
        if (preferences.getBoolean(DEVELOPER_UPDATE_CONFIRMED, false) == confirmed
                || !mnemonic.equals(loadExisting(context))) {
            return;
        }
        if (!preferences.edit().putBoolean(DEVELOPER_UPDATE_CONFIRMED, confirmed).commit()) {
            throw new IllegalStateException("Signing identity preference could not be saved");
        }
    }

    static synchronized void save(Context context, String mnemonic) throws Exception {
        String normalized = Bip39.normalize(mnemonic);
        if (!Bip39.isValid(normalized)) {
            throw new IllegalArgumentException("Invalid 12-word BIP-39 mnemonic");
        }
        boolean confirmed;
        try {
            confirmed = normalized.equals(loadConfirmed(context));
        } catch (Exception unavailable) {
            // An entered backup can replace a mnemonic that can no longer be decrypted.
            confirmed = false;
        }
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey());
        String ciphertext = Base64.encodeToString(
                cipher.doFinal(normalized.getBytes(StandardCharsets.UTF_8)), Base64.NO_WRAP);
        String iv = Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP);
        boolean committed = preferences(context).edit()
                .putString(CIPHERTEXT, ciphertext)
                .putString(IV, iv)
                .putBoolean(DEVELOPER_UPDATE_CONFIRMED, confirmed)
                .commit();
        if (!committed) {
            throw new IllegalStateException("Signing identity could not be saved");
        }
    }

    private static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE);
    }

    private static SecretKey getOrCreateKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(KEY_ALIAS)) {
            return (SecretKey) keyStore.getKey(KEY_ALIAS, null);
        }
        KeyGenerator generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build());
        return generator.generateKey();
    }
}
