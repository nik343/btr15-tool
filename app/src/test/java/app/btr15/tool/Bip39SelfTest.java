package app.btr15.tool;

import java.util.HashSet;
import java.util.Set;

public final class Bip39SelfTest {
    public static void main(String[] args) {
        byte[] zero = new byte[16];
        String zeroMnemonic = Bip39.fromEntropy(zero);
        require(zeroMnemonic.equals(
                "abandon abandon abandon abandon abandon abandon abandon abandon "
                + "abandon abandon abandon about"), "zero-entropy vector mismatch");
        require(Bip39.isValid(zeroMnemonic), "known vector rejected");
        require(!Bip39.isValid(zeroMnemonic.replace("about", "abandon")),
                "bad checksum accepted");

        byte[] ones = new byte[16];
        for (int i = 0; i < ones.length; i++) {
            ones[i] = (byte) 0xFF;
        }
        String onesMnemonic = Bip39.fromEntropy(ones);
        require(onesMnemonic.equals(
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"),
                "all-ones vector mismatch");

        Set<String> generated = new HashSet<>();
        for (int i = 0; i < 128; i++) {
            String mnemonic = Bip39.generate();
            require(Bip39.isValid(mnemonic), "generated mnemonic rejected");
            require(generated.add(mnemonic), "duplicate generated mnemonic");
        }
        System.out.println("BIP-39 self-test passed (known vectors + 128 generated mnemonics)");
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
