package app.btr15.tool;

/** Every fail-closed refusal raised by the offline firmware engine. */
final class FirmwareException extends Exception {
    FirmwareException(String message) {
        super(message);
    }
}
