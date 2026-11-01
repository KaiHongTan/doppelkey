package dev.doppelkey;

/** Raised when the keeper refuses or can't be reached. The message names the next command to run. */
public final class DoppelkeyException extends RuntimeException {
    private final String code;

    DoppelkeyException(String code, String message, String hint) {
        super("doppelkey: " + message.replaceAll("[.\\s]+$", "") + "." + advice(hint));
        this.code = code;
    }

    private static String advice(String hint) {
        if (hint == null) return "";
        return hint.startsWith("doppelkey ") ? " Run \"" + hint + "\"." : " " + hint;
    }

    public String code() { return code; }

    static DoppelkeyException unsupported(String what) {
        return new DoppelkeyException("unsupported", what + " is not supported with a doppelkey handle yet, so the call was refused instead of computing with the handle text", "If you need it, open an issue: https://github.com/KaiHongTan/doppelkey/issues");
    }
}
