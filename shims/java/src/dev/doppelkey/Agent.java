package dev.doppelkey;

import java.lang.instrument.Instrumentation;
import java.security.Security;

/**
 * Java agent entry: JAVA_TOOL_OPTIONS="-javaagent:/path/doppelkey-agent.jar". Installs the
 * Doppelkey JCA provider first, so Mac/Cipher/SecretKeyFactory calls made with a handle key run
 * in the keeper; every other key falls through to the JDK's own providers. Apps can also call
 * Agent.install() themselves.
 */
public final class Agent {
    private Agent() {}

    public static void premain(String args, Instrumentation inst) { install(); }
    public static void agentmain(String args, Instrumentation inst) { install(); }

    public static synchronized void install() {
        if ("off".equals(System.getenv("DOPPELKEY_SHIM"))) return;
        if (Security.getProvider("Doppelkey") == null) Security.insertProviderAt(new DoppelkeyProvider(), 1);
    }
}
