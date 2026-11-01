# doppelkey (Java agent)

A Java agent that installs a JCA provider, `Doppelkey`, ahead of the JDK's own. Zero dependencies, Java 16+.

```bash
JAVA_TOOL_OPTIONS="-javaagent:/path/to/doppelkey-agent.jar" ./mvnw spring-boot:run
# or: doppelkey run -- ./gradlew bootRun    (eval "$(doppelkey env)" prints the variable)
```

| JCA engine | Algorithms | With a handle key |
| --- | --- | --- |
| `Mac` | HmacSHA1/256/384/512 | keeper `hmac` |
| `Cipher` | AES/GCM/NoPadding, AES/CBC/PKCS5Padding, AES/CBC/NoPadding | keeper `aes_gcm` / `aes_cbc` |
| `SecretKeyFactory` | PBKDF2WithHmacSHA1/256/384/512 | a key whose bytes are a new handle |

**How non-handle keys stay untouched.** `Mac` and `Cipher` choose their provider when `init(key)` is called. The Doppelkey engines throw `InvalidKeyException` for any key that isn't a handle, so the JDK moves on to its normal provider. The PBKDF2 factory delegates non-handle passwords to SunJCE. Libraries built on JCA (Spring Security, jjwt, Nimbus JOSE) work unchanged, as long as they don't pin a provider by name.

**Limits.** An app that requests a provider explicitly (`Mac.getInstance("HmacSHA256", "SunJCE")`) bypasses the agent. Oracle JDK builds may require JCE providers to be signed; OpenJDK builds (Temurin, Corretto, distro packages) do not.

Build: `sh build.sh` → `dist/doppelkey-agent.jar`.
