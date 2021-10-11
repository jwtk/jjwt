package io.jsonwebtoken.impl.security;

import java.security.SecureRandom;

/**
 * @since JJWT_RELEASE_VERSION
 */
public final class Randoms {

    private static final SecureRandom DEFAULT_SECURE_RANDOM;

    static {
        DEFAULT_SECURE_RANDOM = new SecureRandom();
        DEFAULT_SECURE_RANDOM.nextBytes(new byte[64]);
    }

    private Randoms() {
    }

    /**
     * Returns JJWT's default SecureRandom number generator - a static singleton which may be cached if desired.
     * The RNG is initialized using the JVM default as follows:
     *
     * <pre><code>
     * static {
     *     DEFAULT_SECURE_RANDOM = new SecureRandom();
     *     DEFAULT_SECURE_RANDOM.nextBytes(new byte[64]);
     * }
     * </code></pre>
     *
     * <p><code>nextBytes</code> is called to force the RNG to initialize itself if not already initialized.  The
     * byte array is not used and discarded immediately for garbage collection.</p>
     *
     * @return JJWT's default SecureRandom number generator.
     */
    public static SecureRandom secureRandom() {
        return DEFAULT_SECURE_RANDOM;
    }
}
